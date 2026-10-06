//! Valerter - Real-time alerting from VictoriaLogs to Mattermost, Telegram, email or webhooks.

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};

use valerter::cli::{Cli, LogFormat};
use valerter::config::{Config, RuntimeConfig, redact_url};
use valerter::{
    DEFAULT_QUEUE_CAPACITY, MetricsServer, NotificationQueue, NotificationWorker, NotifierRegistry,
    RuleEngine, SHUTDOWN_DRAIN_TIMEOUT, await_worker_drain, build_http_client,
    build_metrics_inventory, run_preflight,
};

/// Whether text logs carry ANSI colors: only when stderr is a terminal
/// (journald and log files would store the escape codes as is), and never
/// when `NO_COLOR` is set to a non-empty value.
fn ansi_colors(stderr_is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    stderr_is_terminal && no_color.is_none_or(|value| value.is_empty())
}

/// Initialize the tracing subscriber with the specified log format.
///
/// - `LogFormat::Text`: Human-readable format for journalctl (AD-10), colored
///   only on a terminal ([`ansi_colors`])
/// - `LogFormat::Json`: Structured JSON format for log aggregation (FR42)
fn init_logging(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    match format {
        LogFormat::Text => {
            let ansi = ansi_colors(
                std::io::stderr().is_terminal(),
                std::env::var_os("NO_COLOR").as_deref(),
            );
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(ansi)
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .flatten_event(true)
                .with_env_filter(filter)
                .init();
        }
    }
}

/// Shutdown signal received by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownSignal {
    /// SIGINT (Ctrl+C); Ctrl+C on non-Unix platforms.
    Interrupt,
    /// SIGTERM (systemd stop).
    #[cfg_attr(not(unix), allow(dead_code))]
    Terminate,
}

/// Source of shutdown signals, abstracted so that the two-stage handler can
/// be tested without sending real signals.
trait SignalSource {
    /// Wait for the next signal. `None` means no further signal can be
    /// received.
    async fn next(&mut self) -> Option<ShutdownSignal>;
}

/// SIGINT and SIGTERM handlers, created once for the daemon lifetime so
/// that no signal is lost between two waits.
#[cfg(unix)]
struct UnixSignals {
    sigint: Signal,
    sigterm: Signal,
}

#[cfg(unix)]
impl UnixSignals {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }
}

#[cfg(unix)]
impl SignalSource for UnixSignals {
    async fn next(&mut self) -> Option<ShutdownSignal> {
        tokio::select! {
            s = self.sigint.recv() => s.map(|()| ShutdownSignal::Interrupt),
            s = self.sigterm.recv() => s.map(|()| ShutdownSignal::Terminate),
        }
    }
}

/// Ctrl+C listener used on non-Unix platforms.
#[cfg(not(unix))]
struct CtrlCSignals;

#[cfg(not(unix))]
impl SignalSource for CtrlCSignals {
    async fn next(&mut self) -> Option<ShutdownSignal> {
        match tokio::signal::ctrl_c().await {
            Ok(()) => Some(ShutdownSignal::Interrupt),
            Err(e) => {
                error!(error = %e, "Failed to listen for ctrl-c signal");
                None
            }
        }
    }
}

/// Two-stage shutdown signal handler (FR46).
///
/// The first signal starts the graceful shutdown by cancelling `cancel`. A
/// second signal (SIGINT or SIGTERM, in any order) calls `exit(1)` to force
/// an immediate exit, whatever the shutdown phase.
async fn handle_shutdown_signals(
    mut signals: impl SignalSource,
    cancel: CancellationToken,
    exit: impl FnOnce(i32),
) {
    let Some(first) = signals.next().await else {
        return;
    };
    match first {
        #[cfg(unix)]
        ShutdownSignal::Interrupt => info!("Received SIGINT (Ctrl+C)"),
        #[cfg(not(unix))]
        ShutdownSignal::Interrupt => info!("Received shutdown signal (Ctrl+C)"),
        ShutdownSignal::Terminate => info!("Received SIGTERM"),
    }
    info!("Initiating graceful shutdown");
    cancel.cancel();

    if signals.next().await.is_some() {
        warn!("Second shutdown signal received, forcing immediate exit");
        exit(1);
    }
}

/// Longest wait, when the process ends, for blocking tasks still running in
/// the runtime (e.g. a DNS resolution stuck in the blocking pool).
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Log a fatal error through the configured log format and exit with code 1.
///
/// Every fatal error goes through here, so the process never prints an
/// unstructured `Error: ...` line (which `main() -> Result` would).
fn fatal(err: anyhow::Error) -> ! {
    error!("{err:#}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing subscriber with configured log format (AD-10, FR42)
    init_logging(cli.log_format);

    info!(config_path = %cli.config.display(), "Loading configuration");

    // Load configuration
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, path = %cli.config.display(), "Failed to load configuration");
            std::process::exit(1);
        }
    };

    // Validate configuration (AD-11: fail-fast)
    info!("Validating configuration");
    if let Err(errors) = config.validate() {
        for e in &errors {
            error!(error = %e, "Configuration validation error");
        }
        error!(
            error_count = errors.len(),
            "Configuration validation failed"
        );
        std::process::exit(1);
    }

    // Compile configuration for runtime (FR15)
    let runtime_config = config
        .compile(&cli.config)
        .unwrap_or_else(|e| fatal(e.into()));

    // Validate mode: run the same preflight checks as the daemon startup,
    // display a summary and exit without starting anything.
    if cli.validate {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| fatal(e.into()));
        let result = runtime
            .block_on(async { anyhow::Ok(run_preflight(&runtime_config, build_http_client()?)?) });
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
        let report = result.unwrap_or_else(|e| fatal(e));
        print_validation_summary(&cli.config, &runtime_config, &report.registry);
        return;
    }

    info!(config_path = %cli.config.display(), "valerter starting");

    // Create tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal(e.into()));

    // Run the main async function, then bound the runtime teardown: a task
    // stuck in the blocking pool must not delay the exit.
    let result = runtime.block_on(run(runtime_config));
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    if let Err(e) = result {
        fatal(e);
    }
}

/// Print the `--validate` success summary on stdout.
///
/// Source URLs are redacted: they may embed credentials or tokens.
fn print_validation_summary(
    config_path: &std::path::Path,
    config: &RuntimeConfig,
    registry: &NotifierRegistry,
) {
    println!("Configuration is valid: {}", config_path.display());
    println!(
        "  VictoriaLogs sources: {} [{}]",
        config.victorialogs.len(),
        config
            .victorialogs
            .iter()
            .map(|(name, src)| format!("{}={}", name, redact_url(&src.url)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Rules: {} ({} enabled)",
        config.rules.len(),
        config.rules.iter().filter(|r| r.enabled).count()
    );
    println!("  Templates: {}", config.templates.len());
    let mut notifiers: Vec<(&str, String)> = registry
        .names()
        .filter_map(|name| {
            registry
                .get(name)
                .map(|n| (name, n.notifier_type().to_string()))
        })
        .collect();
    notifiers.sort_unstable();
    println!(
        "  Notifiers: {} [{}]",
        notifiers.len(),
        notifiers
            .iter()
            .map(|(name, kind)| format!("{}={}", name, kind))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Metrics: {} (port {})",
        if config.metrics.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.metrics.port
    );
}

/// Main async entry point.
async fn run(runtime_config: RuntimeConfig) -> Result<()> {
    // Capture start time for uptime metric
    let start_time = Instant::now();

    // Create shared HTTP client for connection pooling (AD-03)
    let http_client = build_http_client()?;

    // Build notifiers and check rule destinations and email templates
    // (same checks as --validate, every error reported before exiting)
    let report = run_preflight(&runtime_config, http_client.clone())?;

    let registry = Arc::new(report.registry);

    // Create one notification queue per notifier (FR32: capacity 100 each)
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY, &registry);

    // Create notification worker with registry
    let mut worker = NotificationWorker::new(&queue, registry.clone());

    // Create cancellation token for graceful shutdown: it stops the rule
    // tasks, the metrics server and the uptime updater.
    let cancel = CancellationToken::new();
    // Separate token for the notification worker, cancelled only once every
    // rule task has stopped, so that it drains queues that can no longer grow.
    let drain = CancellationToken::new();

    // Every label combination to seed at startup, and the per-destination
    // queue series of every notifier.
    let inventory = build_metrics_inventory(&runtime_config, &registry);
    let destinations: Vec<(&str, &str)> = inventory
        .notifiers
        .iter()
        .map(|n| (n.name.as_str(), n.notifier_type.as_str()))
        .collect();

    // Start metrics server if enabled (FR37)
    let metrics_handle = if runtime_config.metrics.enabled {
        // Create a channel to signal when the recorder is ready
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = MetricsServer::with_ready_signal(runtime_config.metrics.port, ready_tx);
        let cancel_metrics = cancel.clone();
        info!(
            port = runtime_config.metrics.port,
            "Starting metrics server"
        );
        let handle = tokio::spawn(async move {
            if let Err(e) = server.run(cancel_metrics).await {
                error!(error = %e, "Metrics server error");
            }
        });

        // Wait for the recorder to be installed before emitting any metrics
        // This fixes the race condition where metrics were lost if emitted
        // before the Prometheus recorder was ready
        // (logged once by `fatal`)
        if ready_rx.await.is_err() {
            return Err(anyhow::anyhow!("Metrics recorder failed to initialize"));
        }

        // Initialize all known metrics to zero now that recorder is ready
        valerter::initialize_metrics(&inventory);
        valerter::initialize_destination_metrics(&destinations);

        Some(handle)
    } else {
        info!("Metrics server disabled");
        None
    };

    // Start uptime metric updater (updates every 15 seconds)
    let uptime_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = uptime_cancel.cancelled() => break,
                _ = interval.tick() => {
                    let uptime = start_time.elapsed().as_secs_f64();
                    metrics::gauge!("valerter_uptime_seconds").set(uptime);
                }
            }
        }
    });

    // Create rule engine
    let engine = RuleEngine::new(runtime_config, http_client, queue.clone());

    // Setup signal handler for graceful shutdown (FR46: SIGTERM support for
    // systemd); a second signal forces an immediate exit.
    #[cfg(unix)]
    let signals = UnixSignals::new()?;
    #[cfg(not(unix))]
    let signals = CtrlCSignals;
    tokio::spawn(handle_shutdown_signals(signals, cancel.clone(), |code| {
        std::process::exit(code)
    }));

    // Spawn notification worker
    let worker_drain = drain.clone();
    let worker_handle = tokio::spawn(async move {
        worker.run(worker_drain).await;
    });

    // Run the engine until cancelled
    let engine_cancel = cancel.clone();
    let engine_result = engine.run(engine_cancel).await;

    // Whatever made the engine return (signal, no task, all tasks stopped),
    // stop the metrics server and uptime updater now instead of letting the
    // timeout below expire. Idempotent after a signal.
    cancel.cancel();

    // Every rule task has stopped: no alert can be queued anymore. Drain the
    // queues, within the bounded shutdown budget.
    drain.cancel();
    await_worker_drain(worker_handle, &queue, SHUTDOWN_DRAIN_TIMEOUT).await;

    // Wait for metrics server to finish
    if let Some(handle) = metrics_handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    match engine_result {
        Ok(()) => {
            info!("valerter shutdown complete");
            Ok(())
        }
        // Logged once by `fatal`.
        Err(e) => Err(anyhow::anyhow!("Engine error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_colors_only_on_a_terminal_without_no_color() {
        use std::ffi::OsStr;
        assert!(ansi_colors(true, None));
        assert!(ansi_colors(true, Some(OsStr::new(""))));
        assert!(!ansi_colors(true, Some(OsStr::new("1"))));
        // journald, a pipe or a file: never colored.
        assert!(!ansi_colors(false, None));
        assert!(!ansi_colors(false, Some(OsStr::new(""))));
    }

    /// Test that cancellation token triggers proper shutdown behavior.
    /// This validates the core shutdown mechanism used by signal handlers.
    #[tokio::test]
    async fn shutdown_cancellation_token_works() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Spawn a task that simulates receiving a shutdown signal
        let handle = tokio::spawn(async move {
            // Small delay to simulate async signal arrival
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_clone.cancel();
        });

        // Wait for cancellation
        cancel.cancelled().await;
        handle.await.unwrap();

        assert!(cancel.is_cancelled());
    }

    /// Test that multiple cancellation clones all see the cancellation.
    #[tokio::test]
    async fn cancellation_propagates_to_all_clones() {
        let cancel = CancellationToken::new();
        let cancel1 = cancel.clone();
        let cancel2 = cancel.clone();
        let cancel3 = cancel.clone();

        // Cancel the original
        cancel.cancel();

        // All clones should see the cancellation
        assert!(cancel1.is_cancelled());
        assert!(cancel2.is_cancelled());
        assert!(cancel3.is_cancelled());
    }

    /// Test that the SIGINT and SIGTERM handlers used by the daemon can be
    /// created.
    #[cfg(unix)]
    #[tokio::test]
    async fn signal_handlers_can_be_created() {
        assert!(
            UnixSignals::new().is_ok(),
            "Should be able to create SIGINT and SIGTERM handlers"
        );
    }

    /// Simulated signal source: one channel message per signal.
    impl SignalSource for tokio::sync::mpsc::UnboundedReceiver<ShutdownSignal> {
        async fn next(&mut self) -> Option<ShutdownSignal> {
            self.recv().await
        }
    }

    /// Spawn the two-stage handler on a simulated source. Returns the signal
    /// sender, the shutdown token, the exit-code receiver and the task.
    fn spawn_signal_handler() -> (
        tokio::sync::mpsc::UnboundedSender<ShutdownSignal>,
        CancellationToken,
        tokio::sync::mpsc::UnboundedReceiver<i32>,
        tokio::task::JoinHandle<()>,
    ) {
        let (signal_tx, signal_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(handle_shutdown_signals(
            signal_rx,
            cancel.clone(),
            move |code| {
                let _ = exit_tx.send(code);
            },
        ));
        (signal_tx, cancel, exit_rx, handle)
    }

    #[tokio::test]
    async fn first_signal_cancels_without_exiting() {
        let (signals, cancel, mut exit, handle) = spawn_signal_handler();

        signals.send(ShutdownSignal::Terminate).unwrap();
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("first signal must start the graceful shutdown");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(exit.try_recv().is_err(), "first signal must not exit");
        assert!(
            !handle.is_finished(),
            "handler keeps waiting for a second signal"
        );
    }

    #[tokio::test]
    async fn second_signal_forces_exit_with_code_1() {
        for (first, second) in [
            (ShutdownSignal::Terminate, ShutdownSignal::Terminate),
            (ShutdownSignal::Interrupt, ShutdownSignal::Terminate),
            (ShutdownSignal::Terminate, ShutdownSignal::Interrupt),
        ] {
            let (signals, cancel, mut exit, handle) = spawn_signal_handler();

            signals.send(first).unwrap();
            signals.send(second).unwrap();

            let code = tokio::time::timeout(Duration::from_secs(1), exit.recv())
                .await
                .expect("second signal must force the exit");
            assert_eq!(code, Some(1));
            assert!(cancel.is_cancelled());
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn closed_signal_source_stops_handler_without_exiting() {
        let (signals, cancel, mut exit, handle) = spawn_signal_handler();

        signals.send(ShutdownSignal::Interrupt).unwrap();
        drop(signals);

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("handler stops when no signal can be received")
            .unwrap();
        assert!(cancel.is_cancelled());
        assert!(exit.try_recv().is_err());
    }

    /// Test the full shutdown flow with cancellation token integration.
    /// This validates that when shutdown_signal would complete, the cancel
    /// token is properly triggered (simulated via direct cancellation).
    #[tokio::test]
    async fn shutdown_flow_cancels_all_tasks() {
        use tokio::time::timeout;

        let cancel = CancellationToken::new();

        // Simulate multiple running tasks
        let cancel1 = cancel.clone();
        let task1 = tokio::spawn(async move {
            cancel1.cancelled().await;
            "task1_done"
        });

        let cancel2 = cancel.clone();
        let task2 = tokio::spawn(async move {
            cancel2.cancelled().await;
            "task2_done"
        });

        // Simulate signal handler triggering cancellation
        let cancel_trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_trigger.cancel();
        });

        // All tasks should complete after cancellation
        let result1 = timeout(Duration::from_secs(1), task1).await;
        let result2 = timeout(Duration::from_secs(1), task2).await;

        assert!(result1.is_ok(), "task1 should complete after cancel");
        assert!(result2.is_ok(), "task2 should complete after cancel");
        assert_eq!(result1.unwrap().unwrap(), "task1_done");
        assert_eq!(result2.unwrap().unwrap(), "task2_done");
    }
}
