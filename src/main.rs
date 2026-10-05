//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

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
    DEFAULT_QUEUE_CAPACITY, DeliverySeries, MetricsInventory, MetricsServer, NotificationQueue,
    NotificationWorker, NotifierRegistry, NotifierSeries, RuleEngine, RuleSourceSeries,
    SHUTDOWN_DRAIN_TIMEOUT, await_worker_drain, build_http_client, run_preflight,
};

/// Initialize the tracing subscriber with the specified log format.
///
/// - `LogFormat::Text`: Human-readable format for journalctl (AD-10)
/// - `LogFormat::Json`: Structured JSON format for log aggregation (FR42)
fn init_logging(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    match format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
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

fn main() -> Result<()> {
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
    let runtime_config = config.compile(&cli.config)?;

    // Validate mode: run the same preflight checks as the daemon startup,
    // display a summary and exit without starting anything.
    if cli.validate {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(async {
            anyhow::Ok(run_preflight(&runtime_config, build_http_client()?)?)
        })?;
        print_validation_summary(&cli.config, &runtime_config, &report.registry);
        return Ok(());
    }

    info!(config_path = %cli.config.display(), "valerter starting");

    // Create tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Run the main async function
    runtime.block_on(run(runtime_config))
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

/// Build the metric series inventory seeded at startup.
///
/// Multi-source observability (v2.0.0 part 2): every per-rule metric also
/// carries `vl_source`, so one pair per `(enabled rule, resolved source)`, with
/// the same fan-out as the engine: empty `vl_sources` means every configured
/// source, a non-empty list restricts to the named, declared sources. Each
/// pair is crossed with the rule destinations, typed through the registry.
fn build_metrics_inventory(
    config: &RuntimeConfig,
    registry: &NotifierRegistry,
) -> MetricsInventory {
    let sources: Vec<String> = config.victorialogs.keys().cloned().collect();
    let mut inventory = MetricsInventory {
        sources,
        ..MetricsInventory::default()
    };

    for rule in config.rules.iter().filter(|r| r.enabled) {
        let rule_sources = inventory
            .sources
            .iter()
            .filter(|s| rule.vl_sources.is_empty() || rule.vl_sources.contains(s));
        for vl_source in rule_sources {
            inventory.rule_sources.push(RuleSourceSeries {
                rule_name: rule.name.clone(),
                vl_source: vl_source.clone(),
                regex_parser: rule.parser.regex.is_some(),
            });
            // Destinations missing from the registry were rejected by the
            // preflight checks.
            for (notifier_name, notifier) in rule
                .notify
                .destinations
                .iter()
                .filter_map(|d| registry.get(d).map(|n| (d, n)))
            {
                inventory.deliveries.push(DeliverySeries {
                    rule_name: rule.name.clone(),
                    vl_source: vl_source.clone(),
                    notifier_name: notifier_name.clone(),
                    notifier_type: notifier.notifier_type().to_string(),
                });
            }
        }
    }

    let mut notifiers: Vec<NotifierSeries> = registry
        .names()
        .filter_map(|name| {
            registry.get(name).map(|n| NotifierSeries {
                name: name.to_string(),
                notifier_type: n.notifier_type().to_string(),
            })
        })
        .collect();
    notifiers.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    inventory.notifiers = notifiers;
    inventory
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
        if ready_rx.await.is_err() {
            error!("Metrics recorder failed to initialize");
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
        Err(e) => {
            error!(error = %e, "Engine error");
            Err(anyhow::anyhow!("Engine error: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // build_metrics_inventory

    /// Notifier stub: only its name and type matter to the inventory.
    struct StubNotifier(&'static str, &'static str);

    #[async_trait::async_trait]
    impl valerter::Notifier for StubNotifier {
        fn name(&self) -> &str {
            self.0
        }
        fn notifier_type(&self) -> &str {
            self.1
        }
        async fn send(
            &self,
            _alert: &valerter::AlertPayload,
        ) -> Result<(), valerter::error::NotifyError> {
            Ok(())
        }
    }

    fn inventory_rule(
        name: &str,
        enabled: bool,
        vl_sources: &[&str],
        destinations: &[&str],
        regex: Option<&str>,
    ) -> valerter::config::CompiledRule {
        use valerter::config::{CompiledParser, CompiledRule, JsonParserConfig, NotifyConfig};
        CompiledRule {
            name: name.to_string(),
            enabled,
            query: "_stream:test".to_string(),
            parser: CompiledParser {
                regex: regex.map(|r| regex::Regex::new(r).unwrap()),
                json: regex.is_none().then(|| JsonParserConfig {
                    fields: vec!["_msg".to_string()],
                }),
            },
            throttle: None,
            notify: NotifyConfig {
                template: "tpl".to_string(),
                mattermost_channel: None,
                destinations: destinations.iter().map(|d| d.to_string()).collect(),
            },
            vl_sources: vl_sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn inventory_config(rules: Vec<valerter::config::CompiledRule>) -> RuntimeConfig {
        use valerter::config::{
            DEFAULT_MAX_STREAMS, DefaultsConfig, MetricsConfig, ThrottleConfig, VlSourceConfig,
        };
        let source = |url: &str| VlSourceConfig {
            url: url.to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        };
        RuntimeConfig {
            victorialogs: [
                ("vldev".to_string(), source("http://vldev:9428")),
                ("vlprod".to_string(), source("http://vlprod:9428")),
                ("vlstaging".to_string(), source("http://vlstaging:9428")),
            ]
            .into_iter()
            .collect(),
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                timestamp_timezone: "UTC".to_string(),
                max_streams: DEFAULT_MAX_STREAMS,
            },
            templates: std::collections::HashMap::new(),
            rules,
            metrics: MetricsConfig::default(),
            notifiers: None,
            config_dir: std::path::PathBuf::from("."),
        }
    }

    #[test]
    fn metrics_inventory_crosses_rule_sources_with_typed_destinations() {
        let config = inventory_config(vec![
            inventory_rule(
                "errors",
                true,
                &["vlprod", "vldev"],
                &["hook", "mail"],
                Some(r"(?P<x>.*)"),
            ),
            inventory_rule("off", false, &[], &["idle"], None),
        ]);
        let mut registry = NotifierRegistry::new();
        for (name, kind) in [("hook", "webhook"), ("mail", "email"), ("idle", "telegram")] {
            registry
                .register(Arc::new(StubNotifier(name, kind)))
                .unwrap();
        }

        let inventory = build_metrics_inventory(&config, &registry);

        assert_eq!(inventory.sources, ["vldev", "vlprod", "vlstaging"]);
        let pairs: Vec<_> = inventory
            .rule_sources
            .iter()
            .map(|p| (p.rule_name.as_str(), p.vl_source.as_str(), p.regex_parser))
            .collect();
        assert_eq!(
            pairs,
            [("errors", "vldev", true), ("errors", "vlprod", true)],
            "the disabled rule gets no series"
        );
        let deliveries: Vec<_> = inventory
            .deliveries
            .iter()
            .map(|d| {
                (
                    d.vl_source.as_str(),
                    d.notifier_name.as_str(),
                    d.notifier_type.as_str(),
                )
            })
            .collect();
        assert_eq!(
            deliveries,
            [
                ("vldev", "hook", "webhook"),
                ("vldev", "mail", "email"),
                ("vlprod", "hook", "webhook"),
                ("vlprod", "mail", "email"),
            ]
        );
        assert!(
            inventory
                .deliveries
                .iter()
                .all(|d| d.notifier_name != "idle"),
            "a notifier used by no enabled rule gets no delivery series"
        );
        let notifiers: Vec<_> = inventory
            .notifiers
            .iter()
            .map(|n| (n.name.as_str(), n.notifier_type.as_str()))
            .collect();
        assert_eq!(
            notifiers,
            [("hook", "webhook"), ("idle", "telegram"), ("mail", "email")]
        );
    }

    #[test]
    fn metrics_inventory_fans_out_empty_vl_sources_to_every_source() {
        let config = inventory_config(vec![inventory_rule("all", true, &[], &[], None)]);

        let inventory = build_metrics_inventory(&config, &NotifierRegistry::new());

        let pairs: Vec<_> = inventory
            .rule_sources
            .iter()
            .map(|p| (p.vl_source.as_str(), p.regex_parser))
            .collect();
        assert_eq!(
            pairs,
            [("vldev", false), ("vlprod", false), ("vlstaging", false)]
        );
        assert!(inventory.deliveries.is_empty());
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
