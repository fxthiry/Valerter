//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

use valerter::cli::{Cli, LogFormat};
use valerter::config::{Config, RuntimeConfig};
use valerter::{
    DEFAULT_QUEUE_CAPACITY, MattermostNotifier, MetricsServer, NotificationQueue,
    NotificationWorker, NotifierRegistry, RuleEngine,
};

/// Initialize the tracing subscriber with the specified log format.
///
/// - `LogFormat::Text`: Human-readable format for journalctl (AD-10)
/// - `LogFormat::Json`: Structured JSON format for log aggregation (FR42)
fn init_logging(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into());

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

/// Wait for a shutdown signal (SIGINT or SIGTERM on Unix, ctrl_c on other platforms).
///
/// On Unix systems, listens for both SIGINT (Ctrl+C) and SIGTERM (systemd stop).
/// On other platforms, only listens for ctrl_c.
#[cfg(unix)]
async fn shutdown_signal() {
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT (Ctrl+C)");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM");
        }
    }
}

/// Wait for a shutdown signal (ctrl_c only on non-Unix platforms).
#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!(error = %e, "Failed to listen for ctrl-c signal");
        return;
    }
    info!("Received shutdown signal (Ctrl+C)");
}

/// Create notifier registry from configuration (Story 6.2).
///
/// Supports two modes with backward compatibility:
/// 1. New: `notifiers:` section in YAML configuration
/// 2. Legacy: `MATTERMOST_WEBHOOK` environment variable
///
/// # Priority
///
/// If both are present, `notifiers:` takes precedence and `MATTERMOST_WEBHOOK`
/// is ignored (with a warning logged).
///
/// # Returns
///
/// * `Ok((registry, default_notifier_name))` - Registry and the name of the first notifier
/// * `Err` - No notifiers configured
fn create_notifier_registry(
    config: &RuntimeConfig,
    http_client: reqwest::Client,
) -> Result<(NotifierRegistry, String)> {
    // Priority 1: Check for notifiers: section in config
    if let Some(notifiers_config) = &config.notifiers
        && !notifiers_config.is_empty()
    {
        // Warn if legacy MATTERMOST_WEBHOOK is also set
        if config.mattermost_webhook.is_some() {
            tracing::warn!(
                "Both 'notifiers:' section and MATTERMOST_WEBHOOK are configured. \
                 Using 'notifiers:' section, MATTERMOST_WEBHOOK is ignored."
            );
        }

        // Create registry from config
        let registry =
            NotifierRegistry::from_config(notifiers_config, http_client).map_err(|errors| {
                for e in &errors {
                    error!(error = %e, "Notifier configuration error");
                }
                anyhow::anyhow!("Failed to create notifiers: {} errors", errors.len())
            })?;

        // Use first notifier alphabetically as default for deterministic behavior (Fix L3)
        let default_name = registry
            .names()
            .min()
            .expect("notifiers_config is not empty")
            .to_string();

        info!(
            notifier_count = registry.len(),
            default_notifier = %default_name,
            "Created notifiers from config"
        );

        return Ok((registry, default_name));
    }

    // Priority 2: Fallback to legacy MATTERMOST_WEBHOOK
    if let Some(webhook_url) = &config.mattermost_webhook {
        let mut registry = NotifierRegistry::new();
        let mattermost =
            MattermostNotifier::new("default".to_string(), webhook_url.clone(), http_client);
        registry
            .register(Arc::new(mattermost))
            .expect("Failed to register default notifier");
        info!("Registered default Mattermost notifier from MATTERMOST_WEBHOOK");
        return Ok((registry, "default".to_string()));
    }

    // No notifiers configured
    error!(
        "No notifiers configured. Either:\n\
         - Add a 'notifiers:' section to your config file, or\n\
         - Set the MATTERMOST_WEBHOOK environment variable"
    );
    Err(anyhow::anyhow!("No notifiers configured"))
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

    // Validate mode: display success and exit
    if cli.validate {
        println!("Configuration is valid: {}", cli.config.display());
        println!("  VictoriaLogs URL: {}", config.victorialogs.url);
        println!(
            "  Rules: {} ({} enabled)",
            config.rules.len(),
            config.rules.iter().filter(|r| r.enabled).count()
        );
        println!("  Templates: {}", config.templates.len());
        println!(
            "  Metrics: {} (port {})",
            if config.metrics.enabled {
                "enabled"
            } else {
                "disabled"
            },
            config.metrics.port
        );
        return Ok(());
    }

    // Compile configuration for runtime (FR15)
    let runtime_config = config.compile()?;

    info!(config_path = %cli.config.display(), "valerter starting");

    // Create tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Run the main async function
    runtime.block_on(run(runtime_config))
}

/// Main async entry point.
async fn run(runtime_config: valerter::config::RuntimeConfig) -> Result<()> {
    // Capture start time for uptime metric
    let start_time = Instant::now();

    // Create shared HTTP client for connection pooling (AD-03)
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Create notification queue (FR32: capacity 100)
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY);

    // Create notifier registry (Story 6.2: named notifiers with backward compatibility)
    let (registry, default_notifier) =
        create_notifier_registry(&runtime_config, http_client.clone())?;

    // Validate rule destinations against registry (Story 6.3: fail-fast at startup)
    let valid_notifiers: Vec<&str> = registry.names().collect();
    if let Err(errors) = runtime_config.validate_rule_destinations(&valid_notifiers) {
        for e in &errors {
            error!(error = %e, "Destination validation error");
        }
        return Err(anyhow::anyhow!(
            "Destination validation failed: {} errors",
            errors.len()
        ));
    }
    info!("All rule destinations validated successfully");

    let registry = Arc::new(registry);

    // Create notification worker with registry
    let mut worker = NotificationWorker::new(&queue, registry.clone(), default_notifier);

    // Create cancellation token for graceful shutdown
    let cancel = CancellationToken::new();

    // Collect rule and notifier names for metric initialization
    let rule_names: Vec<&str> = runtime_config
        .rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.name.as_str())
        .collect();
    let notifier_names: Vec<&str> = registry.names().collect();

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
        valerter::initialize_metrics(&rule_names, &notifier_names);

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

    // Setup signal handler for graceful shutdown (FR46: SIGTERM support for systemd)
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("Initiating graceful shutdown");
        cancel_clone.cancel();
    });

    // Spawn notification worker
    let worker_cancel = cancel.clone();
    let worker_handle = tokio::spawn(async move {
        worker.run(worker_cancel).await;
    });

    // Run the engine until cancelled
    let engine_cancel = cancel.clone();
    let engine_result = engine.run(engine_cancel).await;

    // Wait for worker to finish
    info!("Waiting for notification worker to drain queue...");
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;

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

    /// Test that SIGTERM signal handler is properly configured.
    /// This test validates the signal handler setup by verifying that
    /// tokio::signal::unix::signal can create handlers for both SIGINT and SIGTERM.
    #[cfg(unix)]
    #[tokio::test]
    async fn signal_handlers_can_be_created() {
        use tokio::signal::unix::{SignalKind, signal};

        // Verify we can create SIGTERM handler (same as shutdown_signal uses)
        let sigterm_result = signal(SignalKind::terminate());
        assert!(
            sigterm_result.is_ok(),
            "Should be able to create SIGTERM handler"
        );

        // Verify we can create SIGINT handler (same as shutdown_signal uses)
        let sigint_result = signal(SignalKind::interrupt());
        assert!(
            sigint_result.is_ok(),
            "Should be able to create SIGINT handler"
        );
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
