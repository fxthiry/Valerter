//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use valerter::cli::{Cli, LogFormat};
use valerter::config::Config;
use valerter::{
    MetricsServer, NotificationQueue, NotificationWorker, RuleEngine, DEFAULT_QUEUE_CAPACITY,
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
    // Create shared HTTP client for connection pooling (AD-03)
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Create notification queue (FR32: capacity 100)
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY);

    // Create notification worker
    let mut worker = NotificationWorker::new(&queue, http_client.clone());

    // Create cancellation token for graceful shutdown
    let cancel = CancellationToken::new();

    // Start metrics server if enabled (FR37)
    let metrics_handle = if runtime_config.metrics.enabled {
        let server = MetricsServer::new(runtime_config.metrics.port);
        let cancel_metrics = cancel.clone();
        info!(port = runtime_config.metrics.port, "Starting metrics server");
        Some(tokio::spawn(async move {
            if let Err(e) = server.run(cancel_metrics).await {
                error!(error = %e, "Metrics server error");
            }
        }))
    } else {
        info!("Metrics server disabled");
        None
    };

    // Create rule engine
    let engine = RuleEngine::new(runtime_config, http_client, queue.clone());

    // Setup signal handler for graceful shutdown
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "Failed to listen for ctrl-c signal");
            return;
        }
        info!("Received shutdown signal, initiating graceful shutdown");
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
