//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use valerter::cli::Cli;
use valerter::config::Config;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing subscriber for logging (output to stderr)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

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
        error!(error_count = errors.len(), "Configuration validation failed");
        std::process::exit(1);
    }

    // Validate mode: display success and exit
    if cli.validate {
        println!("Configuration is valid: {}", cli.config.display());
        println!("  VictoriaLogs URL: {}", config.victorialogs.url);
        println!("  Rules: {} ({} enabled)",
            config.rules.len(),
            config.rules.iter().filter(|r| r.enabled).count()
        );
        println!("  Templates: {}", config.templates.len());
        return Ok(());
    }

    // Compile configuration for runtime (FR15)
    let _runtime_config = config.compile()?;

    info!(config_path = %cli.config.display(), "valerter starting");

    // Main application loop will be implemented in future stories
    Ok(())
}
