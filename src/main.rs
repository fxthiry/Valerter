//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

use anyhow::Result;
use clap::Parser;
use valerter::cli::Cli;
use valerter::config::Config;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load(&cli.config)?;

    // Validate mode: just check config and exit
    if cli.validate {
        println!("Configuration valid: {}", cli.config.display());
        println!("  VictoriaLogs URL: {}", config.victorialogs.url);
        println!("  Rules: {}", config.rules.len());
        println!("  Templates: {}", config.templates.len());
        return Ok(());
    }

    println!("valerter starting...");
    println!("  Config: {}", cli.config.display());
    println!("  Rules loaded: {}", config.rules.len());

    // Main application loop will be implemented in future stories
    Ok(())
}
