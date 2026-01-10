//! Command-line interface for valerter using clap.
//!
//! Supports configuration file path via `-c` argument (FR44).

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::config::DEFAULT_CONFIG_PATH;

/// Log output format (AD-10).
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text format for journalctl (default).
    #[default]
    Text,
    /// Structured JSON format for log aggregation.
    Json,
}

/// Real-time alerting from VictoriaLogs to Mattermost.
#[derive(Parser, Debug)]
#[command(name = "valerter")]
#[command(version)]
#[command(about = "Real-time alerting from VictoriaLogs to Mattermost")]
pub struct Cli {
    /// Path to configuration file.
    #[arg(short = 'c', long = "config", default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Validate configuration and exit.
    #[arg(long = "validate")]
    pub validate: bool,

    /// Log format: text or json.
    #[arg(long = "log-format", value_enum, default_value_t = LogFormat::Text, env = "LOG_FORMAT")]
    pub log_format: LogFormat,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn cli_default_config_path() {
        let cli = Cli::try_parse_from(["valerter"]).unwrap();
        assert_eq!(cli.config, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn cli_custom_config_path() {
        let cli = Cli::try_parse_from(["valerter", "-c", "/custom/path.yaml"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("/custom/path.yaml"));
    }

    #[test]
    fn cli_config_long_option() {
        let cli = Cli::try_parse_from(["valerter", "--config", "/long/path.yaml"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("/long/path.yaml"));
    }

    #[test]
    fn cli_validate_flag() {
        let cli = Cli::try_parse_from(["valerter", "--validate"]).unwrap();
        assert!(cli.validate);
    }

    #[test]
    fn cli_log_format_default() {
        let cli = Cli::try_parse_from(["valerter"]).unwrap();
        assert!(matches!(cli.log_format, LogFormat::Text));
    }

    #[test]
    fn cli_log_format_json() {
        let cli = Cli::try_parse_from(["valerter", "--log-format", "json"]).unwrap();
        assert!(matches!(cli.log_format, LogFormat::Json));
    }

    #[test]
    fn cli_log_format_invalid_rejected() {
        let result = Cli::try_parse_from(["valerter", "--log-format", "invalid"]);
        assert!(result.is_err(), "Invalid log format should be rejected");
    }

    #[test]
    #[serial]
    fn cli_log_format_from_env() {
        // Set env var (unsafe in Rust 2024 edition)
        // SAFETY: Test marked #[serial] to prevent parallel execution with other env var tests
        unsafe { std::env::set_var("LOG_FORMAT", "json") };

        // Parse without explicit flag - should use env
        let cli = Cli::try_parse_from(["valerter"]).unwrap();
        assert!(matches!(cli.log_format, LogFormat::Json));

        // Clean up
        unsafe { std::env::remove_var("LOG_FORMAT") };
    }

    #[test]
    #[serial]
    fn cli_log_format_flag_overrides_env() {
        // SAFETY: Test marked #[serial] to prevent parallel execution with other env var tests
        unsafe { std::env::set_var("LOG_FORMAT", "json") };

        // Flag should override env
        let cli = Cli::try_parse_from(["valerter", "--log-format", "text"]).unwrap();
        assert!(matches!(cli.log_format, LogFormat::Text));

        unsafe { std::env::remove_var("LOG_FORMAT") };
    }
}
