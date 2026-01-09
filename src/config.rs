//! Configuration loading and validation for valerter.
//!
//! This module handles loading the YAML configuration file,
//! parsing CLI arguments, and managing environment variables.

use crate::error::ConfigError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Wrapper for secrets that never appears in logs (NFR9).
///
/// This type ensures that sensitive values like webhook URLs are never
/// accidentally logged or displayed. The `Debug` and `Display` implementations
/// always show `[REDACTED]` instead of the actual value.
///
/// # Example
///
/// ```
/// use valerter::config::SecretString;
///
/// let secret = SecretString::new("my-secret-webhook".to_string());
/// assert_eq!(format!("{:?}", secret), "[REDACTED]");
/// assert_eq!(secret.expose(), "my-secret-webhook");
/// ```
pub struct SecretString(String);

impl SecretString {
    /// Creates a new `SecretString` from a regular `String`.
    ///
    /// The input value will be stored internally but never exposed
    /// through `Debug` or `Display` implementations.
    pub fn new(s: String) -> Self {
        SecretString(s)
    }

    /// Exposes the underlying secret value.
    ///
    /// # Security Warning
    ///
    /// Use with care - never pass the result to logging functions
    /// or any output that could be visible to unauthorized users.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Main configuration structure for valerter.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// VictoriaLogs connection settings.
    pub victorialogs: VictoriaLogsConfig,
    /// Default values for throttle and notify.
    pub defaults: DefaultsConfig,
    /// Reusable message templates.
    pub templates: HashMap<String, TemplateConfig>,
    /// Alert rules definitions.
    pub rules: Vec<RuleConfig>,
    /// Mattermost webhook URL (loaded from environment).
    #[serde(skip)]
    pub mattermost_webhook: Option<SecretString>,
}

/// VictoriaLogs connection configuration.
#[derive(Debug, Deserialize)]
pub struct VictoriaLogsConfig {
    /// URL of the VictoriaLogs instance.
    pub url: String,
}

/// Default configuration values applied to rules when not specified.
#[derive(Debug, Deserialize)]
pub struct DefaultsConfig {
    /// Default throttle settings.
    pub throttle: ThrottleConfig,
    /// Default notification settings.
    pub notify: NotifyDefaults,
}

/// Throttle configuration for rate limiting alerts.
#[derive(Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    /// Template key for grouping alerts (e.g., "{{ host }}").
    #[serde(default)]
    pub key: Option<String>,
    /// Maximum number of alerts in the window.
    pub count: u32,
    /// Time window for throttling.
    #[serde(with = "humantime_serde")]
    pub window: Duration,
}

/// Default notification settings.
#[derive(Debug, Deserialize)]
pub struct NotifyDefaults {
    /// Name of the default template to use.
    pub template: String,
}

/// Template configuration for message formatting.
#[derive(Debug, Deserialize)]
pub struct TemplateConfig {
    /// Title template.
    pub title: String,
    /// Body template.
    pub body: String,
    /// Optional color for the message.
    #[serde(default)]
    pub color: Option<String>,
    /// Optional icon for the message.
    #[serde(default)]
    pub icon: Option<String>,
}

/// Alert rule configuration.
#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    /// Unique name of the rule (FR9).
    pub name: String,
    /// Whether the rule is enabled (FR9).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// LogsQL query string (FR10).
    pub query: String,
    /// Parser configuration for log lines.
    pub parser: ParserConfig,
    /// Optional throttle settings (uses defaults if not specified).
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    /// Optional notification settings (uses defaults if not specified).
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
}

/// Parser configuration for extracting data from log lines.
#[derive(Debug, Deserialize)]
pub struct ParserConfig {
    /// Regex pattern with named groups (FR11).
    #[serde(default)]
    pub regex: Option<String>,
    /// JSON parser configuration (FR12).
    #[serde(default)]
    pub json: Option<JsonParserConfig>,
}

/// JSON parser configuration.
#[derive(Debug, Deserialize)]
pub struct JsonParserConfig {
    /// Fields to extract from JSON.
    pub fields: Vec<String>,
}

/// Notification configuration for a rule.
#[derive(Debug, Deserialize)]
pub struct NotifyConfig {
    /// Template name to use (overrides default).
    #[serde(default)]
    pub template: Option<String>,
    /// Channel to send notification to.
    #[serde(default)]
    pub channel: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Default configuration file path (AD-08).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/valerter/config.yaml";

impl Config {
    /// Load configuration from a file path.
    ///
    /// Also loads the `MATTERMOST_WEBHOOK` environment variable if set.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::LoadError` if the file cannot be read.
    /// Returns `ConfigError::ValidationError` if the YAML is invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        // Load webhook from environment (FR45)
        config.mattermost_webhook = std::env::var("MATTERMOST_WEBHOOK")
            .ok()
            .map(SecretString::new);

        Ok(config)
    }

    /// Load configuration from a file path with an explicit webhook.
    ///
    /// Used for testing to avoid environment variable race conditions.
    #[cfg(test)]
    pub fn load_with_webhook(
        path: &Path,
        webhook: Option<String>,
    ) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        config.mattermost_webhook = webhook.map(SecretString::new);

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    // Task 5.1: Test chargement config valide depuis fixture
    #[test]
    fn load_valid_config() {
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();

        // VictoriaLogs settings
        assert_eq!(config.victorialogs.url, "http://victorialogs:9428");

        // Defaults
        assert_eq!(config.defaults.throttle.count, 5);
        assert_eq!(config.defaults.throttle.window, Duration::from_secs(60));
        assert_eq!(config.defaults.notify.template, "default_alert");

        // Templates
        assert!(config.templates.contains_key("default_alert"));
        assert!(config.templates.contains_key("custom_template"));
        let default_template = config.templates.get("default_alert").unwrap();
        assert_eq!(default_template.color, Some("#ff0000".to_string()));

        // Rules
        assert_eq!(config.rules.len(), 3);

        // First rule: high_cpu_alert
        let rule1 = &config.rules[0];
        assert_eq!(rule1.name, "high_cpu_alert");
        assert!(rule1.enabled);
        assert!(rule1.parser.json.is_some());
        let throttle = rule1.throttle.as_ref().unwrap();
        assert_eq!(throttle.count, 3);
        assert_eq!(throttle.window, Duration::from_secs(300)); // 5m = 300s
        let notify = rule1.notify.as_ref().unwrap();
        assert_eq!(notify.channel, Some("alerts".to_string()));

        // Second rule: error_log_alert (uses regex parser)
        let rule2 = &config.rules[1];
        assert_eq!(rule2.name, "error_log_alert");
        assert!(rule2.parser.regex.is_some());
        assert!(rule2.throttle.is_none()); // uses defaults

        // Third rule: disabled
        let rule3 = &config.rules[2];
        assert!(!rule3.enabled);
    }

    // Task 5.2: Test erreur fichier inexistant
    #[test]
    fn load_nonexistent_file_returns_load_error() {
        let result = Config::load(Path::new("/nonexistent/path/config.yaml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::LoadError(msg) => {
                assert!(msg.contains("/nonexistent/path/config.yaml"));
            }
            _ => panic!("Expected LoadError, got {:?}", err),
        }
    }

    // Task 5.3: Test erreur YAML invalide
    #[test]
    fn load_invalid_yaml_returns_validation_error() {
        let result = Config::load(&fixture_path("config_invalid_yaml.yaml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::ValidationError(_) => {}
            _ => panic!("Expected ValidationError, got {:?}", err),
        }
    }

    // Task 5.4: Test valeurs par defaut appliquees aux regles
    #[test]
    fn rules_use_defaults_when_not_specified() {
        let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();

        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];

        // Rule doesn't specify throttle/notify, should be None
        // (defaults are applied at runtime, not during parsing)
        assert!(rule.throttle.is_none());
        assert!(rule.notify.is_none());

        // But defaults should be available from config.defaults
        assert_eq!(config.defaults.throttle.count, 10);
        assert_eq!(config.defaults.notify.template, "simple");
    }

    // Task 5.5: Test variable d'environnement webhook
    #[test]
    fn load_webhook_from_explicit_value() {
        // Use load_with_webhook to avoid environment variable race conditions
        let config = Config::load_with_webhook(
            &fixture_path("config_valid.yaml"),
            Some("https://mattermost.example.com/hooks/xxx".to_string()),
        )
        .unwrap();

        assert!(config.mattermost_webhook.is_some());
        let webhook = config.mattermost_webhook.as_ref().unwrap();
        assert_eq!(
            webhook.expose(),
            "https://mattermost.example.com/hooks/xxx"
        );
    }

    #[test]
    fn load_without_webhook() {
        let config = Config::load_with_webhook(&fixture_path("config_valid.yaml"), None).unwrap();
        assert!(config.mattermost_webhook.is_none());
    }

    // Test enabled defaults to true
    #[test]
    fn rule_enabled_defaults_to_true() {
        let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();
        // The minimal config doesn't specify enabled, should default to true
        assert!(config.rules[0].enabled);
    }

    // Test SecretString never exposes value in Debug/Display
    #[test]
    fn secret_string_redacts_in_debug_and_display() {
        let secret = SecretString::new("super-secret-webhook".to_string());

        // Debug should not contain the actual value
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("super-secret-webhook"));
        assert!(debug_output.contains("[REDACTED]"));

        // Display should not contain the actual value
        let display_output = format!("{}", secret);
        assert!(!display_output.contains("super-secret-webhook"));
        assert!(display_output.contains("[REDACTED]"));

        // But expose() should return the actual value
        assert_eq!(secret.expose(), "super-secret-webhook");
    }

    // Test config can be debugged without leaking webhook
    #[test]
    fn config_debug_does_not_leak_webhook() {
        let config = Config::load_with_webhook(
            &fixture_path("config_valid.yaml"),
            Some("secret-webhook-url".to_string()),
        )
        .unwrap();

        let debug_output = format!("{:?}", config);

        // Should not contain the actual webhook
        assert!(!debug_output.contains("secret-webhook-url"));
        // Should contain [REDACTED] instead
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn default_config_path_is_correct() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/valerter/config.yaml");
    }

    // Fix M2: Test env var MATTERMOST_WEBHOOK is loaded via Config::load()
    #[test]
    fn load_webhook_from_environment_variable() {
        // SAFETY: Tests run single-threaded with --test-threads=1 or we accept
        // the race condition risk for this specific env var test.
        unsafe {
            std::env::set_var("MATTERMOST_WEBHOOK", "https://test.webhook.url/hook");
        }

        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();

        // Clean up before assertions to ensure cleanup happens
        unsafe {
            std::env::remove_var("MATTERMOST_WEBHOOK");
        }

        assert!(config.mattermost_webhook.is_some());
        assert_eq!(
            config.mattermost_webhook.as_ref().unwrap().expose(),
            "https://test.webhook.url/hook"
        );
    }

    // Fix M3: Test that config.example.yaml is valid and parseable
    #[test]
    fn config_example_yaml_is_valid() {
        let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("config.example.yaml");

        let config = Config::load(&example_path);
        assert!(
            config.is_ok(),
            "config.example.yaml should be valid: {:?}",
            config.err()
        );

        let config = config.unwrap();
        // Verify basic structure
        assert!(!config.victorialogs.url.is_empty());
        assert!(!config.templates.is_empty());
        assert!(!config.rules.is_empty());
    }
}
