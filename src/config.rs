//! Configuration loading and validation for valerter.
//!
//! This module handles loading the YAML configuration file,
//! parsing CLI arguments, and managing environment variables.

use crate::error::ConfigError;
use minijinja::Environment;
use regex::Regex;
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

/// Metrics exposition configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics exposition is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Port to expose metrics on.
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

fn default_metrics_port() -> u16 {
    9090
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
        }
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
    /// Metrics exposition configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,
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
#[derive(Debug, Clone, Deserialize)]
pub struct JsonParserConfig {
    /// Fields to extract from JSON.
    pub fields: Vec<String>,
}

/// Notification configuration for a rule.
#[derive(Debug, Clone, Deserialize)]
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

// ============================================================
// RuntimeConfig - Pre-compiled configuration for runtime use
// ============================================================

/// Runtime configuration with pre-compiled regex and templates (FR15).
///
/// This structure is created by calling `Config::compile()` after validation.
/// All regex patterns are pre-compiled to avoid runtime compilation overhead.
#[derive(Debug)]
pub struct RuntimeConfig {
    /// VictoriaLogs connection settings.
    pub victorialogs: VictoriaLogsConfig,
    /// Default values for throttle and notify.
    pub defaults: DefaultsConfig,
    /// Reusable message templates (pre-validated).
    pub templates: HashMap<String, CompiledTemplate>,
    /// Alert rules with pre-compiled regex (FR15).
    pub rules: Vec<CompiledRule>,
    /// Metrics exposition configuration.
    pub metrics: MetricsConfig,
    /// Mattermost webhook URL.
    pub mattermost_webhook: Option<SecretString>,
}

/// Compiled alert rule with pre-compiled regex.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Unique name of the rule.
    pub name: String,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// LogsQL query string.
    pub query: String,
    /// Parser with pre-compiled regex.
    pub parser: CompiledParser,
    /// Throttle settings with template key.
    pub throttle: Option<CompiledThrottle>,
    /// Notification settings.
    pub notify: Option<NotifyConfig>,
}

/// Parser with pre-compiled regex pattern.
#[derive(Debug, Clone)]
pub struct CompiledParser {
    /// Pre-compiled regex pattern (FR15).
    pub regex: Option<Regex>,
    /// JSON parser configuration.
    pub json: Option<JsonParserConfig>,
}

/// Throttle configuration with template key.
#[derive(Debug, Clone)]
pub struct CompiledThrottle {
    /// Template key for grouping alerts.
    pub key_template: Option<String>,
    /// Maximum number of alerts in the window.
    pub count: u32,
    /// Time window for throttling.
    pub window: Duration,
}

/// Pre-validated message template.
#[derive(Debug, Clone)]
pub struct CompiledTemplate {
    /// Title template string.
    pub title: String,
    /// Body template string.
    pub body: String,
    /// Optional color for the message.
    pub color: Option<String>,
    /// Optional icon for the message.
    pub icon: Option<String>,
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
    pub fn load_with_webhook(path: &Path, webhook: Option<String>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        config.mattermost_webhook = webhook.map(SecretString::new);

        Ok(config)
    }

    /// Validate all rules (even disabled ones) - AD-11.
    ///
    /// This method validates:
    /// - All regex patterns are syntactically correct (FR14)
    /// - All Jinja templates are syntactically correct
    /// - All referenced templates exist in the templates map
    /// - Even disabled rules are validated (AD-11)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validations pass
    /// - `Err(Vec<ConfigError>)` with all collected errors
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use valerter::config::Config;
    /// # use std::path::Path;
    /// let config = Config::load(Path::new("/etc/valerter/config.yaml")).unwrap();
    /// if let Err(errors) = config.validate() {
    ///     for e in &errors {
    ///         eprintln!("Error: {}", e);
    ///     }
    ///     std::process::exit(1);
    /// }
    /// ```
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        // Validate all rules, even disabled ones (FR14, AD-11)
        for rule in &self.rules {
            // Validate regex patterns
            if let Some(ref pattern) = rule.parser.regex
                && let Err(e) = Regex::new(pattern)
            {
                errors.push(ConfigError::InvalidRegex {
                    rule: rule.name.clone(),
                    message: e.to_string(),
                });
            }

            // Validate throttle key template (Jinja)
            if let Some(ref throttle) = rule.throttle
                && let Some(ref key_template) = throttle.key
                && let Err(e) = validate_jinja_template(key_template)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: rule.name.clone(),
                    message: format!("throttle.key: {}", e),
                });
            }

            // Validate that notify.template references an existing template (Fix H3)
            if let Some(ref notify) = rule.notify
                && let Some(ref template_name) = notify.template
                && !self.templates.contains_key(template_name)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: rule.name.clone(),
                    message: format!("notify.template '{}' not found in templates", template_name),
                });
            }
        }

        // Validate that defaults.notify.template references an existing template
        if !self.templates.contains_key(&self.defaults.notify.template) {
            errors.push(ConfigError::InvalidTemplate {
                rule: "defaults.notify".to_string(),
                message: format!(
                    "default template '{}' not found in templates",
                    self.defaults.notify.template
                ),
            });
        }

        // Validate named templates
        for (name, template) in &self.templates {
            if let Err(e) = validate_jinja_template(&template.title) {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("title: {}", e),
                });
            }
            if let Err(e) = validate_jinja_template(&template.body) {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("body: {}", e),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Compile configuration into runtime-ready format (FR15).
    ///
    /// This method compiles all regex patterns and prepares the configuration
    /// for efficient runtime use. Should only be called after `validate()`.
    ///
    /// # Panics
    ///
    /// Panics if regex compilation fails. Caller must validate first.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = Config::load(&path)?;
    /// config.validate()?;
    /// let runtime_config = config.compile()?;
    /// ```
    pub fn compile(self) -> Result<RuntimeConfig, ConfigError> {
        let rules =
            self.rules
                .into_iter()
                .map(|rule| {
                    let regex = rule.parser.regex.as_ref().map(|p| {
                        Regex::new(p).expect("validate() should have caught invalid regex")
                    });

                    CompiledRule {
                        name: rule.name,
                        enabled: rule.enabled,
                        query: rule.query,
                        parser: CompiledParser {
                            regex,
                            json: rule.parser.json,
                        },
                        throttle: rule.throttle.map(|t| CompiledThrottle {
                            key_template: t.key,
                            count: t.count,
                            window: t.window,
                        }),
                        notify: rule.notify,
                    }
                })
                .collect();

        let templates = self
            .templates
            .into_iter()
            .map(|(name, template)| {
                (
                    name,
                    CompiledTemplate {
                        title: template.title,
                        body: template.body,
                        color: template.color,
                        icon: template.icon,
                    },
                )
            })
            .collect();

        Ok(RuntimeConfig {
            victorialogs: self.victorialogs,
            defaults: self.defaults,
            templates,
            rules,
            metrics: self.metrics,
            mattermost_webhook: self.mattermost_webhook,
        })
    }
}

/// Validate a Jinja template string.
///
/// Validates any string that might contain Jinja syntax by attempting to parse it
/// as a minijinja template. This catches:
/// - Unclosed blocks (`{% if %}` without `{% endif %}`)
/// - Invalid variable syntax (`{{ }}` with empty content)
/// - Unbalanced delimiters (`}}` without `{{`)
fn validate_jinja_template(source: &str) -> Result<(), String> {
    let mut env = Environment::new();

    // Always validate as a full template to catch any syntax issues (Fix M1)
    // This handles:
    // - Control flow: {% if %}, {% for %}, etc.
    // - Variable expressions: {{ var }}
    // - Stray delimiters: }} without {{
    // - Plain text (always valid)
    env.add_template("_validate", source)
        .map_err(|e| e.to_string())?;

    Ok(())
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
        assert_eq!(webhook.expose(), "https://mattermost.example.com/hooks/xxx");
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

    // ============================================================
    // Story 1.3: Validation Fail-Fast Tests
    // ============================================================

    // Task 1: Regex validation tests

    // Test 6.1: Valid regex - validation passes
    #[test]
    fn validate_valid_config_passes() {
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Valid config should pass validation: {:?}",
            result.err()
        );
    }

    // Test 6.2: Invalid regex - returns InvalidRegex with rule name
    #[test]
    fn validate_invalid_regex_returns_error_with_rule_name() {
        let config = Config::load(&fixture_path("config_invalid_regex.yaml")).unwrap();
        let result = config.validate();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(!errors.is_empty(), "Should have at least one error");

        // Check that the error mentions the rule name
        let has_invalid_regex_error = errors.iter().any(
            |e| matches!(e, ConfigError::InvalidRegex { rule, .. } if rule == "invalid_regex_rule"),
        );
        assert!(
            has_invalid_regex_error,
            "Should have InvalidRegex error for 'invalid_regex_rule'"
        );
    }

    // Test 6.3: Disabled rule with invalid regex - must still fail (AD-11)
    #[test]
    fn validate_disabled_rule_with_invalid_regex_still_fails() {
        let config = Config::load(&fixture_path("config_disabled_invalid.yaml")).unwrap();
        let result = config.validate();
        assert!(
            result.is_err(),
            "Disabled rules with invalid regex should still fail validation"
        );

        let errors = result.unwrap_err();
        let has_disabled_rule_error = errors.iter().any(|e| {
            matches!(e, ConfigError::InvalidRegex { rule, .. } if rule == "disabled_invalid_rule")
        });
        assert!(
            has_disabled_rule_error,
            "Should fail validation for disabled rule with invalid regex"
        );
    }

    // Test: Collects all errors (not just first one)
    #[test]
    fn validate_collects_all_errors() {
        // Create config with multiple invalid rules programmatically
        let config = Config {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
            },
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                notify: NotifyDefaults {
                    template: "default".to_string(),
                },
            },
            templates: {
                // Include the default template so we only test regex errors
                let mut t = HashMap::new();
                t.insert(
                    "default".to_string(),
                    TemplateConfig {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        color: None,
                        icon: None,
                    },
                );
                t
            },
            rules: vec![
                RuleConfig {
                    name: "rule1_invalid".to_string(),
                    enabled: true,
                    query: "test".to_string(),
                    parser: ParserConfig {
                        regex: Some("[invalid(".to_string()),
                        json: None,
                    },
                    throttle: None,
                    notify: None,
                },
                RuleConfig {
                    name: "rule2_invalid".to_string(),
                    enabled: true,
                    query: "test".to_string(),
                    parser: ParserConfig {
                        regex: Some("(?P<unclosed".to_string()),
                        json: None,
                    },
                    throttle: None,
                    notify: None,
                },
            ],
            metrics: MetricsConfig::default(),
            mattermost_webhook: None,
        };

        let result = config.validate();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert_eq!(
            errors.len(),
            2,
            "Should collect all regex errors, not stop at first"
        );
    }

    // Task 2: Template validation tests

    // Test 6.4: Invalid Jinja template - returns InvalidTemplate
    #[test]
    fn validate_invalid_template_returns_error() {
        let config = Config::load(&fixture_path("config_invalid_template.yaml")).unwrap();
        let result = config.validate();
        assert!(result.is_err(), "Invalid template should fail validation");

        let errors = result.unwrap_err();
        let has_template_error = errors
            .iter()
            .any(|e| matches!(e, ConfigError::InvalidTemplate { .. }));
        assert!(has_template_error, "Should have InvalidTemplate error");
    }

    // Test: Valid Jinja templates pass validation
    #[test]
    fn validate_valid_templates_pass() {
        // config_valid.yaml has valid templates
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Valid templates should pass: {:?}",
            result.err()
        );
    }

    // Task 3: RuntimeConfig tests

    // Test: Config compiles to RuntimeConfig with pre-compiled regex
    #[test]
    fn compile_creates_runtime_config_with_compiled_regex() {
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
        config.validate().expect("Valid config should validate");

        let runtime = config.compile().expect("Valid config should compile");

        // Check rules are transferred
        assert_eq!(runtime.rules.len(), 3);

        // Check regex is compiled in rule with regex parser
        let error_rule = runtime
            .rules
            .iter()
            .find(|r| r.name == "error_log_alert")
            .unwrap();
        assert!(
            error_rule.parser.regex.is_some(),
            "Regex should be compiled"
        );

        // Test that compiled regex actually works
        let regex = error_rule.parser.regex.as_ref().unwrap();
        let captures = regex
            .captures("2026-01-09T10:00:00 ERROR something failed")
            .unwrap();
        assert_eq!(captures.name("level").unwrap().as_str(), "ERROR");
    }

    // Test: RuntimeConfig preserves all config values
    #[test]
    fn compile_preserves_config_values() {
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
        config.validate().unwrap();

        let runtime = config.compile().unwrap();

        // VictoriaLogs config
        assert_eq!(runtime.victorialogs.url, "http://victorialogs:9428");

        // Defaults
        assert_eq!(runtime.defaults.throttle.count, 5);

        // Templates
        assert!(runtime.templates.contains_key("default_alert"));

        // Rule details
        let cpu_rule = runtime
            .rules
            .iter()
            .find(|r| r.name == "high_cpu_alert")
            .unwrap();
        assert!(cpu_rule.enabled);
        assert!(cpu_rule.throttle.is_some());
        let throttle = cpu_rule.throttle.as_ref().unwrap();
        assert_eq!(throttle.count, 3);
        assert!(throttle.key_template.is_some());
    }

    // Test: Throttle key template validation
    #[test]
    fn validate_throttle_key_template() {
        let config = Config {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
            },
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                notify: NotifyDefaults {
                    template: "default".to_string(),
                },
            },
            templates: HashMap::new(),
            rules: vec![RuleConfig {
                name: "rule_with_invalid_throttle_key".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: ParserConfig {
                    regex: None,
                    json: None,
                },
                throttle: Some(ThrottleConfig {
                    key: Some("{% if host %}{{ host".to_string()), // Invalid: unclosed
                    count: 5,
                    window: Duration::from_secs(60),
                }),
                notify: None,
            }],
            metrics: MetricsConfig::default(),
            mattermost_webhook: None,
        };

        let result = config.validate();
        assert!(result.is_err(), "Invalid throttle key template should fail");

        let errors = result.unwrap_err();
        let has_template_error = errors.iter().any(|e| {
            matches!(e, ConfigError::InvalidTemplate { rule, message }
                if rule == "rule_with_invalid_throttle_key" && message.contains("throttle.key"))
        });
        assert!(
            has_template_error,
            "Should have InvalidTemplate error for throttle.key"
        );
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

    // Fix H3: Test that notify.template referencing nonexistent template fails validation
    #[test]
    fn validate_nonexistent_notify_template_fails() {
        let config = Config {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
            },
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                notify: NotifyDefaults {
                    template: "existing_template".to_string(),
                },
            },
            templates: {
                let mut t = HashMap::new();
                t.insert(
                    "existing_template".to_string(),
                    TemplateConfig {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        color: None,
                        icon: None,
                    },
                );
                t
            },
            rules: vec![RuleConfig {
                name: "rule_with_missing_template".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: ParserConfig {
                    regex: None,
                    json: None,
                },
                throttle: None,
                notify: Some(NotifyConfig {
                    template: Some("nonexistent_template".to_string()),
                    channel: None,
                }),
            }],
            metrics: MetricsConfig::default(),
            mattermost_webhook: None,
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "Should fail when notify.template doesn't exist"
        );

        let errors = result.unwrap_err();
        let has_missing_template_error = errors.iter().any(|e| {
            matches!(e, ConfigError::InvalidTemplate { rule, message }
                if rule == "rule_with_missing_template"
                && message.contains("nonexistent_template")
                && message.contains("not found"))
        });
        assert!(
            has_missing_template_error,
            "Should have error for missing notify.template: {:?}",
            errors
        );
    }

    // Fix H3: Test that defaults.notify.template referencing nonexistent template fails
    #[test]
    fn validate_nonexistent_default_template_fails() {
        let config = Config {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
            },
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                notify: NotifyDefaults {
                    template: "missing_default".to_string(),
                },
            },
            templates: HashMap::new(), // No templates defined!
            rules: vec![],
            metrics: MetricsConfig::default(),
            mattermost_webhook: None,
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "Should fail when defaults.notify.template doesn't exist"
        );

        let errors = result.unwrap_err();
        let has_default_error = errors.iter().any(|e| {
            matches!(e, ConfigError::InvalidTemplate { rule, message }
                if rule == "defaults.notify"
                && message.contains("missing_default"))
        });
        assert!(
            has_default_error,
            "Should have error for missing default template: {:?}",
            errors
        );
    }

    // ===================================================================
    // Story 4.3 Task 4.4: Security audit test - no secrets in logs
    // ===================================================================

    /// Test that sensitive patterns (webhook URLs, tokens) are never exposed
    /// when SecretString values are formatted via Debug or Display.
    /// This is a regression test for AC#4 (NFR9).
    #[test]
    fn security_audit_no_secrets_leaked_in_any_format() {
        // Create secrets with recognizable patterns
        let webhook_secret =
            SecretString::new("https://mattermost.example.com/hooks/abc123xyz".to_string());
        let token_secret =
            SecretString::new("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string());

        // Collect all possible string representations
        let representations = vec![
            format!("{:?}", webhook_secret),
            format!("{}", webhook_secret),
            format!("{:?}", token_secret),
            format!("{}", token_secret),
            // Also test in struct context
            format!("{:?}", Some(&webhook_secret)),
            format!("{:?}", vec![&webhook_secret]),
        ];

        // Sensitive patterns that must NEVER appear
        let forbidden_patterns = [
            "hooks/",
            "abc123xyz",
            "Bearer",
            "eyJ", // JWT prefix
            "mattermost.example.com",
        ];

        for repr in &representations {
            for pattern in &forbidden_patterns {
                assert!(
                    !repr.contains(pattern),
                    "SECURITY VIOLATION: Secret leaked! Found '{}' in output: {}",
                    pattern,
                    repr
                );
            }
            // Must contain redacted marker
            assert!(
                repr.contains("[REDACTED]") || repr.contains("Some") || repr.contains("["),
                "Output should contain [REDACTED] or be a wrapper: {}",
                repr
            );
        }
    }

    /// Test that a config with webhook can be fully debug-printed without leaks.
    /// Simulates what would happen if someone accidentally logs the entire config.
    #[test]
    fn security_audit_full_config_debug_safe() {
        let config = Config::load_with_webhook(
            &fixture_path("config_valid.yaml"),
            Some("https://secret.webhook.url/hooks/supersecret123".to_string()),
        )
        .unwrap();

        // Simulate accidental full config logging
        let debug_output = format!("{:?}", config);

        // These patterns must NEVER appear
        let forbidden = ["secret.webhook.url", "supersecret123", "hooks/"];

        for pattern in &forbidden {
            assert!(
                !debug_output.contains(pattern),
                "SECURITY VIOLATION: Config debug leaked '{}' - full output: {}",
                pattern,
                &debug_output[..debug_output.len().min(500)]
            );
        }

        // Verify redaction is present
        assert!(
            debug_output.contains("[REDACTED]"),
            "Config debug should show [REDACTED] for webhook"
        );
    }
}
