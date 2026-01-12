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
#[derive(Clone)]
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

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
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
    /// Named notifier configurations (Story 6.2).
    /// If None, falls back to MATTERMOST_WEBHOOK env var for backward compatibility.
    #[serde(default)]
    pub notifiers: Option<NotifiersConfig>,
    /// Mattermost webhook URL (loaded from environment).
    #[serde(skip)]
    pub mattermost_webhook: Option<SecretString>,
}

/// VictoriaLogs connection configuration.
#[derive(Debug, Deserialize)]
pub struct VictoriaLogsConfig {
    /// URL of the VictoriaLogs instance.
    pub url: String,
    /// Optional Basic Auth credentials.
    #[serde(default)]
    pub basic_auth: Option<BasicAuthConfig>,
    /// Optional custom headers (for tokens, API keys, etc.).
    #[serde(default)]
    pub headers: Option<HashMap<String, SecretString>>,
    /// Optional TLS configuration.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Basic Auth configuration for VictoriaLogs connection.
///
/// Both `username` and `password` are required when Basic Auth is configured.
/// The password is stored as a `SecretString` to prevent accidental exposure.
#[derive(Clone)]
pub struct BasicAuthConfig {
    /// Username for Basic Auth.
    pub username: String,
    /// Password for Basic Auth (never exposed in logs).
    pub password: SecretString,
}

impl std::fmt::Debug for BasicAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthConfig")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl<'de> serde::Deserialize<'de> for BasicAuthConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawBasicAuth {
            username: String,
            password: String,
        }

        let raw = RawBasicAuth::deserialize(deserializer)?;
        Ok(BasicAuthConfig {
            username: raw.username,
            password: SecretString::new(raw.password),
        })
    }
}

/// TLS configuration for VictoriaLogs connection.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Whether to verify TLS certificates (default: true).
    /// Set to false for self-signed certificates.
    #[serde(default = "default_true")]
    pub verify: bool,
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
    /// Channel to send notification to (legacy).
    #[serde(default)]
    pub channel: Option<String>,
    /// List of notification destinations (Story 6.3).
    /// If not specified, uses the default notifier.
    #[serde(default)]
    pub destinations: Option<Vec<String>>,
}

// ============================================================
// Notifiers Configuration (Story 6.2)
// ============================================================

/// Map of named notifier configurations.
pub type NotifiersConfig = HashMap<String, NotifierConfig>;

/// Notifier configuration with type tag for deserialization.
///
/// Uses serde's internally tagged enum to support multiple notifier types.
/// Currently only `mattermost` is supported, with more types planned.
///
/// # Example YAML
///
/// ```yaml
/// notifiers:
///   mattermost-infra:
///     type: mattermost
///     webhook_url: ${MATTERMOST_WEBHOOK_INFRA}
///     channel: infra-alerts
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum NotifierConfig {
    /// Mattermost notifier configuration.
    #[serde(rename = "mattermost")]
    Mattermost(MattermostNotifierConfig),
    /// Webhook notifier configuration (Story 6.5).
    #[serde(rename = "webhook")]
    Webhook(WebhookNotifierConfig),
}

/// Configuration for a Mattermost notifier instance.
///
/// The `webhook_url` field supports environment variable substitution
/// using the `${VAR_NAME}` syntax.
#[derive(Debug, Clone, Deserialize)]
pub struct MattermostNotifierConfig {
    /// Webhook URL for the Mattermost incoming webhook.
    /// Supports `${ENV_VAR}` substitution for secrets.
    pub webhook_url: String,
    /// Optional channel override (e.g., "infra-alerts").
    #[serde(default)]
    pub channel: Option<String>,
    /// Optional username override for the webhook.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional icon URL for the webhook messages.
    #[serde(default)]
    pub icon_url: Option<String>,
}

/// Configuration for a generic webhook notifier (Story 6.5).
///
/// Supports custom HTTP endpoints with templated body and custom headers.
/// Headers support `${ENV_VAR}` substitution for secrets.
///
/// # Example YAML
///
/// ```yaml
/// notifiers:
///   my-webhook:
///     type: webhook
///     url: https://api.example.com/alerts
///     method: POST  # optional, defaults to POST
///     headers:
///       Authorization: Bearer ${WEBHOOK_TOKEN}
///       Content-Type: application/json
///     body_template: |
///       {"alert": "{{ title }}", "message": "{{ body }}"}
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookNotifierConfig {
    /// Target URL for the webhook.
    /// Supports `${ENV_VAR}` substitution for secrets.
    pub url: String,
    /// HTTP method to use (default: POST).
    #[serde(default = "default_post")]
    pub method: String,
    /// Custom headers to include in the request.
    /// Values support `${ENV_VAR}` substitution for secrets (e.g., Authorization).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional body template (minijinja).
    /// If not provided, a default JSON payload is used.
    #[serde(default)]
    pub body_template: Option<String>,
}

fn default_post() -> String {
    "POST".to_string()
}

fn default_true() -> bool {
    true
}

// ============================================================
// Environment Variable Substitution (Story 6.2)
// ============================================================

/// Resolve environment variable references in a string.
///
/// Supports the `${VAR_NAME}` syntax for environment variable substitution.
/// Variable names must match `[A-Z_][A-Z0-9_]*` pattern.
///
/// # Arguments
///
/// * `value` - The string that may contain `${VAR_NAME}` patterns
///
/// # Returns
///
/// * `Ok(String)` - The string with all variables resolved
/// * `Err(ConfigError)` - If a referenced variable is not defined
///
/// # Examples
///
/// ```ignore
/// // With WEBHOOK_URL set to "https://example.com"
/// let result = resolve_env_vars("${WEBHOOK_URL}/path");
/// assert_eq!(result.unwrap(), "https://example.com/path");
/// ```
pub fn resolve_env_vars(value: &str) -> Result<String, ConfigError> {
    // Regex to match ${VAR_NAME} where VAR_NAME is a valid env var name
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("Invalid regex");

    let mut result = value.to_string();
    let mut errors = Vec::new();

    // Find all matches and collect them first (to avoid borrowing issues)
    let matches: Vec<_> = re.captures_iter(value).collect();

    for cap in matches {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = &cap[1];

        match std::env::var(var_name) {
            Ok(var_value) => {
                result = result.replace(full_match, &var_value);
            }
            Err(_) => {
                errors.push(var_name.to_string());
            }
        }
    }

    if errors.is_empty() {
        Ok(result)
    } else {
        Err(ConfigError::ValidationError(format!(
            "undefined environment variable{}: {}",
            if errors.len() > 1 { "s" } else { "" },
            errors.join(", ")
        )))
    }
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
    /// Named notifiers configuration (Story 6.2).
    pub notifiers: Option<NotifiersConfig>,
    /// Mattermost webhook URL (legacy - for backward compatibility).
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

impl RuntimeConfig {
    /// Collect all unique destination names referenced in rules (Story 6.3).
    ///
    /// This is used to validate that all destinations exist in the notifier registry
    /// at startup time (fail-fast validation).
    ///
    /// # Returns
    ///
    /// A vector of tuples (rule_name, destinations) for rules that have
    /// explicit destinations configured.
    pub fn collect_rule_destinations(&self) -> Vec<(&str, &[String])> {
        self.rules
            .iter()
            .filter_map(|rule| {
                rule.notify
                    .as_ref()
                    .and_then(|n| n.destinations.as_ref())
                    .filter(|d| !d.is_empty())
                    .map(|d| (rule.name.as_str(), d.as_slice()))
            })
            .collect()
    }

    /// Validate that all rule destinations exist in a list of valid notifier names (Story 6.3).
    ///
    /// # Arguments
    ///
    /// * `valid_notifiers` - List of valid notifier names from the registry
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All destinations are valid
    /// * `Err(Vec<ConfigError>)` - List of errors for invalid destinations
    pub fn validate_rule_destinations(
        &self,
        valid_notifiers: &[&str],
    ) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        for (rule_name, destinations) in self.collect_rule_destinations() {
            let unknown: Vec<_> = destinations
                .iter()
                .filter(|d| !valid_notifiers.contains(&d.as_str()))
                .collect();

            if !unknown.is_empty() {
                errors.push(ConfigError::ValidationError(format!(
                    "rule '{}': unknown notifier{} {}",
                    rule_name,
                    if unknown.len() > 1 { "s" } else { "" },
                    unknown
                        .iter()
                        .map(|s| format!("'{}'", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }

        // Also validate that rules with notifiers: section configured have at least one destination
        // when config.notifiers is present (AC#4 - destinations required)
        if self.notifiers.is_some() {
            for rule in &self.rules {
                if let Some(ref notify) = rule.notify
                    && let Some(ref destinations) = notify.destinations
                    && destinations.is_empty()
                {
                    errors.push(ConfigError::ValidationError(format!(
                        "rule '{}': notify.destinations cannot be empty",
                        rule.name
                    )));
                }
                // If destinations is None, it will use the default notifier (backward compat)
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

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
            notifiers: self.notifiers,
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
                basic_auth: None,
                headers: None,
                tls: None,
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
            notifiers: None,
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
                basic_auth: None,
                headers: None,
                tls: None,
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
            notifiers: None,
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
        // Use temp_env for safe env var handling (Fix M3)
        temp_env::with_var("MATTERMOST_WEBHOOK", Some("https://test.webhook.url/hook"), || {
            let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();

            assert!(config.mattermost_webhook.is_some());
            assert_eq!(
                config.mattermost_webhook.as_ref().unwrap().expose(),
                "https://test.webhook.url/hook"
            );
        });
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
                basic_auth: None,
                headers: None,
                tls: None,
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
                    destinations: None,
                }),
            }],
            metrics: MetricsConfig::default(),
            notifiers: None,
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
                basic_auth: None,
                headers: None,
                tls: None,
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
            notifiers: None,
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

    // ===================================================================
    // Story 5.4: VictoriaLogs Connection Options Tests
    // ===================================================================

    // Task 1: Test parsing config with basic_auth, headers, and tls

    #[test]
    fn load_config_with_basic_auth() {
        let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

        // Basic Auth should be parsed
        assert!(config.victorialogs.basic_auth.is_some());
        let basic_auth = config.victorialogs.basic_auth.as_ref().unwrap();
        assert_eq!(basic_auth.username, "testuser");
        assert_eq!(basic_auth.password.expose(), "testpassword");
    }

    #[test]
    fn load_config_with_headers() {
        let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

        // Headers should be parsed
        assert!(config.victorialogs.headers.is_some());
        let headers = config.victorialogs.headers.as_ref().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get("X-API-Key").unwrap().expose(),
            "secret-api-key-12345"
        );
        assert_eq!(
            headers.get("X-Custom-Header").unwrap().expose(),
            "custom-value"
        );
    }

    #[test]
    fn load_config_with_tls_verify_false() {
        let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

        // TLS config should be parsed with verify: false
        assert!(config.victorialogs.tls.is_some());
        let tls = config.victorialogs.tls.as_ref().unwrap();
        assert!(!tls.verify);
    }

    #[test]
    fn load_config_without_auth_options() {
        // Existing config should still work with new optional fields
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();

        assert!(config.victorialogs.basic_auth.is_none());
        assert!(config.victorialogs.headers.is_none());
        assert!(config.victorialogs.tls.is_none());
    }

    // Task 2: Test SecretString protection for basic_auth and headers

    #[test]
    fn basic_auth_debug_redacts_password() {
        let basic_auth = BasicAuthConfig {
            username: "admin".to_string(),
            password: SecretString::new("super-secret-password".to_string()),
        };

        let debug_output = format!("{:?}", basic_auth);

        // Username should be visible
        assert!(debug_output.contains("admin"));
        // Password must be redacted
        assert!(!debug_output.contains("super-secret-password"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn headers_with_secret_values_are_redacted_in_debug() {
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            SecretString::new("Bearer secret-token".to_string()),
        );
        headers.insert(
            "X-API-Key".to_string(),
            SecretString::new("api-key-12345".to_string()),
        );

        let debug_output = format!("{:?}", headers);

        // Secret values must not appear
        assert!(!debug_output.contains("secret-token"));
        assert!(!debug_output.contains("Bearer"));
        assert!(!debug_output.contains("api-key-12345"));
        // Keys are fine to show
        assert!(debug_output.contains("Authorization"));
        assert!(debug_output.contains("X-API-Key"));
    }

    #[test]
    fn full_config_with_auth_debug_redacts_all_secrets() {
        let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

        let debug_output = format!("{:?}", config);

        // These secrets must NEVER appear
        assert!(
            !debug_output.contains("testpassword"),
            "Password leaked in debug"
        );
        assert!(
            !debug_output.contains("secret-api-key-12345"),
            "API key leaked in debug"
        );

        // But username and header keys are OK
        assert!(debug_output.contains("testuser"));
    }

    // Task 3: Test TLS verify defaults to true

    #[test]
    fn tls_verify_defaults_to_true() {
        let tls: TlsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(tls.verify, "TLS verify should default to true");
    }

    #[test]
    fn tls_verify_can_be_set_to_false() {
        let tls: TlsConfig = serde_yaml::from_str("verify: false").unwrap();
        assert!(!tls.verify);
    }

    // Task 3: Validation for incomplete basic_auth

    #[test]
    fn load_config_with_incomplete_basic_auth_fails() {
        let result = Config::load(&fixture_path("config_invalid_basic_auth.yaml"));

        assert!(result.is_err(), "Should fail when basic_auth is incomplete");
        let err = result.unwrap_err();
        match err {
            ConfigError::ValidationError(msg) => {
                // Serde should report missing 'password' field
                assert!(
                    msg.contains("password") || msg.contains("missing"),
                    "Error should mention missing password field: {}",
                    msg
                );
            }
            _ => panic!("Expected ValidationError, got {:?}", err),
        }
    }

    #[test]
    fn validate_config_with_auth_passes() {
        let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

        // Validation should pass for valid config with auth options
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Valid config with auth should pass validation: {:?}",
            result.err()
        );
    }

    // ===================================================================
    // Story 6.2: Notifiers Configuration Tests
    // ===================================================================

    // Task 1: Test parsing config with notifiers section

    #[test]
    fn load_config_with_notifiers_section() {
        let config = Config::load(&fixture_path("config_with_notifiers.yaml")).unwrap();

        // Notifiers should be parsed (3 mattermost + 2 webhook = 5)
        assert!(config.notifiers.is_some());
        let notifiers = config.notifiers.as_ref().unwrap();
        assert_eq!(notifiers.len(), 5);

        // Check mattermost-infra notifier with all fields
        let infra = notifiers.get("mattermost-infra").expect("mattermost-infra should exist");
        match infra {
            NotifierConfig::Mattermost(cfg) => {
                assert_eq!(cfg.webhook_url, "https://mattermost.example.com/hooks/infra123");
                assert_eq!(cfg.channel, Some("infra-alerts".to_string()));
                assert_eq!(cfg.username, Some("valerter-infra".to_string()));
                assert_eq!(cfg.icon_url, Some("https://example.com/infra-icon.png".to_string()));
            }
            _ => panic!("Expected Mattermost variant"),
        }

        // Check mattermost-ops notifier with only required field
        let ops = notifiers.get("mattermost-ops").expect("mattermost-ops should exist");
        match ops {
            NotifierConfig::Mattermost(cfg) => {
                assert_eq!(cfg.webhook_url, "https://mattermost.example.com/hooks/ops456");
                assert!(cfg.channel.is_none());
                assert!(cfg.username.is_none());
                assert!(cfg.icon_url.is_none());
            }
            _ => panic!("Expected Mattermost variant"),
        }

        // Story 6.5: Check webhook-pagerduty notifier
        let pagerduty = notifiers.get("webhook-pagerduty").expect("webhook-pagerduty should exist");
        match pagerduty {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.url, "https://events.pagerduty.com/v2/enqueue");
                assert_eq!(cfg.method, "POST");
                assert_eq!(cfg.headers.len(), 2);
                assert!(cfg.body_template.is_some());
            }
            _ => panic!("Expected Webhook variant"),
        }

        // Story 6.5: Check webhook-simple notifier (defaults)
        let simple = notifiers.get("webhook-simple").expect("webhook-simple should exist");
        match simple {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.url, "https://api.example.com/alerts");
                assert_eq!(cfg.method, "POST"); // default
                assert!(cfg.headers.is_empty()); // default
                assert!(cfg.body_template.is_none()); // default
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn load_config_without_notifiers_section_is_valid() {
        // Existing configs without notifiers: should still work (backward compatibility)
        let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
        assert!(config.notifiers.is_none());
    }

    #[test]
    fn load_config_with_unknown_notifier_type_fails() {
        let result = Config::load(&fixture_path("config_invalid_notifier_type.yaml"));

        assert!(result.is_err(), "Unknown notifier type should fail to parse");
        let err = result.unwrap_err();
        match err {
            ConfigError::ValidationError(msg) => {
                // Serde should report unknown variant
                assert!(
                    msg.contains("unknown") || msg.contains("variant") || msg.contains("type"),
                    "Error should mention unknown type: {}",
                    msg
                );
            }
            _ => panic!("Expected ValidationError, got {:?}", err),
        }
    }

    #[test]
    fn mattermost_notifier_config_requires_webhook_url() {
        // Test that webhook_url is required
        let yaml = r#"
            type: mattermost
            channel: "test"
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Missing webhook_url should fail");
    }

    #[test]
    fn mattermost_notifier_config_optional_fields_default() {
        let yaml = r#"
            type: mattermost
            webhook_url: "https://example.com/hooks/test"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Mattermost(cfg) => {
                assert_eq!(cfg.webhook_url, "https://example.com/hooks/test");
                assert!(cfg.channel.is_none());
                assert!(cfg.username.is_none());
                assert!(cfg.icon_url.is_none());
            }
            _ => panic!("Expected Mattermost variant"),
        }
    }

    #[test]
    fn notifiers_config_is_hashmap() {
        let yaml = r#"
            notifier-a:
              type: mattermost
              webhook_url: "https://a.example.com"
            notifier-b:
              type: mattermost
              webhook_url: "https://b.example.com"
        "#;
        let config: NotifiersConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.len(), 2);
        assert!(config.contains_key("notifier-a"));
        assert!(config.contains_key("notifier-b"));
    }

    // Task 2: Environment variable substitution tests
    // All tests use temp_env for safe env var handling (Fix M3)

    #[test]
    fn resolve_env_vars_substitutes_single_variable() {
        temp_env::with_var("TEST_WEBHOOK_VAR", Some("https://example.com/hooks/abc"), || {
            let result = resolve_env_vars("${TEST_WEBHOOK_VAR}");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "https://example.com/hooks/abc");
        });
    }

    #[test]
    fn resolve_env_vars_substitutes_multiple_variables() {
        temp_env::with_vars(
            [
                ("TEST_HOST", Some("mattermost.example.com")),
                ("TEST_TOKEN", Some("secret123")),
            ],
            || {
                let result = resolve_env_vars("https://${TEST_HOST}/hooks/${TEST_TOKEN}");
                assert!(result.is_ok());
                assert_eq!(
                    result.unwrap(),
                    "https://mattermost.example.com/hooks/secret123"
                );
            },
        );
    }

    #[test]
    fn resolve_env_vars_returns_unchanged_without_pattern() {
        let input = "https://example.com/static/path";
        let result = resolve_env_vars(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    fn resolve_env_vars_error_on_undefined_variable() {
        temp_env::with_var("UNDEFINED_VAR_XYZ_123", None::<&str>, || {
            let result = resolve_env_vars("https://${UNDEFINED_VAR_XYZ_123}/path");
            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                ConfigError::ValidationError(msg) => {
                    assert!(
                        msg.contains("UNDEFINED_VAR_XYZ_123"),
                        "Error should mention the undefined variable: {}",
                        msg
                    );
                    assert!(
                        msg.contains("undefined") || msg.contains("environment"),
                        "Error should mention it's undefined: {}",
                        msg
                    );
                }
                _ => panic!("Expected ValidationError, got {:?}", err),
            }
        });
    }

    #[test]
    fn resolve_env_vars_error_lists_all_undefined_variables() {
        temp_env::with_vars(
            [
                ("UNDEFINED_A", None::<&str>),
                ("UNDEFINED_B", None::<&str>),
            ],
            || {
                let result = resolve_env_vars("${UNDEFINED_A} and ${UNDEFINED_B}");
                assert!(result.is_err());

                let err = result.unwrap_err();
                match err {
                    ConfigError::ValidationError(msg) => {
                        assert!(msg.contains("UNDEFINED_A"), "Should mention UNDEFINED_A: {}", msg);
                        assert!(msg.contains("UNDEFINED_B"), "Should mention UNDEFINED_B: {}", msg);
                    }
                    _ => panic!("Expected ValidationError, got {:?}", err),
                }
            },
        );
    }

    #[test]
    fn resolve_env_vars_preserves_text_around_variables() {
        temp_env::with_var("TEST_MIDDLE", Some("REPLACED"), || {
            let result = resolve_env_vars("prefix_${TEST_MIDDLE}_suffix");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "prefix_REPLACED_suffix");
        });
    }

    #[test]
    fn resolve_env_vars_handles_empty_env_value() {
        temp_env::with_var("TEST_EMPTY_VAR", Some(""), || {
            let result = resolve_env_vars("before${TEST_EMPTY_VAR}after");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "beforeafter");
        });
    }

    #[test]
    fn resolve_env_vars_supports_lowercase_variables() {
        // Some systems allow lowercase env vars
        temp_env::with_var("test_lowercase_var", Some("lowercase_value"), || {
            let result = resolve_env_vars("${test_lowercase_var}");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "lowercase_value");
        });
    }

    // ===================================================================
    // Story 6.3: NotifyConfig with destinations tests
    // ===================================================================

    #[test]
    fn notify_config_parses_with_destinations() {
        let yaml = r#"
            template: custom_alert
            destinations:
              - mattermost-infra
              - mattermost-ops
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.template, Some("custom_alert".to_string()));
        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0], "mattermost-infra");
        assert_eq!(destinations[1], "mattermost-ops");
    }

    #[test]
    fn notify_config_parses_without_destinations_for_backward_compat() {
        let yaml = r#"
            template: default_alert
            channel: alerts
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.template, Some("default_alert".to_string()));
        assert_eq!(config.channel, Some("alerts".to_string()));
        assert!(config.destinations.is_none());
    }

    #[test]
    fn notify_config_parses_with_single_destination() {
        let yaml = r#"
            destinations:
              - mattermost-infra
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0], "mattermost-infra");
    }

    #[test]
    fn notify_config_parses_empty_destinations_as_empty_vec() {
        let yaml = r#"
            destinations: []
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert!(destinations.is_empty());
    }

    #[test]
    fn notify_config_default_is_all_none() {
        let yaml = "{}";
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.template.is_none());
        assert!(config.channel.is_none());
        assert!(config.destinations.is_none());
    }

    // ===================================================================
    // Story 6.3: RuntimeConfig destination validation tests
    // ===================================================================

    fn make_runtime_config_with_destinations(destinations: Option<Vec<String>>) -> RuntimeConfig {
        use std::collections::HashMap;

        RuntimeConfig {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
                basic_auth: None,
                headers: None,
                tls: None,
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
                let mut t = HashMap::new();
                t.insert(
                    "default".to_string(),
                    CompiledTemplate {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        color: None,
                        icon: None,
                    },
                );
                t
            },
            rules: vec![CompiledRule {
                name: "test_rule".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: CompiledParser {
                    regex: None,
                    json: None,
                },
                throttle: None,
                notify: Some(NotifyConfig {
                    template: None,
                    channel: None,
                    destinations,
                }),
            }],
            metrics: MetricsConfig::default(),
            notifiers: Some(HashMap::new()), // Notifiers section exists
            mattermost_webhook: None,
        }
    }

    #[test]
    fn collect_rule_destinations_returns_configured_destinations() {
        let config = make_runtime_config_with_destinations(Some(vec![
            "mattermost-infra".to_string(),
            "mattermost-ops".to_string(),
        ]));

        let destinations = config.collect_rule_destinations();
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0].0, "test_rule");
        assert_eq!(destinations[0].1, &["mattermost-infra", "mattermost-ops"]);
    }

    #[test]
    fn collect_rule_destinations_skips_rules_without_destinations() {
        let config = make_runtime_config_with_destinations(None);

        let destinations = config.collect_rule_destinations();
        assert!(destinations.is_empty());
    }

    #[test]
    fn collect_rule_destinations_skips_empty_destinations() {
        let config = make_runtime_config_with_destinations(Some(vec![]));

        let destinations = config.collect_rule_destinations();
        assert!(destinations.is_empty());
    }

    #[test]
    fn validate_rule_destinations_passes_for_valid_destinations() {
        let config = make_runtime_config_with_destinations(Some(vec![
            "notifier-a".to_string(),
            "notifier-b".to_string(),
        ]));

        let valid_notifiers = vec!["notifier-a", "notifier-b", "notifier-c"];
        let result = config.validate_rule_destinations(&valid_notifiers);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rule_destinations_fails_for_unknown_destination() {
        let config = make_runtime_config_with_destinations(Some(vec![
            "notifier-a".to_string(),
            "unknown-notifier".to_string(),
        ]));

        let valid_notifiers = vec!["notifier-a", "notifier-b"];
        let result = config.validate_rule_destinations(&valid_notifiers);

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        let msg = errors[0].to_string();
        assert!(msg.contains("test_rule"));
        assert!(msg.contains("unknown-notifier"));
    }

    #[test]
    fn validate_rule_destinations_fails_for_empty_destinations_when_notifiers_configured() {
        let config = make_runtime_config_with_destinations(Some(vec![]));

        let valid_notifiers = vec!["notifier-a"];
        let result = config.validate_rule_destinations(&valid_notifiers);

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        let msg = errors[0].to_string();
        assert!(msg.contains("test_rule"));
        assert!(msg.contains("cannot be empty"));
    }

    #[test]
    fn validate_rule_destinations_passes_for_none_destinations_backward_compat() {
        let config = make_runtime_config_with_destinations(None);

        let valid_notifiers = vec!["notifier-a"];
        let result = config.validate_rule_destinations(&valid_notifiers);

        // None destinations should be allowed for backward compatibility
        // (will use default notifier at runtime)
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rule_destinations_collects_all_errors() {
        use std::collections::HashMap;

        let config = RuntimeConfig {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
                basic_auth: None,
                headers: None,
                tls: None,
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
                let mut t = HashMap::new();
                t.insert(
                    "default".to_string(),
                    CompiledTemplate {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        color: None,
                        icon: None,
                    },
                );
                t
            },
            rules: vec![
                CompiledRule {
                    name: "rule_1".to_string(),
                    enabled: true,
                    query: "test".to_string(),
                    parser: CompiledParser { regex: None, json: None },
                    throttle: None,
                    notify: Some(NotifyConfig {
                        template: None,
                        channel: None,
                        destinations: Some(vec!["unknown-1".to_string()]),
                    }),
                },
                CompiledRule {
                    name: "rule_2".to_string(),
                    enabled: true,
                    query: "test".to_string(),
                    parser: CompiledParser { regex: None, json: None },
                    throttle: None,
                    notify: Some(NotifyConfig {
                        template: None,
                        channel: None,
                        destinations: Some(vec!["unknown-2".to_string()]),
                    }),
                },
            ],
            metrics: MetricsConfig::default(),
            notifiers: Some(HashMap::new()),
            mattermost_webhook: None,
        };

        let valid_notifiers = vec!["valid-notifier"];
        let result = config.validate_rule_destinations(&valid_notifiers);

        assert!(result.is_err());
        let errors = result.unwrap_err();
        // Should have 2 errors - one for each rule with unknown destination
        assert_eq!(errors.len(), 2, "Should collect all destination errors");
    }

    // ===================================================================
    // Story 6.5: WebhookNotifierConfig Tests
    // ===================================================================

    #[test]
    fn webhook_notifier_config_parses_with_all_fields() {
        let yaml = r#"
            type: webhook
            url: https://api.example.com/alerts
            method: PUT
            headers:
              Authorization: Bearer token123
              Content-Type: application/json
            body_template: |
              {"alert": "{{ title }}", "message": "{{ body }}"}
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.url, "https://api.example.com/alerts");
                assert_eq!(cfg.method, "PUT");
                assert_eq!(cfg.headers.len(), 2);
                assert_eq!(cfg.headers.get("Authorization").unwrap(), "Bearer token123");
                assert_eq!(cfg.headers.get("Content-Type").unwrap(), "application/json");
                assert!(cfg.body_template.is_some());
                assert!(cfg.body_template.unwrap().contains("{{ title }}"));
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_parses_with_defaults() {
        let yaml = r#"
            type: webhook
            url: https://api.example.com/alerts
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.url, "https://api.example.com/alerts");
                assert_eq!(cfg.method, "POST"); // default
                assert!(cfg.headers.is_empty()); // default
                assert!(cfg.body_template.is_none()); // default
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_requires_url() {
        let yaml = r#"
            type: webhook
            method: POST
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Missing url should fail");
    }

    #[test]
    fn webhook_notifier_config_method_defaults_to_post() {
        let yaml = r#"
            type: webhook
            url: https://example.com/hook
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.method, "POST");
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_headers_with_env_var_pattern() {
        let yaml = r#"
            type: webhook
            url: https://api.example.com/alerts
            headers:
              Authorization: Bearer ${WEBHOOK_TOKEN}
              X-API-Key: ${API_KEY}
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.headers.len(), 2);
                // Headers are stored as-is, env var resolution happens at notifier creation
                assert_eq!(cfg.headers.get("Authorization").unwrap(), "Bearer ${WEBHOOK_TOKEN}");
                assert_eq!(cfg.headers.get("X-API-Key").unwrap(), "${API_KEY}");
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_empty_headers_is_valid() {
        let yaml = r#"
            type: webhook
            url: https://example.com/hook
            headers: {}
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert!(cfg.headers.is_empty());
            }
            _ => panic!("Expected Webhook variant"),
        }
    }
}
