//! Core configuration types and loading.

use super::notifiers::{NotifiersConfig, default_true};
use super::secret::SecretString;
use super::validation::{validate_hex_color, validate_jinja_template};
use crate::error::ConfigError;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Default configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/valerter/config.yaml";

/// Environment variable name for Mattermost webhook URL.
pub const ENV_MATTERMOST_WEBHOOK: &str = "MATTERMOST_WEBHOOK";

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
    /// Mattermost webhook URL (loaded from environment, not from YAML).
    #[serde(skip)]
    pub mattermost_webhook: Option<SecretString>,
}

/// VictoriaLogs connection configuration.
#[derive(Debug, Clone, Deserialize)]
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

impl<'de> Deserialize<'de> for BasicAuthConfig {
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
    #[serde(default = "default_true")]
    pub verify: bool,
}

/// Metrics exposition configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics exposition is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Port to expose metrics on (default: 9090).
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

/// Default configuration values.
#[derive(Debug, Deserialize)]
pub struct DefaultsConfig {
    pub throttle: ThrottleConfig,
    pub notify: NotifyDefaults,
    /// Timezone for formatted timestamps (e.g., "UTC", "Europe/Paris").
    #[serde(default = "default_timestamp_timezone")]
    pub timestamp_timezone: String,
}

fn default_timestamp_timezone() -> String {
    "UTC".to_string()
}

/// Throttle configuration for rate limiting.
#[derive(Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    #[serde(default)]
    pub key: Option<String>,
    pub count: u32,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
}

/// Default notification settings.
#[derive(Debug, Deserialize)]
pub struct NotifyDefaults {
    pub template: String,
}

/// Template configuration for message formatting.
#[derive(Debug, Deserialize)]
pub struct TemplateConfig {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub body_html: Option<String>,
    #[serde(default)]
    pub accent_color: Option<String>,
}

/// Alert rule configuration.
#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub query: String,
    pub parser: ParserConfig,
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
}

/// Parser configuration for extracting data from log lines.
#[derive(Debug, Deserialize)]
pub struct ParserConfig {
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub json: Option<JsonParserConfig>,
}

/// JSON parser configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonParserConfig {
    pub fields: Vec<String>,
}

/// Notification configuration for a rule.
#[derive(Debug, Clone, Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub destinations: Option<Vec<String>>,
}

impl Config {
    /// Load configuration from a file path.
    ///
    /// # Errors
    /// Returns [`ConfigError::LoadError`] if the file cannot be read.
    /// Returns [`ConfigError::ValidationError`] if the YAML is invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        config.mattermost_webhook = std::env::var(ENV_MATTERMOST_WEBHOOK)
            .ok()
            .map(SecretString::new);

        Ok(config)
    }

    /// Load configuration with an explicit webhook (for testing).
    ///
    /// # Errors
    /// Returns [`ConfigError::LoadError`] if the file cannot be read.
    /// Returns [`ConfigError::ValidationError`] if the YAML is invalid.
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
    /// # Errors
    /// Returns a `Vec<ConfigError>` containing all validation errors found.
    /// Possible errors: `InvalidRegex`, `InvalidTemplate`, `ValidationError` (for invalid colors).
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        // Validate all rules
        for rule in &self.rules {
            if let Some(ref pattern) = rule.parser.regex
                && let Err(e) = Regex::new(pattern)
            {
                errors.push(ConfigError::InvalidRegex {
                    rule: rule.name.clone(),
                    message: e.to_string(),
                });
            }

            if let Some(ref throttle) = rule.throttle
                && let Some(ref key_template) = throttle.key
                && let Err(e) = validate_jinja_template(key_template)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: rule.name.clone(),
                    message: format!("throttle.key: {}", e),
                });
            }

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

        // Validate default template exists
        if !self.templates.contains_key(&self.defaults.notify.template) {
            errors.push(ConfigError::InvalidTemplate {
                rule: "defaults.notify".to_string(),
                message: format!(
                    "default template '{}' not found in templates",
                    self.defaults.notify.template
                ),
            });
        }

        // Validate named templates (syntax)
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
            if let Some(body_html) = &template.body_html
                && let Err(e) = validate_jinja_template(body_html)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("body_html: {}", e),
                });
            }
        }

        // Validate named templates (render test)
        for (name, template) in &self.templates {
            if let Err(e) = super::validation::validate_template_render(&template.title) {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("title render: {}", e),
                });
            }
            if let Err(e) = super::validation::validate_template_render(&template.body) {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("body render: {}", e),
                });
            }
            if let Some(body_html) = &template.body_html
                && let Err(e) = super::validation::validate_template_render(body_html)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("body_html render: {}", e),
                });
            }
        }

        // Validate accent_color hex format
        for (name, template) in &self.templates {
            if let Some(accent_color) = &template.accent_color
                && let Err(e) = validate_hex_color(accent_color)
            {
                errors.push(ConfigError::ValidationError(format!(
                    "template '{}': {}",
                    name, e
                )));
            }
        }

        // Validate timestamp_timezone
        if self
            .defaults
            .timestamp_timezone
            .parse::<chrono_tz::Tz>()
            .is_err()
        {
            errors.push(ConfigError::ValidationError(format!(
                "defaults.timestamp_timezone '{}' is not a valid timezone",
                self.defaults.timestamp_timezone
            )));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
