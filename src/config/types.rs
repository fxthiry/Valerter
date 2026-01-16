//! Core configuration types and loading.

use super::notifiers::{NotifiersConfig, default_true};
use super::secret::SecretString;
use super::validation::{validate_hex_color, validate_jinja_template};
use crate::error::ConfigError;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/valerter/config.yaml";

/// Main configuration structure for valerter.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// VictoriaLogs connection settings.
    pub victorialogs: VictoriaLogsConfig,
    /// Default values for throttle and notify.
    pub defaults: DefaultsConfig,
    /// Reusable message templates.
    #[serde(default)]
    pub templates: HashMap<String, TemplateConfig>,
    /// Alert rules definitions.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Metrics exposition configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Named notifier configurations.
    #[serde(default)]
    pub notifiers: Option<NotifiersConfig>,
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

/// Rule configuration without the `name` field, for deserializing `.d/` files.
/// In `.d/` files, the rule name is the YAML key, not a field.
#[derive(Debug, Deserialize)]
struct RuleConfigWithoutName {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub query: String,
    pub parser: ParserConfig,
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
}

impl RuleConfigWithoutName {
    /// Convert to `RuleConfig` by injecting the name from the YAML key.
    fn into_rule_config(self, name: String) -> RuleConfig {
        RuleConfig {
            name,
            enabled: self.enabled,
            query: self.query,
            parser: self.parser,
            throttle: self.throttle,
            notify: self.notify,
        }
    }
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

// ============================================================
// Multi-file config loading (rules.d/, templates.d/, notifiers.d/)
// ============================================================

use super::notifiers::NotifierConfig;

/// Load rules from a `.d/` directory.
/// Returns a HashMap of rule name → (RuleConfig, source path) for collision detection.
fn load_rules_directory(dir: &Path) -> Result<HashMap<String, (RuleConfig, PathBuf)>, ConfigError> {
    load_directory_generic::<RuleConfigWithoutName, RuleConfig>(dir, "rules.d", |name, config| {
        config.into_rule_config(name)
    })
}

/// Load templates from a `.d/` directory.
/// Returns a HashMap of template name → (TemplateConfig, source path).
fn load_templates_directory(
    dir: &Path,
) -> Result<HashMap<String, (TemplateConfig, PathBuf)>, ConfigError> {
    load_directory_generic::<TemplateConfig, TemplateConfig>(dir, "templates.d", |_, config| config)
}

/// Load notifiers from a `.d/` directory.
/// Returns a HashMap of notifier name → (NotifierConfig, source path).
fn load_notifiers_directory(
    dir: &Path,
) -> Result<HashMap<String, (NotifierConfig, PathBuf)>, ConfigError> {
    load_directory_generic::<NotifierConfig, NotifierConfig>(dir, "notifiers.d", |_, config| config)
}

/// Generic function to load configs from a `.d/` directory.
fn load_directory_generic<D, T>(
    dir: &Path,
    dir_name: &str,
    convert: fn(String, D) -> T,
) -> Result<HashMap<String, (T, PathBuf)>, ConfigError>
where
    D: for<'de> Deserialize<'de>,
{
    let mut result = HashMap::new();

    if !dir.exists() {
        return Ok(result);
    }

    let entries = std::fs::read_dir(dir).map_err(|e| ConfigError::DirectoryError {
        path: dir.display().to_string(),
        message: e.to_string(),
    })?;

    // Collect and sort entries for deterministic processing order
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        // Skip non-files
        if !path.is_file() {
            continue;
        }

        // Skip hidden files (starting with '.')
        if let Some(name) = path.file_name()
            && name.to_string_lossy().starts_with('.')
        {
            continue;
        }

        // Only process .yaml and .yml files
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yaml") | Some("yml")) {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        // Skip empty files
        if content.trim().is_empty() {
            continue;
        }

        let items: HashMap<String, D> = serde_yaml::from_str(&content).map_err(|e| {
            ConfigError::ValidationError(format!("{} ({}): {}", dir_name, path.display(), e))
        })?;

        for (name, config) in items {
            // Check for collision within .d/ directory (across files)
            if let Some((_, existing_path)) = result.get(&name) {
                return Err(ConfigError::DuplicateName {
                    resource_type: dir_name.trim_end_matches(".d").to_string(),
                    name,
                    source1: existing_path.display().to_string(),
                    source2: path.display().to_string(),
                });
            }
            let converted = convert(name.clone(), config);
            result.insert(name, (converted, path.clone()));
        }
    }

    Ok(result)
}

/// Merge rules from config.yaml (Vec) with rules from .d/ directory (HashMap).
fn merge_rules(
    inline: Vec<RuleConfig>,
    from_dir: HashMap<String, (RuleConfig, PathBuf)>,
    config_path: &Path,
) -> Result<Vec<RuleConfig>, ConfigError> {
    let config_source = config_path.display().to_string();
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut merged = Vec::new();

    // First, add inline rules and track their names
    for rule in inline {
        seen.insert(rule.name.clone(), config_source.clone());
        merged.push(rule);
    }

    // Then, add rules from .d/ directory, checking for collisions
    for (name, (rule, source_path)) in from_dir {
        if let Some(first_source) = seen.get(&name) {
            return Err(ConfigError::DuplicateName {
                resource_type: "rule".to_string(),
                name,
                source1: first_source.clone(),
                source2: source_path.display().to_string(),
            });
        }
        merged.push(rule);
    }

    Ok(merged)
}

/// Merge templates from config.yaml with templates from .d/ directory.
fn merge_templates(
    inline: HashMap<String, TemplateConfig>,
    from_dir: HashMap<String, (TemplateConfig, PathBuf)>,
    config_path: &Path,
) -> Result<HashMap<String, TemplateConfig>, ConfigError> {
    merge_hashmap(inline, from_dir, "template", config_path)
}

/// Merge notifiers from config.yaml with notifiers from .d/ directory.
fn merge_notifiers(
    inline: Option<NotifiersConfig>,
    from_dir: HashMap<String, (NotifierConfig, PathBuf)>,
    config_path: &Path,
) -> Result<Option<NotifiersConfig>, ConfigError> {
    let inline = inline.unwrap_or_default();

    // If both are empty, return None for backward compatibility
    if inline.is_empty() && from_dir.is_empty() {
        return Ok(None);
    }

    let merged = merge_hashmap(inline, from_dir, "notifier", config_path)?;
    Ok(Some(merged))
}

/// Generic merge function for HashMap-based configs.
fn merge_hashmap<T>(
    inline: HashMap<String, T>,
    from_dir: HashMap<String, (T, PathBuf)>,
    resource_type: &str,
    config_path: &Path,
) -> Result<HashMap<String, T>, ConfigError> {
    let config_source = config_path.display().to_string();
    let mut merged = HashMap::new();

    // First, add inline items
    for (name, item) in inline {
        merged.insert(name, (item, config_source.clone()));
    }

    // Then, add items from .d/ directory, checking for collisions
    for (name, (item, source_path)) in from_dir {
        if let Some((_, first_source)) = merged.get(&name) {
            return Err(ConfigError::DuplicateName {
                resource_type: resource_type.to_string(),
                name,
                source1: first_source.clone(),
                source2: source_path.display().to_string(),
            });
        }
        merged.insert(name, (item, source_path.display().to_string()));
    }

    // Strip source info and return just the items
    Ok(merged.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

impl Config {
    /// Load configuration from a file path.
    ///
    /// Also loads and merges configs from `rules.d/`, `templates.d/`, and `notifiers.d/`
    /// directories if they exist in the same directory as the config file.
    ///
    /// # Errors
    /// Returns [`ConfigError::LoadError`] if the file cannot be read.
    /// Returns [`ConfigError::ValidationError`] if the YAML is invalid.
    /// Returns [`ConfigError::DuplicateName`] if a name collision is detected.
    /// Returns [`ConfigError::DirectoryError`] if a `.d/` directory cannot be read.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(format!("{}: {}", path.display(), e)))?;

        let mut config: Config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        // Load and merge from .d/ directories
        if let Some(config_dir) = path.parent() {
            let rules_dir = config_dir.join("rules.d");
            let templates_dir = config_dir.join("templates.d");
            let notifiers_dir = config_dir.join("notifiers.d");

            let rules_from_dir = load_rules_directory(&rules_dir)?;
            let templates_from_dir = load_templates_directory(&templates_dir)?;
            let notifiers_from_dir = load_notifiers_directory(&notifiers_dir)?;

            config.rules = merge_rules(config.rules, rules_from_dir, path)?;
            config.templates = merge_templates(config.templates, templates_from_dir, path)?;
            config.notifiers = merge_notifiers(config.notifiers, notifiers_from_dir, path)?;
        }

        Ok(config)
    }

    /// Validate all rules (even disabled ones) - AD-11.
    ///
    /// # Errors
    /// Returns a `Vec<ConfigError>` containing all validation errors found.
    /// Possible errors: `InvalidRegex`, `InvalidTemplate`, `ValidationError` (for invalid colors).
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        // ===== Mandatory config sections (after .d/ merge) =====

        // Validate that at least one notifier is configured
        let has_notifiers = self
            .notifiers
            .as_ref()
            .map(|n| !n.is_empty())
            .unwrap_or(false);
        if !has_notifiers {
            errors.push(ConfigError::ValidationError(
                "no notifiers configured: add notifiers in config.yaml or notifiers.d/".to_string(),
            ));
        }

        // Validate that at least one template is defined
        if self.templates.is_empty() {
            errors.push(ConfigError::ValidationError(
                "no templates defined: add templates in config.yaml or templates.d/".to_string(),
            ));
        }

        // Validate that at least one rule is defined
        if self.rules.is_empty() {
            errors.push(ConfigError::ValidationError(
                "no rules defined: add rules in config.yaml or rules.d/".to_string(),
            ));
        }

        // ===== Rule validations =====
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
