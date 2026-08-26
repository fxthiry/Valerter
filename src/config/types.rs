//! Core configuration types and loading.

use super::notifiers::{NotifiersConfig, default_true};
use super::secret::SecretString;
use super::validation::{validate_hex_color, validate_jinja_template, validate_url};
use crate::error::ConfigError;
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/valerter/config.yaml";

/// Main configuration structure for valerter.
///
/// `victorialogs` is a map of named source configurations. A BTreeMap is used
/// explicitly (never HashMap) so iteration over sources is deterministic —
/// crucial for test assertions, diagnostic logs, and spawn order.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Named VictoriaLogs sources. At least one is required (enforced at validate()).
    #[serde(deserialize_with = "deserialize_vl_sources")]
    pub victorialogs: BTreeMap<String, VlSourceConfig>,
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

/// Configuration for a single named VictoriaLogs source.
///
/// Renamed from `VictoriaLogsConfig` in v2.0.0 (multi-source support). The
/// field set is unchanged; only the containing map structure changed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlSourceConfig {
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

/// Legacy single-URL `victorialogs` shape. Kept for detection only so we can
/// emit a precise migration error when users upgrade from v1.x.
///
/// Intentionally does NOT set `deny_unknown_fields`: v1 users with a forked
/// build or an extra field still land on the migration error rather than a
/// cryptic v2 parse failure.
#[derive(Debug, Deserialize)]
struct LegacyVictoriaLogsConfig {
    #[allow(dead_code)]
    url: String,
    #[serde(default)]
    #[allow(dead_code)]
    basic_auth: Option<BasicAuthConfig>,
    #[serde(default)]
    #[allow(dead_code)]
    headers: Option<HashMap<String, SecretString>>,
    #[serde(default)]
    #[allow(dead_code)]
    tls: Option<TlsConfig>,
}

/// Migration error text pointing users from the v1 single-URL shape to the
/// v2 map shape. Exposed so tests can assert wording.
pub(crate) const LEGACY_VL_MIGRATION_MESSAGE: &str = "\nConfiguration incompatible with valerter v2.0.0.\n\nYour config uses the v1.x single-URL shape (`victorialogs.url`), replaced by a map of named sources in v2.\n\nMigrate from:\n  victorialogs:\n    url: \"http://...\"\n    basic_auth:\n      username: \"u\"\n      password: \"p\"\nTo:\n  victorialogs:\n    default:\n      url: \"http://...\"\n      basic_auth:\n        username: \"u\"\n        password: \"p\"\n\nThen optionally target sources per rule via `vl_sources: [default]` (or omit to fan out across all sources).\n\nFull migration guide: https://github.com/fxthiry/valerter/blob/main/MIGRATION.md\nRollback: install the last v1.x release from https://github.com/fxthiry/valerter/releases";

/// Deserialize `victorialogs` as `BTreeMap<String, VlSourceConfig>`, but
/// emit a migration-oriented error when the legacy single-object shape
/// (`url: ...` at the `victorialogs` level) is detected.
fn deserialize_vl_sources<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, VlSourceConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = serde_yaml::Value::deserialize(deserializer)?;

    // Legacy-shape detection: a YAML mapping that parses cleanly as the v1
    // struct is the old shape. The new shape's outer map has named keys whose
    // values are objects — these fail the v1 struct parse due to
    // `deny_unknown_fields`.
    if serde_yaml::from_value::<LegacyVictoriaLogsConfig>(raw.clone()).is_ok() {
        return Err(serde::de::Error::custom(LEGACY_VL_MIGRATION_MESSAGE));
    }

    serde_yaml::from_value::<BTreeMap<String, VlSourceConfig>>(raw)
        .map_err(serde::de::Error::custom)
}

/// A VictoriaLogs source name is valid if it is non-empty and contains only
/// alphanumeric ASCII characters or underscores. This restriction guarantees
/// the default throttle key `{rule}-{source}:global` parses unambiguously and
/// avoids collisions when rule and source names share the `-` separator.
fn is_valid_source_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub verify: bool,
}

/// Metrics exposition configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    pub throttle: ThrottleConfig,
    /// Timezone for formatted timestamps (e.g., "UTC", "Europe/Paris").
    #[serde(default = "default_timestamp_timezone")]
    pub timestamp_timezone: String,
    /// Maximum total number of concurrent VictoriaLogs streams (sum of
    /// `(rule, source)` task pairs for enabled rules). Hard cap enforced at
    /// load time to prevent unintentional fan-out from DoSing a backend.
    ///
    /// Default: 50. Configurable via `defaults.max_streams: <usize>` in
    /// `config.yaml`.
    #[serde(default = "default_max_streams")]
    pub max_streams: usize,
}

/// Default upper bound on the total number of concurrent VL streams.
///
/// Picked to comfortably accommodate small/mid-size deployments (~10 sources ×
/// a handful of fan-out rules) while still failing fast on accidentally large
/// fan-outs. Configurable per-deployment via `defaults.max_streams`.
pub const DEFAULT_MAX_STREAMS: usize = 50;

fn default_max_streams() -> usize {
    DEFAULT_MAX_STREAMS
}

fn default_timestamp_timezone() -> String {
    "UTC".to_string()
}

/// Throttle configuration for rate limiting.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleConfig {
    #[serde(default)]
    pub key: Option<String>,
    pub count: u32,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
}

/// Template configuration for message formatting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateConfig {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub email_body_html: Option<String>,
    #[serde(default)]
    pub accent_color: Option<String>,
}

/// Alert rule configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub query: String,
    pub parser: ParserConfig,
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    pub notify: NotifyConfig,
    /// Optional list of VictoriaLogs source names to target. An empty list (the
    /// default) means "fan out across every configured source". All listed
    /// names must exist in the top-level `victorialogs` map; unknown refs are
    /// rejected at `Config::validate()` time.
    #[serde(default)]
    pub vl_sources: Vec<String>,
}

/// Rule configuration without the `name` field, for deserializing `.d/` files.
/// In `.d/` files, the rule name is the YAML key, not a field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleConfigWithoutName {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub query: String,
    pub parser: ParserConfig,
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    pub notify: NotifyConfig,
    #[serde(default)]
    pub vl_sources: Vec<String>,
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
            vl_sources: self.vl_sources,
        }
    }
}

/// Parser configuration for extracting data from log lines.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserConfig {
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub json: Option<JsonParserConfig>,
}

/// JSON parser configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonParserConfig {
    pub fields: Vec<String>,
}

/// Notification configuration for a rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    pub template: String,
    #[serde(default)]
    pub mattermost_channel: Option<String>,
    pub destinations: Vec<String>,
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

        config.resolve_source_env_vars()?;

        Ok(config)
    }

    /// Resolve `${VAR}` placeholders in every VictoriaLogs source (`url`,
    /// `basic_auth`, `headers`). Notifier secrets are resolved when the
    /// registry is built; sources were never resolved at all, so a documented
    /// `password: "${VL_PASS}"` was sent verbatim to VictoriaLogs.
    fn resolve_source_env_vars(&mut self) -> Result<(), ConfigError> {
        use super::env::resolve_env_vars;
        for (name, source) in self.victorialogs.iter_mut() {
            let ctx = |e: ConfigError| {
                ConfigError::ValidationError(format!("victorialogs source '{name}': {e}"))
            };
            source.url = resolve_env_vars(&source.url).map_err(ctx)?;
            if let Some(auth) = source.basic_auth.as_mut() {
                auth.username = resolve_env_vars(&auth.username).map_err(ctx)?;
                auth.password =
                    SecretString::new(resolve_env_vars(auth.password.expose()).map_err(ctx)?);
            }
            if let Some(headers) = source.headers.as_mut() {
                for value in headers.values_mut() {
                    *value = SecretString::new(resolve_env_vars(value.expose()).map_err(ctx)?);
                }
            }
        }
        Ok(())
    }

    /// Validate all rules (even disabled ones) - AD-11.
    ///
    /// # Errors
    /// Returns a `Vec<ConfigError>` containing all validation errors found.
    /// Possible errors: `InvalidRegex`, `InvalidTemplate`, `ValidationError` (for invalid colors).
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        // ===== VictoriaLogs source validations =====

        // At least one source is required (zero-source rejection).
        if self.victorialogs.is_empty() {
            errors.push(ConfigError::ValidationError(
                "victorialogs: at least one source required (define e.g. `victorialogs: { default: { url: \"http://...\" } }`)"
                    .to_string(),
            ));
        }

        // Validate each source's URL and name format.
        for (source_name, source) in &self.victorialogs {
            if let Err(e) = validate_url(&source.url) {
                errors.push(ConfigError::ValidationError(format!(
                    "victorialogs.{}.url: {}",
                    source_name, e
                )));
            }
            if !is_valid_source_name(source_name) {
                errors.push(ConfigError::ValidationError(format!(
                    "victorialogs source name '{}' is invalid: must match `^[a-zA-Z0-9_]+$` (alphanumeric or underscore). \
                     This avoids ambiguity in the default throttle key `{{rule}}-{{source}}:global`.",
                    source_name
                )));
            }
        }

        // Validate that every rule.vl_sources entry references a declared source
        // and that the rule's vl_sources list contains no duplicates.
        let known_sources: Vec<&str> = self.victorialogs.keys().map(String::as_str).collect();
        for rule in &self.rules {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for referenced in &rule.vl_sources {
                if !self.victorialogs.contains_key(referenced) {
                    errors.push(ConfigError::ValidationError(format!(
                        "rule '{}': vl_sources references unknown source '{}' (known sources: [{}])",
                        rule.name,
                        referenced,
                        known_sources.join(", ")
                    )));
                }
                if !seen.insert(referenced.as_str()) {
                    errors.push(ConfigError::ValidationError(format!(
                        "rule '{}': vl_sources contains duplicate entry '{}' (each source may appear at most once)",
                        rule.name, referenced
                    )));
                }
            }
        }

        // Validate notifier URLs
        if let Some(notifiers) = &self.notifiers {
            for (name, notifier) in notifiers {
                match notifier {
                    super::notifiers::NotifierConfig::Mattermost(cfg) => {
                        if let Err(e) = validate_url(cfg.webhook_url.expose()) {
                            errors.push(ConfigError::ValidationError(format!(
                                "notifier '{}': webhook_url: {}",
                                name, e
                            )));
                        }
                    }
                    super::notifiers::NotifierConfig::Webhook(cfg) => {
                        if let Err(e) = validate_url(cfg.url.expose()) {
                            errors.push(ConfigError::ValidationError(format!(
                                "notifier '{}': url: {}",
                                name, e
                            )));
                        }
                    }
                    super::notifiers::NotifierConfig::Email(_) => {
                        // Email notifier doesn't have URLs to validate
                    }
                    super::notifiers::NotifierConfig::Telegram(cfg) => {
                        if cfg.chat_ids.is_empty() {
                            errors.push(ConfigError::ValidationError(format!(
                                "notifier '{}': chat_ids must not be empty",
                                name
                            )));
                        }
                    }
                }
            }
        }

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
        let mut seen_rule_names = std::collections::HashSet::new();
        for rule in &self.rules {
            if !seen_rule_names.insert(rule.name.as_str()) {
                errors.push(ConfigError::ValidationError(format!(
                    "duplicate rule name '{}': rule names must be unique (they key throttling and metrics)",
                    rule.name
                )));
            }

            if let Some(ref throttle) = rule.throttle {
                if throttle.count == 0 {
                    errors.push(ConfigError::ValidationError(format!(
                        "rule '{}': throttle.count must be >= 1 (0 would suppress every alert)",
                        rule.name
                    )));
                }
                if throttle.window.is_zero() {
                    errors.push(ConfigError::ValidationError(format!(
                        "rule '{}': throttle.window must be > 0 (0s disables throttling)",
                        rule.name
                    )));
                }
            }

            if let Err(e) = super::validation::validate_tail_query(&rule.query) {
                errors.push(ConfigError::ValidationError(format!(
                    "rule '{}': invalid query: {}",
                    rule.name, e
                )));
            }

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

            // Validate template exists
            if !self.templates.contains_key(&rule.notify.template) {
                errors.push(ConfigError::InvalidTemplate {
                    rule: rule.name.clone(),
                    message: format!(
                        "notify.template '{}' not found in templates",
                        rule.notify.template
                    ),
                });
            }

            // Validate destinations is not empty
            if rule.notify.destinations.is_empty() {
                errors.push(ConfigError::ValidationError(format!(
                    "rule '{}': notify.destinations must contain at least one notifier",
                    rule.name
                )));
            }
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
            if let Some(email_body_html) = &template.email_body_html
                && let Err(e) = validate_jinja_template(email_body_html)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("email_body_html: {}", e),
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
            if let Some(email_body_html) = &template.email_body_html
                && let Err(e) = super::validation::validate_template_render(email_body_html)
            {
                errors.push(ConfigError::InvalidTemplate {
                    rule: format!("template:{}", name),
                    message: format!("email_body_html render: {}", e),
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

        // Validate `defaults.max_streams` cap against the actual fan-out.
        // Total stream count = sum, over enabled rules, of:
        //   - `sources.len()` if `rule.vl_sources` is empty (fan out across all)
        //   - `rule.vl_sources.len()` otherwise.
        // Disabled rules do not contribute. Enforced at load (not runtime) so
        // a misconfigured fan-out fails fast at startup.
        if self.defaults.max_streams == 0 {
            errors.push(ConfigError::ValidationError(
                "defaults.max_streams must be >= 1 (a value of 0 would reject every config). \
                 Omit the field to use the default (50) or set an explicit positive value."
                    .to_string(),
            ));
        }
        let source_count = self.victorialogs.len();
        let total_streams: usize = self
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| {
                if r.vl_sources.is_empty() {
                    source_count
                } else {
                    r.vl_sources.len()
                }
            })
            .sum();
        if total_streams > self.defaults.max_streams {
            errors.push(ConfigError::ValidationError(format!(
                "defaults.max_streams exceeded: {} stream(s) required by enabled rules > cap of {}. \
                 Either raise `defaults.max_streams` or trim rules / `vl_sources` to reduce fan-out.",
                total_streams, self.defaults.max_streams
            )));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
