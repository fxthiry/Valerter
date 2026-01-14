//! Runtime configuration with pre-compiled regex and templates.

use super::notifiers::NotifiersConfig;
use super::secret::SecretString;
use super::types::{
    Config, DefaultsConfig, JsonParserConfig, MetricsConfig, NotifyConfig, VictoriaLogsConfig,
};
use crate::error::ConfigError;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Runtime configuration with pre-compiled regex (FR15).
#[derive(Debug)]
pub struct RuntimeConfig {
    pub victorialogs: VictoriaLogsConfig,
    pub defaults: DefaultsConfig,
    pub templates: HashMap<String, CompiledTemplate>,
    pub rules: Vec<CompiledRule>,
    pub metrics: MetricsConfig,
    pub notifiers: Option<NotifiersConfig>,
    pub mattermost_webhook: Option<SecretString>,
    pub config_dir: std::path::PathBuf,
}

/// Compiled alert rule with pre-compiled regex.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub enabled: bool,
    pub query: String,
    pub parser: CompiledParser,
    pub throttle: Option<CompiledThrottle>,
    pub notify: Option<NotifyConfig>,
}

/// Parser with pre-compiled regex pattern.
#[derive(Debug, Clone)]
pub struct CompiledParser {
    pub regex: Option<Regex>,
    pub json: Option<JsonParserConfig>,
}

/// Throttle configuration with template key.
#[derive(Debug, Clone)]
pub struct CompiledThrottle {
    pub key_template: Option<String>,
    pub count: u32,
    pub window: Duration,
}

/// Pre-validated message template.
#[derive(Debug, Clone)]
pub struct CompiledTemplate {
    pub title: String,
    pub body: String,
    pub body_html: Option<String>,
    pub accent_color: Option<String>,
}

impl RuntimeConfig {
    /// Collect all unique destination names referenced in rules.
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

    /// Validate that all rule destinations exist in valid notifier names.
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

        // Validate empty destinations when notifiers section exists
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
    /// Compile configuration into runtime-ready format (FR15).
    pub fn compile(self, config_path: &Path) -> Result<RuntimeConfig, ConfigError> {
        let config_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();

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
                        body_html: template.body_html,
                        accent_color: template.accent_color,
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
            config_dir,
        })
    }
}
