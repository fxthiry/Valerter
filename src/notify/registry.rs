//! Notifier registry for managing named notifiers.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::config::{NotifierConfig, NotifiersConfig, SecretString, resolve_env_vars};
use crate::error::ConfigError;

use super::{EmailNotifier, MattermostNotifier, Notifier, WebhookNotifier};

/// Registry for managing named notifiers.
///
/// Provides lookup by name and validation of destination references.
#[derive(Debug, Default)]
pub struct NotifierRegistry {
    notifiers: HashMap<String, Arc<dyn Notifier>>,
}

impl NotifierRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            notifiers: HashMap::new(),
        }
    }

    /// Register a notifier by name.
    ///
    /// # Arguments
    ///
    /// * `notifier` - The notifier to register (will be wrapped in Arc)
    ///
    /// # Returns
    ///
    /// Error if a notifier with the same name already exists.
    pub fn register(&mut self, notifier: Arc<dyn Notifier>) -> Result<(), ConfigError> {
        let name = notifier.name().to_string();
        if self.notifiers.contains_key(&name) {
            return Err(ConfigError::ValidationError(format!(
                "notifier '{}' already registered",
                name
            )));
        }
        self.notifiers.insert(name, notifier);
        Ok(())
    }

    /// Get a notifier by name.
    ///
    /// # Returns
    ///
    /// The notifier if found, None otherwise.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Notifier>> {
        self.notifiers.get(name).cloned()
    }

    /// Get all registered notifier names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.notifiers.keys().map(|s| s.as_str())
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.notifiers.is_empty()
    }

    /// Get the number of registered notifiers.
    pub fn len(&self) -> usize {
        self.notifiers.len()
    }

    /// Validate that all destination names exist in the registry.
    ///
    /// # Arguments
    ///
    /// * `names` - List of notifier names to validate
    ///
    /// # Returns
    ///
    /// Error listing all unknown notifier names if any are not found.
    pub fn validate_destinations(&self, names: &[String]) -> Result<(), ConfigError> {
        let unknown: Vec<_> = names
            .iter()
            .filter(|name| !self.notifiers.contains_key(*name))
            .collect();

        if unknown.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::ValidationError(format!(
                "unknown notifiers referenced: {}",
                unknown
                    .iter()
                    .map(|s| format!("'{}'", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }

    /// Create a registry from configuration (Story 6.2).
    ///
    /// Parses the `notifiers` section from config and instantiates
    /// all configured notifiers with environment variable substitution.
    ///
    /// # Arguments
    ///
    /// * `notifiers_config` - Map of named notifier configurations
    /// * `http_client` - Shared HTTP client for all notifiers
    ///
    /// # Returns
    ///
    /// * `Ok(NotifierRegistry)` - Registry with all configured notifiers
    /// * `Err(Vec<ConfigError>)` - All errors encountered during instantiation
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = Config::load("config.yaml")?;
    /// if let Some(notifiers_config) = config.notifiers {
    ///     let registry = NotifierRegistry::from_config(&notifiers_config, http_client, config_dir)?;
    /// }
    /// ```
    pub fn from_config(
        notifiers_config: &NotifiersConfig,
        http_client: reqwest::Client,
        config_dir: &Path,
    ) -> Result<Self, Vec<ConfigError>> {
        let mut registry = NotifierRegistry::new();
        let mut errors = Vec::new();

        for (name, config) in notifiers_config {
            match Self::create_notifier(name, config, &http_client, config_dir) {
                Ok(notifier) => {
                    if let Err(e) = registry.register(notifier) {
                        errors.push(e);
                    }
                }
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(registry)
        } else {
            Err(errors)
        }
    }

    /// Create a single notifier from configuration.
    fn create_notifier(
        name: &str,
        config: &NotifierConfig,
        http_client: &reqwest::Client,
        config_dir: &Path,
    ) -> Result<Arc<dyn Notifier>, ConfigError> {
        match config {
            NotifierConfig::Mattermost(mm_config) => {
                // Resolve environment variables in webhook_url
                let resolved_url = resolve_env_vars(&mm_config.webhook_url).map_err(|e| {
                    // Track env var resolution failures for monitoring (Fix M1)
                    metrics::counter!(
                        "valerter_notifier_config_errors_total",
                        "notifier" => name.to_string(),
                        "error_type" => "env_var_resolution"
                    )
                    .increment(1);
                    ConfigError::InvalidNotifier {
                        name: name.to_string(),
                        message: format!("webhook_url: {}", e),
                    }
                })?;

                let notifier = MattermostNotifier::with_options(
                    name.to_string(),
                    SecretString::new(resolved_url),
                    mm_config.channel.clone(),
                    mm_config.username.clone(),
                    mm_config.icon_url.clone(),
                    http_client.clone(),
                );

                tracing::info!(
                    notifier_name = %name,
                    notifier_type = "mattermost",
                    channel = ?mm_config.channel,
                    "Registered notifier from config"
                );

                Ok(Arc::new(notifier))
            }
            NotifierConfig::Webhook(wh_config) => {
                let notifier = WebhookNotifier::from_config(name, wh_config, http_client.clone())?;

                tracing::info!(
                    notifier_name = %name,
                    notifier_type = "webhook",
                    method = %wh_config.method,
                    "Registered webhook notifier from config"
                );

                Ok(Arc::new(notifier))
            }
            NotifierConfig::Email(email_config) => {
                let notifier = EmailNotifier::from_config(name, email_config, config_dir)?;

                tracing::info!(
                    notifier_name = %name,
                    notifier_type = "email",
                    from = %email_config.from,
                    to_count = email_config.to.len(),
                    "Registered email notifier from config"
                );

                Ok(Arc::new(notifier))
            }
        }
    }
}
