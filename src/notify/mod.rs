//! Asynchronous notification system for valerter alerts.
//!
//! This module implements a modular notification system with:
//! - Abstract `Notifier` trait for different notification channels
//! - `NotifierRegistry` for managing named notifiers
//! - Bounded notification queue with Drop Oldest strategy (AD-02)
//! - HTTP sending with exponential backoff retry (AD-07)
//!
//! # Architecture
//!
//! The notification module sits at the end of the pipeline:
//! ```text
//! parser.rs -> throttle.rs -> template.rs -> notify/ -> Notifiers
//! ```
//!
//! # Key Features
//!
//! - **Modular notifiers**: Abstract trait allows adding new channels
//! - **Non-blocking send**: Callers never block when submitting alerts
//! - **Drop Oldest**: When queue is full, oldest alerts are dropped (AD-02)
//! - **Metrics**: Queue size and dropped alerts are tracked (AD-05)
//! - **Graceful shutdown**: Worker supports cancellation token

pub mod email;
pub mod mattermost;
pub mod webhook;

use crate::config::{NotifierConfig, NotifiersConfig, SecretString, resolve_env_vars};
use crate::error::{ConfigError, NotifyError, QueueError};
use crate::template::RenderedMessage;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

// Re-export notifiers for convenience
pub use email::EmailNotifier;
pub use mattermost::MattermostNotifier;
pub use webhook::WebhookNotifier;

/// Default queue capacity (FR32).
pub const DEFAULT_QUEUE_CAPACITY: usize = 100;

// =============================================================================
// Notifier Trait (AC1)
// =============================================================================

/// Abstract notifier trait for sending alerts to different channels.
///
/// Implementations must be `Send + Sync` to work across async tasks.
/// Each notifier manages its own retry/backoff logic internally.
///
/// # Example
///
/// ```ignore
/// use valerter::notify::{Notifier, AlertPayload};
///
/// struct MyNotifier { name: String }
///
/// #[async_trait]
/// impl Notifier for MyNotifier {
///     fn name(&self) -> &str { &self.name }
///     fn notifier_type(&self) -> &str { "my_type" }
///     async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
///         // Send implementation
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Unique name of this notifier instance (e.g., "mattermost-infra").
    fn name(&self) -> &str;

    /// Type of the notifier (e.g., "mattermost", "webhook", "email").
    fn notifier_type(&self) -> &str;

    /// Send an alert through this notifier.
    ///
    /// Implementations should handle their own retry/backoff logic.
    ///
    /// # Arguments
    ///
    /// * `alert` - The alert payload to send
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Alert sent successfully
    /// * `Err(NotifyError)` - Failed to send after all retries
    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError>;
}

// =============================================================================
// NotifierRegistry (AC2, AC4)
// =============================================================================

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

// Implement Debug for dyn Notifier to satisfy HashMap debug requirement
impl std::fmt::Debug for dyn Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("name", &self.name())
            .field("type", &self.notifier_type())
            .finish()
    }
}

// =============================================================================
// AlertPayload
// =============================================================================

/// Payload ready to be sent to a notifier.
///
/// Contains all fields needed to send a notification.
/// Must implement `Clone` as required by `broadcast::Sender`.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    /// Rendered message content (title, body, color, icon).
    pub message: RenderedMessage,
    /// Rule name for tracing and metrics.
    pub rule_name: String,
    /// Notification destinations (notifier names).
    /// If empty, uses the default notifier.
    pub destinations: Vec<String>,
}

// =============================================================================
// NotificationQueue
// =============================================================================

/// Notification queue using broadcast channel with ring buffer.
///
/// The broadcast channel provides native Drop Oldest behavior:
/// when capacity is reached, old messages are automatically overwritten.
///
/// # Thread Safety
///
/// The queue is `Clone + Send + Sync` and can be shared across tasks.
#[derive(Debug, Clone)]
pub struct NotificationQueue {
    tx: broadcast::Sender<AlertPayload>,
}

impl NotificationQueue {
    /// Create a new notification queue with specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of messages in the queue (FR32: 100).
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Send an alert to the queue (non-blocking).
    ///
    /// This operation never blocks. If the queue is full, the oldest
    /// messages will be dropped (detected by receivers as `Lagged`).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Alert queued successfully.
    /// * `Err(QueueError::Closed)` - No active receivers.
    pub fn send(&self, payload: AlertPayload) -> Result<(), QueueError> {
        self.tx.send(payload).map_err(|_| QueueError::Closed)?;

        // Update queue size metric (AD-05)
        metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);

        Ok(())
    }

    /// Create a new receiver for this queue.
    pub fn subscribe(&self) -> broadcast::Receiver<AlertPayload> {
        self.tx.subscribe()
    }

    /// Get the current number of messages in the queue.
    pub fn len(&self) -> usize {
        self.tx.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tx.len() == 0
    }
}

// =============================================================================
// NotificationWorker
// =============================================================================

/// Worker that consumes alerts from the queue and sends them via the registry.
///
/// The worker runs in a loop, processing alerts until cancelled
/// or the queue is closed.
pub struct NotificationWorker {
    rx: broadcast::Receiver<AlertPayload>,
    /// Reference to sender for queue size metrics.
    tx: broadcast::Sender<AlertPayload>,
    /// Registry of notifiers for sending.
    registry: Arc<NotifierRegistry>,
    /// Default notifier name to use when no specific destination is specified.
    default_notifier: String,
}

impl NotificationWorker {
    /// Create a new notification worker from a queue and registry.
    ///
    /// # Arguments
    ///
    /// * `queue` - Reference to the notification queue.
    /// * `registry` - Registry of available notifiers.
    /// * `default_notifier` - Name of the default notifier to use.
    pub fn new(
        queue: &NotificationQueue,
        registry: Arc<NotifierRegistry>,
        default_notifier: String,
    ) -> Self {
        Self {
            rx: queue.subscribe(),
            tx: queue.tx.clone(),
            registry,
            default_notifier,
        }
    }

    /// Run the worker loop until cancelled or queue closed.
    ///
    /// The worker will:
    /// 1. Consume alerts from the queue
    /// 2. Handle `Lagged` errors by logging and updating metrics
    /// 3. Send alerts via the appropriate notifier
    /// 4. Stop gracefully when cancellation is requested
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    pub async fn run(&mut self, cancel: CancellationToken) {
        tracing::info!("Notification worker started");

        loop {
            tokio::select! {
                result = self.rx.recv() => {
                    match result {
                        Ok(payload) => {
                            self.process_alert(payload).await;
                            // Update queue size metric after consuming (AD-05)
                            metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Drop Oldest detected - log and update metric (AD-02)
                            tracing::warn!(
                                dropped_count = n,
                                "Queue full, dropping {} oldest alerts",
                                n
                            );
                            metrics::counter!("valerter_alerts_dropped_total")
                                .increment(n);

                            // Update queue size metric after lag recovery
                            metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("Notification queue closed");
                            return;
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::info!("Notification worker shutting down gracefully");
                    return;
                }
            }
        }
    }

    /// Process a single alert payload.
    ///
    /// Implements fan-out routing (Story 6.3):
    /// - If destinations is empty, sends to default notifier
    /// - Otherwise, sends to ALL specified destinations in parallel (AC #2)
    async fn process_alert(&self, payload: AlertPayload) {
        let span = tracing::info_span!(
            "process_notification",
            rule_name = %payload.rule_name
        );
        let _guard = span.enter();

        // Determine which destinations to use (Story 6.3)
        let destinations: Vec<&str> = if payload.destinations.is_empty() {
            // Backward compatibility: use default notifier
            vec![&self.default_notifier]
        } else {
            // Use configured destinations
            payload.destinations.iter().map(String::as_str).collect()
        };

        tracing::debug!(
            destination_count = destinations.len(),
            destinations = ?destinations,
            "Processing alert with fan-out"
        );

        // AC #2: Send to all destinations in PARALLEL
        // AC #7: each destination failure is independent
        let futures: Vec<_> = destinations
            .iter()
            .filter_map(|dest_name| {
                match self.registry.get(dest_name) {
                    Some(notifier) => Some((dest_name.to_string(), notifier, payload.clone())),
                    None => {
                        // Should never happen if validation passed at startup
                        tracing::error!(
                            notifier = %dest_name,
                            rule_name = %payload.rule_name,
                            "Notifier not found in registry (validation should have caught this)"
                        );
                        metrics::counter!(
                            "valerter_notify_errors_total",
                            "notifier_name" => dest_name.to_string(),
                            "notifier_type" => "unknown",
                            "rule_name" => payload.rule_name.clone()
                        )
                        .increment(1);
                        None
                    }
                }
            })
            .map(|(dest_name, notifier, payload)| async move {
                let result = notifier.send(&payload).await;
                (dest_name, notifier.name().to_string(), result)
            })
            .collect();

        // Execute all sends in parallel and collect results
        let results = futures_util::future::join_all(futures).await;

        // Log results (AC #7: each result logged independently)
        for (dest_name, notifier_name, result) in results {
            match result {
                Ok(()) => {
                    tracing::debug!(
                        notifier = %notifier_name,
                        rule_name = %payload.rule_name,
                        "Notification sent successfully"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        notifier = %notifier_name,
                        destination = %dest_name,
                        rule_name = %payload.rule_name,
                        "Failed to send notification after all retries"
                    );
                    // Metrics are already recorded in the notifier implementation
                }
            }
        }
    }
}

impl std::fmt::Debug for NotificationWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationWorker")
            .field("default_notifier", &self.default_notifier)
            .finish()
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Calculate exponential backoff delay.
///
/// Formula: min(base * 2^attempt, max)
///
/// # Arguments
///
/// * `attempt` - Current attempt number (0-indexed)
/// * `base` - Base delay duration
/// * `max` - Maximum delay cap
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
    std::cmp::min(delay, max)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn make_payload(rule_name: &str) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: format!("Alert from {}", rule_name),
                body: "Test body".to_string(),
                body_html: None,
                color: Some("#ff0000".to_string()),
                icon: None,
            },
            rule_name: rule_name.to_string(),
            destinations: vec![], // Uses default notifier
        }
    }

    fn make_payload_with_destinations(rule_name: &str, destinations: Vec<String>) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: format!("Alert from {}", rule_name),
                body: "Test body".to_string(),
                body_html: None,
                color: Some("#ff0000".to_string()),
                icon: None,
            },
            rule_name: rule_name.to_string(),
            destinations,
        }
    }

    // ===================================================================
    // Notifier trait tests
    // ===================================================================

    struct TestNotifier {
        name: String,
        notifier_type: String,
        should_fail: bool,
    }

    #[async_trait]
    impl Notifier for TestNotifier {
        fn name(&self) -> &str {
            &self.name
        }

        fn notifier_type(&self) -> &str {
            &self.notifier_type
        }

        async fn send(&self, _alert: &AlertPayload) -> Result<(), NotifyError> {
            if self.should_fail {
                Err(NotifyError::SendFailed("test failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn notifier_trait_methods() {
        let notifier = TestNotifier {
            name: "test-notifier".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        };

        assert_eq!(notifier.name(), "test-notifier");
        assert_eq!(notifier.notifier_type(), "test");

        let payload = make_payload("test_rule");
        assert!(notifier.send(&payload).await.is_ok());
    }

    #[tokio::test]
    async fn notifier_trait_failure() {
        let notifier = TestNotifier {
            name: "failing-notifier".to_string(),
            notifier_type: "test".to_string(),
            should_fail: true,
        };

        let payload = make_payload("test_rule");
        assert!(notifier.send(&payload).await.is_err());
    }

    // ===================================================================
    // NotifierRegistry tests
    // ===================================================================

    #[test]
    fn registry_register_and_get() {
        let mut registry = NotifierRegistry::new();
        let notifier = Arc::new(TestNotifier {
            name: "test-1".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        });

        assert!(registry.register(notifier).is_ok());
        assert!(registry.get("test-1").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn registry_duplicate_name_error() {
        let mut registry = NotifierRegistry::new();
        let notifier1 = Arc::new(TestNotifier {
            name: "same-name".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        });
        let notifier2 = Arc::new(TestNotifier {
            name: "same-name".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        });

        assert!(registry.register(notifier1).is_ok());
        assert!(registry.register(notifier2).is_err());
    }

    #[test]
    fn registry_names() {
        let mut registry = NotifierRegistry::new();
        registry
            .register(Arc::new(TestNotifier {
                name: "alpha".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();
        registry
            .register(Arc::new(TestNotifier {
                name: "beta".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();

        let names: Vec<_> = registry.names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[test]
    fn registry_validate_destinations_success() {
        let mut registry = NotifierRegistry::new();
        registry
            .register(Arc::new(TestNotifier {
                name: "notifier-a".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();
        registry
            .register(Arc::new(TestNotifier {
                name: "notifier-b".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();

        let result =
            registry.validate_destinations(&["notifier-a".to_string(), "notifier-b".to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn registry_validate_destinations_failure() {
        let mut registry = NotifierRegistry::new();
        registry
            .register(Arc::new(TestNotifier {
                name: "exists".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();

        let result = registry.validate_destinations(&[
            "exists".to_string(),
            "unknown1".to_string(),
            "unknown2".to_string(),
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown1"));
        assert!(msg.contains("unknown2"));
    }

    #[test]
    fn registry_is_empty_and_len() {
        let mut registry = NotifierRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry
            .register(Arc::new(TestNotifier {
                name: "test".to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    // ===================================================================
    // Story 6.2: from_config tests
    // ===================================================================

    #[test]
    fn registry_from_config_creates_mattermost_notifiers() {
        use crate::config::{MattermostNotifierConfig, NotifierConfig};

        // Use temp_env for safe env var handling (Fix M3)
        temp_env::with_var(
            "TEST_MM_WEBHOOK",
            Some("https://mm.example.com/hooks/test123"),
            || {
                let mut notifiers_config = HashMap::new();
                notifiers_config.insert(
                    "mattermost-infra".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "${TEST_MM_WEBHOOK}".to_string(),
                        channel: Some("infra-alerts".to_string()),
                        username: Some("valerter".to_string()),
                        icon_url: None,
                    }),
                );
                notifiers_config.insert(
                    "mattermost-ops".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "https://static.example.com/hooks/static".to_string(),
                        channel: None,
                        username: None,
                        icon_url: None,
                    }),
                );

                let client = reqwest::Client::new();
                let result =
                    NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

                assert!(
                    result.is_ok(),
                    "from_config should succeed: {:?}",
                    result.err()
                );
                let registry = result.unwrap();

                assert_eq!(registry.len(), 2);
                assert!(registry.get("mattermost-infra").is_some());
                assert!(registry.get("mattermost-ops").is_some());

                // Check types
                let infra = registry.get("mattermost-infra").unwrap();
                assert_eq!(infra.name(), "mattermost-infra");
                assert_eq!(infra.notifier_type(), "mattermost");
            },
        );
    }

    #[test]
    fn registry_from_config_fails_on_undefined_env_var() {
        use crate::config::{MattermostNotifierConfig, NotifierConfig};

        // Use temp_env to ensure env var doesn't exist (Fix M3)
        temp_env::with_var("UNDEFINED_WEBHOOK_VAR", None::<&str>, || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "bad-notifier".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: "${UNDEFINED_WEBHOOK_VAR}".to_string(),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.len(), 1);

            match &errors[0] {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-notifier");
                    assert!(
                        message.contains("UNDEFINED_WEBHOOK_VAR"),
                        "Error should mention the undefined var: {}",
                        message
                    );
                }
                other => panic!("Expected InvalidNotifier, got {:?}", other),
            }
        });
    }

    #[test]
    fn registry_from_config_collects_all_errors() {
        use crate::config::{MattermostNotifierConfig, NotifierConfig};

        // Use temp_env to ensure env vars don't exist (Fix M3)
        temp_env::with_vars(
            [
                ("UNDEFINED_VAR_1", None::<&str>),
                ("UNDEFINED_VAR_2", None::<&str>),
            ],
            || {
                let mut notifiers_config = HashMap::new();
                notifiers_config.insert(
                    "bad-notifier-1".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "${UNDEFINED_VAR_1}".to_string(),
                        channel: None,
                        username: None,
                        icon_url: None,
                    }),
                );
                notifiers_config.insert(
                    "bad-notifier-2".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "${UNDEFINED_VAR_2}".to_string(),
                        channel: None,
                        username: None,
                        icon_url: None,
                    }),
                );

                let client = reqwest::Client::new();
                let result =
                    NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

                assert!(result.is_err());
                let errors = result.unwrap_err();
                assert_eq!(
                    errors.len(),
                    2,
                    "Should collect all errors, not stop at first"
                );
            },
        );
    }

    #[test]
    fn registry_from_config_empty_config_returns_empty_registry() {
        let notifiers_config = HashMap::new();
        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_ok());
        let registry = result.unwrap();
        assert!(registry.is_empty());
    }

    // ===================================================================
    // Story 6.5: Webhook notifier integration tests
    // ===================================================================

    #[test]
    fn registry_from_config_creates_webhook_notifiers() {
        use crate::config::{NotifierConfig, WebhookNotifierConfig};

        temp_env::with_var("TEST_WEBHOOK_TOKEN", Some("secret-token-abc123"), || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "webhook-alerts".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: "https://api.example.com/alerts".to_string(),
                    method: "POST".to_string(),
                    headers: {
                        let mut h = std::collections::HashMap::new();
                        h.insert(
                            "Authorization".to_string(),
                            "Bearer ${TEST_WEBHOOK_TOKEN}".to_string(),
                        );
                        h.insert("Content-Type".to_string(), "application/json".to_string());
                        h
                    },
                    body_template: Some(r#"{"alert": "{{ title }}"}"#.to_string()),
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(
                result.is_ok(),
                "Should successfully create webhook notifier: {:?}",
                result
            );
            let registry = result.unwrap();
            assert_eq!(registry.len(), 1);

            let notifier = registry.get("webhook-alerts");
            assert!(notifier.is_some());
            let notifier = notifier.unwrap();
            assert_eq!(notifier.name(), "webhook-alerts");
            assert_eq!(notifier.notifier_type(), "webhook");
        });
    }

    #[test]
    fn registry_from_config_webhook_with_defaults() {
        use crate::config::{NotifierConfig, WebhookNotifierConfig};

        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "simple-webhook".to_string(),
            NotifierConfig::Webhook(WebhookNotifierConfig {
                url: "https://api.example.com/hook".to_string(),
                method: "POST".to_string(),
                headers: std::collections::HashMap::new(),
                body_template: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_ok());
        let registry = result.unwrap();
        assert_eq!(registry.len(), 1);

        let notifier = registry.get("simple-webhook");
        assert!(notifier.is_some());
        assert_eq!(notifier.unwrap().notifier_type(), "webhook");
    }

    #[test]
    fn registry_from_config_webhook_fails_on_undefined_env_var() {
        use crate::config::{NotifierConfig, WebhookNotifierConfig};

        temp_env::with_var("UNDEFINED_WEBHOOK_TOKEN", None::<&str>, || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "bad-webhook".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: "https://api.example.com/alerts".to_string(),
                    method: "POST".to_string(),
                    headers: {
                        let mut h = std::collections::HashMap::new();
                        h.insert(
                            "Authorization".to_string(),
                            "Bearer ${UNDEFINED_WEBHOOK_TOKEN}".to_string(),
                        );
                        h
                    },
                    body_template: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.len(), 1);

            match &errors[0] {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-webhook");
                    assert!(message.contains("Authorization"));
                    assert!(message.contains("UNDEFINED_WEBHOOK_TOKEN"));
                }
                other => panic!("Expected InvalidNotifier, got {:?}", other),
            }
        });
    }

    #[test]
    fn registry_from_config_mixed_notifiers() {
        use crate::config::{MattermostNotifierConfig, NotifierConfig, WebhookNotifierConfig};

        temp_env::with_vars(
            [
                (
                    "TEST_MM_WEBHOOK_MIXED",
                    Some("https://mm.example.com/hooks/abc"),
                ),
                ("TEST_WH_TOKEN_MIXED", Some("token-xyz")),
            ],
            || {
                let mut notifiers_config = HashMap::new();
                notifiers_config.insert(
                    "mattermost-1".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "${TEST_MM_WEBHOOK_MIXED}".to_string(),
                        channel: None,
                        username: None,
                        icon_url: None,
                    }),
                );
                notifiers_config.insert(
                    "webhook-1".to_string(),
                    NotifierConfig::Webhook(WebhookNotifierConfig {
                        url: "https://api.example.com/alerts".to_string(),
                        method: "POST".to_string(),
                        headers: {
                            let mut h = std::collections::HashMap::new();
                            h.insert(
                                "X-API-Key".to_string(),
                                "${TEST_WH_TOKEN_MIXED}".to_string(),
                            );
                            h
                        },
                        body_template: None,
                    }),
                );

                let client = reqwest::Client::new();
                let result =
                    NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

                assert!(
                    result.is_ok(),
                    "Should create mixed notifiers: {:?}",
                    result
                );
                let registry = result.unwrap();
                assert_eq!(registry.len(), 2);

                let mm = registry.get("mattermost-1");
                assert!(mm.is_some());
                assert_eq!(mm.unwrap().notifier_type(), "mattermost");

                let wh = registry.get("webhook-1");
                assert!(wh.is_some());
                assert_eq!(wh.unwrap().notifier_type(), "webhook");
            },
        );
    }

    // ===================================================================
    // Queue tests
    // ===================================================================

    #[test]
    fn send_to_queue_is_non_blocking() {
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let payload = make_payload("test_rule");
        let result = queue.send(payload);

        assert!(result.is_ok());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn send_without_receiver_returns_error() {
        let queue = NotificationQueue::new(10);

        let payload = make_payload("test_rule");
        let result = queue.send(payload);

        assert!(result.is_err());
        match result.unwrap_err() {
            QueueError::Closed => {}
        }
    }

    #[tokio::test]
    async fn drop_oldest_when_queue_full() {
        let queue = NotificationQueue::new(5);
        let mut rx = queue.subscribe();

        for i in 0..10 {
            let payload = make_payload(&format!("rule_{}", i));
            let _ = queue.send(payload);
        }

        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(n)) => {
                assert!(n >= 1, "Expected at least 1 lagged message, got {}", n);
                assert!(n <= 10, "Cannot drop more messages than sent");
            }
            Ok(_) => panic!("Expected Lagged error when queue overflows"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn queue_size_updates_on_send() {
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());

        queue.send(make_payload("rule_1")).unwrap();
        assert_eq!(queue.len(), 1);

        queue.send(make_payload("rule_2")).unwrap();
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn queue_capacity_is_respected() {
        let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY);
        let _rx = queue.subscribe();

        for i in 0..DEFAULT_QUEUE_CAPACITY {
            let payload = make_payload(&format!("rule_{}", i));
            queue.send(payload).unwrap();
        }

        assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);
    }

    // ===================================================================
    // Backoff tests
    // ===================================================================

    #[test]
    fn backoff_delay_calculation() {
        let base = Duration::from_millis(500);
        let max = Duration::from_secs(5);

        assert_eq!(backoff_delay(0, base, max), Duration::from_millis(500));
        assert_eq!(backoff_delay(1, base, max), Duration::from_millis(1000));
        assert_eq!(backoff_delay(2, base, max), Duration::from_millis(2000));
        assert_eq!(backoff_delay(3, base, max), Duration::from_millis(4000));
        assert_eq!(backoff_delay(4, base, max), Duration::from_secs(5));
        assert_eq!(backoff_delay(10, base, max), Duration::from_secs(5));
    }

    #[test]
    fn backoff_delay_handles_overflow() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(backoff_delay(100, base, max), max);
    }

    // ===================================================================
    // Additional tests
    // ===================================================================

    #[test]
    fn alert_payload_clone_works() {
        let payload = AlertPayload {
            message: RenderedMessage {
                title: "Test".to_string(),
                body: "Body".to_string(),
                body_html: None,
                color: Some("#ff0000".to_string()),
                icon: Some(":warning:".to_string()),
            },
            rule_name: "my_rule".to_string(),
            destinations: vec!["mattermost-infra".to_string()],
        };

        let cloned = payload.clone();
        assert_eq!(cloned.rule_name, payload.rule_name);
        assert_eq!(cloned.message.title, payload.message.title);
        assert_eq!(cloned.destinations, payload.destinations);
    }

    #[test]
    fn queue_is_clone() {
        let queue1 = NotificationQueue::new(10);
        let queue2 = queue1.clone();

        let _rx = queue1.subscribe();

        queue1.send(make_payload("rule_1")).unwrap();
        assert_eq!(queue2.len(), 1);
    }

    #[test]
    fn queue_debug_format() {
        let queue = NotificationQueue::new(10);
        let debug = format!("{:?}", queue);
        assert!(debug.contains("NotificationQueue"));
    }

    #[tokio::test]
    async fn multiple_messages_consumed_in_order() {
        let queue = NotificationQueue::new(10);
        let mut rx = queue.subscribe();

        for i in 0..3 {
            queue.send(make_payload(&format!("rule_{}", i))).unwrap();
        }

        let msg0 = rx.recv().await.unwrap();
        assert_eq!(msg0.rule_name, "rule_0");

        let msg1 = rx.recv().await.unwrap();
        assert_eq!(msg1.rule_name, "rule_1");

        let msg2 = rx.recv().await.unwrap();
        assert_eq!(msg2.rule_name, "rule_2");
    }

    // ===================================================================
    // Story 6.3: Fan-out routing tests
    // ===================================================================

    #[test]
    fn alert_payload_with_empty_destinations_uses_default() {
        let payload = make_payload("test_rule");
        assert!(payload.destinations.is_empty());
    }

    #[test]
    fn alert_payload_with_destinations() {
        let payload = make_payload_with_destinations(
            "test_rule",
            vec!["dest-a".to_string(), "dest-b".to_string()],
        );
        assert_eq!(payload.destinations.len(), 2);
        assert_eq!(payload.destinations[0], "dest-a");
        assert_eq!(payload.destinations[1], "dest-b");
    }

    // ===================================================================
    // Story 6.6: Email notifier integration tests
    // ===================================================================

    #[test]
    fn registry_from_config_creates_email_notifiers() {
        use crate::config::{EmailNotifierConfig, NotifierConfig, SmtpConfig, TlsMode};

        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "email-ops".to_string(),
            NotifierConfig::Email(EmailNotifierConfig {
                smtp: SmtpConfig {
                    host: "smtp.example.com".to_string(),
                    port: 587,
                    username: None,
                    password: None,
                    tls: TlsMode::Starttls,
                    tls_verify: true,
                },
                from: "valerter@example.com".to_string(),
                to: vec!["ops@example.com".to_string()],
                subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
                body_template: None,
                body_template_file: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_ok(), "Should create email notifier: {:?}", result);
        let registry = result.unwrap();
        assert_eq!(registry.len(), 1);

        let notifier = registry.get("email-ops");
        assert!(notifier.is_some());
        let notifier = notifier.unwrap();
        assert_eq!(notifier.name(), "email-ops");
        assert_eq!(notifier.notifier_type(), "email");
    }

    #[test]
    fn registry_from_config_email_with_auth() {
        use crate::config::{EmailNotifierConfig, NotifierConfig, SmtpConfig, TlsMode};

        temp_env::with_vars(
            [
                ("TEST_SMTP_USER_REG", Some("testuser")),
                ("TEST_SMTP_PASS_REG", Some("testpass")),
            ],
            || {
                let mut notifiers_config = HashMap::new();
                notifiers_config.insert(
                    "email-auth".to_string(),
                    NotifierConfig::Email(EmailNotifierConfig {
                        smtp: SmtpConfig {
                            host: "smtp.example.com".to_string(),
                            port: 587,
                            username: Some("${TEST_SMTP_USER_REG}".to_string()),
                            password: Some("${TEST_SMTP_PASS_REG}".to_string()),
                            tls: TlsMode::Starttls,
                            tls_verify: true,
                        },
                        from: "valerter@example.com".to_string(),
                        to: vec!["ops@example.com".to_string()],
                        subject_template: "{{ title }}".to_string(),
                        body_template: None,
                        body_template_file: None,
                    }),
                );

                let client = reqwest::Client::new();
                let result =
                    NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

                assert!(
                    result.is_ok(),
                    "Should resolve env vars for email auth: {:?}",
                    result
                );
                let registry = result.unwrap();
                assert_eq!(registry.get("email-auth").unwrap().notifier_type(), "email");
            },
        );
    }

    #[test]
    fn registry_from_config_email_fails_on_undefined_env_var() {
        use crate::config::{EmailNotifierConfig, NotifierConfig, SmtpConfig, TlsMode};

        temp_env::with_var("UNDEFINED_SMTP_VAR_REG", None::<&str>, || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "bad-email".to_string(),
                NotifierConfig::Email(EmailNotifierConfig {
                    smtp: SmtpConfig {
                        host: "smtp.example.com".to_string(),
                        port: 587,
                        username: Some("${UNDEFINED_SMTP_VAR_REG}".to_string()),
                        password: Some("somepass".to_string()),
                        tls: TlsMode::Starttls,
                        tls_verify: true,
                    },
                    from: "valerter@example.com".to_string(),
                    to: vec!["ops@example.com".to_string()],
                    subject_template: "{{ title }}".to_string(),
                    body_template: None,
                    body_template_file: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.len(), 1);

            match &errors[0] {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-email");
                    assert!(message.contains("UNDEFINED_SMTP_VAR_REG"));
                }
                other => panic!("Expected InvalidNotifier, got {:?}", other),
            }
        });
    }

    #[test]
    fn registry_from_config_email_fails_on_invalid_from_address() {
        use crate::config::{EmailNotifierConfig, NotifierConfig, SmtpConfig, TlsMode};

        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "bad-from-email".to_string(),
            NotifierConfig::Email(EmailNotifierConfig {
                smtp: SmtpConfig {
                    host: "smtp.example.com".to_string(),
                    port: 587,
                    username: None,
                    password: None,
                    tls: TlsMode::Starttls,
                    tls_verify: true,
                },
                from: "not-an-email".to_string(),
                to: vec!["ops@example.com".to_string()],
                subject_template: "{{ title }}".to_string(),
                body_template: None,
                body_template_file: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);

        match &errors[0] {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-from-email");
                assert!(message.contains("from"));
            }
            other => panic!("Expected InvalidNotifier, got {:?}", other),
        }
    }

    #[test]
    fn registry_from_config_all_three_notifier_types() {
        use crate::config::{
            EmailNotifierConfig, MattermostNotifierConfig, NotifierConfig, SmtpConfig, TlsMode,
            WebhookNotifierConfig,
        };

        temp_env::with_var(
            "TEST_MM_ALL_TYPES",
            Some("https://mm.example.com/hooks/abc"),
            || {
                let mut notifiers_config = HashMap::new();

                // Mattermost
                notifiers_config.insert(
                    "mattermost".to_string(),
                    NotifierConfig::Mattermost(MattermostNotifierConfig {
                        webhook_url: "${TEST_MM_ALL_TYPES}".to_string(),
                        channel: None,
                        username: None,
                        icon_url: None,
                    }),
                );

                // Webhook
                notifiers_config.insert(
                    "webhook".to_string(),
                    NotifierConfig::Webhook(WebhookNotifierConfig {
                        url: "https://api.example.com/alerts".to_string(),
                        method: "POST".to_string(),
                        headers: std::collections::HashMap::new(),
                        body_template: None,
                    }),
                );

                // Email
                notifiers_config.insert(
                    "email".to_string(),
                    NotifierConfig::Email(EmailNotifierConfig {
                        smtp: SmtpConfig {
                            host: "smtp.example.com".to_string(),
                            port: 587,
                            username: None,
                            password: None,
                            tls: TlsMode::Starttls,
                            tls_verify: true,
                        },
                        from: "valerter@example.com".to_string(),
                        to: vec!["ops@example.com".to_string()],
                        subject_template: "{{ title }}".to_string(),
                        body_template: None,
                        body_template_file: None,
                    }),
                );

                let client = reqwest::Client::new();
                let result =
                    NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

                assert!(
                    result.is_ok(),
                    "Should create all three notifier types: {:?}",
                    result
                );
                let registry = result.unwrap();
                assert_eq!(registry.len(), 3);

                assert_eq!(
                    registry.get("mattermost").unwrap().notifier_type(),
                    "mattermost"
                );
                assert_eq!(registry.get("webhook").unwrap().notifier_type(), "webhook");
                assert_eq!(registry.get("email").unwrap().notifier_type(), "email");
            },
        );
    }
}
