//! Mattermost notifier implementation.
//!
//! Implements the `Notifier` trait for sending alerts to Mattermost
//! via incoming webhooks with exponential backoff retry.

use crate::config::SecretString;
use crate::error::NotifyError;
use crate::notify::{AlertPayload, Notifier, backoff_delay};
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;

/// Backoff base delay for Mattermost retries (AD-07).
const MATTERMOST_BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Maximum backoff delay for Mattermost retries (AD-07).
const MATTERMOST_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Maximum number of retry attempts for Mattermost (AD-07).
const MATTERMOST_MAX_RETRIES: u32 = 3;

/// Mattermost attachment structure for incoming webhooks.
#[derive(Debug, Clone, Serialize)]
struct MattermostAttachment {
    fallback: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
    title: String,
    text: String,
    footer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer_icon: Option<String>,
}

/// Mattermost webhook payload structure.
#[derive(Debug, Clone, Serialize)]
struct MattermostPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_url: Option<String>,
    attachments: Vec<MattermostAttachment>,
}

/// Build Mattermost webhook payload from rendered message.
fn build_mattermost_payload(
    message: &crate::template::RenderedMessage,
    rule_name: &str,
    channel: Option<&str>,
    username: Option<&str>,
    icon_url: Option<&str>,
) -> MattermostPayload {
    MattermostPayload {
        channel: channel.map(String::from),
        username: username.map(String::from),
        icon_url: icon_url.map(String::from),
        attachments: vec![MattermostAttachment {
            fallback: message.title.clone(),
            color: message.color.clone(),
            title: message.title.clone(),
            text: message.body.clone(),
            footer: format!("valerter | {}", rule_name),
            footer_icon: message.icon.clone(),
        }],
    }
}

/// Mattermost notifier implementation.
///
/// Sends alerts to Mattermost via incoming webhook with exponential backoff.
///
/// # Retry Policy
///
/// - **5xx errors**: Retry (server temporarily unavailable)
/// - **Network errors**: Retry (timeout, connection refused)
/// - **4xx errors**: Do NOT retry (client error, invalid payload)
///
/// # Example
///
/// ```ignore
/// let notifier = MattermostNotifier::new(
///     "default".to_string(),
///     SecretString::new("https://mattermost.example.com/hooks/xxx".to_string()),
///     client,
/// );
/// notifier.send(&alert_payload).await?;
/// ```
pub struct MattermostNotifier {
    /// Unique name for this notifier instance.
    name: String,
    /// Webhook URL for sending notifications (stored as SecretString for NFR9).
    webhook_url: SecretString,
    /// Optional channel override.
    channel: Option<String>,
    /// Optional username override.
    username: Option<String>,
    /// Optional icon URL override.
    icon_url: Option<String>,
    /// HTTP client for Mattermost requests (shared, connection pooling).
    client: reqwest::Client,
}

impl MattermostNotifier {
    /// Create a new Mattermost notifier.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this notifier instance
    /// * `webhook_url` - Webhook URL (wrapped in SecretString for security)
    /// * `client` - HTTP client (shared for connection pooling)
    pub fn new(name: String, webhook_url: SecretString, client: reqwest::Client) -> Self {
        Self {
            name,
            webhook_url,
            channel: None,
            username: None,
            icon_url: None,
            client,
        }
    }

    /// Create a new Mattermost notifier with all optional fields.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this notifier instance
    /// * `webhook_url` - Webhook URL (wrapped in SecretString for security)
    /// * `channel` - Optional channel override
    /// * `username` - Optional username override
    /// * `icon_url` - Optional icon URL override
    /// * `client` - HTTP client (shared for connection pooling)
    pub fn with_options(
        name: String,
        webhook_url: SecretString,
        channel: Option<String>,
        username: Option<String>,
        icon_url: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            name,
            webhook_url,
            channel,
            username,
            icon_url,
            client,
        }
    }
}

#[async_trait]
impl Notifier for MattermostNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "mattermost"
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_mattermost",
            rule_name = %alert.rule_name,
            notifier_name = %self.name
        );
        let _guard = span.enter();

        let mattermost_payload = build_mattermost_payload(
            &alert.message,
            &alert.rule_name,
            self.channel.as_deref(),
            self.username.as_deref(),
            self.icon_url.as_deref(),
        );

        // Use the notifier's own webhook_url (Story 6.2)
        let webhook_url = self.webhook_url.expose();

        for attempt in 0..MATTERMOST_MAX_RETRIES {
            match self
                .client
                .post(webhook_url)
                .json(&mattermost_payload)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    tracing::info!("Alert sent successfully");
                    metrics::counter!(
                        "valerter_alerts_sent_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "mattermost"
                    )
                    .increment(1);
                    return Ok(());
                }
                Ok(response) if response.status().is_client_error() => {
                    // 4xx errors: don't retry (invalid payload, bad webhook)
                    let status = response.status();
                    tracing::error!(
                        status = %status,
                        "Mattermost returned client error, not retrying"
                    );
                    metrics::counter!(
                        "valerter_notify_errors_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "mattermost"
                    )
                    .increment(1);
                    return Err(NotifyError::SendFailed(format!("client error: {}", status)));
                }
                Ok(response) => {
                    // 5xx errors: retry
                    tracing::warn!(
                        attempt = attempt,
                        status = %response.status(),
                        "Mattermost returned server error, retrying"
                    );
                }
                Err(e) => {
                    // Network errors: retry
                    tracing::warn!(
                        attempt = attempt,
                        error = %e,
                        "Failed to send to Mattermost, retrying"
                    );
                }
            }

            // Apply backoff delay before next retry (except after last attempt)
            if attempt < MATTERMOST_MAX_RETRIES - 1 {
                let delay = backoff_delay(attempt, MATTERMOST_BACKOFF_BASE, MATTERMOST_BACKOFF_MAX);
                tracing::debug!(delay_ms = delay.as_millis(), "Waiting before retry");
                tokio::time::sleep(delay).await;
            }
        }

        // All retries exhausted
        tracing::error!(
            max_retries = MATTERMOST_MAX_RETRIES,
            "Failed to send alert after all retries"
        );
        metrics::counter!(
            "valerter_notify_errors_total",
            "rule_name" => alert.rule_name.clone(),
            "notifier_name" => self.name.clone(),
            "notifier_type" => "mattermost"
        )
        .increment(1);
        Err(NotifyError::MaxRetriesExceeded)
    }
}

impl std::fmt::Debug for MattermostNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MattermostNotifier")
            .field("name", &self.name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::RenderedMessage;

    #[test]
    fn build_mattermost_payload_structure() {
        let message = RenderedMessage {
            title: "Test Alert".to_string(),
            body: "Something happened".to_string(),
            color: Some("#ff0000".to_string()),
            icon: Some(":warning:".to_string()),
        };

        let payload = build_mattermost_payload(&message, "test_rule", None, None, None);

        assert_eq!(payload.attachments.len(), 1);
        let attachment = &payload.attachments[0];
        assert_eq!(attachment.fallback, "Test Alert");
        assert_eq!(attachment.title, "Test Alert");
        assert_eq!(attachment.text, "Something happened");
        assert_eq!(attachment.color, Some("#ff0000".to_string()));
        assert_eq!(attachment.footer, "valerter | test_rule");
        assert_eq!(attachment.footer_icon, Some(":warning:".to_string()));
        // Optional fields should be None
        assert!(payload.channel.is_none());
        assert!(payload.username.is_none());
        assert!(payload.icon_url.is_none());
    }

    #[test]
    fn build_mattermost_payload_without_optional_fields() {
        let message = RenderedMessage {
            title: "Simple Alert".to_string(),
            body: "Body text".to_string(),
            color: None,
            icon: None,
        };

        let payload = build_mattermost_payload(&message, "simple_rule", None, None, None);

        let attachment = &payload.attachments[0];
        assert_eq!(attachment.color, None);
        assert_eq!(attachment.footer_icon, None);
    }

    #[test]
    fn build_mattermost_payload_with_optional_fields() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            color: None,
            icon: None,
        };

        let payload = build_mattermost_payload(
            &message,
            "rule",
            Some("infra-alerts"),
            Some("valerter-bot"),
            Some("https://example.com/icon.png"),
        );

        assert_eq!(payload.channel, Some("infra-alerts".to_string()));
        assert_eq!(payload.username, Some("valerter-bot".to_string()));
        assert_eq!(
            payload.icon_url,
            Some("https://example.com/icon.png".to_string())
        );
    }

    #[test]
    fn mattermost_payload_serializes_correctly() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            color: Some("#00ff00".to_string()),
            icon: None,
        };

        let payload = build_mattermost_payload(&message, "rule", None, None, None);
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"attachments\""));
        assert!(json.contains("\"fallback\":\"Test\""));
        assert!(json.contains("\"title\":\"Test\""));
        assert!(json.contains("\"text\":\"Body\""));
        assert!(json.contains("\"color\":\"#00ff00\""));
        assert!(json.contains("\"footer\":\"valerter | rule\""));
        // Optional fields should be omitted when None
        assert!(!json.contains("footer_icon"));
        assert!(!json.contains("channel"));
        assert!(!json.contains("username"));
        assert!(!json.contains("icon_url"));
    }

    #[test]
    fn mattermost_payload_serializes_with_optional_fields() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            color: None,
            icon: None,
        };

        let payload = build_mattermost_payload(&message, "rule", Some("alerts"), Some("bot"), None);
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"channel\":\"alerts\""));
        assert!(json.contains("\"username\":\"bot\""));
        assert!(!json.contains("icon_url")); // Still None
    }

    #[test]
    fn mattermost_notifier_properties() {
        let client = reqwest::Client::new();
        let notifier = MattermostNotifier::new(
            "test-mattermost".to_string(),
            SecretString::new("https://example.com/hooks/test".to_string()),
            client,
        );

        assert_eq!(notifier.name(), "test-mattermost");
        assert_eq!(notifier.notifier_type(), "mattermost");
    }

    #[test]
    fn mattermost_notifier_debug() {
        let client = reqwest::Client::new();
        let notifier = MattermostNotifier::new(
            "test".to_string(),
            SecretString::new("https://example.com/hooks/test".to_string()),
            client,
        );
        let debug = format!("{:?}", notifier);
        assert!(debug.contains("MattermostNotifier"));
        assert!(debug.contains("test"));
        // Webhook URL should NOT appear in debug output (NFR9)
        assert!(!debug.contains("hooks/test"));
    }

    #[tokio::test]
    async fn notifier_trait_is_object_safe() {
        // Verify we can use MattermostNotifier as dyn Notifier
        let client = reqwest::Client::new();
        let notifier: Box<dyn Notifier> = Box::new(MattermostNotifier::new(
            "test".to_string(),
            SecretString::new("https://example.com/hooks/test".to_string()),
            client,
        ));

        assert_eq!(notifier.name(), "test");
        assert_eq!(notifier.notifier_type(), "mattermost");
    }

    #[test]
    fn mattermost_notifier_with_options() {
        let client = reqwest::Client::new();
        let notifier = MattermostNotifier::with_options(
            "infra".to_string(),
            SecretString::new("https://mm.example.com/hooks/xxx".to_string()),
            Some("infra-alerts".to_string()),
            Some("valerter-bot".to_string()),
            Some("https://example.com/icon.png".to_string()),
            client,
        );

        assert_eq!(notifier.name(), "infra");
        assert_eq!(notifier.notifier_type(), "mattermost");
        assert_eq!(notifier.channel, Some("infra-alerts".to_string()));
        assert_eq!(notifier.username, Some("valerter-bot".to_string()));
        assert_eq!(
            notifier.icon_url,
            Some("https://example.com/icon.png".to_string())
        );
    }
}
