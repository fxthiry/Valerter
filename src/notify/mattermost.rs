//! Mattermost notifier implementation.
//!
//! Implements the `Notifier` trait for sending alerts to Mattermost
//! via incoming webhooks with exponential backoff retry.

use crate::config::{OutputFormat, SecretString};
use crate::error::NotifyError;
use crate::notify::{AlertPayload, Notifier, backoff_delay, record_permanent_failure};
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;
use tracing::Instrument;

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
#[allow(clippy::too_many_arguments)]
fn build_mattermost_payload(
    message: &crate::template::RenderedMessage,
    rule_name: &str,
    vl_source: &str,
    log_timestamp_formatted: &str,
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
            color: message.accent_color.clone(),
            title: message.title.clone(),
            text: message.body_for(OutputFormat::Markdown).text.to_string(),
            footer: format!(
                "valerter | {} | {} | {}",
                rule_name, vl_source, log_timestamp_formatted
            ),
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
/// - **4xx errors**: Do NOT retry (client error, invalid payload), except a
///   rejected rule-level channel override, resent once without `channel`
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
    /// Optional channel override (a rule's `mattermost_channel` takes precedence).
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

    /// POST `payload` to the webhook with the retry policy: 5xx, 429 and
    /// network errors are retried with backoff, up to
    /// `MATTERMOST_MAX_RETRIES` attempts; any other 4xx stops immediately.
    async fn post_with_retries(&self, payload: &MattermostPayload) -> Delivery {
        // Use the notifier's own webhook_url (Story 6.2)
        let webhook_url = self.webhook_url.expose();

        for attempt in 0..MATTERMOST_MAX_RETRIES {
            match self.client.post(webhook_url).json(payload).send().await {
                Ok(response) if response.status().is_success() => return Delivery::Sent,
                Ok(response)
                    if response.status().is_client_error()
                        && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    // 4xx errors: don't retry (invalid payload, bad webhook)
                    return Delivery::ClientError(response.status());
                }
                Ok(response) => {
                    // 5xx and 429 errors: retry
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
                        error = %e.without_url(),
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

        Delivery::RetriesExhausted
    }
}

/// Outcome of one payload delivery, retries included.
enum Delivery {
    /// The webhook accepted the payload.
    Sent,
    /// Non-retryable client error (4xx other than 429).
    ClientError(reqwest::StatusCode),
    /// Every attempt failed with a retryable error.
    RetriesExhausted,
}

#[async_trait]
impl Notifier for MattermostNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "mattermost"
    }

    /// Mattermost renders Markdown natively: `markdown` is its only format.
    fn output_format(&self) -> OutputFormat {
        OutputFormat::Markdown
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_mattermost",
            rule_name = %alert.rule_name,
            notifier_name = %self.name
        );

        async {
            // Channel priority: rule override > notifier channel > webhook default.
            let rule_channel = alert.mattermost_channel.as_deref();
            let mattermost_payload = build_mattermost_payload(
                &alert.message,
                &alert.rule_name,
                &alert.vl_source,
                &alert.log_timestamp_formatted,
                rule_channel.or(self.channel.as_deref()),
                self.username.as_deref(),
                self.icon_url.as_deref(),
            );
            tracing::trace!(
                payload_size = std::mem::size_of_val(&mattermost_payload),
                "Payload built"
            );

            let mut delivery = self.post_with_retries(&mattermost_payload).await;

            // A rejected rule override (locked webhook, unknown channel) is
            // resent once to the notifier's channel if it has one (and it
            // differs), otherwise without `channel`, to the webhook's default.
            if let (Delivery::ClientError(status), Some(channel)) = (&delivery, rule_channel) {
                let fallback_channel = self.channel.as_deref().filter(|c| *c != channel);
                tracing::warn!(
                    notifier_name = %self.name,
                    rule_name = %alert.rule_name,
                    channel = %channel,
                    fallback_channel = fallback_channel.map(tracing::field::display),
                    status = %status,
                    "Mattermost rejected channel override, resending to notifier default"
                );
                let fallback_payload = MattermostPayload {
                    channel: fallback_channel.map(str::to_string),
                    ..mattermost_payload
                };
                delivery = self.post_with_retries(&fallback_payload).await;
            }

            match delivery {
                Delivery::Sent => {
                    tracing::debug!("Alert sent successfully");
                    metrics::counter!(
                        "valerter_alerts_sent_total",
                        "rule_name" => alert.rule_name.clone(),
                        "vl_source" => alert.vl_source.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "mattermost",
                    )
                    .increment(1);
                    Ok(())
                }
                Delivery::ClientError(status) => {
                    tracing::error!(
                        status = %status,
                        "Mattermost returned client error, not retrying"
                    );
                    record_permanent_failure(alert, &self.name, "mattermost");
                    Err(NotifyError::SendFailed(format!("client error: {}", status)))
                }
                Delivery::RetriesExhausted => {
                    tracing::error!(
                        max_retries = MATTERMOST_MAX_RETRIES,
                        "Failed to send alert after all retries"
                    );
                    record_permanent_failure(alert, &self.name, "mattermost");
                    Err(NotifyError::MaxRetriesExceeded)
                }
            }
        }
        .instrument(span)
        .await
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
            email_body_html: None,
            accent_color: Some("#ff0000".to_string()),
            ..Default::default()
        };

        let payload = build_mattermost_payload(
            &message,
            "test_rule",
            "vlprod",
            "15/01/2026 10:49:35 UTC",
            None,
            None,
            None,
        );

        assert_eq!(payload.attachments.len(), 1);
        let attachment = &payload.attachments[0];
        assert_eq!(attachment.fallback, "Test Alert");
        assert_eq!(attachment.title, "Test Alert");
        assert_eq!(attachment.text, "Something happened");
        assert_eq!(attachment.color, Some("#ff0000".to_string()));
        assert_eq!(
            attachment.footer,
            "valerter | test_rule | vlprod | 15/01/2026 10:49:35 UTC"
        );
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
            email_body_html: None,
            accent_color: None,
            ..Default::default()
        };

        let payload = build_mattermost_payload(
            &message,
            "simple_rule",
            "vlprod",
            "09/01/2026 10:00:00 UTC",
            None,
            None,
            None,
        );

        let attachment = &payload.attachments[0];
        assert_eq!(attachment.color, None);
    }

    #[test]
    fn build_mattermost_payload_with_optional_fields() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            email_body_html: None,
            accent_color: None,
            ..Default::default()
        };

        let payload = build_mattermost_payload(
            &message,
            "rule",
            "vlprod",
            "09/01/2026 10:00:00 UTC",
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
            email_body_html: None,
            accent_color: Some("#00ff00".to_string()),
            ..Default::default()
        };

        let payload = build_mattermost_payload(
            &message,
            "rule",
            "vlprod",
            "09/01/2026 10:00:00 UTC",
            None,
            None,
            None,
        );
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"attachments\""));
        assert!(json.contains("\"fallback\":\"Test\""));
        assert!(json.contains("\"title\":\"Test\""));
        assert!(json.contains("\"text\":\"Body\""));
        assert!(json.contains("\"color\":\"#00ff00\""));
        assert!(json.contains("\"footer\":\"valerter | rule | vlprod | 09/01/2026 10:00:00 UTC\""));
        // Optional fields should be omitted when None
        assert!(!json.contains("channel"));
        assert!(!json.contains("username"));
        assert!(!json.contains("icon_url"));
    }

    #[test]
    fn mattermost_payload_serializes_with_optional_fields() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            email_body_html: None,
            accent_color: None,
            ..Default::default()
        };

        let payload = build_mattermost_payload(
            &message,
            "rule",
            "vlprod",
            "09/01/2026 10:00:00 UTC",
            Some("alerts"),
            Some("bot"),
            None,
        );
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

    // ===================================================================
    // Channel selection and fallback (wiremock)
    // ===================================================================

    use crate::notify::test_metrics::{counter_total, run_with_recorder};
    use std::sync::{Arc, Mutex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_alert(rule_channel: Option<&str>) -> AlertPayload {
        AlertPayload {
            mattermost_channel: rule_channel.map(String::from),
            message: RenderedMessage {
                title: "Test Alert".to_string(),
                body: "Something happened".to_string(),
                email_body_html: None,
                accent_color: None,
                ..Default::default()
            },
            rule_name: "r".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec!["mm".to_string()],
            log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
            log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
            log: AlertPayload::log_from_fields(&serde_json::json!({})),
        }
    }

    /// Log lines written by `tracing` during a test.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// Outcome of `send_with_responses`.
    struct SendOutcome {
        result: Result<(), NotifyError>,
        /// JSON bodies received by the webhook, in order.
        bodies: Vec<serde_json::Value>,
        logs: String,
        metrics: String,
    }

    /// Send `alert` through a notifier configured with `notifier_channel`,
    /// to a webhook answering `statuses` in order (then 200).
    fn send_with_responses(
        notifier_channel: Option<&str>,
        alert: AlertPayload,
        statuses: &[u16],
    ) -> SendOutcome {
        let logs = CapturedLogs::default();
        let writer = logs.clone();
        let notifier_channel = notifier_channel.map(String::from);
        let statuses = statuses.to_vec();

        let ((result, bodies), metrics) = run_with_recorder(|| async move {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .finish();
            let _guard = tracing::subscriber::set_default(subscriber);

            let server = MockServer::start().await;
            for status in &statuses {
                Mock::given(wiremock::matchers::any())
                    .respond_with(ResponseTemplate::new(*status))
                    .up_to_n_times(1)
                    .mount(&server)
                    .await;
            }
            Mock::given(wiremock::matchers::any())
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let notifier = MattermostNotifier::with_options(
                "mm".to_string(),
                SecretString::new(format!("{}/hooks/secret-token", server.uri())),
                notifier_channel,
                None,
                None,
                reqwest::Client::new(),
            );
            let result = notifier.send(&alert).await;
            let bodies = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .map(|r| serde_json::from_slice(&r.body).unwrap())
                .collect::<Vec<serde_json::Value>>();
            (result, bodies)
        });

        SendOutcome {
            result,
            bodies,
            logs: logs.text(),
            metrics,
        }
    }

    fn alert_with_message(message: RenderedMessage) -> AlertPayload {
        AlertPayload {
            message,
            ..make_alert(None)
        }
    }

    #[test]
    fn markdown_body_is_sent_as_mattermost_markdown() {
        let message = crate::template::render_test_message(
            "Disk",
            "**{{ host }}** at {{ ts }}",
            crate::config::BodyFormat::Markdown,
            &serde_json::json!({"host": "web_01", "ts": "10:49:35"}),
        );
        let out = send_with_responses(None, alert_with_message(message), &[]);

        assert!(out.result.is_ok());
        assert_eq!(
            out.bodies[0]["attachments"][0]["text"],
            r"**web\_01** at 10:49:35"
        );
        assert!(
            serde_json::to_string(&out.bodies[0])
                .unwrap()
                .contains(r#""text":"**web\\_01** at 10:49:35""#)
        );
    }

    #[test]
    fn text_body_is_sent_unchanged() {
        let message = crate::template::render_test_message(
            "Disk",
            "**{{ host }}** at {{ ts }}",
            crate::config::BodyFormat::Text,
            &serde_json::json!({"host": "web_01", "ts": "10:49:35"}),
        );
        let out = send_with_responses(None, alert_with_message(message), &[]);

        assert_eq!(
            out.bodies[0]["attachments"][0]["text"],
            "**web_01** at 10:49:35"
        );
    }

    #[test]
    fn rule_channel_takes_precedence_over_notifier_channel() {
        let out = send_with_responses(Some("ops"), make_alert(Some("alerts")), &[]);

        assert!(out.result.is_ok());
        assert_eq!(out.bodies.len(), 1);
        assert_eq!(out.bodies[0]["channel"], "alerts");
    }

    #[test]
    fn notifier_channel_used_without_rule_channel() {
        let out = send_with_responses(Some("ops"), make_alert(None), &[]);

        assert!(out.result.is_ok());
        assert_eq!(out.bodies.len(), 1);
        assert_eq!(out.bodies[0]["channel"], "ops");
    }

    #[test]
    fn channel_key_omitted_without_any_channel() {
        let out = send_with_responses(None, make_alert(None), &[]);

        assert!(out.result.is_ok());
        assert_eq!(out.bodies.len(), 1);
        assert!(out.bodies[0].get("channel").is_none());
    }

    /// The fallback warning line, which must never carry the webhook URL.
    fn fallback_warning(out: &SendOutcome) -> &str {
        let warn = out
            .logs
            .lines()
            .find(|l| {
                l.contains("Mattermost rejected channel override, resending to notifier default")
            })
            .unwrap_or_else(|| panic!("missing fallback warning in:\n{}", out.logs));
        assert!(warn.contains("WARN"));
        assert!(warn.contains("notifier_name=mm"));
        assert!(warn.contains("rule_name=r"));
        assert!(warn.contains("channel=alerts"));
        assert!(warn.contains("status=400 Bad Request"));
        assert!(
            !out.logs.contains("secret-token"),
            "webhook URL leaked:\n{}",
            out.logs
        );
        warn
    }

    #[test]
    fn rejected_rule_channel_is_resent_to_notifier_channel() {
        let out = send_with_responses(Some("ops"), make_alert(Some("alerts")), &[400]);

        assert!(out.result.is_ok(), "unexpected error: {:?}", out.result);
        assert_eq!(out.bodies.len(), 2);
        assert_eq!(out.bodies[0]["channel"], "alerts");
        assert_eq!(out.bodies[1]["channel"], "ops");
        // Same message otherwise.
        assert_eq!(out.bodies[0]["attachments"], out.bodies[1]["attachments"]);
        assert!(fallback_warning(&out).contains("fallback_channel=ops"));

        assert_eq!(counter_total(&out.metrics, "valerter_alerts_sent_total"), 1);
        assert_eq!(
            counter_total(&out.metrics, "valerter_alerts_failed_total"),
            0
        );
        assert_eq!(
            counter_total(&out.metrics, "valerter_notify_errors_total"),
            0
        );
    }

    #[test]
    fn rejected_rule_channel_without_notifier_channel_is_resent_without_channel() {
        let out = send_with_responses(None, make_alert(Some("alerts")), &[400]);

        assert!(out.result.is_ok(), "unexpected error: {:?}", out.result);
        assert_eq!(out.bodies.len(), 2);
        assert_eq!(out.bodies[0]["channel"], "alerts");
        assert!(out.bodies[1].get("channel").is_none());
        assert!(!fallback_warning(&out).contains("fallback_channel"));
        assert_eq!(counter_total(&out.metrics, "valerter_alerts_sent_total"), 1);
    }

    #[test]
    fn rejected_rule_channel_equal_to_notifier_channel_is_resent_without_channel() {
        let out = send_with_responses(Some("ops"), make_alert(Some("ops")), &[400]);

        assert!(out.result.is_ok(), "unexpected error: {:?}", out.result);
        assert_eq!(out.bodies.len(), 2);
        assert_eq!(out.bodies[0]["channel"], "ops");
        assert!(out.bodies[1].get("channel").is_none());
    }

    #[test]
    fn rejected_fallback_is_a_permanent_failure() {
        let out = send_with_responses(None, make_alert(Some("alerts")), &[400, 400]);

        assert_eq!(out.bodies.len(), 2);
        let err = out.result.expect_err("second 4xx must fail the alert");
        assert_eq!(
            err.to_string(),
            "failed to send notification: client error: 400 Bad Request"
        );
        assert!(
            out.logs
                .contains("Mattermost returned client error, not retrying")
        );
        assert_eq!(counter_total(&out.metrics, "valerter_alerts_sent_total"), 0);
        assert_eq!(
            counter_total(&out.metrics, "valerter_alerts_failed_total"),
            1
        );
        assert_eq!(
            counter_total(&out.metrics, "valerter_notify_errors_total"),
            1
        );
    }

    #[test]
    fn fallback_follows_the_retry_policy() {
        let out = send_with_responses(None, make_alert(Some("alerts")), &[403, 500]);

        assert!(out.result.is_ok(), "unexpected error: {:?}", out.result);
        assert_eq!(out.bodies.len(), 3);
        assert_eq!(out.bodies[0]["channel"], "alerts");
        assert!(out.bodies[1].get("channel").is_none());
        assert!(out.bodies[2].get("channel").is_none());
        assert_eq!(counter_total(&out.metrics, "valerter_alerts_sent_total"), 1);
    }

    #[test]
    fn notifier_channel_rejection_has_no_fallback() {
        let out = send_with_responses(Some("ops"), make_alert(None), &[400]);

        assert_eq!(out.bodies.len(), 1);
        assert_eq!(
            out.result.unwrap_err().to_string(),
            "failed to send notification: client error: 400 Bad Request"
        );
        assert!(!out.logs.contains("Mattermost rejected channel override"));
    }

    #[test]
    fn rule_channel_rate_limited_is_retried_without_fallback() {
        let out = send_with_responses(None, make_alert(Some("alerts")), &[429]);

        assert!(out.result.is_ok(), "unexpected error: {:?}", out.result);
        assert_eq!(out.bodies.len(), 2);
        assert_eq!(out.bodies[0]["channel"], "alerts");
        assert_eq!(out.bodies[1]["channel"], "alerts");
        assert!(!out.logs.contains("Mattermost rejected channel override"));
    }
}
