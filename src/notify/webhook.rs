//! Generic webhook notifier implementation (Story 6.5).
//!
//! Implements the `Notifier` trait for sending alerts to arbitrary HTTP endpoints
//! with customizable body templates and headers.

use crate::config::{SecretString, WebhookNotifierConfig, resolve_env_vars};
use crate::error::{ConfigError, NotifyError};
use crate::notify::{AlertPayload, Notifier, backoff_delay};
use async_trait::async_trait;
use chrono::Utc;
use minijinja::{Environment, context};
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use std::str::FromStr;
use std::time::Duration;
use tracing::Instrument;

/// Backoff base delay for webhook retries (AD-07).
const WEBHOOK_BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Maximum backoff delay for webhook retries (AD-07).
const WEBHOOK_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Maximum number of retry attempts for webhook (AD-07).
const WEBHOOK_MAX_RETRIES: u32 = 3;

/// Default webhook payload when no body_template is configured (AC4).
///
/// Contains standard alert fields in a JSON structure.
/// This is a generic webhook - no accent_color/icon fields as these are
/// notifier-specific (use body_template for custom payloads).
#[derive(Debug, Clone, Serialize)]
pub struct DefaultWebhookPayload {
    /// Name of the notifier that sent this alert.
    pub alert_name: String,
    /// Name of the rule that triggered the alert.
    pub rule_name: String,
    /// Alert title (rendered).
    pub title: String,
    /// Alert body (rendered).
    pub body: String,
    /// ISO 8601 timestamp of when the alert was sent.
    pub timestamp: String,
    /// Original log timestamp in ISO 8601 format (for VictoriaLogs search).
    pub log_timestamp: String,
    /// Human-readable formatted log timestamp.
    pub log_timestamp_formatted: String,
}

impl DefaultWebhookPayload {
    /// Create a DefaultWebhookPayload from an AlertPayload and notifier name.
    pub fn from_alert(alert: &AlertPayload, notifier_name: &str) -> Self {
        Self {
            alert_name: notifier_name.to_string(),
            rule_name: alert.rule_name.clone(),
            title: alert.message.title.clone(),
            body: alert.message.body.clone(),
            timestamp: Utc::now().to_rfc3339(),
            log_timestamp: alert.log_timestamp.clone(),
            log_timestamp_formatted: alert.log_timestamp_formatted.clone(),
        }
    }
}

/// Generic webhook notifier implementation (Story 6.5).
///
/// Sends alerts to arbitrary HTTP endpoints with:
/// - Configurable HTTP method (POST/PUT)
/// - Custom headers with environment variable substitution
/// - Templated or default JSON body
/// - Exponential backoff retry (AD-07)
///
/// # Retry Policy
///
/// - **5xx errors**: Retry (server temporarily unavailable)
/// - **Network errors**: Retry (timeout, connection refused)
/// - **4xx errors**: Do NOT retry (client error, invalid request)
pub struct WebhookNotifier {
    /// Unique name for this notifier instance.
    name: String,
    /// HTTP client for webhook requests (shared, connection pooling).
    client: reqwest::Client,
    /// Target URL for the webhook.
    url: SecretString,
    /// HTTP method to use (POST or PUT).
    method: Method,
    /// Headers to include in requests (secrets resolved).
    headers: HeaderMap,
    /// Body template source (if configured).
    body_template_source: Option<String>,
}

/// Validate a body template at configuration time.
fn validate_body_template(source: &str) -> Result<(), ConfigError> {
    let mut env = Environment::new();
    env.add_template("_validate", source)
        .map_err(|e| ConfigError::InvalidTemplate {
            rule: "webhook.body_template".to_string(),
            message: e.to_string(),
        })?;
    Ok(())
}

/// Render a body template with alert context.
///
/// Generic webhook templates have access to standard fields (title, body, rule_name)
/// plus log timestamps. accent_color is not exposed as webhooks are meant to be generic.
fn render_body_template(source: &str, alert: &AlertPayload) -> Result<String, NotifyError> {
    let mut env = Environment::new();
    env.add_template("body", source)
        .map_err(|e| NotifyError::SendFailed(format!("template error: {}", e)))?;

    let tmpl = env
        .get_template("body")
        .map_err(|e| NotifyError::SendFailed(format!("template error: {}", e)))?;

    tmpl.render(context! {
        title => &alert.message.title,
        body => &alert.message.body,
        rule_name => &alert.rule_name,
        log_timestamp => &alert.log_timestamp,
        log_timestamp_formatted => &alert.log_timestamp_formatted,
    })
    .map_err(|e| NotifyError::SendFailed(format!("template render error: {}", e)))
}

impl WebhookNotifier {
    /// Create a new WebhookNotifier from configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this notifier instance
    /// * `config` - Webhook notifier configuration
    /// * `client` - HTTP client (shared for connection pooling)
    ///
    /// # Returns
    ///
    /// * `Ok(WebhookNotifier)` - Configured notifier ready to send
    /// * `Err(ConfigError)` - If URL resolution, header parsing, or template compilation fails
    pub fn from_config(
        name: &str,
        config: &WebhookNotifierConfig,
        client: reqwest::Client,
    ) -> Result<Self, ConfigError> {
        // Resolve environment variables in URL
        let resolved_url =
            resolve_env_vars(&config.url).map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("url: {}", e),
            })?;

        // Parse and validate HTTP method (AC6: only POST and PUT supported)
        let method_upper = config.method.to_uppercase();
        if method_upper != "POST" && method_upper != "PUT" {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!(
                    "unsupported method '{}': only POST and PUT are supported",
                    config.method
                ),
            });
        }
        let method = Method::from_str(&method_upper).map_err(|_| ConfigError::InvalidNotifier {
            name: name.to_string(),
            message: format!("invalid method: {}", config.method),
        })?;

        // Resolve headers with environment variable substitution
        let mut headers = HeaderMap::new();
        for (key, value) in &config.headers {
            let resolved_value =
                resolve_env_vars(value).map_err(|e| ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!("header '{}': {}", key, e),
                })?;

            let header_name =
                HeaderName::from_str(key).map_err(|_| ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!("invalid header name: {}", key),
                })?;

            let header_value = HeaderValue::from_str(&resolved_value).map_err(|_| {
                ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!("invalid header value for '{}'", key),
                }
            })?;

            headers.insert(header_name, header_value);
        }

        // Validate body template if provided
        let body_template_source = match &config.body_template {
            Some(template_str) => {
                validate_body_template(template_str).map_err(|e| ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!("body_template: {}", e),
                })?;
                Some(template_str.clone())
            }
            None => None,
        };

        Ok(Self {
            name: name.to_string(),
            client,
            url: SecretString::new(resolved_url),
            method,
            headers,
            body_template_source,
        })
    }

    /// Get the resolved URL (for testing).
    #[cfg(test)]
    pub fn url(&self) -> &str {
        self.url.expose()
    }

    /// Get the HTTP method (for testing).
    #[cfg(test)]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Check if a body template is configured (for testing).
    #[cfg(test)]
    pub fn has_body_template(&self) -> bool {
        self.body_template_source.is_some()
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "webhook"
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_webhook",
            rule_name = %alert.rule_name,
            notifier_name = %self.name
        );

        async {
            // Build request body
        let body = match &self.body_template_source {
            Some(template_source) => render_body_template(template_source, alert)?,
            None => {
                let payload = DefaultWebhookPayload::from_alert(alert, &self.name);
                serde_json::to_string(&payload).map_err(|e| {
                    NotifyError::SendFailed(format!("JSON serialization error: {}", e))
                })?
            }
        };
        tracing::trace!(body_len = body.len(), "Request body built");

        // Retry loop with exponential backoff (AD-07)
        for attempt in 0..WEBHOOK_MAX_RETRIES {
            match self
                .client
                .request(self.method.clone(), self.url.expose())
                .headers(self.headers.clone())
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    tracing::debug!("Webhook alert sent successfully");
                    metrics::counter!(
                        "valerter_alerts_sent_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "webhook"
                    )
                    .increment(1);
                    return Ok(());
                }
                Ok(response) if response.status().is_client_error() => {
                    // 4xx errors: don't retry (AC5)
                    let status = response.status();
                    tracing::error!(
                        status = %status,
                        "Webhook returned client error, not retrying"
                    );
                    metrics::counter!(
                        "valerter_notify_errors_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "webhook"
                    )
                    .increment(1);
                    // Permanent failure - count as failed alert
                    metrics::counter!(
                        "valerter_alerts_failed_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone(),
                        "notifier_type" => "webhook"
                    )
                    .increment(1);
                    return Err(NotifyError::SendFailed(format!("client error: {}", status)));
                }
                Ok(response) => {
                    // 5xx errors: retry (AC5)
                    tracing::warn!(
                        attempt = attempt,
                        status = %response.status(),
                        "Webhook returned server error, retrying"
                    );
                }
                Err(e) => {
                    // Network errors: retry (AC5)
                    tracing::warn!(
                        attempt = attempt,
                        error = %e,
                        "Failed to send webhook, retrying"
                    );
                }
            }

            // Apply backoff delay before next retry (except after last attempt)
            if attempt < WEBHOOK_MAX_RETRIES - 1 {
                let delay = backoff_delay(attempt, WEBHOOK_BACKOFF_BASE, WEBHOOK_BACKOFF_MAX);
                tracing::debug!(delay_ms = delay.as_millis(), "Waiting before retry");
                tokio::time::sleep(delay).await;
            }
        }

        // All retries exhausted
        tracing::error!(
            max_retries = WEBHOOK_MAX_RETRIES,
            "Failed to send webhook alert after all retries"
        );
        metrics::counter!(
            "valerter_notify_errors_total",
            "rule_name" => alert.rule_name.clone(),
            "notifier_name" => self.name.clone(),
            "notifier_type" => "webhook"
        )
        .increment(1);
        // Permanent failure after retries exhausted
        metrics::counter!(
            "valerter_alerts_failed_total",
            "rule_name" => alert.rule_name.clone(),
            "notifier_name" => self.name.clone(),
            "notifier_type" => "webhook"
        )
        .increment(1);
            Err(NotifyError::MaxRetriesExceeded)
        }
        .instrument(span)
        .await
    }
}

impl std::fmt::Debug for WebhookNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NFR9: Never expose URL or headers in debug output
        f.debug_struct("WebhookNotifier")
            .field("name", &self.name)
            .field("method", &self.method.as_str())
            .field("has_body_template", &self.body_template_source.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::RenderedMessage;
    use serial_test::serial;
    use std::collections::HashMap;

    fn make_alert_payload(rule_name: &str) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: "Test Alert".to_string(),
                body: "Something happened".to_string(),
                body_html: None,
                accent_color: Some("#ff0000".to_string()),
            },
            rule_name: rule_name.to_string(),
            destinations: vec![],
            log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
            log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
        }
    }

    // ===================================================================
    // WebhookNotifier construction tests
    // ===================================================================

    #[test]
    #[serial]
    fn from_config_with_all_fields() {
        temp_env::with_var("TEST_WEBHOOK_TOKEN", Some("secret-token-123"), || {
            let config = WebhookNotifierConfig {
                url: "https://api.example.com/alerts".to_string(),
                method: "PUT".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        "Bearer ${TEST_WEBHOOK_TOKEN}".to_string(),
                    );
                    h.insert("Content-Type".to_string(), "application/json".to_string());
                    h
                },
                body_template: Some(r#"{"alert": "{{ title }}"}"#.to_string()),
            };

            let client = reqwest::Client::new();
            let notifier = WebhookNotifier::from_config("test-webhook", &config, client).unwrap();

            assert_eq!(notifier.name(), "test-webhook");
            assert_eq!(notifier.notifier_type(), "webhook");
            assert_eq!(notifier.url(), "https://api.example.com/alerts");
            assert_eq!(notifier.method(), &Method::PUT);
            assert!(notifier.has_body_template());
        });
    }

    #[test]
    fn from_config_with_defaults() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let notifier = WebhookNotifier::from_config("simple-webhook", &config, client).unwrap();

        assert_eq!(notifier.name(), "simple-webhook");
        assert_eq!(notifier.method(), &Method::POST);
        assert!(!notifier.has_body_template());
    }

    #[test]
    #[serial]
    fn from_config_resolves_url_env_var() {
        temp_env::with_var(
            "TEST_WEBHOOK_URL",
            Some("https://resolved.example.com/hook"),
            || {
                let config = WebhookNotifierConfig {
                    url: "${TEST_WEBHOOK_URL}".to_string(),
                    method: "POST".to_string(),
                    headers: HashMap::new(),
                    body_template: None,
                };

                let client = reqwest::Client::new();
                let notifier =
                    WebhookNotifier::from_config("env-webhook", &config, client).unwrap();

                assert_eq!(notifier.url(), "https://resolved.example.com/hook");
            },
        );
    }

    #[test]
    #[serial]
    fn from_config_fails_on_undefined_url_env_var() {
        temp_env::with_var("UNDEFINED_WEBHOOK_URL", None::<&str>, || {
            let config = WebhookNotifierConfig {
                url: "${UNDEFINED_WEBHOOK_URL}".to_string(),
                method: "POST".to_string(),
                headers: HashMap::new(),
                body_template: None,
            };

            let client = reqwest::Client::new();
            let result = WebhookNotifier::from_config("bad-webhook", &config, client);

            assert!(result.is_err());
            let err = result.unwrap_err();
            match err {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-webhook");
                    assert!(message.contains("url"));
                    assert!(message.contains("UNDEFINED_WEBHOOK_URL"));
                }
                _ => panic!("Expected InvalidNotifier, got {:?}", err),
            }
        });
    }

    #[test]
    #[serial]
    fn from_config_fails_on_undefined_header_env_var() {
        temp_env::with_var("UNDEFINED_TOKEN", None::<&str>, || {
            let config = WebhookNotifierConfig {
                url: "https://api.example.com/alerts".to_string(),
                method: "POST".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        "Bearer ${UNDEFINED_TOKEN}".to_string(),
                    );
                    h
                },
                body_template: None,
            };

            let client = reqwest::Client::new();
            let result = WebhookNotifier::from_config("bad-header-webhook", &config, client);

            assert!(result.is_err());
            let err = result.unwrap_err();
            match err {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-header-webhook");
                    assert!(message.contains("header"));
                    assert!(message.contains("Authorization"));
                }
                _ => panic!("Expected InvalidNotifier, got {:?}", err),
            }
        });
    }

    #[test]
    fn from_config_rejects_unsupported_methods() {
        // AC6: Only POST and PUT are supported
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "PATCH".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let result = WebhookNotifier::from_config("patch-webhook", &config, client);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "patch-webhook");
                assert!(message.contains("unsupported method"));
                assert!(message.contains("PATCH"));
                assert!(message.contains("POST and PUT"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_accepts_put_method() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "PUT".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let result = WebhookNotifier::from_config("put-webhook", &config, client);

        assert!(result.is_ok());
        let notifier = result.unwrap();
        assert_eq!(notifier.method().as_str(), "PUT");
    }

    #[test]
    fn from_config_rejects_delete_method() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "DELETE".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let result = WebhookNotifier::from_config("delete-webhook", &config, client);

        assert!(result.is_err());
    }

    #[test]
    fn from_config_fails_on_invalid_body_template() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: Some("{% if unclosed".to_string()),
        };

        let client = reqwest::Client::new();
        let result = WebhookNotifier::from_config("bad-template-webhook", &config, client);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-template-webhook");
                assert!(message.contains("body_template"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    // ===================================================================
    // DefaultWebhookPayload tests
    // ===================================================================

    #[test]
    fn default_webhook_payload_from_alert() {
        let alert = make_alert_payload("test_rule");
        let payload = DefaultWebhookPayload::from_alert(&alert, "my-webhook");

        assert_eq!(payload.alert_name, "my-webhook");
        assert_eq!(payload.rule_name, "test_rule");
        assert_eq!(payload.title, "Test Alert");
        assert_eq!(payload.body, "Something happened");
        // Generic webhook - no color/icon fields
        assert!(!payload.timestamp.is_empty());
        // Log timestamp fields
        assert_eq!(payload.log_timestamp, "2026-01-15T10:49:35.799Z");
        assert_eq!(payload.log_timestamp_formatted, "15/01/2026 10:49:35 UTC");
    }

    #[test]
    fn default_webhook_payload_serializes_correctly() {
        let alert = make_alert_payload("cpu_alert");
        let payload = DefaultWebhookPayload::from_alert(&alert, "webhook-1");
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"alert_name\":\"webhook-1\""));
        assert!(json.contains("\"rule_name\":\"cpu_alert\""));
        assert!(json.contains("\"title\":\"Test Alert\""));
        assert!(json.contains("\"body\":\"Something happened\""));
        assert!(json.contains("\"timestamp\":"));
        assert!(json.contains("\"log_timestamp\":\"2026-01-15T10:49:35.799Z\""));
        assert!(json.contains("\"log_timestamp_formatted\":\"15/01/2026 10:49:35 UTC\""));
        // Generic webhook - no color/icon in payload
        assert!(!json.contains("\"color\""));
        assert!(!json.contains("\"icon\""));
    }

    #[test]
    fn default_webhook_payload_is_generic() {
        let alert = AlertPayload {
            message: RenderedMessage {
                title: "Simple".to_string(),
                body: "Body".to_string(),
                body_html: None,
                accent_color: None,
            },
            rule_name: "simple_rule".to_string(),
            destinations: vec![],
            log_timestamp: "2026-01-15T10:00:00Z".to_string(),
            log_timestamp_formatted: "15/01/2026 10:00:00 UTC".to_string(),
        };
        let payload = DefaultWebhookPayload::from_alert(&alert, "webhook");
        let json = serde_json::to_string(&payload).unwrap();

        // Generic webhook payload should not contain accent_color or icon
        assert!(!json.contains("\"color\""));
        assert!(!json.contains("\"icon\""));
        assert!(!json.contains("\"accent_color\""));
    }

    // ===================================================================
    // Notifier trait tests
    // ===================================================================

    #[test]
    fn webhook_notifier_properties() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let notifier = WebhookNotifier::from_config("test", &config, client).unwrap();

        assert_eq!(notifier.name(), "test");
        assert_eq!(notifier.notifier_type(), "webhook");
    }

    #[tokio::test]
    async fn notifier_trait_is_object_safe() {
        let config = WebhookNotifierConfig {
            url: "https://api.example.com/alerts".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: None,
        };

        let client = reqwest::Client::new();
        let notifier: Box<dyn Notifier> =
            Box::new(WebhookNotifier::from_config("test", &config, client).unwrap());

        assert_eq!(notifier.name(), "test");
        assert_eq!(notifier.notifier_type(), "webhook");
    }

    // ===================================================================
    // Debug output security tests (NFR9)
    // ===================================================================

    #[test]
    #[serial]
    fn debug_output_does_not_expose_url() {
        temp_env::with_var(
            "TEST_SECRET_URL",
            Some("https://secret.example.com/hook/abc123"),
            || {
                let config = WebhookNotifierConfig {
                    url: "${TEST_SECRET_URL}".to_string(),
                    method: "POST".to_string(),
                    headers: HashMap::new(),
                    body_template: None,
                };

                let client = reqwest::Client::new();
                let notifier =
                    WebhookNotifier::from_config("secret-webhook", &config, client).unwrap();
                let debug = format!("{:?}", notifier);

                // URL should NOT appear in debug output
                assert!(!debug.contains("secret.example.com"));
                assert!(!debug.contains("abc123"));
                // Name and method are OK to show
                assert!(debug.contains("secret-webhook"));
                assert!(debug.contains("POST"));
            },
        );
    }

    #[test]
    #[serial]
    fn debug_output_does_not_expose_headers() {
        temp_env::with_var("TEST_AUTH_TOKEN", Some("Bearer super-secret-token"), || {
            let config = WebhookNotifierConfig {
                url: "https://api.example.com/alerts".to_string(),
                method: "POST".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        "${TEST_AUTH_TOKEN}".to_string(),
                    );
                    h
                },
                body_template: None,
            };

            let client = reqwest::Client::new();
            let notifier = WebhookNotifier::from_config("auth-webhook", &config, client).unwrap();
            let debug = format!("{:?}", notifier);

            // Token should NOT appear in debug output
            assert!(!debug.contains("super-secret-token"));
            assert!(!debug.contains("Bearer"));
        });
    }

    // ===================================================================
    // Body template rendering tests
    // ===================================================================

    #[test]
    fn body_template_renders_alert_fields() {
        let source = r#"{"title": "{{ title }}", "body": "{{ body }}", "rule": "{{ rule_name }}"}"#;

        let alert = make_alert_payload("test_rule");
        let result = render_body_template(source, &alert).unwrap();

        assert!(result.contains("\"title\": \"Test Alert\""));
        assert!(result.contains("\"body\": \"Something happened\""));
        assert!(result.contains("\"rule\": \"test_rule\""));
    }

    #[test]
    fn body_template_uses_standard_fields_only() {
        // Generic webhook templates have access to title, body, rule_name, and log timestamps
        let source = r#"{"title": "{{ title }}", "rule": "{{ rule_name }}", "log_time": "{{ log_timestamp_formatted }}"}"#;

        let alert = AlertPayload {
            message: RenderedMessage {
                title: "Test".to_string(),
                body: "Body".to_string(),
                body_html: None,
                accent_color: Some("#ff0000".to_string()),
            },
            rule_name: "test_rule".to_string(),
            destinations: vec![],
            log_timestamp: "2026-01-15T10:00:00Z".to_string(),
            log_timestamp_formatted: "15/01/2026 10:00:00 UTC".to_string(),
        };
        let result = render_body_template(source, &alert).unwrap();

        assert!(result.contains("\"title\": \"Test\""));
        assert!(result.contains("\"rule\": \"test_rule\""));
        assert!(result.contains("\"log_time\": \"15/01/2026 10:00:00 UTC\""));
    }

    #[test]
    fn validate_body_template_accepts_valid_template() {
        let result = validate_body_template(r#"{"msg": "{{ title }}"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_body_template_rejects_invalid_template() {
        let result = validate_body_template("{% if unclosed");
        assert!(result.is_err());
    }
}
