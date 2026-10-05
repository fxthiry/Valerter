//! Generic webhook notifier implementation (Story 6.5).
//!
//! Implements the `Notifier` trait for sending alerts to arbitrary HTTP endpoints
//! with customizable body templates and headers.

use crate::config::{
    SecretString, WebhookNotifierConfig, resolve_env_vars, validate_notifier_template,
    validate_resolved_url,
};
use crate::error::{ConfigError, NotifyError};
use crate::notify::{AlertPayload, Notifier, backoff_delay, record_permanent_failure};
use async_trait::async_trait;
use chrono::Utc;
use minijinja::{Environment, context};
use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
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
    /// Name of the VictoriaLogs source that produced the matching event.
    pub vl_source: String,
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
            vl_source: alert.vl_source.clone(),
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
    /// Body template source, environment variables resolved (if configured).
    body_template_source: Option<String>,
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
        vl_source => &alert.vl_source,
        log_timestamp => &alert.log_timestamp,
        log_timestamp_formatted => &alert.log_timestamp_formatted,
    })
    .map_err(|e| NotifyError::SendFailed(format!("template render error: {}", e)))
}

/// Whether a Content-Type header value denotes JSON.
///
/// Matches `application/json` and any `+json` structured suffix, ignoring case
/// and media type parameters (e.g. `; charset=utf-8`).
fn is_json_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

/// Check a rendered body against the effective Content-Type.
///
/// Returns the JSON parse error when the Content-Type is JSON and the body is
/// not a valid JSON document, `None` otherwise.
fn json_body_error(headers: &HeaderMap, body: &str) -> Option<serde_json::Error> {
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_json_content_type);
    if !is_json {
        return None;
    }
    serde_json::from_str::<serde::de::IgnoredAny>(body).err()
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
            resolve_env_vars(config.url.expose()).map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("url: {}", e),
            })?;
        // `Config::validate()` skips URLs holding a `${VAR}`: re-check the
        // resolved value (never echoed, it may carry a token).
        validate_resolved_url(&resolved_url).map_err(|e| ConfigError::InvalidNotifier {
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

        // Resolve headers with environment variable substitution (by sorted
        // name, so the reported invalid header is stable)
        let mut headers = HeaderMap::new();
        let mut sorted_headers: Vec<_> = config.headers.iter().collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in sorted_headers {
            let resolved_value =
                resolve_env_vars(value.expose()).map_err(|e| ConfigError::InvalidNotifier {
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

        // Default to JSON unless the operator configured a Content-Type
        // (HeaderMap lookups are case-insensitive).
        if !headers.contains_key(CONTENT_TYPE) {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        // Resolve `${VAR}` in the template source (never in rendered values),
        // then validate the resolved source (syntax, then render test). The
        // resolved source may hold a secret: it is never logged.
        let body_template_source = match &config.body_template {
            Some(template_str) => {
                let resolved =
                    resolve_env_vars(template_str).map_err(|e| ConfigError::InvalidNotifier {
                        name: name.to_string(),
                        message: format!("body_template: {}", e),
                    })?;
                validate_notifier_template("body_template", &resolved).map_err(|message| {
                    ConfigError::InvalidNotifier {
                        name: name.to_string(),
                        message,
                    }
                })?;
                Some(resolved)
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

    /// Build the request body: the rendered `body_template`, or the default
    /// JSON payload.
    fn build_body(&self, alert: &AlertPayload) -> Result<String, NotifyError> {
        match &self.body_template_source {
            Some(template_source) => {
                let rendered = render_body_template(template_source, alert)?;
                // Safety net: warn (without the body, which may hold secrets or
                // log data) but still send, as some endpoints tolerate it.
                if let Some(e) = json_body_error(&self.headers, &rendered) {
                    tracing::warn!(
                        line = e.line(),
                        column = e.column(),
                        "Webhook body is not valid JSON"
                    );
                }
                Ok(rendered)
            }
            None => {
                let payload = DefaultWebhookPayload::from_alert(alert, &self.name);
                serde_json::to_string(&payload).map_err(|e| {
                    NotifyError::SendFailed(format!("JSON serialization error: {}", e))
                })
            }
        }
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

    /// Get the resolved headers (for testing).
    #[cfg(test)]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
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
            // A body that cannot be built is a permanent failure for this
            // alert: count it, send nothing.
            let body = match self.build_body(alert) {
                Ok(body) => body,
                Err(e) => {
                    record_permanent_failure(alert, &self.name, "webhook");
                    return Err(e);
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
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.name.clone(),
                            "notifier_type" => "webhook",
                        )
                        .increment(1);
                        return Ok(());
                    }
                    Ok(response)
                        if response.status().is_client_error()
                            && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS =>
                    {
                        // 4xx errors: don't retry (AC5)
                        let status = response.status();
                        tracing::error!(
                            status = %status,
                            "Webhook returned client error, not retrying"
                        );
                        record_permanent_failure(alert, &self.name, "webhook");
                        return Err(NotifyError::SendFailed(format!("client error: {}", status)));
                    }
                    Ok(response) => {
                        // 5xx and 429 errors: retry (AC5)
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
                            error = %e.without_url(),
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
            record_permanent_failure(alert, &self.name, "webhook");
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
            mattermost_channel: None,
            message: RenderedMessage {
                title: "Test Alert".to_string(),
                body: "Something happened".to_string(),
                email_body_html: None,
                accent_color: Some("#ff0000".to_string()),
            },
            rule_name: rule_name.to_string(),
            vl_source: "vlprod".to_string(),
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
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "PUT".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        SecretString::new("Bearer ${TEST_WEBHOOK_TOKEN}".to_string()),
                    );
                    h.insert(
                        "Content-Type".to_string(),
                        SecretString::new("application/json".to_string()),
                    );
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
                    url: SecretString::new("${TEST_WEBHOOK_URL}".to_string()),
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
                url: SecretString::new("${UNDEFINED_WEBHOOK_URL}".to_string()),
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
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "POST".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        SecretString::new("Bearer ${UNDEFINED_TOKEN}".to_string()),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
            mattermost_channel: None,
            message: RenderedMessage {
                title: "Simple".to_string(),
                body: "Body".to_string(),
                email_body_html: None,
                accent_color: None,
            },
            rule_name: "simple_rule".to_string(),
            vl_source: "vlprod".to_string(),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
            url: SecretString::new("https://api.example.com/alerts".to_string()),
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
                    url: SecretString::new("${TEST_SECRET_URL}".to_string()),
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
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "POST".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        SecretString::new("${TEST_AUTH_TOKEN}".to_string()),
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
            mattermost_channel: None,
            message: RenderedMessage {
                title: "Test".to_string(),
                body: "Body".to_string(),
                email_body_html: None,
                accent_color: Some("#ff0000".to_string()),
            },
            rule_name: "test_rule".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec![],
            log_timestamp: "2026-01-15T10:00:00Z".to_string(),
            log_timestamp_formatted: "15/01/2026 10:00:00 UTC".to_string(),
        };
        let result = render_body_template(source, &alert).unwrap();

        assert!(result.contains("\"title\": \"Test\""));
        assert!(result.contains("\"rule\": \"test_rule\""));
        assert!(result.contains("\"log_time\": \"15/01/2026 10:00:00 UTC\""));
    }

    fn body_template_config(template: &str) -> WebhookNotifierConfig {
        WebhookNotifierConfig {
            url: SecretString::new("https://api.example.com/alerts".to_string()),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: Some(template.to_string()),
        }
    }

    fn from_config_error(config: &WebhookNotifierConfig) -> String {
        WebhookNotifier::from_config("wh", config, reqwest::Client::new())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn from_config_rejects_unknown_filter_in_body_template() {
        let err = from_config_error(&body_template_config(
            r#"{"alert": "{{ title | nosuchfilter }}"}"#,
        ));
        assert!(
            err.contains("invalid notifier 'wh': body_template render: "),
            "{err}"
        );
        assert!(err.contains("nosuchfilter"), "{err}");
    }

    #[test]
    fn from_config_syntax_error_keeps_body_template_prefix() {
        let err = from_config_error(&body_template_config("{% if unclosed"));
        assert!(
            err.contains("invalid notifier 'wh': body_template: "),
            "{err}"
        );
        assert!(!err.contains("body_template render"), "{err}");
    }

    #[test]
    fn from_config_accepts_builtin_filters_in_body_template() {
        let config = body_template_config(
            r#"{"alert": {{ title | tojson }}, "rule": "{{ rule_name | upper }}", "b": "{{ body | e }}"}"#,
        );
        assert!(WebhookNotifier::from_config("wh", &config, reqwest::Client::new()).is_ok());
    }

    #[test]
    #[serial]
    fn from_config_rejects_resolved_url_with_bad_scheme_without_echoing_it() {
        temp_env::with_var(
            "HCV_WEBHOOK_URL",
            Some("ftp://hooks.example.com/SECRET"),
            || {
                let mut config = body_template_config("{{ title }}");
                config.url = SecretString::new("${HCV_WEBHOOK_URL}".to_string());
                let err = from_config_error(&config);
                assert!(
                    err.contains("url: invalid URL: unsupported scheme 'ftp'"),
                    "{err}"
                );
                assert!(!err.contains("SECRET"), "{err}");
            },
        );
    }

    #[test]
    #[serial]
    fn from_config_rejects_resolved_url_that_does_not_parse() {
        temp_env::with_var("HCV_WEBHOOK_URL", Some("not a url SECRET"), || {
            let mut config = body_template_config("{{ title }}");
            config.url = SecretString::new("${HCV_WEBHOOK_URL}".to_string());
            let err = from_config_error(&config);
            assert!(
                err.contains("invalid notifier 'wh': url: invalid URL:"),
                "{err}"
            );
            assert!(!err.contains("SECRET"), "{err}");
        });
    }

    // ===================================================================
    // Invalid header tests (config validation)
    // ===================================================================

    #[test]
    fn from_config_rejects_invalid_header_name() {
        let config = WebhookNotifierConfig {
            url: SecretString::new("https://api.example.com/alerts".to_string()),
            method: "POST".to_string(),
            headers: {
                let mut h = HashMap::new();
                // Header names cannot contain spaces or special chars
                h.insert(
                    "Invalid Header Name".to_string(),
                    SecretString::new("value".to_string()),
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
                assert!(message.contains("invalid header name"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_reports_first_invalid_header_in_name_order() {
        // Several HashMaps built in the same run iterate in different orders.
        for _ in 0..8 {
            let config = WebhookNotifierConfig {
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "POST".to_string(),
                headers: ["Bad Header B", "Bad Header A"]
                    .into_iter()
                    .map(|k| (k.to_string(), SecretString::new("value".to_string())))
                    .collect(),
                body_template: None,
            };

            let Err(err) = WebhookNotifier::from_config("wh", &config, reqwest::Client::new())
            else {
                panic!("invalid header names must be rejected");
            };
            match err {
                ConfigError::InvalidNotifier { message, .. } => {
                    assert_eq!(message, "invalid header name: Bad Header A");
                }
                other => panic!("Expected InvalidNotifier, got {:?}", other),
            }
        }
    }

    #[test]
    fn from_config_rejects_invalid_header_value() {
        let config = WebhookNotifierConfig {
            url: SecretString::new("https://api.example.com/alerts".to_string()),
            method: "POST".to_string(),
            headers: {
                let mut h = HashMap::new();
                // Header values cannot contain control characters (e.g., newlines)
                h.insert(
                    "X-Custom".to_string(),
                    SecretString::new("value\nwith\nnewlines".to_string()),
                );
                h
            },
            body_template: None,
        };

        let client = reqwest::Client::new();
        let result = WebhookNotifier::from_config("bad-value-webhook", &config, client);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-value-webhook");
                assert!(message.contains("invalid header value"));
                assert!(message.contains("X-Custom"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    // ===================================================================
    // Content-Type default and JSON body checks
    // ===================================================================

    fn config_with_headers(headers: &[(&str, &str)]) -> WebhookNotifierConfig {
        WebhookNotifierConfig {
            url: SecretString::new("https://api.example.com/alerts".to_string()),
            method: "POST".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), SecretString::new(v.to_string())))
                .collect(),
            body_template: None,
        }
    }

    fn make_alert_with_body(body: &str) -> AlertPayload {
        let mut alert = make_alert_payload("test_rule");
        alert.message.body = body.to_string();
        alert
    }

    #[test]
    fn from_config_defaults_content_type_to_json() {
        let config = config_with_headers(&[]);
        let notifier =
            WebhookNotifier::from_config("ct-default", &config, reqwest::Client::new()).unwrap();

        let values: Vec<_> = notifier.headers().get_all(CONTENT_TYPE).iter().collect();
        assert_eq!(values, vec![HeaderValue::from_static("application/json")]);
    }

    #[test]
    fn from_config_keeps_configured_content_type() {
        let config = config_with_headers(&[("content-type", "text/plain")]);
        let notifier =
            WebhookNotifier::from_config("ct-custom", &config, reqwest::Client::new()).unwrap();

        let values: Vec<_> = notifier.headers().get_all(CONTENT_TYPE).iter().collect();
        assert_eq!(values, vec![HeaderValue::from_static("text/plain")]);
    }

    #[test]
    fn is_json_content_type_matches_json_media_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/vnd.api+json"));
        assert!(is_json_content_type("application/problem+JSON;q=1"));
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/x-www-form-urlencoded"));
        assert!(!is_json_content_type("application/jsonl"));
    }

    #[test]
    fn json_body_error_detects_unescaped_quote() {
        let config = config_with_headers(&[]);
        let notifier =
            WebhookNotifier::from_config("json-check", &config, reqwest::Client::new()).unwrap();
        let alert = make_alert_with_body(r#"say "hi""#);
        let body = render_body_template(r#"{"text": "{{ body }}"}"#, &alert).unwrap();

        assert!(json_body_error(notifier.headers(), &body).is_some());
    }

    #[test]
    fn json_body_error_ignores_non_json_content_type() {
        let config = config_with_headers(&[("Content-Type", "text/plain")]);
        let notifier =
            WebhookNotifier::from_config("plain-check", &config, reqwest::Client::new()).unwrap();

        assert!(json_body_error(notifier.headers(), "not json at all").is_none());
    }

    #[test]
    fn json_body_error_accepts_valid_json() {
        let config = config_with_headers(&[]);
        let notifier =
            WebhookNotifier::from_config("valid-check", &config, reqwest::Client::new()).unwrap();

        assert!(json_body_error(notifier.headers(), r#"{"a": [1, 2, null]}"#).is_none());
    }

    #[test]
    fn tojson_filter_produces_valid_json() {
        let original = "say \"hi\"\npath C:\\tmp <b>&'";
        let alert = make_alert_with_body(original);
        let body = render_body_template(r#"{"text": {{ body | tojson }}}"#, &alert).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["text"], original);
    }

    // ===================================================================
    // `${VAR}` resolution in body_template
    // ===================================================================

    #[test]
    #[serial]
    fn from_config_resolves_env_var_in_body_template() {
        temp_env::with_var("TEST_ROUTING_KEY", Some("abc123"), || {
            let config = body_template_config(r#"{"routing_key": "${TEST_ROUTING_KEY}"}"#);
            let notifier =
                WebhookNotifier::from_config("pagerduty", &config, reqwest::Client::new()).unwrap();

            let body = notifier.build_body(&make_alert_payload("r")).unwrap();
            assert_eq!(body, r#"{"routing_key": "abc123"}"#);
        });
    }

    #[test]
    #[serial]
    fn from_config_fails_on_undefined_env_var_in_body_template() {
        temp_env::with_var("UNDEFINED_ROUTING_KEY", None::<&str>, || {
            let config = body_template_config(r#"{"routing_key": "${UNDEFINED_ROUTING_KEY}"}"#);
            let err = from_config_error(&config);

            // Same wording as `url` and `headers`.
            assert!(
                err.starts_with("invalid notifier 'wh': body_template: "),
                "unexpected error: {err}"
            );
            assert!(err.contains("undefined environment variable: UNDEFINED_ROUTING_KEY"));
        });
    }

    #[test]
    #[serial]
    fn debug_output_does_not_expose_resolved_body_template() {
        temp_env::with_var("TEST_BODY_SECRET", Some("s3cr3t-routing-key"), || {
            let config = body_template_config(r#"{"routing_key": "${TEST_BODY_SECRET}"}"#);
            let notifier =
                WebhookNotifier::from_config("pagerduty", &config, reqwest::Client::new()).unwrap();
            let debug = format!("{:?}", notifier);

            assert!(!debug.contains("s3cr3t-routing-key"));
            assert!(debug.contains("has_body_template: true"));
        });
    }

    #[test]
    #[serial]
    fn escaped_placeholder_renders_literal_dollar_brace() {
        temp_env::with_var("NOT_A_VAR", None::<&str>, || {
            let notifier = WebhookNotifier::from_config(
                "wh",
                &body_template_config(r#"{"note": "{{ '$' }}{NOT_A_VAR}"}"#),
                reqwest::Client::new(),
            )
            .expect("an escaped placeholder is not an env var reference");

            let body = notifier.build_body(&make_alert_with_body("b")).unwrap();
            assert_eq!(body, r#"{"note": "${NOT_A_VAR}"}"#);
        });
    }

    #[test]
    fn rendered_values_are_not_env_resolved() {
        let alert = make_alert_with_body("path is ${HOME}");
        let body = render_body_template(r#"{"text": {{ body | tojson }}}"#, &alert).unwrap();

        assert_eq!(body, r#"{"text": "path is ${HOME}"}"#);
    }

    /// Body templates of the examples in docs/notifiers.md and
    /// config/config.example.yaml (kept in sync by hand).
    const DOC_EXAMPLE_TEMPLATES: &[(&str, &str)] = &[
        (
            "pagerduty",
            r#"{
  "routing_key": "${PAGERDUTY_ROUTING_KEY}",
  "event_action": "trigger",
  "payload": {
    "summary": {{ title | tojson }},
    "source": "valerter",
    "severity": "error",
    "custom_details": {
      "body": {{ body | tojson }},
      "rule": {{ rule_name | tojson }}
    }
  }
}
"#,
        ),
        (
            "slack",
            r#"{
  "text": {{ ("*" ~ title ~ "*\n" ~ body) | tojson }},
  "username": "Valerter"
}
"#,
        ),
        (
            "discord",
            r#"{
  "content": {{ ("**" ~ title ~ "**\n" ~ body) | tojson }}
}
"#,
        ),
        (
            "custom-api",
            r#"{"alert": {{ title | tojson }}, "details": {{ body | tojson }}, "rule": {{ rule_name | tojson }}}
"#,
        ),
    ];

    #[test]
    #[serial]
    fn doc_example_templates_render_valid_json() {
        let mut alert = make_alert_with_body("line 1 \"quoted\"\nline 2 C:\\path <x> & y");
        alert.message.title = "Disk \"full\" on db-1".to_string();

        temp_env::with_var("PAGERDUTY_ROUTING_KEY", Some("abc123"), || {
            for (name, source) in DOC_EXAMPLE_TEMPLATES {
                let notifier = WebhookNotifier::from_config(
                    name,
                    &body_template_config(source),
                    reqwest::Client::new(),
                )
                .unwrap();
                let body = notifier.build_body(&alert).unwrap();
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
                assert!(
                    parsed.is_ok(),
                    "{name} example rendered invalid JSON: {body}"
                );
            }
        });

        let pagerduty = temp_env::with_var("PAGERDUTY_ROUTING_KEY", Some("abc123"), || {
            WebhookNotifier::from_config(
                "pagerduty",
                &body_template_config(DOC_EXAMPLE_TEMPLATES[0].1),
                reqwest::Client::new(),
            )
            .unwrap()
        });
        let parsed: serde_json::Value =
            serde_json::from_str(&pagerduty.build_body(&alert).unwrap()).unwrap();
        assert_eq!(parsed["routing_key"], "abc123");
        assert_eq!(parsed["payload"]["summary"], alert.message.title);

        let slack = render_body_template(DOC_EXAMPLE_TEMPLATES[1].1, &alert).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&slack).unwrap();
        assert_eq!(
            parsed["text"],
            format!("*{}*\n{}", alert.message.title, alert.message.body)
        );
    }

    // ===================================================================
    // Render failure at send time
    // ===================================================================

    #[test]
    fn render_failure_at_send_is_counted_and_sends_nothing() {
        use crate::notify::test_metrics::{counter_total, run_with_recorder};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let ((err, requests), rendered) = run_with_recorder(|| async {
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::any())
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
            let config = WebhookNotifierConfig {
                url: SecretString::new(format!("{}/hook", server.uri())),
                method: "POST".to_string(),
                headers: HashMap::new(),
                body_template: None,
            };
            let mut notifier =
                WebhookNotifier::from_config("hook", &config, reqwest::Client::new()).unwrap();
            // Fails only at render time (load-time validation bypassed).
            notifier.body_template_source = Some("{{ title | no_such_filter }}".to_string());

            let err = notifier
                .send(&make_alert_payload("r"))
                .await
                .expect_err("render failure must fail the alert");
            (err, server.received_requests().await.unwrap().len())
        });

        assert_eq!(requests, 0, "no request may reach the endpoint");
        assert!(
            matches!(&err, NotifyError::SendFailed(_))
                && err
                    .to_string()
                    .starts_with("failed to send notification: template render error: "),
            "unexpected error: {err:?}"
        );
        for series in [
            "valerter_notify_errors_total{rule_name=\"r\",vl_source=\"vlprod\",notifier_name=\"hook\",notifier_type=\"webhook\"} 1",
            "valerter_alerts_failed_total{rule_name=\"r\",vl_source=\"vlprod\",notifier_name=\"hook\",notifier_type=\"webhook\"} 1",
        ] {
            assert!(
                rendered.lines().any(|l| l == series),
                "missing `{series}` in:\n{rendered}"
            );
        }
        assert_eq!(counter_total(&rendered, "valerter_alerts_sent_total"), 0);
    }
}
