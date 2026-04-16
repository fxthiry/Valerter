//! Telegram Bot notifier implementation.
//!
//! Sends alerts via the Bot API `sendMessage` endpoint. One HTTP call per
//! configured `chat_id`, sequentially — Telegram rate-limits at 1 msg/sec/chat,
//! so batching would not help. The notifier returns `Ok(())` as soon as at
//! least one chat succeeds (partial success); `Err` only when all fail.

use crate::config::{SecretString, TelegramNotifierConfig, resolve_env_vars};
use crate::error::{ConfigError, NotifyError};
use crate::notify::{AlertPayload, Notifier, backoff_delay};
use async_trait::async_trait;
use minijinja::{Environment, context};
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::Instrument;

/// Backoff base delay for Telegram retries.
const TELEGRAM_BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Maximum backoff delay for Telegram retries.
const TELEGRAM_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Maximum number of retry attempts (pool partagé 5xx + réseau + 429).
const TELEGRAM_MAX_RETRIES: u32 = 3;

/// Per-request HTTP timeout.
const TELEGRAM_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Floor applied to a parsed `Retry-After` value. Guards against tight retry
/// loops on `Retry-After: 0` or malformed floats that round down to zero.
const RETRY_AFTER_MIN: Duration = Duration::from_secs(1);

/// Ceiling applied to a parsed `Retry-After` value. Protects against an
/// adversarial or misconfigured upstream sending us a delay measured in hours.
const RETRY_AFTER_MAX: Duration = Duration::from_secs(60);

/// Telegram `sendMessage` hard limit on `text` (in Unicode codepoints).
const TELEGRAM_TEXT_MAX_CODEPOINTS: usize = 4096;

/// Default `body_template` when none is configured. The `|e` filter escapes
/// `< > &` so the HTML `parse_mode` does not choke on raw symbols coming
/// from log bodies.
const DEFAULT_BODY_TEMPLATE: &str = "<b>{{ title|e }}</b>\n{{ body|e }}";

/// Default `parse_mode` sent to Telegram when none is configured.
const DEFAULT_PARSE_MODE: &str = "HTML";

/// Payload serialized as the body of a `sendMessage` request.
#[derive(Debug, Serialize)]
struct TelegramPayload<'a> {
    chat_id: &'a str,
    text: &'a str,
    parse_mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_web_page_preview: Option<bool>,
}

/// Truncate `text` so that it does not exceed [`TELEGRAM_TEXT_MAX_CODEPOINTS`]
/// Unicode codepoints. When truncation happens, a single `…` (U+2026) is
/// appended so the final codepoint count is exactly the limit.
fn truncate_text(text: &str) -> (String, bool) {
    if text.chars().count() <= TELEGRAM_TEXT_MAX_CODEPOINTS {
        return (text.to_string(), false);
    }
    let mut out: String = text
        .chars()
        .take(TELEGRAM_TEXT_MAX_CODEPOINTS - 1)
        .collect();
    out.push('…');
    (out, true)
}

/// Validate a `body_template` at configuration time so startup fails fast on
/// malformed Jinja.
fn validate_body_template(source: &str) -> Result<(), ConfigError> {
    let mut env = Environment::new();
    env.add_template("_validate", source)
        .map_err(|e| ConfigError::InvalidTemplate {
            rule: "telegram.body_template".to_string(),
            message: e.to_string(),
        })?;
    Ok(())
}

/// Render a body template with alert context.
fn render_body_template(source: &str, alert: &AlertPayload) -> Result<String, NotifyError> {
    let mut env = Environment::new();
    env.add_template("body", source)
        .map_err(|e| NotifyError::TemplateError(e.to_string()))?;
    let tmpl = env
        .get_template("body")
        .map_err(|e| NotifyError::TemplateError(e.to_string()))?;
    tmpl.render(context! {
        title => &alert.message.title,
        body => &alert.message.body,
        rule_name => &alert.rule_name,
        vl_source => &alert.vl_source,
        log_timestamp => &alert.log_timestamp,
        log_timestamp_formatted => &alert.log_timestamp_formatted,
    })
    .map_err(|e| NotifyError::TemplateError(e.to_string()))
}

/// Strips tags like `<b>`, `<i></i>` from a rendered Telegram HTML body.
static HTML_TAG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]*>").expect("valid regex"));

/// Cap on title length when wrapping into `<b>…</b>` for the fallback, to stay
/// under `TELEGRAM_TEXT_MAX_CODEPOINTS` even after HTML-escaping and wrapping.
const FALLBACK_TITLE_MAX_CODEPOINTS: usize = TELEGRAM_TEXT_MAX_CODEPOINTS - 16;

/// Escape the three characters Telegram's HTML parse_mode treats as markup.
fn escape_telegram_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Return a fallback text + reason when `text` has no visible content, else `None`.
fn fallback_if_empty(text: &str, alert: &AlertPayload) -> Option<(String, &'static str)> {
    let reason = if text.is_empty() {
        "empty_after_render"
    } else if text.trim().is_empty() {
        "whitespace_only"
    } else if HTML_TAG_REGEX.replace_all(text, "").trim().is_empty() {
        "no_text_content"
    } else {
        return None;
    };

    let fallback = if !alert.message.title.trim().is_empty() {
        let capped: String = alert
            .message
            .title
            .chars()
            .take(FALLBACK_TITLE_MAX_CODEPOINTS)
            .collect();
        format!("<b>{}</b>", escape_telegram_html(&capped))
    } else if !alert.rule_name.trim().is_empty() {
        format!("Alert: {}", escape_telegram_html(&alert.rule_name))
    } else {
        "(valerter alert, empty render)".to_string()
    };
    Some((fallback, reason))
}

/// Clamp a parsed retry-after value to the `[RETRY_AFTER_MIN, RETRY_AFTER_MAX]`
/// window. A zero or near-zero value is bumped up to 1s to avoid tight loops;
/// a very large value is capped so we never hold an executor hostage on
/// adversarial input.
fn clamp_retry_after(seconds: f64) -> Duration {
    let clamped = seconds
        .max(RETRY_AFTER_MIN.as_secs_f64())
        .min(RETRY_AFTER_MAX.as_secs_f64());
    Duration::from_secs_f64(clamped)
}

/// Parse a `Retry-After` string as an integer first (fastest path), then fall
/// back to a float parse to accept values like `"1.5"` which some proxies emit.
fn parse_retry_after_value(s: &str) -> Option<f64> {
    let trimmed = s.trim();
    if let Ok(n) = trimmed.parse::<u64>() {
        return Some(n as f64);
    }
    trimmed.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// Pure parsing logic for the retry-after chain — unit-tested directly.
fn extract_retry_after(header: Option<&str>, body: &str, attempt: u32) -> Duration {
    if let Some(raw) = header
        && let Some(secs) = parse_retry_after_value(raw)
    {
        return clamp_retry_after(secs);
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(secs) = json
            .get("parameters")
            .and_then(|p| p.get("retry_after"))
            .and_then(|v| v.as_f64().or_else(|| v.as_u64().map(|n| n as f64)))
    {
        return clamp_retry_after(secs);
    }
    backoff_delay(attempt, TELEGRAM_BACKOFF_BASE, TELEGRAM_BACKOFF_MAX)
}

/// Extract a retry-after duration after a 429 response. Tries the HTTP header
/// first, then the JSON body `parameters.retry_after`, then falls back to the
/// standard exponential backoff. Safe on malformed input — never panics.
async fn parse_retry_after(response: reqwest::Response, attempt: u32) -> Duration {
    let header = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = response.text().await.unwrap_or_default();
    extract_retry_after(header.as_deref(), &body, attempt)
}

/// Telegram Bot notifier. One instance per configured `notifiers.<name>` entry.
pub struct TelegramNotifier {
    name: String,
    /// Full Bot API endpoint including the token
    /// (`https://api.telegram.org/bot<token>/sendMessage`). Stored as
    /// [`SecretString`] so it never leaks through `Debug` or tracing.
    endpoint: SecretString,
    client: reqwest::Client,
    chat_ids: Vec<String>,
    parse_mode: String,
    disable_notification: Option<bool>,
    disable_web_page_preview: Option<bool>,
    body_template_source: Option<String>,
}

impl TelegramNotifier {
    /// Build a notifier from its validated configuration.
    pub fn from_config(
        name: &str,
        config: &TelegramNotifierConfig,
        client: reqwest::Client,
    ) -> Result<Self, ConfigError> {
        if config.chat_ids.is_empty() {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: "chat_ids must not be empty".to_string(),
            });
        }
        if let Some((index, _)) = config
            .chat_ids
            .iter()
            .enumerate()
            .find(|(_, id)| id.trim().is_empty())
        {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("chat_ids[{}] must not be empty", index),
            });
        }

        let resolved_token =
            resolve_env_vars(&config.bot_token).map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("bot_token: {}", e),
            })?;
        if resolved_token.trim().is_empty() {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: "bot_token resolved to an empty value".to_string(),
            });
        }

        if let Some(template) = &config.body_template {
            validate_body_template(template).map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("body_template: {}", e),
            })?;
        }

        let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", resolved_token);

        Ok(Self {
            name: name.to_string(),
            endpoint: SecretString::new(endpoint),
            client,
            chat_ids: config.chat_ids.clone(),
            parse_mode: config
                .parse_mode
                .clone()
                .unwrap_or_else(|| DEFAULT_PARSE_MODE.to_string()),
            disable_notification: config.disable_notification,
            disable_web_page_preview: config.disable_web_page_preview,
            body_template_source: config.body_template.clone(),
        })
    }

    /// Render and truncate the message text once, before fan-out to chats.
    fn prepare_text(&self, alert: &AlertPayload) -> Result<(String, bool), NotifyError> {
        let template = self
            .body_template_source
            .as_deref()
            .unwrap_or(DEFAULT_BODY_TEMPLATE);
        let rendered = render_body_template(template, alert)?;
        let guarded = if let Some((fallback, reason)) = fallback_if_empty(&rendered, alert) {
            tracing::warn!(
                rule_name = %alert.rule_name,
                notifier_name = %self.name,
                reason = reason,
                "Telegram body_template rendered empty, applied fallback"
            );
            fallback
        } else {
            rendered
        };
        Ok(truncate_text(&guarded))
    }

    /// Send the prepared text to a single chat_id with retry. Returns `Ok` on
    /// success, `Err` on permanent failure (retries exhausted or 4xx other
    /// than 429).
    async fn send_to_chat(
        &self,
        alert: &AlertPayload,
        chat_id: &str,
        text: &str,
    ) -> Result<(), NotifyError> {
        let payload = TelegramPayload {
            chat_id,
            text,
            parse_mode: &self.parse_mode,
            disable_notification: self.disable_notification,
            disable_web_page_preview: self.disable_web_page_preview,
        };

        for attempt in 0..TELEGRAM_MAX_RETRIES {
            let result = self
                .client
                .post(self.endpoint.expose())
                .timeout(TELEGRAM_HTTP_TIMEOUT)
                .json(&payload)
                .send()
                .await;

            match result {
                Ok(response) if response.status().is_success() => {
                    tracing::debug!(chat_id = %chat_id, "Telegram alert sent");
                    return Ok(());
                }
                Ok(response) if response.status().as_u16() == 429 => {
                    let delay = parse_retry_after(response, attempt).await;
                    tracing::warn!(
                        attempt = attempt,
                        chat_id = %chat_id,
                        delay_ms = delay.as_millis() as u64,
                        "Telegram rate-limited, waiting"
                    );
                    if attempt < TELEGRAM_MAX_RETRIES - 1 {
                        tokio::time::sleep(delay).await;
                    }
                    continue;
                }
                Ok(response) if response.status().is_client_error() => {
                    let status = response.status();
                    tracing::error!(
                        chat_id = %chat_id,
                        status = %status,
                        "Telegram returned client error, not retrying"
                    );
                    return Err(NotifyError::SendFailed(format!("client error: {}", status)));
                }
                Ok(response) => {
                    tracing::warn!(
                        attempt = attempt,
                        chat_id = %chat_id,
                        status = %response.status(),
                        "Telegram returned server error, retrying"
                    );
                }
                Err(e) => {
                    // `reqwest::Error` includes the full request URL (which
                    // contains the bot token) in its Display. Strip it before
                    // logging.
                    tracing::warn!(
                        attempt = attempt,
                        chat_id = %chat_id,
                        error = %e.without_url(),
                        "Telegram request failed, retrying"
                    );
                }
            }

            if attempt < TELEGRAM_MAX_RETRIES - 1 {
                let delay = backoff_delay(attempt, TELEGRAM_BACKOFF_BASE, TELEGRAM_BACKOFF_MAX);
                tokio::time::sleep(delay).await;
            }
        }

        tracing::error!(
            chat_id = %chat_id,
            max_retries = TELEGRAM_MAX_RETRIES,
            rule_name = %alert.rule_name,
            "Telegram send exhausted retries"
        );
        Err(NotifyError::MaxRetriesExceeded)
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "telegram"
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_telegram",
            rule_name = %alert.rule_name,
            notifier_name = %self.name,
            chat_count = self.chat_ids.len()
        );

        async {
            let (text, truncated) = self.prepare_text(alert)?;
            if truncated {
                tracing::warn!(
                    rule_name = %alert.rule_name,
                    limit = TELEGRAM_TEXT_MAX_CODEPOINTS,
                    "Telegram message truncated to fit codepoint limit"
                );
                metrics::counter!(
                    "valerter_alerts_truncated_total",
                    "notifier_type" => "telegram",
                    "notifier_name" => self.name.clone()
                )
                .increment(1);
            }

            let mut any_success = false;
            for chat_id in &self.chat_ids {
                match self.send_to_chat(alert, chat_id, &text).await {
                    Ok(()) => {
                        any_success = true;
                        metrics::counter!(
                            "valerter_alerts_sent_total",
                            "rule_name" => alert.rule_name.clone(),
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.name.clone(),
                            "notifier_type" => "telegram",
                        )
                        .increment(1);
                    }
                    Err(e) => {
                        tracing::error!(
                            chat_id = %chat_id,
                            error = %e,
                            "Telegram send permanently failed for chat"
                        );
                        metrics::counter!(
                            "valerter_notify_errors_total",
                            "rule_name" => alert.rule_name.clone(),
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.name.clone(),
                            "notifier_type" => "telegram",
                        )
                        .increment(1);
                        metrics::counter!(
                            "valerter_alerts_failed_total",
                            "rule_name" => alert.rule_name.clone(),
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.name.clone(),
                            "notifier_type" => "telegram",
                        )
                        .increment(1);
                    }
                }
            }

            if any_success {
                Ok(())
            } else {
                Err(NotifyError::SendFailed("all chat_ids failed".to_string()))
            }
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
impl TelegramNotifier {
    /// Test-only constructor that bypasses the real Bot API URL. Used by
    /// integration tests to redirect requests to a wiremock server.
    pub(crate) fn new_for_tests(
        name: &str,
        endpoint: String,
        chat_ids: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            name: name.to_string(),
            endpoint: SecretString::new(endpoint),
            client,
            chat_ids,
            parse_mode: DEFAULT_PARSE_MODE.to_string(),
            disable_notification: None,
            disable_web_page_preview: None,
            body_template_source: None,
        }
    }
}

impl std::fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak endpoint (contains the bot token) or chat_ids.
        f.debug_struct("TelegramNotifier")
            .field("name", &self.name)
            .field("chat_count", &self.chat_ids.len())
            .field("parse_mode", &self.parse_mode)
            .field("has_body_template", &self.body_template_source.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::RenderedMessage;

    fn sample_alert(title: &str, body: &str) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: title.to_string(),
                body: body.to_string(),
                email_body_html: None,
                accent_color: None,
            },
            rule_name: "test_rule".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec![],
            log_timestamp: "2026-04-14T10:00:00Z".to_string(),
            log_timestamp_formatted: "14/04/2026 10:00:00 UTC".to_string(),
        }
    }

    fn config_with(chat_ids: Vec<String>) -> TelegramNotifierConfig {
        TelegramNotifierConfig {
            bot_token: "fake-token".to_string(),
            chat_ids,
            parse_mode: None,
            disable_notification: None,
            disable_web_page_preview: None,
            body_template: None,
        }
    }

    #[test]
    fn truncate_text_leaves_short_text_alone() {
        let input = "hello";
        let (out, was_truncated) = truncate_text(input);
        assert_eq!(out, "hello");
        assert!(!was_truncated);
    }

    #[test]
    fn truncate_text_allows_exact_limit() {
        let input: String = "a".repeat(TELEGRAM_TEXT_MAX_CODEPOINTS);
        let (out, was_truncated) = truncate_text(&input);
        assert_eq!(out.chars().count(), TELEGRAM_TEXT_MAX_CODEPOINTS);
        assert!(!was_truncated);
    }

    #[test]
    fn truncate_text_cuts_over_limit_to_exactly_4096_codepoints() {
        let input: String = "a".repeat(TELEGRAM_TEXT_MAX_CODEPOINTS + 1);
        let (out, was_truncated) = truncate_text(&input);
        assert!(was_truncated);
        assert_eq!(out.chars().count(), TELEGRAM_TEXT_MAX_CODEPOINTS);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_text_respects_codepoints_not_bytes_on_multibyte() {
        // Build a 5000-codepoint string of 4-byte emojis (🌟 = U+1F31F, 4 bytes).
        let star = "🌟";
        let input: String = star.repeat(5000);
        assert!(
            input.len() > TELEGRAM_TEXT_MAX_CODEPOINTS * 2,
            "input should be byte-heavy"
        );
        let (out, was_truncated) = truncate_text(&input);
        assert!(was_truncated);
        // Limit is in codepoints, not bytes.
        assert_eq!(out.chars().count(), TELEGRAM_TEXT_MAX_CODEPOINTS);
        assert!(out.ends_with('…'));
        // First 4095 codepoints must still be intact emojis (no byte splitting).
        let kept: String = out.chars().take(TELEGRAM_TEXT_MAX_CODEPOINTS - 1).collect();
        assert_eq!(kept, star.repeat(TELEGRAM_TEXT_MAX_CODEPOINTS - 1));
    }

    #[test]
    fn from_config_rejects_empty_chat_ids() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec![]);
        let err = TelegramNotifier::from_config("tg", &cfg, client).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNotifier { .. }));
        assert!(err.to_string().contains("chat_ids"));
    }

    #[test]
    fn from_config_fails_fast_on_unresolved_env_var() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.bot_token = "${VALERTER_TELEGRAM_TEST_MISSING_VAR}".to_string();
        let err = TelegramNotifier::from_config("tg", &cfg, client).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNotifier { .. }));
        assert!(err.to_string().contains("bot_token"));
    }

    #[test]
    fn from_config_rejects_invalid_body_template() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template = Some("{% broken %}".to_string());
        let err = TelegramNotifier::from_config("tg", &cfg, client).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNotifier { .. }));
        assert!(err.to_string().contains("body_template"));
    }

    #[test]
    fn from_config_applies_defaults() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string()]);
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        assert_eq!(notifier.name(), "tg");
        assert_eq!(notifier.notifier_type(), "telegram");
        assert_eq!(notifier.parse_mode, DEFAULT_PARSE_MODE);
        assert!(notifier.body_template_source.is_none());
    }

    #[test]
    fn default_body_template_escapes_html() {
        let alert = sample_alert("<script>", "A & B");
        let rendered = render_body_template(DEFAULT_BODY_TEMPLATE, &alert).unwrap();
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("&lt;script&gt;"));
        assert!(rendered.contains("A &amp; B"));
        assert!(rendered.starts_with("<b>"));
    }

    #[test]
    fn debug_impl_does_not_leak_token_or_endpoint() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.bot_token = "SUPER_SECRET_TOKEN".to_string();
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        let dbg = format!("{:?}", notifier);
        assert!(dbg.contains("TelegramNotifier"));
        assert!(dbg.contains("tg"));
        assert!(!dbg.contains("SUPER_SECRET_TOKEN"));
        assert!(!dbg.contains("api.telegram.org"));
    }

    #[test]
    fn payload_serializes_and_skips_none_options() {
        let payload = TelegramPayload {
            chat_id: "-100",
            text: "hello",
            parse_mode: "HTML",
            disable_notification: None,
            disable_web_page_preview: Some(true),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"chat_id\":\"-100\""));
        assert!(json.contains("\"text\":\"hello\""));
        assert!(json.contains("\"parse_mode\":\"HTML\""));
        assert!(json.contains("\"disable_web_page_preview\":true"));
        assert!(!json.contains("disable_notification"));
    }

    #[tokio::test]
    async fn notifier_trait_is_object_safe() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string()]);
        let notifier: Box<dyn Notifier> =
            Box::new(TelegramNotifier::from_config("tg", &cfg, client).unwrap());
        assert_eq!(notifier.name(), "tg");
        assert_eq!(notifier.notifier_type(), "telegram");
    }

    // ── extract_retry_after ──────────────────────────────────────────────

    #[test]
    fn extract_retry_after_prefers_valid_header() {
        let delay = extract_retry_after(Some("7"), r#"{"parameters":{"retry_after":99}}"#, 0);
        assert_eq!(delay, Duration::from_secs(7));
    }

    #[test]
    fn extract_retry_after_falls_back_to_json_on_malformed_header() {
        let delay = extract_retry_after(
            Some("not-a-number"),
            r#"{"parameters":{"retry_after":3}}"#,
            0,
        );
        assert_eq!(delay, Duration::from_secs(3));
    }

    #[test]
    fn extract_retry_after_falls_back_to_backoff_when_all_malformed() {
        let delay = extract_retry_after(Some("???"), "not-json-at-all", 0);
        assert_eq!(delay, TELEGRAM_BACKOFF_BASE);
    }

    #[test]
    fn extract_retry_after_handles_no_header_no_body() {
        let delay = extract_retry_after(None, "", 0);
        assert_eq!(delay, TELEGRAM_BACKOFF_BASE);
    }

    #[test]
    fn extract_retry_after_handles_missing_retry_after_field() {
        let delay = extract_retry_after(None, r#"{"parameters":{"other":1}}"#, 0);
        assert_eq!(delay, TELEGRAM_BACKOFF_BASE);
    }

    #[test]
    fn extract_retry_after_parses_float_header() {
        let delay = extract_retry_after(Some("1.5"), "", 0);
        // 1.5s is within [MIN, MAX] so we expect the exact clamped value.
        assert_eq!(delay, Duration::from_secs_f64(1.5));
    }

    #[test]
    fn extract_retry_after_bumps_zero_to_min_floor() {
        let delay = extract_retry_after(Some("0"), "", 0);
        assert_eq!(delay, RETRY_AFTER_MIN);
    }

    #[test]
    fn extract_retry_after_caps_runaway_value() {
        let delay = extract_retry_after(Some("36000"), "", 0);
        assert_eq!(delay, RETRY_AFTER_MAX);
    }

    #[test]
    fn extract_retry_after_parses_float_json_body() {
        let delay = extract_retry_after(None, r#"{"parameters":{"retry_after":2.5}}"#, 0);
        assert_eq!(delay, Duration::from_secs_f64(2.5));
    }

    // ── Empty-value validation ───────────────────────────────────────────

    #[test]
    fn from_config_rejects_empty_chat_id_element() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string(), "   ".to_string()]);
        let err = TelegramNotifier::from_config("tg", &cfg, client).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNotifier { .. }));
        assert!(err.to_string().contains("chat_ids[1]"));
    }

    #[test]
    fn from_config_rejects_empty_resolved_bot_token() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.bot_token = "   ".to_string();
        let err = TelegramNotifier::from_config("tg", &cfg, client).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNotifier { .. }));
        assert!(err.to_string().contains("bot_token"));
    }

    // ── End-to-end send() via wiremock ───────────────────────────────────
    //
    // These tests cover AC1, AC7 and the multi-chat retry path that the
    // earlier unit tests cannot exercise. Requests are redirected to a local
    // wiremock server via `TelegramNotifier::new_for_tests`.

    use serial_test::serial;
    use wiremock::matchers::{body_partial_json, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_notifier(server: &MockServer, chat_ids: Vec<String>) -> TelegramNotifier {
        // Use alphanumeric-only path so reqwest doesn't percent-encode anything.
        let endpoint = format!("{}/botTESTTOKEN/sendMessage", server.uri());
        TelegramNotifier::new_for_tests("tg-test", endpoint, chat_ids, reqwest::Client::new())
    }

    #[tokio::test]
    #[serial]
    async fn send_all_chats_success_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/botTESTTOKEN/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(2)
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string(), "-100B".to_string()]);
        let alert = sample_alert("hi", "body");
        notifier.send(&alert).await.expect("should succeed");

        server.verify().await;
    }

    #[tokio::test]
    #[serial]
    async fn send_partial_success_returns_ok_and_does_not_stop_after_failure() {
        let server = MockServer::start().await;
        // Every chat gets 200 — we verify the important property: 3 requests
        // are issued in order even when the middle one hits a permanent error
        // in a separate test. Here we first establish that the multi-chat
        // fan-out reaches all chats.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(3)
            .mount(&server)
            .await;

        let notifier = test_notifier(
            &server,
            vec![
                "-100A".to_string(),
                "-100B".to_string(),
                "-100C".to_string(),
            ],
        );
        let alert = sample_alert("hi", "body");
        notifier.send(&alert).await.expect("should succeed");
        server.verify().await;
    }

    #[tokio::test]
    #[serial]
    async fn send_one_permanent_failure_in_middle_still_returns_ok_partial() {
        // wiremock can't route per chat_id (it's in the JSON body), but we can
        // assert the partial-success behaviour by exhausting a single mock
        // endpoint's 200 response after 1 hit then returning 400 for the rest.
        // The last chat will still fail permanently, but the first success is
        // enough for the notifier to return Ok.
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        Mock::given(method("POST"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = calls_clone.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_string("{\"ok\":true}")
                } else {
                    ResponseTemplate::new(400)
                        .set_body_string("{\"ok\":false,\"description\":\"bad chat\"}")
                }
            })
            .mount(&server)
            .await;

        let notifier = test_notifier(
            &server,
            vec![
                "-100A".to_string(),
                "-100B".to_string(),
                "-100C".to_string(),
            ],
        );
        let alert = sample_alert("hi", "body");
        notifier
            .send(&alert)
            .await
            .expect("partial success should be Ok");

        // 1 success + 2 permanent failures = 3 requests. The failing chats are
        // 4xx so there is no retry.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    #[serial]
    async fn send_all_chats_permanent_failure_returns_err() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("{\"ok\":false,\"description\":\"bad chat\"}"),
            )
            .expect(2)
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string(), "-100B".to_string()]);
        let alert = sample_alert("hi", "body");
        let err = notifier.send(&alert).await.unwrap_err();
        assert!(matches!(err, NotifyError::SendFailed(_)));
        server.verify().await;
    }

    #[tokio::test]
    #[serial]
    async fn send_payload_has_expected_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "chat_id": "-100A",
                "parse_mode": "HTML",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string()]);
        let alert = sample_alert("Hello", "World");
        notifier.send(&alert).await.expect("should succeed");
        server.verify().await;
    }

    #[tokio::test]
    #[serial]
    async fn send_retries_on_5xx_then_succeeds() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        Mock::given(method("POST"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = calls_clone.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(503).set_body_string("server error")
                } else {
                    ResponseTemplate::new(200).set_body_string("{\"ok\":true}")
                }
            })
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string()]);
        let alert = sample_alert("hi", "body");
        notifier
            .send(&alert)
            .await
            .expect("should succeed after 5xx retry");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[serial]
    async fn send_exhausts_retries_on_persistent_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
            .expect(3)
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string()]);
        let alert = sample_alert("hi", "body");
        let err = notifier.send(&alert).await.unwrap_err();
        assert!(matches!(err, NotifyError::SendFailed(_)));
        server.verify().await;
    }

    #[tokio::test]
    #[serial]
    async fn send_network_error_exhausts_retries() {
        // Point the notifier at a TEST-NET-1 address (RFC 5737, reserved for
        // documentation and never routed). The connection attempt fails at
        // the TCP level, exercising the Err(reqwest::Error) branch of the
        // retry loop without depending on a released port.
        let endpoint = "http://192.0.2.1:1/botTESTTOKEN/sendMessage".to_string();
        // Short timeout on the shared client so the test doesn't take 30s
        // waiting for three TCP timeouts to fire.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let notifier =
            TelegramNotifier::new_for_tests("tg-test", endpoint, vec!["-100A".to_string()], client);
        let alert = sample_alert("hi", "body");
        let err = notifier.send(&alert).await.unwrap_err();
        assert!(matches!(err, NotifyError::SendFailed(_)));
    }

    #[tokio::test]
    #[serial]
    async fn send_body_under_limit_is_not_truncated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                // Default template renders "<b>{{title|e}}</b>\n{{body|e}}" so
                // the exact body text for a short input is deterministic.
                "text": "<b>hello</b>\nworld",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = test_notifier(&server, vec!["-100A".to_string()]);
        let alert = sample_alert("hello", "world");
        notifier.send(&alert).await.expect("should succeed");
        server.verify().await;
    }

    // ── Imports for the wiremock tests (kept near the tests to minimize
    //    churn in the rest of the module).
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ── fallback_if_empty (#26 empty-render guard) ───────────────────────

    #[test]
    fn fallback_if_empty_triggers_on_empty() {
        let alert = sample_alert("", "");
        let out = fallback_if_empty("", &alert);
        assert!(out.is_some(), "empty string should trigger fallback");
        let (_, reason) = out.unwrap();
        assert_eq!(reason, "empty_after_render");
    }

    #[test]
    fn fallback_if_empty_triggers_on_whitespace() {
        let alert = sample_alert("", "");
        let out = fallback_if_empty("  \n\t ", &alert);
        assert!(out.is_some(), "whitespace-only should trigger fallback");
        let (_, reason) = out.unwrap();
        assert_eq!(reason, "whitespace_only");
    }

    #[test]
    fn fallback_if_empty_triggers_on_html_only() {
        let alert = sample_alert("", "");
        let out = fallback_if_empty("<b></b>\n", &alert);
        assert!(out.is_some(), "html-only should trigger fallback");
        let (_, reason) = out.unwrap();
        assert_eq!(reason, "no_text_content");
    }

    #[test]
    fn fallback_if_empty_uses_title_when_available() {
        let alert = sample_alert("Disk full", "");
        let (text, _) = fallback_if_empty("<b></b>\n", &alert).unwrap();
        assert_eq!(text, "<b>Disk full</b>");
    }

    #[test]
    fn fallback_if_empty_uses_rule_name_as_fallback() {
        // title is empty → fallback leans on rule_name.
        let mut alert = sample_alert("", "");
        alert.rule_name = "nginx-5xx".to_string();
        let (text, _) = fallback_if_empty("", &alert).unwrap();
        assert_eq!(text, "Alert: nginx-5xx");
    }

    #[test]
    fn fallback_if_empty_uses_literal_when_all_empty() {
        let mut alert = sample_alert("", "");
        alert.rule_name = String::new();
        let (text, _) = fallback_if_empty("", &alert).unwrap();
        assert_eq!(text, "(valerter alert, empty render)");
    }

    #[test]
    fn fallback_escapes_html_specials_in_title() {
        // Post-review guard: a title containing `<`, `>`, or `&` must not
        // produce a payload that Telegram's HTML parse_mode would reject.
        let alert = sample_alert("<script>alert(&amp;)</script>", "");
        let (text, _) = fallback_if_empty("", &alert).unwrap();
        assert_eq!(text, "<b>&lt;script&gt;alert(&amp;amp;)&lt;/script&gt;</b>");
    }

    #[test]
    fn fallback_escapes_html_specials_in_rule_name() {
        let mut alert = sample_alert("", "");
        alert.rule_name = "a<b & c".to_string();
        let (text, _) = fallback_if_empty("", &alert).unwrap();
        assert_eq!(text, "Alert: a&lt;b &amp; c");
    }

    #[test]
    fn fallback_caps_long_title_to_stay_under_telegram_limit() {
        // A pathological 10k-codepoint title must not overflow the
        // Telegram `text` limit once wrapped in `<b>…</b>`.
        let long_title: String = "x".repeat(10_000);
        let alert = sample_alert(&long_title, "");
        let (text, _) = fallback_if_empty("", &alert).unwrap();
        assert!(text.chars().count() <= TELEGRAM_TEXT_MAX_CODEPOINTS);
        assert!(text.starts_with("<b>"));
        assert!(text.ends_with("</b>"));
    }

    #[test]
    fn fallback_if_empty_returns_none_for_non_empty() {
        let alert = sample_alert("", "");
        assert!(fallback_if_empty("Hello world", &alert).is_none());
    }

    #[test]
    fn fallback_if_empty_returns_none_for_html_with_text() {
        let alert = sample_alert("", "");
        assert!(fallback_if_empty("<b>ok</b>", &alert).is_none());
    }

    // ── prepare_text empty-guard integration ─────────────────────────────

    #[test]
    fn prepare_text_substitutes_on_empty_render() {
        // A body_template that renders to literally empty (no vars in context).
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template = Some("".to_string());
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        let alert = sample_alert("Disk full", "");
        let (text, _) = notifier.prepare_text(&alert).unwrap();
        assert!(!text.trim().is_empty(), "fallback text must not be empty");
        assert_eq!(text, "<b>Disk full</b>");
    }

    #[test]
    fn prepare_text_substitutes_on_html_only_render() {
        // Reproduces issue #26: default template + empty title/body → "<b></b>\n".
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string()]);
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        let mut alert = sample_alert("", "");
        alert.rule_name = "nginx-5xx".to_string();
        let (text, _) = notifier.prepare_text(&alert).unwrap();
        assert_eq!(text, "Alert: nginx-5xx");
    }

    #[test]
    fn prepare_text_preserves_non_empty_render() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string()]);
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        let alert = sample_alert("hello", "world");
        let (text, _) = notifier.prepare_text(&alert).unwrap();
        assert_eq!(text, "<b>hello</b>\nworld");
    }
}
