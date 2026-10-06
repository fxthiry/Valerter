//! Telegram Bot notifier implementation.
//!
//! Sends alerts via the Bot API `sendMessage` endpoint. One HTTP call per
//! configured `chat_id`, sequentially — Telegram rate-limits at 1 msg/sec/chat,
//! so batching would not help. The notifier returns `Ok(())` as soon as at
//! least one chat succeeds (partial success); `Err` only when all fail.

use crate::config::{
    OutputFormat, SecretString, TelegramNotifierConfig, resolve_env_vars,
    validate_notifier_template,
};
use crate::error::{ConfigError, NotifyError};
use crate::http_body::read_body_prefix;
use crate::notify::notifier_template::{CONTEXT_VARIABLES, NotifierTemplate};
use crate::notify::{AlertPayload, Notifier, backoff_delay, record_permanent_failure};
use async_trait::async_trait;
use minijinja::context;
use regex::Regex;
use serde::{Deserialize, Serialize};
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

/// `parse_mode` values accepted by the Bot API, in canonical form.
const SUPPORTED_PARSE_MODES: [&str; 3] = ["HTML", "MarkdownV2", "Markdown"];

/// Returns the canonical form of a `parse_mode` (`html` → `HTML`), compared
/// case-insensitively, or `None` when the Bot API does not support it.
fn normalize_parse_mode(value: &str) -> Option<&'static str> {
    SUPPORTED_PARSE_MODES
        .into_iter()
        .find(|mode| mode.eq_ignore_ascii_case(value))
}

/// Payload serialized as the body of a `sendMessage` request.
#[derive(Debug, Serialize)]
struct TelegramPayload<'a> {
    chat_id: &'a str,
    text: &'a str,
    /// Omitted when resending as plain text after an HTML rejection.
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<&'a str>,
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

/// Render the compiled body template with alert context.
fn render_body_template(
    template: &NotifierTemplate,
    alert: &AlertPayload,
    format: OutputFormat,
) -> Result<String, NotifyError> {
    template
        .render(context! {
            title => &alert.message.title,
            body => alert.message.body_for(format).to_value(),
            rule_name => &alert.rule_name,
            vl_source => &alert.vl_source,
            log_timestamp => &alert.log_timestamp,
            log_timestamp_formatted => &alert.log_timestamp_formatted,
            log => &alert.log,
        })
        .map_err(|e| NotifyError::TemplateError(e.to_string()))
}

/// Compile the configured `body_template`, or the default one. The source
/// has already been validated, so an error here is unexpected.
fn compile_body_template(
    name: &str,
    source: Option<&str>,
) -> Result<NotifierTemplate, ConfigError> {
    let source = source.unwrap_or(DEFAULT_BODY_TEMPLATE);
    NotifierTemplate::compile(source.to_string(), false).map_err(|e| ConfigError::InvalidNotifier {
        name: name.to_string(),
        message: format!("body_template: {e}"),
    })
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

/// Bytes of a 400 response body read at most to find its `description`.
const ERROR_BODY_MAX_BYTES: usize = 4096;

/// `description` field of a Bot API error body, if the body is JSON.
fn error_description(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        description: Option<String>,
    }
    serde_json::from_slice::<ErrorBody>(body).ok()?.description
}

/// Whether a 400 description reports malformed HTML markup (`Bad Request:
/// can't parse entities: ...`), the only rejection a plain-text resend fixes.
fn is_entity_parse_error(description: &str) -> bool {
    description.to_lowercase().contains("can't parse entities")
}

/// Why a `sendMessage` request to one chat failed for good.
#[derive(Debug)]
enum ChatSendError {
    /// 4xx other than 429: the request itself was rejected, not retried.
    /// `description` is the Bot API error description, read for a 400 only.
    Client {
        status: reqwest::StatusCode,
        description: Option<String>,
    },
    /// 5xx, 429 and network errors until the retry pool was exhausted.
    RetriesExhausted,
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
    /// Whether `body_template` is configured (else the default is used).
    has_body_template: bool,
    /// `body_template` or the default template, compiled once.
    body_template: NotifierTemplate,
    /// Format of the body of a Markdown alert.
    format: OutputFormat,
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

        let resolved_token = resolve_env_vars(config.bot_token.expose()).map_err(|e| {
            ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("bot_token: {}", e),
            }
        })?;
        if resolved_token.trim().is_empty() {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: "bot_token resolved to an empty value".to_string(),
            });
        }

        if let Some(template) = &config.body_template {
            validate_notifier_template("body_template", template).map_err(|message| {
                ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message,
                }
            })?;
        }

        let parse_mode = match config.parse_mode.as_deref() {
            None => DEFAULT_PARSE_MODE,
            Some(value) => {
                normalize_parse_mode(value).ok_or_else(|| ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!(
                        "parse_mode '{value}' is not supported (expected HTML, MarkdownV2 or Markdown)"
                    ),
                })?
            }
        };

        // `telegram_html` needs Telegram to parse the text as HTML; another
        // parse mode gets plain text by default (the template escapes it).
        if config.format == Some(OutputFormat::TelegramHtml) && parse_mode != "HTML" {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: "format 'telegram_html' requires parse_mode HTML".to_string(),
            });
        }
        let format = OutputFormat::resolve(
            config.format,
            if parse_mode == "HTML" {
                OutputFormat::TelegramHtml
            } else {
                OutputFormat::Plain
            },
            &[OutputFormat::TelegramHtml, OutputFormat::Plain],
            name,
            "telegram",
        )?;

        let body_template = compile_body_template(name, config.body_template.as_deref())?;
        body_template.warn_unknown_variables(name, "body_template", &CONTEXT_VARIABLES);

        let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", resolved_token);

        Ok(Self {
            name: name.to_string(),
            endpoint: SecretString::new(endpoint),
            client,
            chat_ids: config.chat_ids.clone(),
            parse_mode: parse_mode.to_string(),
            disable_notification: config.disable_notification,
            disable_web_page_preview: config.disable_web_page_preview,
            has_body_template: config.body_template.is_some(),
            body_template,
            format,
        })
    }

    /// Render and truncate the message text once, before fan-out to chats.
    fn prepare_text(&self, alert: &AlertPayload) -> Result<(String, bool), NotifyError> {
        let rendered = render_body_template(&self.body_template, alert, self.format)?;
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
    ///
    /// A 400 `can't parse entities` on an HTML message (malformed markup: a
    /// tag cut by truncation, an unescaped `<` or `&` in a custom template) is
    /// resent once as plain text, so the alert is delivered with its tags
    /// shown literally rather than lost. Any other 400 (`chat not found`,
    /// `message text is empty`…) fails the chat at once.
    async fn send_to_chat(
        &self,
        alert: &AlertPayload,
        chat_id: &str,
        text: &str,
    ) -> Result<(), NotifyError> {
        let mut payload = TelegramPayload {
            chat_id,
            text,
            parse_mode: Some(&self.parse_mode),
            disable_notification: self.disable_notification,
            disable_web_page_preview: self.disable_web_page_preview,
        };

        let result = match self.post_with_retry(chat_id, &payload).await {
            Err(ChatSendError::Client {
                status,
                description: Some(description),
            }) if status == reqwest::StatusCode::BAD_REQUEST
                && self.parse_mode.eq_ignore_ascii_case("HTML")
                && is_entity_parse_error(&description) =>
            {
                tracing::warn!(
                    notifier_name = %self.name,
                    rule_name = %alert.rule_name,
                    chat_id = %chat_id,
                    status = %status,
                    "Telegram rejected HTML message, resending as plain text"
                );
                payload.parse_mode = None;
                self.post_with_retry(chat_id, &payload).await
            }
            other => other,
        };

        match result {
            Ok(()) => Ok(()),
            Err(ChatSendError::Client { status, .. }) => {
                tracing::error!(
                    chat_id = %chat_id,
                    status = %status,
                    "Telegram returned client error, not retrying"
                );
                Err(NotifyError::SendFailed(format!("client error: {}", status)))
            }
            Err(ChatSendError::RetriesExhausted) => {
                tracing::error!(
                    chat_id = %chat_id,
                    max_retries = TELEGRAM_MAX_RETRIES,
                    rule_name = %alert.rule_name,
                    "Telegram send exhausted retries"
                );
                Err(NotifyError::MaxRetriesExceeded)
            }
        }
    }

    /// POST one `sendMessage` payload, retrying 5xx, 429 and network errors
    /// up to [`TELEGRAM_MAX_RETRIES`] attempts. A 4xx other than 429 stops
    /// immediately.
    async fn post_with_retry(
        &self,
        chat_id: &str,
        payload: &TelegramPayload<'_>,
    ) -> Result<(), ChatSendError> {
        for attempt in 0..TELEGRAM_MAX_RETRIES {
            let result = self
                .client
                .post(self.endpoint.expose())
                .timeout(TELEGRAM_HTTP_TIMEOUT)
                .json(payload)
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
                    // Only a 400 can trigger the plain-text fallback: read
                    // its description, within a size limit (the duration is
                    // bounded by the request timeout).
                    let description = if status == reqwest::StatusCode::BAD_REQUEST {
                        let body =
                            read_body_prefix(response, ERROR_BODY_MAX_BYTES, TELEGRAM_HTTP_TIMEOUT)
                                .await;
                        error_description(&body)
                    } else {
                        None
                    };
                    return Err(ChatSendError::Client {
                        status,
                        description,
                    });
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

        Err(ChatSendError::RetriesExhausted)
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

    fn output_format(&self) -> OutputFormat {
        self.format
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_telegram",
            rule_name = %alert.rule_name,
            notifier_name = %self.name,
            chat_count = self.chat_ids.len()
        );

        async {
            // A render error is a permanent failure for this alert: count it,
            // send nothing.
            let (text, truncated) = match self.prepare_text(alert) {
                Ok(prepared) => prepared,
                Err(e) => {
                    record_permanent_failure(alert, &self.name, "telegram");
                    return Err(e);
                }
            };
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

            // Counted once per alert, like email: sent if at least one chat
            // succeeded, failed if every chat failed. Each failed chat is
            // counted in `valerter_telegram_chat_errors_total`.
            let mut any_success = false;
            for chat_id in &self.chat_ids {
                match self.send_to_chat(alert, chat_id, &text).await {
                    Ok(()) => any_success = true,
                    Err(e) => {
                        tracing::error!(
                            chat_id = %chat_id,
                            error = %e,
                            "Telegram send permanently failed for chat"
                        );
                        metrics::counter!(
                            "valerter_telegram_chat_errors_total",
                            "rule_name" => alert.rule_name.clone(),
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.name.clone(),
                        )
                        .increment(1);
                    }
                }
            }

            if any_success {
                metrics::counter!(
                    "valerter_alerts_sent_total",
                    "rule_name" => alert.rule_name.clone(),
                    "vl_source" => alert.vl_source.clone(),
                    "notifier_name" => self.name.clone(),
                    "notifier_type" => "telegram",
                )
                .increment(1);
                Ok(())
            } else {
                record_permanent_failure(alert, &self.name, "telegram");
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
            has_body_template: false,
            body_template: compile_body_template(name, None).expect("default template compiles"),
            format: OutputFormat::TelegramHtml,
        }
    }

    /// Test-only: replace the body template, bypassing validation.
    pub(crate) fn set_body_template_for_tests(&mut self, source: Option<&str>) {
        self.has_body_template = source.is_some();
        self.body_template =
            compile_body_template(&self.name, source).expect("test template compiles");
    }
}

impl std::fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak endpoint (contains the bot token) or chat_ids.
        f.debug_struct("TelegramNotifier")
            .field("name", &self.name)
            .field("chat_count", &self.chat_ids.len())
            .field("parse_mode", &self.parse_mode)
            .field("has_body_template", &self.has_body_template)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::RenderedMessage;

    fn sample_alert(title: &str, body: &str) -> AlertPayload {
        AlertPayload {
            mattermost_channel: None,
            message: RenderedMessage {
                title: title.to_string(),
                body: body.to_string(),
                email_body_html: None,
                accent_color: None,
                ..Default::default()
            },
            rule_name: "test_rule".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec![],
            log_timestamp: "2026-04-14T10:00:00Z".to_string(),
            log_timestamp_formatted: "14/04/2026 10:00:00 UTC".to_string(),
            log: AlertPayload::log_from_fields(&serde_json::json!({})),
        }
    }

    fn config_with(chat_ids: Vec<String>) -> TelegramNotifierConfig {
        TelegramNotifierConfig {
            bot_token: SecretString::new("fake-token".to_string()),
            chat_ids,
            parse_mode: None,
            disable_notification: None,
            disable_web_page_preview: None,
            body_template: None,
            format: None,
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
        cfg.bot_token = SecretString::new("${VALERTER_TELEGRAM_TEST_MISSING_VAR}".to_string());
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
        let msg = err.to_string();
        assert!(
            msg.contains("invalid notifier 'tg': body_template: "),
            "{msg}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_filter_in_body_template() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template = Some("<b>{{ title | nosuchfilter }}</b>".to_string());
        let msg = TelegramNotifier::from_config("tg", &cfg, client)
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("invalid notifier 'tg': body_template render: "),
            "{msg}"
        );
        assert!(msg.contains("nosuchfilter"), "{msg}");
    }

    #[test]
    fn from_config_accepts_escaping_body_template() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template =
            Some("<b>{{ title | e }}</b>\n{{ body | e }} {{ title | tojson }}".to_string());
        assert!(TelegramNotifier::from_config("tg", &cfg, client).is_ok());
    }

    #[test]
    fn normalize_parse_mode_returns_canonical_form() {
        assert_eq!(normalize_parse_mode("html"), Some("HTML"));
        assert_eq!(normalize_parse_mode("HTML"), Some("HTML"));
        assert_eq!(normalize_parse_mode("markdownv2"), Some("MarkdownV2"));
        assert_eq!(normalize_parse_mode("MARKDOWN"), Some("Markdown"));
        assert_eq!(normalize_parse_mode("Markdown2"), None);
        assert_eq!(normalize_parse_mode("markdown_v2"), None);
        assert_eq!(normalize_parse_mode(""), None);
    }

    #[test]
    fn from_config_stores_canonical_parse_mode() {
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.parse_mode = Some("markdownv2".to_string());
        let notifier = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        assert_eq!(notifier.parse_mode, "MarkdownV2");
        cfg.parse_mode = Some("html".to_string());
        let notifier = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        assert_eq!(notifier.parse_mode, "HTML");
    }

    #[test]
    fn from_config_rejects_unsupported_parse_mode() {
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.parse_mode = Some("Markdown2".to_string());
        let msg = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new())
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains(
                "invalid notifier 'tg': parse_mode 'Markdown2' is not supported (expected HTML, MarkdownV2 or Markdown)"
            ),
            "{msg}"
        );
    }

    #[test]
    fn from_config_applies_defaults() {
        let client = reqwest::Client::new();
        let cfg = config_with(vec!["-100".to_string()]);
        let notifier = TelegramNotifier::from_config("tg", &cfg, client).unwrap();
        assert_eq!(notifier.name(), "tg");
        assert_eq!(notifier.notifier_type(), "telegram");
        assert_eq!(notifier.parse_mode, DEFAULT_PARSE_MODE);
        assert!(!notifier.has_body_template);
    }

    #[test]
    fn default_body_template_escapes_html() {
        let alert = sample_alert("<script>", "A & B");
        let template = compile_body_template("tg", None).unwrap();
        let rendered = render_body_template(&template, &alert, OutputFormat::TelegramHtml).unwrap();
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("&lt;script&gt;"));
        assert!(rendered.contains("A &amp; B"));
        assert!(rendered.starts_with("<b>"));
    }

    #[test]
    fn default_body_template_escapes_body() {
        let template = compile_body_template("tg", None).unwrap();
        let rendered = render_body_template(
            &template,
            &sample_alert("T", "a < b & c"),
            OutputFormat::TelegramHtml,
        )
        .unwrap();
        assert_eq!(rendered, "<b>T</b>\na &lt; b &amp; c");
    }

    #[test]
    fn body_template_markup_with_escaped_log_fields() {
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template = Some("<b>{{ title|e }}</b>\n<code>{{ log.host|e }}</code>".to_string());
        let notifier = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        let mut alert = sample_alert("Disk", "body");
        alert.log = AlertPayload::log_from_fields(&serde_json::json!({"host": "<web&01>"}));

        let (text, _) = notifier.prepare_text(&alert).unwrap();

        assert_eq!(text, "<b>Disk</b>\n<code>&lt;web&amp;01&gt;</code>");
    }

    #[test]
    fn body_template_reads_log_fields_flat_and_unflattened() {
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template = Some(
            "{{ log.host }}: {{ body }} {{ log[\"k8s.pod\"] }}|{{ log.k8s.pod }}|{{ log.missing }}|{{ log.rule_name }}"
                .to_string(),
        );
        let notifier = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        let mut alert = sample_alert("T", "disk full");
        alert.log = AlertPayload::log_from_fields(
            &serde_json::json!({"host": "web-01", "k8s.pod": "api-7f"}),
        );

        let (text, _) = notifier.prepare_text(&alert).unwrap();

        assert_eq!(text, "web-01: disk full api-7f|api-7f||");
    }

    #[test]
    fn from_config_accepts_valerter_filters_on_log_fields() {
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.body_template =
            Some("{{ log.host | mdv2_escape }} {{ log.msg | md_escape | upper }}".to_string());
        let notifier = TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        let mut alert = sample_alert("T", "b");
        alert.log =
            AlertPayload::log_from_fields(&serde_json::json!({"host": "a.b", "msg": "x_y"}));

        let (text, _) = notifier.prepare_text(&alert).unwrap();

        assert_eq!(text, r"a\.b X\_Y");
    }

    #[test]
    fn debug_impl_does_not_leak_token_or_endpoint() {
        let client = reqwest::Client::new();
        let mut cfg = config_with(vec!["-100".to_string()]);
        cfg.bot_token = SecretString::new("SUPER_SECRET_TOKEN".to_string());
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
            parse_mode: Some("HTML"),
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
        cfg.bot_token = SecretString::new("   ".to_string());
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
    async fn configured_lowercase_parse_mode_is_sent_in_canonical_form() {
        // `from_config` targets api.telegram.org: build the notifier from the
        // configuration, then point it at wiremock (the Bot API endpoint is
        // not configurable, so this cannot live in tests/integration_notify.rs).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/botTESTTOKEN/sendMessage"))
            .and(body_partial_json(
                serde_json::json!({ "parse_mode": "HTML" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = config_with(vec!["-100A".to_string()]);
        cfg.parse_mode = Some("html".to_string());
        let mut notifier =
            TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        notifier.endpoint = SecretString::new(format!("{}/botTESTTOKEN/sendMessage", server.uri()));

        notifier
            .send(&sample_alert("hi", "body"))
            .await
            .expect("should succeed");
        server.verify().await;
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
                    ResponseTemplate::new(400).set_body_string(
                        "{\"ok\":false,\"description\":\"Bad Request: chat not found\"}",
                    )
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

        // 1 success + 2 permanent failures. `chat not found` is not a markup
        // error: no plain-text resend, no retry: 1 + 2 = 3 requests.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    #[serial]
    async fn send_all_chats_permanent_failure_returns_err() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(
                    "{\"ok\":false,\"description\":\"Bad Request: chat not found\"}",
                ),
            )
            // One request per chat: `chat not found` is not resent.
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

    // ── Plain-text fallback on HTML rejection ────────────────────────────

    /// Bot API body of a 400 caused by malformed HTML markup.
    const ENTITY_ERROR_BODY: &str = "{\"ok\":false,\"error_code\":400,\"description\":\
        \"Bad Request: can't parse entities: Unclosed start tag at byte offset 4090\"}";

    /// Mount a responder answering the given `(status, body)` pairs in order
    /// (the last one repeats) and return the notifier pointed at it.
    async fn scripted_responses(
        server: &MockServer,
        responses: Vec<(u16, &'static str)>,
        parse_mode: &str,
    ) -> TelegramNotifier {
        let calls = Arc::new(AtomicU32::new(0));
        Mock::given(method("POST"))
            .respond_with(move |_req: &wiremock::Request| {
                let n = calls.fetch_add(1, Ordering::SeqCst) as usize;
                let (status, body) = responses[n.min(responses.len() - 1)];
                ResponseTemplate::new(status).set_body_string(body)
            })
            .mount(server)
            .await;
        let mut notifier = test_notifier(server, vec!["-100A".to_string()]);
        notifier.parse_mode = parse_mode.to_string();
        notifier
    }

    /// Like [`scripted_responses`], with `{"ok":true}` for a 200 and a
    /// realistic `can't parse entities` body for any other status.
    async fn scripted_notifier(
        server: &MockServer,
        statuses: &'static [u16],
        parse_mode: &str,
    ) -> TelegramNotifier {
        let responses: Vec<(u16, &'static str)> = statuses
            .iter()
            .map(|&status| {
                (
                    status,
                    if status == 200 {
                        "{\"ok\":true}"
                    } else {
                        ENTITY_ERROR_BODY
                    },
                )
            })
            .collect();
        scripted_responses(server, responses, parse_mode).await
    }

    #[tokio::test]
    #[serial]
    async fn html_400_other_than_entity_parse_error_is_not_resent() {
        for body in [
            "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: chat not found\"}",
            "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: message text is empty\"}",
            "",
            "not json",
        ] {
            let server = MockServer::start().await;
            let responses = vec![(400, body), (200, "{\"ok\":true}")];
            let notifier = scripted_responses(&server, responses, "HTML").await;

            let err = notifier
                .send_to_chat(&sample_alert("hi", "body"), "-100A", "text")
                .await
                .unwrap_err();

            assert!(
                matches!(&err, NotifyError::SendFailed(msg) if msg == "client error: 400 Bad Request"),
                "{body}: unexpected error: {err:?}"
            );
            assert_eq!(request_bodies(&server).await.len(), 1, "{body}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn entity_parse_error_is_matched_case_insensitively() {
        let server = MockServer::start().await;
        let notifier = scripted_responses(
            &server,
            vec![
                (
                    400,
                    "{\"ok\":false,\"error_code\":400,\"description\":\
                     \"Bad Request: Can't Parse Entities: unsupported start tag\"}",
                ),
                (200, "{\"ok\":true}"),
            ],
            "HTML",
        )
        .await;

        notifier.send(&sample_alert("hi", "body")).await.unwrap();

        assert_eq!(request_bodies(&server).await.len(), 2);
    }

    async fn request_bodies(server: &MockServer) -> Vec<serde_json::Value> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    #[tokio::test]
    #[serial]
    async fn html_400_is_resent_once_as_plain_text() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 200], "HTML").await;

        notifier
            .send(&sample_alert("hi", "a < b"))
            .await
            .expect("plain-text resend should succeed");

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0]["parse_mode"], "HTML");
        assert!(bodies[1].get("parse_mode").is_none());
        assert_eq!(bodies[0]["text"], bodies[1]["text"]);
        assert_eq!(bodies[0]["chat_id"], bodies[1]["chat_id"]);
    }

    #[tokio::test]
    #[serial]
    async fn html_parse_mode_is_matched_case_insensitively() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 200], "html").await;

        notifier.send(&sample_alert("hi", "body")).await.unwrap();

        assert_eq!(request_bodies(&server).await.len(), 2);
    }

    #[tokio::test]
    #[serial]
    async fn plain_text_resend_rejected_fails_chat() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 400], "HTML").await;

        let err = notifier
            .send_to_chat(&sample_alert("hi", "body"), "-100A", "text")
            .await
            .unwrap_err();

        assert!(
            matches!(&err, NotifyError::SendFailed(msg) if msg == "client error: 400 Bad Request"),
            "unexpected error: {err:?}"
        );
        assert_eq!(request_bodies(&server).await.len(), 2);
    }

    #[tokio::test]
    #[serial]
    async fn markdown_400_is_not_resent() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 200], "MarkdownV2").await;

        assert!(notifier.send(&sample_alert("hi", "body")).await.is_err());
        assert_eq!(request_bodies(&server).await.len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn html_403_is_not_resent() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[403, 200], "HTML").await;

        assert!(notifier.send(&sample_alert("hi", "body")).await.is_err());
        assert_eq!(request_bodies(&server).await.len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn plain_text_resend_follows_retry_policy() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 500, 200], "HTML").await;

        notifier
            .send(&sample_alert("hi", "body"))
            .await
            .expect("resend should be retried after 5xx");

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies.len(), 3);
        assert!(bodies[1].get("parse_mode").is_none());
        assert!(bodies[2].get("parse_mode").is_none());
    }

    #[test]
    #[serial]
    fn truncated_html_rejected_is_delivered_as_plain_text() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let bodies = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let server = MockServer::start().await;
                let mut notifier = scripted_notifier(&server, &[400, 200], "HTML").await;
                // `<pre>` opened and never closed once the text is cut.
                notifier.set_body_template_for_tests(Some("<pre>{{ body }}</pre>"));
                let long_body = "x".repeat(TELEGRAM_TEXT_MAX_CODEPOINTS + 100);

                notifier
                    .send(&sample_alert("hi", &long_body))
                    .await
                    .expect("plain-text resend should deliver the alert");
                request_bodies(&server).await
            })
        });

        assert_eq!(bodies.len(), 2);
        assert!(bodies[1].get("parse_mode").is_none());
        let text = bodies[1]["text"].as_str().unwrap();
        assert!(text.starts_with("<pre>"));
        assert!(text.ends_with('…'));
        assert_eq!(text.chars().count(), TELEGRAM_TEXT_MAX_CODEPOINTS);

        let rendered = handle.render();
        let truncated: Vec<_> = rendered
            .lines()
            .filter(|l| l.starts_with("valerter_alerts_truncated_total{"))
            .collect();
        assert_eq!(
            truncated,
            vec![
                "valerter_alerts_truncated_total{notifier_type=\"telegram\",notifier_name=\"tg-test\"} 1"
            ]
        );
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

    // ── Per-alert counting ──────────────────────────────────────────────

    /// Send one alert to `chat_ids` against a server answering `statuses`
    /// per request (the last one repeats), under a local recorder. Returns
    /// the result, the number of requests and the rendering.
    fn send_counted(
        chat_ids: &[&str],
        statuses: &'static [u16],
        body_template: Option<&str>,
    ) -> (Result<(), NotifyError>, usize, String) {
        use crate::notify::test_metrics::run_with_recorder;

        let ((result, requests), rendered) = run_with_recorder(|| async {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicU32::new(0));
            Mock::given(method("POST"))
                .respond_with(move |_req: &wiremock::Request| {
                    let n = calls.fetch_add(1, Ordering::SeqCst) as usize;
                    let status = statuses[n.min(statuses.len() - 1)];
                    ResponseTemplate::new(status).set_body_string(match status {
                        200 => "{\"ok\":true}",
                        400 => ENTITY_ERROR_BODY,
                        _ => "{\"ok\":false,\"description\":\"Forbidden\"}",
                    })
                })
                .mount(&server)
                .await;
            let mut notifier =
                test_notifier(&server, chat_ids.iter().map(|c| c.to_string()).collect());
            notifier.set_body_template_for_tests(body_template);
            let result = notifier.send(&sample_alert("hi", "body")).await;
            (result, server.received_requests().await.unwrap().len())
        });
        (result, requests, rendered)
    }

    #[test]
    #[serial]
    fn partial_success_counts_alert_once_and_failed_chat() {
        use crate::notify::test_metrics::counter_total;

        // Chat A succeeds, chat B gets a 403 (not resent as plain text).
        let (result, _, rendered) = send_counted(&["-100A", "-100B"], &[200, 403], None);

        assert!(result.is_ok());
        for series in [
            "valerter_alerts_sent_total{rule_name=\"test_rule\",vl_source=\"vlprod\",notifier_name=\"tg-test\",notifier_type=\"telegram\"} 1",
            "valerter_telegram_chat_errors_total{rule_name=\"test_rule\",vl_source=\"vlprod\",notifier_name=\"tg-test\"} 1",
        ] {
            assert!(
                rendered.lines().any(|l| l == series),
                "missing `{series}` in:\n{rendered}"
            );
        }
        assert_eq!(counter_total(&rendered, "valerter_alerts_failed_total"), 0);
        assert_eq!(counter_total(&rendered, "valerter_notify_errors_total"), 0);
    }

    #[test]
    #[serial]
    fn three_successful_chats_count_one_sent_alert() {
        use crate::notify::test_metrics::counter_total;

        let (result, requests, rendered) = send_counted(&["-100A", "-100B", "-100C"], &[200], None);

        assert!(result.is_ok());
        assert_eq!(requests, 3);
        assert_eq!(counter_total(&rendered, "valerter_alerts_sent_total"), 1);
        assert_eq!(
            counter_total(&rendered, "valerter_telegram_chat_errors_total"),
            0
        );
    }

    #[test]
    #[serial]
    fn plain_text_resend_success_is_not_a_failure() {
        use crate::notify::test_metrics::counter_total;

        // HTML rejected with 400, then delivered as plain text.
        let (result, requests, rendered) = send_counted(&["-100A"], &[400, 200], None);

        assert!(result.is_ok());
        assert_eq!(requests, 2);
        assert_eq!(counter_total(&rendered, "valerter_alerts_sent_total"), 1);
        assert_eq!(
            counter_total(&rendered, "valerter_telegram_chat_errors_total"),
            0
        );
        assert_eq!(counter_total(&rendered, "valerter_alerts_failed_total"), 0);
    }

    #[test]
    #[serial]
    fn total_failure_counts_each_chat_and_one_failed_alert() {
        use crate::notify::test_metrics::counter_total;

        let (result, _, rendered) = send_counted(&["-100A", "-100B"], &[403], None);

        match result {
            Err(NotifyError::SendFailed(m)) => assert_eq!(m, "all chat_ids failed"),
            other => panic!("unexpected result: {other:?}"),
        }
        assert_eq!(
            counter_total(&rendered, "valerter_telegram_chat_errors_total"),
            2
        );
        for series in [
            "valerter_notify_errors_total{rule_name=\"test_rule\",vl_source=\"vlprod\",notifier_name=\"tg-test\",notifier_type=\"telegram\"} 1",
            "valerter_alerts_failed_total{rule_name=\"test_rule\",vl_source=\"vlprod\",notifier_name=\"tg-test\",notifier_type=\"telegram\"} 1",
        ] {
            assert!(
                rendered.lines().any(|l| l == series),
                "missing `{series}` in:\n{rendered}"
            );
        }
        assert_eq!(counter_total(&rendered, "valerter_alerts_sent_total"), 0);
    }

    #[test]
    #[serial]
    fn render_failure_at_send_is_counted_and_sends_nothing() {
        use crate::notify::test_metrics::counter_total;

        let (result, requests, rendered) = send_counted(
            &["-100A", "-100B"],
            &[200],
            Some("{{ body | no_such_filter }}"),
        );

        assert!(
            matches!(result, Err(NotifyError::TemplateError(_))),
            "unexpected result: {result:?}"
        );
        let message = result.unwrap_err().to_string();
        assert!(message.starts_with("template error: "), "{message}");
        assert_eq!(requests, 0, "no sendMessage request may be issued");
        assert_eq!(counter_total(&rendered, "valerter_notify_errors_total"), 1);
        assert_eq!(counter_total(&rendered, "valerter_alerts_failed_total"), 1);
        assert_eq!(counter_total(&rendered, "valerter_alerts_sent_total"), 0);
        assert_eq!(
            counter_total(&rendered, "valerter_telegram_chat_errors_total"),
            0
        );
    }

    // ── Markdown bodies (markdown-body-format) ───────────────────────────

    fn markdown_alert(title: &str, body: &str, fields: serde_json::Value) -> AlertPayload {
        AlertPayload {
            message: crate::template::render_test_message(
                title,
                body,
                crate::config::BodyFormat::Markdown,
                &fields,
            ),
            ..sample_alert("", "")
        }
    }

    #[tokio::test]
    #[serial]
    async fn markdown_body_with_default_template() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[200], "HTML").await;

        notifier
            .send(&markdown_alert(
                "Disk",
                "**{{ host }}** < 10%",
                serde_json::json!({"host": "a_b"}),
            ))
            .await
            .unwrap();

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies[0]["text"], "<b>Disk</b>\n<b>a_b</b> &lt; 10%");
        assert_eq!(bodies[0]["parse_mode"], "HTML");
    }

    #[tokio::test]
    #[serial]
    async fn markdown_body_in_markdownv2_is_plain_text() {
        let server = MockServer::start().await;
        let mut cfg = config_with(vec!["-100A".to_string()]);
        cfg.parse_mode = Some("MarkdownV2".to_string());
        cfg.body_template = Some("{{ body | mdv2_escape }}".to_string());
        let mut notifier =
            TelegramNotifier::from_config("tg", &cfg, reqwest::Client::new()).unwrap();
        assert_eq!(notifier.output_format(), OutputFormat::Plain);
        notifier.endpoint = SecretString::new(format!("{}/botTESTTOKEN/sendMessage", server.uri()));
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .mount(&server)
            .await;

        notifier
            .send(&markdown_alert(
                "t",
                "**{{ v }}**",
                serde_json::json!({"v": 1.5}),
            ))
            .await
            .unwrap();

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies[0]["text"], r"1\.5");
        assert_eq!(bodies[0]["parse_mode"], "MarkdownV2");
    }

    #[tokio::test]
    #[serial]
    async fn text_body_with_default_template_is_unchanged() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[200], "HTML").await;

        notifier
            .send(&sample_alert("Disk", "**a_b** < 10%"))
            .await
            .unwrap();

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies[0]["text"], "<b>Disk</b>\n**a_b** &lt; 10%");
    }

    #[tokio::test]
    #[serial]
    async fn long_markdown_body_is_truncated_then_resent_as_plain_text() {
        let server = MockServer::start().await;
        let notifier = scripted_notifier(&server, &[400, 200], "HTML").await;
        let long = "x".repeat(TELEGRAM_TEXT_MAX_CODEPOINTS);

        notifier
            .send(&markdown_alert(
                "t",
                "**{{ v }}**",
                serde_json::json!({"v": long}),
            ))
            .await
            .expect("plain-text resend should deliver the alert");

        let bodies = request_bodies(&server).await;
        assert_eq!(bodies.len(), 2);
        let text = bodies[0]["text"].as_str().unwrap();
        assert!(text.starts_with("<b>t</b>\n<b>xxx"), "{text}");
        assert!(text.ends_with('…'));
        assert_eq!(text.chars().count(), TELEGRAM_TEXT_MAX_CODEPOINTS);
        assert!(bodies[1].get("parse_mode").is_none());
        assert_eq!(bodies[0]["text"], bodies[1]["text"]);
    }

    #[test]
    fn markdown_fallback_message_is_escaped_by_the_default_template() {
        let mut alert = sample_alert("", "");
        alert.message = crate::template::TemplateEngine::new(std::collections::HashMap::from([(
            "t".to_string(),
            crate::config::CompiledTemplate {
                title: "T".to_string(),
                body: "{{ x | nosuchfilter }}".to_string(),
                email_body_html: None,
                accent_color: None,
                body_format: crate::config::BodyFormat::Markdown,
            },
        )]))
        .render_with_fallback("t", &serde_json::json!({}), "r", "vl");
        alert.message.body.push_str(" <x> **y**");

        let template = compile_body_template("tg", None).unwrap();
        let text = render_body_template(&template, &alert, OutputFormat::TelegramHtml).unwrap();
        assert!(text.contains("Template render failed"), "{text}");
        assert!(text.ends_with("&lt;x&gt; **y**"), "{text}");
    }
}
