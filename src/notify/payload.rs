//! Alert payload for notification system.

use crate::template::RenderedMessage;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;

/// Payload ready to be sent to a notifier.
///
/// Contains all fields needed to send a notification.
/// Shared between destination queues through `Arc` (queued once, not copied).
///
/// `Debug` is implemented by hand: it shows how many event fields `log`
/// holds, never their values (they may carry secrets).
#[derive(Clone)]
pub struct AlertPayload {
    /// Rendered message content (title, body, accent_color).
    pub message: RenderedMessage,
    /// Rule name for tracing and metrics.
    pub rule_name: String,
    /// Name of the VictoriaLogs source that produced the matching event.
    /// Owned `String` (not `&str`) so it survives task lifetimes and can be
    /// cloned into notifier render contexts safely.
    pub vl_source: String,
    /// Notification destinations (notifier names).
    /// If empty, uses the default notifier.
    pub destinations: Vec<String>,
    /// Mattermost channel override of the rule (`notify.mattermost_channel`).
    /// Takes precedence over the notifier's `channel`; ignored by the other
    /// notifier types.
    pub mattermost_channel: Option<String>,
    /// Original log timestamp in ISO 8601 format (from VictoriaLogs _time field).
    /// Used for searching in VictoriaLogs.
    pub log_timestamp: String,
    /// Human-readable formatted timestamp (respects configured timezone).
    /// Format: "DD/MM/YYYY HH:MM:SS TZ" (e.g., "15/01/2026 11:49:35 CET")
    pub log_timestamp_formatted: String,
    /// Fields of the parsed event, dotted keys unflattened (the layer 1
    /// view, without the synthetic `rule_name` and `vl_source`), exposed as
    /// `log` to notifier templates. Built once per alert by
    /// [`AlertPayload::log_from_fields`]; a `minijinja::Value` is immutable
    /// and reference-counted, so notifiers share it without copying.
    pub log: minijinja::Value,
}

impl AlertPayload {
    /// Builds the [`AlertPayload::log`] value of an event: dotted keys are
    /// unflattened once (flat keys kept), then the result is converted once.
    pub fn log_from_fields(fields: &serde_json::Value) -> minijinja::Value {
        minijinja::Value::from_serialize(crate::parser::unflatten_dotted_keys(fields))
    }
}

impl std::fmt::Debug for AlertPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertPayload")
            .field("message", &self.message)
            .field("rule_name", &self.rule_name)
            .field("vl_source", &self.vl_source)
            .field("destinations", &self.destinations)
            .field("mattermost_channel", &self.mattermost_channel)
            .field("log_timestamp", &self.log_timestamp)
            .field("log_timestamp_formatted", &self.log_timestamp_formatted)
            .field("log_field_count", &self.log.len().unwrap_or(0))
            .finish()
    }
}

/// Count a permanent delivery failure of `alert` for one notifier.
///
/// Increments `valerter_notify_errors_total` and `valerter_alerts_failed_total`
/// once, with the `rule_name`, `vl_source`, `notifier_name` and
/// `notifier_type` labels. Notifiers call it for every permanent failure
/// (retries exhausted, non-retryable response, render error at send time),
/// once per alert.
pub(crate) fn record_permanent_failure(
    alert: &AlertPayload,
    notifier_name: &str,
    notifier_type: &'static str,
) {
    for name in [
        "valerter_notify_errors_total",
        "valerter_alerts_failed_total",
    ] {
        metrics::counter!(
            name,
            "rule_name" => alert.rule_name.clone(),
            "vl_source" => alert.vl_source.clone(),
            "notifier_name" => notifier_name.to_string(),
            "notifier_type" => notifier_type,
        )
        .increment(1);
    }
}

/// Format a raw ISO 8601 timestamp to human-readable format.
///
/// # Arguments
/// * `raw_timestamp` - ISO 8601 timestamp string (e.g., "2026-01-15T10:49:35.799Z")
/// * `timezone` - Timezone name (e.g., "UTC", "Europe/Paris")
///
/// # Returns
/// Formatted string like "15/01/2026 10:49:35 UTC" or "15/01/2026 11:49:35 CET"
///
/// # Note
/// - Subsecond precision is truncated to seconds for readability
/// - If timestamp parsing fails, returns the raw timestamp unchanged
/// - Timezone is validated at config load time, so invalid timezone here is unexpected
pub fn format_log_timestamp(raw_timestamp: &str, timezone: &str) -> String {
    // Parse the ISO 8601 timestamp
    let dt = match DateTime::parse_from_rfc3339(raw_timestamp) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => {
            // Fallback: return raw if parsing fails (should not happen with VictoriaLogs)
            tracing::warn!(timestamp = %raw_timestamp, "Failed to parse timestamp, using raw value");
            return raw_timestamp.to_string();
        }
    };

    // Parse timezone (validated at config time, so should always succeed)
    let tz: Tz = timezone.parse().unwrap_or_else(|_| {
        tracing::warn!(timezone = %timezone, "Invalid timezone, falling back to UTC");
        chrono_tz::UTC
    });

    // Convert to target timezone and format (truncates subsecond precision)
    let local_dt = dt.with_timezone(&tz);
    local_dt.format("%d/%m/%Y %H:%M:%S %Z").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_field_count_but_no_field_value() {
        let alert = AlertPayload {
            message: RenderedMessage {
                title: "t".to_string(),
                body: "b".to_string(),
                email_body_html: None,
                accent_color: None,
                ..Default::default()
            },
            rule_name: "r".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec![],
            mattermost_channel: None,
            log_timestamp: String::new(),
            log_timestamp_formatted: String::new(),
            log: AlertPayload::log_from_fields(&serde_json::json!({
                "_msg": "login password=hunter2",
                "password": "hunter2",
                "host": "web-01"
            })),
        };

        let debug = format!("{alert:?}");

        assert!(debug.contains("log_field_count: 3"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains("web-01"), "{debug}");
    }

    #[test]
    fn format_log_timestamp_utc() {
        let result = format_log_timestamp("2026-01-15T10:49:35.799Z", "UTC");
        assert_eq!(result, "15/01/2026 10:49:35 UTC");
    }

    #[test]
    fn format_log_timestamp_europe_paris_winter() {
        // January = CET (UTC+1)
        let result = format_log_timestamp("2026-01-15T10:00:00Z", "Europe/Paris");
        assert_eq!(result, "15/01/2026 11:00:00 CET");
    }

    #[test]
    fn format_log_timestamp_europe_paris_summer() {
        // July = CEST (UTC+2)
        let result = format_log_timestamp("2026-07-15T10:00:00Z", "Europe/Paris");
        assert_eq!(result, "15/07/2026 12:00:00 CEST");
    }

    #[test]
    fn format_log_timestamp_invalid_timestamp_returns_raw() {
        let result = format_log_timestamp("not-a-timestamp", "UTC");
        assert_eq!(result, "not-a-timestamp");
    }

    #[test]
    fn format_log_timestamp_truncates_subseconds() {
        let result = format_log_timestamp("2026-01-15T10:49:35.123456789Z", "UTC");
        assert_eq!(result, "15/01/2026 10:49:35 UTC");
    }
}
