//! Alert payload for notification system.

use crate::template::RenderedMessage;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;

/// Payload ready to be sent to a notifier.
///
/// Contains all fields needed to send a notification.
/// Shared between destination queues through `Arc` (queued once, not copied).
#[derive(Debug, Clone)]
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
    /// Original log timestamp in ISO 8601 format (from VictoriaLogs _time field).
    /// Used for searching in VictoriaLogs.
    pub log_timestamp: String,
    /// Human-readable formatted timestamp (respects configured timezone).
    /// Format: "DD/MM/YYYY HH:MM:SS TZ" (e.g., "15/01/2026 11:49:35 CET")
    pub log_timestamp_formatted: String,
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
