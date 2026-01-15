//! Alert payload for notification system.

use crate::template::RenderedMessage;

/// Payload ready to be sent to a notifier.
///
/// Contains all fields needed to send a notification.
/// Must implement `Clone` as required by `broadcast::Sender`.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    /// Rendered message content (title, body, accent_color).
    pub message: RenderedMessage,
    /// Rule name for tracing and metrics.
    pub rule_name: String,
    /// Notification destinations (notifier names).
    /// If empty, uses the default notifier.
    pub destinations: Vec<String>,
}
