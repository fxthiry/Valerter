//! Notifier trait definition.

use async_trait::async_trait;

use super::AlertPayload;
use crate::config::OutputFormat;
use crate::error::NotifyError;

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
///     fn output_format(&self) -> OutputFormat { OutputFormat::Plain }
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

    /// Format in which this notifier sends the body of a Markdown alert
    /// (`format` key, or the default of its type). See
    /// [`crate::template::RenderedMessage::body_for`].
    fn output_format(&self) -> OutputFormat;

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

// Implement Debug for dyn Notifier to satisfy HashMap debug requirement
impl std::fmt::Debug for dyn Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("name", &self.name())
            .field("type", &self.notifier_type())
            .finish()
    }
}
