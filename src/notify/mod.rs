//! Asynchronous notification system for valerter alerts.
//!
//! This module implements a modular notification system with:
//! - Abstract `Notifier` trait for different notification channels
//! - `NotifierRegistry` for managing named notifiers
//! - Bounded notification queue with Drop Oldest strategy (AD-02)
//! - HTTP sending with exponential backoff retry (AD-07)

mod payload;
mod queue;
mod registry;
mod traits;

pub mod email;
pub mod mattermost;
pub mod webhook;

// Re-exports
pub use email::EmailNotifier;
pub use mattermost::MattermostNotifier;
pub use payload::{AlertPayload, format_log_timestamp};
pub use queue::{DEFAULT_QUEUE_CAPACITY, NotificationQueue, NotificationWorker, backoff_delay};
pub use registry::NotifierRegistry;
pub use traits::Notifier;
pub use webhook::WebhookNotifier;

#[cfg(test)]
mod tests;
