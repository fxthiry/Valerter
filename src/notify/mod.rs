//! Asynchronous notification system for valerter alerts.
//!
//! This module implements a modular notification system with:
//! - Abstract `Notifier` trait for different notification channels
//! - `NotifierRegistry` for managing named notifiers
//! - One bounded queue and delivery task per notifier, with Drop Oldest
//!   strategy per destination (AD-02)
//! - HTTP sending with exponential backoff retry (AD-07)

mod payload;
mod queue;
mod registry;
mod traits;

pub mod email;
pub mod mattermost;
pub mod telegram;
pub mod webhook;

// Re-exports
pub use email::EmailNotifier;
pub use mattermost::MattermostNotifier;
pub use payload::{AlertPayload, format_log_timestamp};
pub use queue::{
    DEFAULT_QUEUE_CAPACITY, DrainOutcome, NotificationQueue, NotificationWorker,
    SHUTDOWN_DRAIN_TIMEOUT, await_worker_drain, backoff_delay,
};
pub use registry::NotifierRegistry;
pub use telegram::TelegramNotifier;
pub use traits::Notifier;
pub use webhook::WebhookNotifier;

#[cfg(test)]
mod tests;
