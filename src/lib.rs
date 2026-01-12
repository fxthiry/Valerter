// src/lib.rs
//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod metrics;
pub mod notify;
pub mod parser;
pub mod stream_buffer;
pub mod tail;
pub mod template;
pub mod throttle;

// Re-export commonly used types
pub use cli::LogFormat;
pub use engine::RuleEngine;
pub use metrics::{MetricsServer, register_metric_descriptions};
pub use notify::{
    backoff_delay, AlertPayload, MattermostNotifier, Notifier, NotificationQueue,
    NotificationWorker, NotifierRegistry, DEFAULT_QUEUE_CAPACITY,
};
pub use parser::{RuleParser, record_parse_error};
pub use stream_buffer::StreamBuffer;
pub use template::{RenderedMessage, TemplateEngine};
pub use throttle::{ThrottleResult, Throttler};
