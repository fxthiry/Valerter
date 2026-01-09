// src/lib.rs
//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

pub mod cli;
pub mod config;
pub mod error;
pub mod notify;
pub mod parser;
pub mod stream_buffer;
pub mod tail;
pub mod template;
pub mod throttle;

// Re-export commonly used types
pub use cli::LogFormat;
pub use notify::{AlertPayload, NotificationQueue, NotificationWorker, DEFAULT_QUEUE_CAPACITY};
pub use parser::{record_parse_error, RuleParser};
pub use stream_buffer::StreamBuffer;
pub use template::{RenderedMessage, TemplateEngine};
pub use throttle::{ThrottleResult, Throttler};
