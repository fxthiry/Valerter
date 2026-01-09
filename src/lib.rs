// src/lib.rs
//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

pub mod cli;
pub mod config;
pub mod error;
pub mod parser;
pub mod stream_buffer;
pub mod tail;

// Re-export commonly used types
pub use cli::LogFormat;
pub use parser::{record_parse_error, RuleParser};
pub use stream_buffer::StreamBuffer;
