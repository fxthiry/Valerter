// src/lib.rs
//! Valerter - Real-time alerting from VictoriaLogs to Mattermost.

pub mod cli;
pub mod config;
pub mod error;

// Re-export commonly used types
pub use cli::LogFormat;
// Autres modules seront ajoutes dans les stories suivantes:
// pub mod stream_buffer;
// pub mod tail;
// pub mod parser;
// pub mod throttle;
// pub mod template;
// pub mod notify;
// pub mod metrics;
