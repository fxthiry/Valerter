// src/lib.rs
//! Valerter - Real-time alerting from VictoriaLogs to Mattermost, Telegram, email or webhooks.

pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub(crate) mod http_body;
pub mod markdown;
pub mod metrics;
pub mod notify;
pub mod parser;
pub mod preflight;
pub mod stream_buffer;
pub mod tail;
pub mod template;
pub mod throttle;

// Re-export commonly used types
pub use cli::LogFormat;
pub use engine::RuleEngine;
pub use metrics::{
    DeliverySeries, MetricsInventory, MetricsServer, NotifierSeries, RuleSourceSeries,
    build_metrics_inventory, initialize_destination_metrics, initialize_metrics,
    register_metric_descriptions,
};
pub use notify::{
    AlertPayload, DEFAULT_QUEUE_CAPACITY, DrainOutcome, MattermostNotifier, NotificationQueue,
    NotificationWorker, Notifier, NotifierRegistry, SHUTDOWN_DRAIN_TIMEOUT, await_worker_drain,
    backoff_delay,
};
pub use parser::{RuleParser, record_log_matched, record_parse_error};
pub use preflight::{PreflightError, PreflightReport, build_http_client, run_preflight};
pub use stream_buffer::StreamBuffer;
pub use template::{RenderedMessage, TemplateEngine};
pub use throttle::{ThrottleResult, Throttler};
