//! Centralized error types for valerter using thiserror.
//!
//! This module defines all error types used throughout the application,
//! following AD-04 architectural decision.

use thiserror::Error;

/// Errors related to configuration loading and validation.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to load config file: {0}")]
    LoadError(String),
    #[error("invalid configuration: {0}")]
    ValidationError(String),
    #[error("invalid regex pattern in rule '{rule}': {message}")]
    InvalidRegex { rule: String, message: String },
    #[error("invalid template in rule '{rule}': {message}")]
    InvalidTemplate { rule: String, message: String },
    /// Story 6.2: Error for invalid notifier configuration.
    #[error("invalid notifier '{name}': {message}")]
    InvalidNotifier { name: String, message: String },
}

/// Errors related to VictoriaLogs streaming connection.
#[derive(Error, Debug)]
pub enum StreamError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("invalid UTF-8 in stream: {0}")]
    Utf8Error(String),
}

/// Errors related to log line parsing (regex and JSON extraction).
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("regex did not match")]
    NoMatch,
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
}

/// Errors related to Mattermost notification sending.
#[derive(Error, Debug)]
pub enum NotifyError {
    #[error("failed to send notification: {0}")]
    SendFailed(String),
    #[error("max retries exceeded")]
    MaxRetriesExceeded,
}

/// Errors related to template rendering.
#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("template '{name}' not found")]
    NotFound { name: String },
    #[error("template render failed: {message}")]
    RenderFailed { message: String },
}

/// Errors related to notification queue operations.
#[derive(Error, Debug)]
pub enum QueueError {
    #[error("notification queue closed")]
    Closed,
}

/// Errors related to rule execution.
#[derive(Error, Debug)]
pub enum RuleError {
    #[error("stream error: {0}")]
    Stream(#[from] StreamError),
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("template error: {0}")]
    Template(#[from] TemplateError),
    #[error("queue error: {0}")]
    Queue(#[from] QueueError),
    #[error("rule panicked")]
    Panic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_display() {
        let err = ConfigError::LoadError("file not found".to_string());
        assert_eq!(
            err.to_string(),
            "failed to load config file: file not found"
        );
    }

    #[test]
    fn config_error_validation_display() {
        let err = ConfigError::ValidationError("missing field".to_string());
        assert_eq!(err.to_string(), "invalid configuration: missing field");
    }

    #[test]
    fn config_error_invalid_regex_display() {
        let err = ConfigError::InvalidRegex {
            rule: "my_rule".to_string(),
            message: "unclosed group".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "invalid regex pattern in rule 'my_rule': unclosed group"
        );
    }

    #[test]
    fn config_error_invalid_notifier_display() {
        let err = ConfigError::InvalidNotifier {
            name: "mattermost-infra".to_string(),
            message: "missing webhook_url".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "invalid notifier 'mattermost-infra': missing webhook_url"
        );
    }

    #[test]
    fn stream_error_display() {
        let err = StreamError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "connection failed: timeout");

        let err = StreamError::Utf8Error("invalid sequence".to_string());
        assert_eq!(err.to_string(), "invalid UTF-8 in stream: invalid sequence");
    }

    #[test]
    fn parse_error_display() {
        let err = ParseError::NoMatch;
        assert_eq!(err.to_string(), "regex did not match");

        let err = ParseError::InvalidJson("unexpected token".to_string());
        assert_eq!(err.to_string(), "invalid JSON: unexpected token");
    }

    #[test]
    fn notify_error_display() {
        let err = NotifyError::SendFailed("network error".to_string());
        assert_eq!(
            err.to_string(),
            "failed to send notification: network error"
        );

        let err = NotifyError::MaxRetriesExceeded;
        assert_eq!(err.to_string(), "max retries exceeded");
    }

    #[test]
    fn template_error_display() {
        let err = TemplateError::NotFound {
            name: "alert_template".to_string(),
        };
        assert_eq!(err.to_string(), "template 'alert_template' not found");

        let err = TemplateError::RenderFailed {
            message: "undefined variable".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "template render failed: undefined variable"
        );
    }

    #[test]
    fn queue_error_display() {
        let err = QueueError::Closed;
        assert_eq!(err.to_string(), "notification queue closed");
    }

    #[test]
    fn rule_error_display() {
        let err = RuleError::Panic;
        assert_eq!(err.to_string(), "rule panicked");

        let err = RuleError::Stream(StreamError::ConnectionFailed("network error".to_string()));
        assert_eq!(
            err.to_string(),
            "stream error: connection failed: network error"
        );

        let err = RuleError::Parse(ParseError::NoMatch);
        assert_eq!(err.to_string(), "parse error: regex did not match");

        let err = RuleError::Queue(QueueError::Closed);
        assert_eq!(err.to_string(), "queue error: notification queue closed");
    }
}
