//! VictoriaLogs streaming tail client.
//!
//! This module handles streaming connections to VictoriaLogs `/select/logsql/tail`
//! endpoint, including reconnection with exponential backoff.
//!
//! # Architecture Decisions
//!
//! - AD-03: Fan-out model (1 connection per rule) is acceptable for MVP
//! - AD-07: Manual exponential backoff (base=1s, max=60s)
//!
//! # Example
//!
//! ```no_run
//! use valerter::tail::{TailConfig, TailClient};
//!
//! # async fn example() -> Result<(), valerter::error::StreamError> {
//! let config = TailConfig {
//!     base_url: "http://localhost:9428".to_string(),
//!     query: "_stream:myapp".to_string(),
//!     start: None,
//!     basic_auth: None,
//!     headers: None,
//!     tls: None,
//! };
//!
//! let mut client = TailClient::new(config)?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::Client;
use tracing::{info, warn};

use crate::config::{BasicAuthConfig, SecretString, TlsConfig};
use crate::error::StreamError;
use crate::stream_buffer::StreamBuffer;

// Note: No read_timeout - VictoriaLogs tail endpoint doesn't send keepalives,
// so we rely on CancellationToken for shutdown. Connection health is implicit
// (if VL dies, the stream ends and we reconnect via backoff).

/// Base delay for exponential backoff (AD-07).
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Maximum delay for exponential backoff (AD-07).
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Configuration for connecting to VictoriaLogs tail endpoint.
#[derive(Debug, Clone)]
pub struct TailConfig {
    /// Base URL of VictoriaLogs (e.g., "http://localhost:9428").
    pub base_url: String,
    /// LogsQL query to execute.
    pub query: String,
    /// Optional start timestamp (e.g., "now-1h").
    pub start: Option<String>,
    /// Optional Basic Auth credentials.
    pub basic_auth: Option<BasicAuthConfig>,
    /// Optional custom headers (for tokens, API keys, etc.).
    pub headers: Option<HashMap<String, SecretString>>,
    /// Optional TLS configuration.
    pub tls: Option<TlsConfig>,
}

/// Client for streaming logs from VictoriaLogs tail endpoint.
///
/// Handles connection establishment, reconnection with exponential backoff,
/// and UTF-8 safe buffering via `StreamBuffer`.
pub struct TailClient {
    config: TailConfig,
    client: Client,
    buffer: StreamBuffer,
}

impl TailClient {
    /// Create a new TailClient with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `StreamError::ConnectionFailed` if the HTTP client cannot be built.
    pub fn new(config: TailConfig) -> Result<Self, StreamError> {
        let mut builder = Client::builder();

        // Configure TLS verification (AC #6, #7)
        if let Some(ref tls) = config.tls
            && !tls.verify
        {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder
            .build()
            .map_err(|e| StreamError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            config,
            client,
            buffer: StreamBuffer::new(),
        })
    }

    /// Build a request with all configured auth and headers.
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .get(url)
            .header("Accept", "application/x-ndjson")
            .header("Connection", "keep-alive");

        // Add Basic Auth if configured (AC #1)
        if let Some(ref auth) = self.config.basic_auth {
            request = request.basic_auth(&auth.username, Some(auth.password.expose()));
        }

        // Add custom headers if configured (AC #3, #5)
        if let Some(ref headers) = self.config.headers {
            for (name, value) in headers {
                request = request.header(name, value.expose());
            }
        }

        request
    }

    /// Build the full URL for the VictoriaLogs tail endpoint.
    pub fn build_url(&self) -> String {
        let mut url = format!(
            "{}/select/logsql/tail?query={}",
            self.config.base_url,
            urlencoding::encode(&self.config.query)
        );

        if let Some(ref start) = self.config.start {
            url.push_str("&start=");
            url.push_str(&urlencoding::encode(start));
        }

        url
    }

    /// Connect to VictoriaLogs and stream log lines.
    ///
    /// This method establishes a streaming HTTP connection to the VictoriaLogs
    /// tail endpoint and processes incoming chunks through the `StreamBuffer`
    /// to handle UTF-8 boundaries correctly.
    ///
    /// # Arguments
    ///
    /// * `rule_name` - Name of the rule for tracing and metrics
    /// * `on_reconnect` - Callback invoked when connection is restored after failure (FR7)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<String>)` with complete log lines, or an error if the
    /// connection fails or encounters invalid UTF-8.
    ///
    /// # Errors
    ///
    /// - `StreamError::ConnectionFailed` if HTTP connection fails
    /// - `StreamError::Utf8Error` if stream contains invalid UTF-8
    pub async fn connect_and_receive(
        &mut self,
        rule_name: &str,
    ) -> Result<Vec<String>, StreamError> {
        let url = self.build_url();

        let response = self
            .build_request(&url)
            .send()
            .await
            .map_err(|e| StreamError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(StreamError::ConnectionFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        // Get the bytes stream
        let mut stream = response.bytes_stream();

        // Collect lines from this connection attempt
        let mut all_lines = Vec::new();

        // Process chunks as they arrive
        while let Some(chunk_result) = stream.next().await {
            let chunk: Bytes =
                chunk_result.map_err(|e| StreamError::ConnectionFailed(e.to_string()))?;

            // Push chunk to buffer and extract complete lines
            self.buffer.push(&chunk);
            let lines = self.buffer.drain_complete_lines()?;

            for line in lines {
                if !line.is_empty() {
                    info!(rule_name = %rule_name, "Received log line");
                    all_lines.push(line);
                }
            }
        }

        Ok(all_lines)
    }

    /// Get a reference to the internal buffer for testing.
    #[cfg(test)]
    pub fn buffer(&self) -> &StreamBuffer {
        &self.buffer
    }

    /// Stream logs with automatic reconnection on failure.
    ///
    /// This method implements the full reconnection pattern with exponential backoff
    /// as specified in AD-07. It will retry indefinitely on connection failures,
    /// calling the provided callback when connection is restored after a failure.
    ///
    /// # Arguments
    ///
    /// * `rule_name` - Name of the rule for tracing and metrics
    /// * `on_reconnect` - Optional callback invoked when connection is restored after failure (FR7)
    /// * `line_handler` - Async function called for each received log line
    ///
    /// # Errors
    ///
    /// - `StreamError::Utf8Error` if stream contains invalid UTF-8 (not retried)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use valerter::tail::{TailConfig, TailClient};
    ///
    /// # async fn example() -> Result<(), valerter::error::StreamError> {
    /// let config = TailConfig {
    ///     base_url: "http://localhost:9428".to_string(),
    ///     query: "_stream:myapp".to_string(),
    ///     start: None,
    ///     basic_auth: None,
    ///     headers: None,
    ///     tls: None,
    /// };
    ///
    /// let mut client = TailClient::new(config)?;
    ///
    /// // Stream with reconnection - runs until cancelled
    /// client.stream_with_reconnect(
    ///     "my_rule",
    ///     None,
    ///     |line| async move {
    ///         println!("Received: {}", line);
    ///         Ok(())
    ///     },
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stream_with_reconnect<F, Fut>(
        &mut self,
        rule_name: &str,
        on_reconnect: Option<&dyn ReconnectCallback>,
        mut line_handler: F,
    ) -> Result<(), StreamError>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<(), StreamError>>,
    {
        let mut attempt: u32 = 0;
        let mut had_failure = false;

        loop {
            let url = self.build_url();
            info!(rule_name = %rule_name, url = %url, "Connecting to VictoriaLogs tail endpoint");

            // Start timing for query_duration metric
            let request_start = Instant::now();
            let connect_result = self.build_request(&url).send().await;

            let response = match connect_result {
                Ok(resp) if resp.status().is_success() => {
                    info!(rule_name = %rule_name, status = %resp.status(), "Connection successful, starting to stream");
                    // Connection successful - mark VictoriaLogs as up
                    metrics::gauge!(
                        "valerter_victorialogs_up",
                        "rule_name" => rule_name.to_string()
                    )
                    .set(1.0);

                    if had_failure {
                        // We recovered from a failure
                        log_reconnection_success(rule_name);
                        if let Some(callback) = on_reconnect {
                            callback.on_reconnect(rule_name);
                        }
                    }
                    attempt = 0;
                    had_failure = false;
                    resp
                }
                Ok(resp) => {
                    // HTTP error (4xx, 5xx) - mark VictoriaLogs as down
                    metrics::gauge!(
                        "valerter_victorialogs_up",
                        "rule_name" => rule_name.to_string()
                    )
                    .set(0.0);

                    had_failure = true;
                    let delay = backoff_delay_default(attempt);
                    log_reconnection_attempt(rule_name, attempt, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    warn!(
                        rule_name = %rule_name,
                        status = %resp.status(),
                        "HTTP error from VictoriaLogs"
                    );
                    continue;
                }
                Err(e) => {
                    // Connection error - mark VictoriaLogs as down
                    metrics::gauge!(
                        "valerter_victorialogs_up",
                        "rule_name" => rule_name.to_string()
                    )
                    .set(0.0);

                    had_failure = true;
                    let delay = backoff_delay_default(attempt);
                    log_reconnection_attempt(rule_name, attempt, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    warn!(rule_name = %rule_name, error = %e, "Connection failed");
                    continue;
                }
            };

            // Process the stream
            let mut stream = response.bytes_stream();
            let mut first_chunk_received = false;

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        // Record query duration on first chunk only
                        if !first_chunk_received {
                            first_chunk_received = true;
                            let duration = request_start.elapsed();
                            metrics::histogram!(
                                "valerter_query_duration_seconds",
                                "rule_name" => rule_name.to_string()
                            )
                            .record(duration.as_secs_f64());
                        }

                        // Update last query timestamp on each successful chunk
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::ZERO)
                            .as_secs_f64();
                        metrics::gauge!(
                            "valerter_last_query_timestamp",
                            "rule_name" => rule_name.to_string()
                        )
                        .set(now);

                        self.buffer.push(&chunk);
                        let lines = self.buffer.drain_complete_lines()?;

                        for line in lines {
                            if !line.is_empty() {
                                info!(rule_name = %rule_name, "Received log line");
                                line_handler(line).await?;
                            }
                        }
                    }
                    Err(e) => {
                        // Stream error - mark VictoriaLogs as down and reconnect
                        metrics::gauge!(
                            "valerter_victorialogs_up",
                            "rule_name" => rule_name.to_string()
                        )
                        .set(0.0);

                        had_failure = true;
                        let delay = backoff_delay_default(attempt);
                        log_reconnection_attempt(rule_name, attempt, delay);
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        warn!(rule_name = %rule_name, error = %e, "Stream read error");
                        break; // Break inner loop to reconnect
                    }
                }
            }

            // Stream ended (server closed connection) - reconnect
            if !had_failure {
                // Normal stream end, not a failure - still need to reconnect
                info!(rule_name = %rule_name, "Stream ended, reconnecting");
            }
            had_failure = true;
        }
    }
}

/// Calculate exponential backoff delay.
///
/// Implements AD-07: base=1s, max=60s with exponential growth.
///
/// # Arguments
///
/// * `attempt` - The current retry attempt number (0-indexed)
/// * `base` - Base delay duration
/// * `max` - Maximum delay duration cap
///
/// # Returns
///
/// The delay duration for the given attempt, capped at `max`.
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let multiplier = 2_u32.saturating_pow(attempt);
    let delay = base.saturating_mul(multiplier);
    std::cmp::min(delay, max)
}

/// Calculate exponential backoff delay using default VictoriaLogs parameters.
///
/// Uses BACKOFF_BASE (1s) and BACKOFF_MAX (60s) as per AD-07.
pub fn backoff_delay_default(attempt: u32) -> Duration {
    backoff_delay(attempt, BACKOFF_BASE, BACKOFF_MAX)
}

/// Trait for reconnection callbacks.
///
/// Implementors receive notification when a connection is restored after failure.
/// This is used to reset throttle caches as per FR7.
pub trait ReconnectCallback: Send + Sync {
    /// Called when connection is restored after failure.
    fn on_reconnect(&self, rule_name: &str);
}

/// Log the reconnection attempt with proper tracing.
///
/// # Arguments
///
/// * `rule_name` - Name of the rule for the tracing span
/// * `attempt` - Current retry attempt number
/// * `delay` - Delay before next retry
pub fn log_reconnection_attempt(rule_name: &str, attempt: u32, delay: Duration) {
    warn!(
        rule_name = %rule_name,
        attempt = attempt,
        delay_secs = delay.as_secs(),
        "Connection failed, retrying"
    );

    // Increment reconnection metric
    metrics::counter!("valerter_reconnections_total", "rule_name" => rule_name.to_string())
        .increment(1);
}

/// Log successful reconnection after failure.
///
/// # Arguments
///
/// * `rule_name` - Name of the rule for the tracing span
pub fn log_reconnection_success(rule_name: &str) {
    info!(
        rule_name = %rule_name,
        "Connection restored, throttle cache reset signal sent"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a simple TailConfig for testing
    fn test_config(base_url: &str, query: &str, start: Option<&str>) -> TailConfig {
        TailConfig {
            base_url: base_url.to_string(),
            query: query.to_string(),
            start: start.map(|s| s.to_string()),
            basic_auth: None,
            headers: None,
            tls: None,
        }
    }

    // ==========================================================================
    // Task 7.1: Test URL construction with LogsQL query
    // ==========================================================================

    #[test]
    fn test_build_url_basic() {
        let config = test_config("http://localhost:9428", "_stream:myapp", None);

        let client = TailClient::new(config).unwrap();
        let url = client.build_url();

        assert_eq!(
            url,
            "http://localhost:9428/select/logsql/tail?query=_stream%3Amyapp"
        );
    }

    #[test]
    fn test_build_url_with_start() {
        let config = test_config("http://localhost:9428", "_stream:myapp", Some("now-1h"));

        let client = TailClient::new(config).unwrap();
        let url = client.build_url();

        assert_eq!(
            url,
            "http://localhost:9428/select/logsql/tail?query=_stream%3Amyapp&start=now-1h"
        );
    }

    #[test]
    fn test_build_url_complex_query() {
        let config = test_config(
            "http://vlogs.local:9428",
            r#"_stream:{app="myapp"} | level:error"#,
            None,
        );

        let client = TailClient::new(config).unwrap();
        let url = client.build_url();

        // Verify URL encoding of special characters
        assert!(url.contains("query="));
        assert!(url.contains("%3A")); // : encoded
        assert!(url.contains("%7B")); // { encoded
        assert!(url.contains("%7D")); // } encoded
        assert!(url.contains("%3D")); // = encoded
        assert!(url.contains("%22")); // " encoded
        assert!(url.contains("%7C")); // | encoded
    }

    #[test]
    fn test_build_url_with_spaces_in_query() {
        let config = test_config(
            "http://localhost:9428",
            "level:error message contains test",
            None,
        );

        let client = TailClient::new(config).unwrap();
        let url = client.build_url();

        // Spaces should be encoded as %20
        assert!(url.contains("%20"));
    }

    // ==========================================================================
    // Task 7.2: Test backoff delay calculation
    // ==========================================================================

    #[test]
    fn test_backoff_delay_attempt_0() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(0, base, max);
        assert_eq!(delay, Duration::from_secs(1)); // 1 * 2^0 = 1
    }

    #[test]
    fn test_backoff_delay_attempt_1() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(1, base, max);
        assert_eq!(delay, Duration::from_secs(2)); // 1 * 2^1 = 2
    }

    #[test]
    fn test_backoff_delay_attempt_2() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(2, base, max);
        assert_eq!(delay, Duration::from_secs(4)); // 1 * 2^2 = 4
    }

    #[test]
    fn test_backoff_delay_attempt_3() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(3, base, max);
        assert_eq!(delay, Duration::from_secs(8)); // 1 * 2^3 = 8
    }

    #[test]
    fn test_backoff_delay_attempt_4() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(4, base, max);
        assert_eq!(delay, Duration::from_secs(16)); // 1 * 2^4 = 16
    }

    #[test]
    fn test_backoff_delay_attempt_5() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let delay = backoff_delay(5, base, max);
        assert_eq!(delay, Duration::from_secs(32)); // 1 * 2^5 = 32
    }

    // ==========================================================================
    // Task 7.3: Test backoff does not exceed max (60s)
    // ==========================================================================

    #[test]
    fn test_backoff_delay_capped_at_max() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        // attempt 6: 1 * 2^6 = 64, should be capped at 60
        let delay = backoff_delay(6, base, max);
        assert_eq!(delay, Duration::from_secs(60));

        // attempt 7: 1 * 2^7 = 128, should be capped at 60
        let delay = backoff_delay(7, base, max);
        assert_eq!(delay, Duration::from_secs(60));

        // attempt 10: 1 * 2^10 = 1024, should be capped at 60
        let delay = backoff_delay(10, base, max);
        assert_eq!(delay, Duration::from_secs(60));
    }

    #[test]
    fn test_backoff_delay_very_high_attempt() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        // Even with very high attempt numbers, should be capped at max
        let delay = backoff_delay(100, base, max);
        assert_eq!(delay, Duration::from_secs(60));
    }

    #[test]
    fn test_backoff_delay_default_uses_correct_params() {
        // Verify default function uses BACKOFF_BASE and BACKOFF_MAX
        let delay_default = backoff_delay_default(0);
        let delay_explicit = backoff_delay(0, BACKOFF_BASE, BACKOFF_MAX);

        assert_eq!(delay_default, delay_explicit);
        assert_eq!(delay_default, Duration::from_secs(1));
    }

    #[test]
    fn test_backoff_delay_default_caps_correctly() {
        let delay = backoff_delay_default(10);
        assert_eq!(delay, Duration::from_secs(60));
    }

    // ==========================================================================
    // Task 7.4: Test integration with StreamBuffer (chunk -> lines)
    // ==========================================================================

    #[test]
    fn test_client_has_buffer() {
        let config = test_config("http://localhost:9428", "_stream:test", None);

        let client = TailClient::new(config).unwrap();

        // Buffer should be empty initially
        assert!(client.buffer().is_empty());
    }

    #[test]
    fn test_tail_config_clone() {
        let config = test_config("http://localhost:9428", "_stream:test", Some("now-1h"));

        let cloned = config.clone();

        assert_eq!(config.base_url, cloned.base_url);
        assert_eq!(config.query, cloned.query);
        assert_eq!(config.start, cloned.start);
    }

    #[test]
    fn test_tail_config_debug() {
        let config = test_config("http://localhost:9428", "_stream:test", None);

        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("TailConfig"));
        assert!(debug_str.contains("localhost:9428"));
        assert!(debug_str.contains("_stream:test"));
    }

    // ==========================================================================
    // Additional unit tests for constants and types
    // ==========================================================================

    #[test]
    fn test_constants_values() {
        assert_eq!(BACKOFF_BASE, Duration::from_secs(1));
        assert_eq!(BACKOFF_MAX, Duration::from_secs(60));
    }

    #[test]
    fn test_client_creation_success() {
        let config = test_config("http://localhost:9428", "test", None);

        let result = TailClient::new(config);
        assert!(result.is_ok());
    }

    // Test that StreamBuffer integration works correctly
    #[test]
    fn test_buffer_integration_simulation() {
        // Simulate what happens when chunks are received
        let mut buffer = StreamBuffer::new();

        // Simulate receiving chunked JSON lines like VictoriaLogs sends
        buffer.push(br#"{"_msg":"test1"}"#);
        buffer.push(b"\n");

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], r#"{"_msg":"test1"}"#);

        // Simulate multiple lines in one chunk
        buffer.push(
            br#"{"_msg":"test2"}
{"_msg":"test3"}
"#,
        );

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], r#"{"_msg":"test2"}"#);
        assert_eq!(lines[1], r#"{"_msg":"test3"}"#);
    }

    #[test]
    fn test_buffer_partial_json() {
        let mut buffer = StreamBuffer::new();

        // Partial JSON (no newline yet)
        buffer.push(br#"{"_msg":"partial"#);

        let lines = buffer.drain_complete_lines().unwrap();
        assert!(lines.is_empty()); // No complete lines yet

        // Complete it
        buffer.push(br#""}"#);
        buffer.push(b"\n");

        let lines = buffer.drain_complete_lines().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], r#"{"_msg":"partial"}"#);
    }
}
