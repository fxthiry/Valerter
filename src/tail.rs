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
use reqwest::header::{ACCEPT, AUTHORIZATION, CONNECTION, HeaderMap, HeaderName, HeaderValue};
use tracing::{debug, info, trace, warn};

use crate::config::{BasicAuthConfig, SecretString, TlsConfig, VlSourceConfig};
use crate::error::StreamError;
use crate::stream_buffer::{MAX_LINE_SIZE, StreamBuffer};

// Note: No read_timeout - VictoriaLogs tail endpoint doesn't send keepalives,
// so we rely on CancellationToken for shutdown. Connection health is implicit
// (if VL dies, the stream ends and we reconnect via backoff).
// TCP Keepalive is enabled (TCP_KEEPALIVE) to detect dead connections through firewalls/NAT.

/// Base delay for exponential backoff (AD-07).
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Maximum delay for exponential backoff (AD-07).
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// TCP keepalive interval to detect dead connections through firewalls/NAT.
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

/// Number of consecutive connection / stream failures a task must observe
/// before flipping the per-source `valerter_vl_source_up` gauge to 0.
/// Debounces transient errors (EOF, isolated 5xx, timeout) so a flaky source
/// does not generate spurious `ValerterVlSourceDown` Prometheus alerts. Fixed
/// value (not configurable) to keep the contract simple; operators who want
/// a different threshold should use Prometheus `for:` on the alert rule.
pub const VL_SOURCE_UP_FAILURE_THRESHOLD: u32 = 3;

/// Gate for the per-source reachability gauge flip. Extracted so the debounce
/// decision is covered by a deterministic unit test without requiring a live
/// Prometheus recorder.
#[inline]
pub(crate) fn should_report_source_down(consecutive_failures: u32) -> bool {
    consecutive_failures >= VL_SOURCE_UP_FAILURE_THRESHOLD
}

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

/// TCP connect timeout. Without it a blackholed host blocks each attempt for
/// the OS SYN timeout (~2 min on Linux) on top of the backoff.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of characters of an error response body kept in logs.
const ERROR_BODY_MAX_CHARS: usize = 512;

/// Maximum number of characters of an invalid header name kept in errors.
const HEADER_NAME_MAX_CHARS: usize = 64;

/// Feed one network chunk to the buffer and return the lines it completes.
///
/// Dropped lines are logged and counted in `valerter_lines_discarded_total`:
/// one `oversized` warning and increment per oversized line, and a single
/// invalid UTF-8 warning per chunk (so a binary stream cannot flood the logs)
/// with the counter incremented once per dropped line.
fn process_chunk_logged(
    buffer: &mut StreamBuffer,
    chunk: &[u8],
    rule_name: &str,
    vl_source: &str,
) -> Vec<String> {
    let outcome = buffer.process_chunk(chunk);

    for size in outcome.oversized {
        warn!(
            rule_name = %rule_name,
            vl_source = %vl_source,
            size_bytes = size,
            max_bytes = MAX_LINE_SIZE,
            "Discarding oversized log line, buffer cleared"
        );
        metrics::counter!(
            "valerter_lines_discarded_total",
            "rule_name" => rule_name.to_string(),
            "vl_source" => vl_source.to_string(),
            "reason" => "oversized",
        )
        .increment(1);
    }

    if outcome.invalid_utf8 > 0 {
        warn!(
            rule_name = %rule_name,
            vl_source = %vl_source,
            discarded_lines = outcome.invalid_utf8,
            "Discarding log data with invalid UTF-8"
        );
        metrics::counter!(
            "valerter_lines_discarded_total",
            "rule_name" => rule_name.to_string(),
            "vl_source" => vl_source.to_string(),
            "reason" => "invalid_utf8",
        )
        .increment(outcome.invalid_utf8 as u64);
    }

    for line in &outcome.lines {
        trace!(
            rule_name = %rule_name,
            vl_source = %vl_source,
            line_len = line.len(),
            "Received log line"
        );
    }

    outcome.lines
}

/// Error for a custom header that is not a valid HTTP header. Names the header
/// (truncated) but never includes its value, which may hold a secret.
fn invalid_header_error(name: &str) -> StreamError {
    let name: String = name.chars().take(HEADER_NAME_MAX_CHARS).collect();
    StreamError::ConnectionFailed(format!(
        "invalid header '{name}' in VictoriaLogs source configuration"
    ))
}

/// Reads the body of a non-2xx VictoriaLogs response so the actual error
/// (e.g. `unsupported pipe "stats" in /tail`) surfaces in logs instead of a
/// bare status code (issue #42). Truncated and collapsed to a single line.
async fn response_error_body(resp: reqwest::Response) -> String {
    let text = resp.text().await.unwrap_or_default();
    let one_line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.is_empty() {
        return "<empty body>".to_string();
    }
    if one_line.chars().count() > ERROR_BODY_MAX_CHARS {
        let cut: String = one_line.chars().take(ERROR_BODY_MAX_CHARS).collect();
        format!("{cut}…")
    } else {
        one_line
    }
}

impl TailConfig {
    /// Build a `TailConfig` from a named VL source and a rule query.
    ///
    /// Credentials, TLS, and headers are all per-source. `start` is unset so
    /// the tail endpoint follows live tail semantics.
    pub fn from_source(source: &VlSourceConfig, query: String) -> Self {
        Self {
            base_url: source.url.clone(),
            query,
            start: None,
            basic_auth: source.basic_auth.clone(),
            headers: source.headers.clone(),
            tls: source.tls.clone(),
        }
    }

    /// True when a custom `Authorization` header (any case) replaces the one
    /// generated from `basic_auth`.
    pub fn custom_authorization_overrides_basic_auth(&self) -> bool {
        self.basic_auth.is_some()
            && self.headers.as_ref().is_some_and(|headers| {
                headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(AUTHORIZATION.as_str()))
            })
    }
}

/// Client for streaming logs from VictoriaLogs tail endpoint.
///
/// Handles connection establishment, reconnection with exponential backoff,
/// and UTF-8 safe buffering via `StreamBuffer`.
pub struct TailClient {
    config: TailConfig,
    client: Client,
    headers: HeaderMap,
    buffer: StreamBuffer,
}

impl TailClient {
    /// Create a new TailClient with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `StreamError::ConnectionFailed` if the HTTP client cannot be
    /// built or if a custom header name or value is not a valid HTTP header.
    pub fn new(config: TailConfig) -> Result<Self, StreamError> {
        let mut builder = Client::builder();

        // Configure TLS verification (AC #6, #7)
        if let Some(ref tls) = config.tls
            && !tls.verify
        {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder
            .tcp_keepalive(TCP_KEEPALIVE)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| StreamError::ConnectionFailed(e.to_string()))?;

        let headers = build_headers(&client, &config)?;

        Ok(Self {
            config,
            client,
            headers,
            buffer: StreamBuffer::new(),
        })
    }

    /// Build a request with all configured auth and headers.
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        self.client.get(url).headers(self.headers.clone())
    }

    /// Build the full URL for the VictoriaLogs tail endpoint.
    ///
    /// Trailing slashes of `base_url` are dropped so `http://vl:9428/` does
    /// not produce `//select/logsql/tail`.
    pub fn build_url(&self) -> String {
        let mut url = format!(
            "{}/select/logsql/tail?query={}",
            self.config.base_url.trim_end_matches('/'),
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
    /// connection fails. Invalid UTF-8 and oversized lines are dropped, logged
    /// and counted, never returned as errors.
    ///
    /// # Errors
    ///
    /// - `StreamError::ConnectionFailed` if HTTP connection fails
    pub async fn connect_and_receive(
        &mut self,
        rule_name: &str,
        vl_source: &str,
    ) -> Result<Vec<String>, StreamError> {
        let url = self.build_url();

        let response = self
            .build_request(&url)
            .send()
            .await
            .map_err(|e| StreamError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response_error_body(response).await;
            return Err(StreamError::ConnectionFailed(format!(
                "HTTP {status}: {body}"
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

            all_lines.extend(process_chunk_logged(
                &mut self.buffer,
                &chunk,
                rule_name,
                vl_source,
            ));
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
    /// Returns the first error produced by `line_handler`; connection and
    /// stream errors are retried.
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
    ///     "vlprod",
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
        vl_source: &str,
        on_reconnect: Option<&dyn ReconnectCallback>,
        mut line_handler: F,
    ) -> Result<(), StreamError>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<(), StreamError>>,
    {
        let mut attempt: u32 = 0;
        let mut had_failure = false;
        let mut consecutive_failures: u32 = 0;
        // Consecutive clean EOFs with no data received (server closing the
        // tail right away): backed off separately from real failures.
        let mut empty_eof_streak: u32 = 0;

        loop {
            // Never glue a partial line from the previous connection to the
            // first bytes of the new one.
            self.buffer.clear();
            let url = self.build_url();
            debug!(
                rule_name = %rule_name,
                vl_source = %vl_source,
                url = %url,
                "Connecting to VictoriaLogs tail endpoint"
            );

            // Start timing for query_duration metric
            let request_start = Instant::now();
            let connect_result = self.build_request(&url).send().await;

            let response = match connect_result {
                Ok(resp) if resp.status().is_success() => {
                    info!(
                        rule_name = %rule_name,
                        vl_source = %vl_source,
                        status = %resp.status(),
                        "Connected to VictoriaLogs"
                    );
                    // Connection successful - mark this source as up
                    // (per-source gauge replaces the v1.x per-rule
                    // `valerter_victorialogs_up{rule_name}`).
                    metrics::gauge!(
                        "valerter_vl_source_up",
                        "vl_source" => vl_source.to_string(),
                    )
                    .set(1.0);

                    if had_failure {
                        // We recovered from a failure
                        log_reconnection_success(rule_name, vl_source);
                        if let Some(callback) = on_reconnect {
                            callback.on_reconnect(rule_name, vl_source);
                        }
                    }
                    attempt = 0;
                    had_failure = false;
                    consecutive_failures = 0;
                    resp
                }
                Ok(resp) => {
                    // HTTP error (4xx, 5xx). Debounced flip via
                    // `should_report_source_down`: only flips to 0 once we
                    // reach `VL_SOURCE_UP_FAILURE_THRESHOLD` consecutive
                    // failures, so transient 5xx do not page.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if should_report_source_down(consecutive_failures) {
                        metrics::gauge!(
                            "valerter_vl_source_up",
                            "vl_source" => vl_source.to_string(),
                        )
                        .set(0.0);
                    }

                    had_failure = true;
                    let status = resp.status();
                    let body = response_error_body(resp).await;
                    warn!(
                        rule_name = %rule_name,
                        vl_source = %vl_source,
                        status = %status,
                        response = %body,
                        "HTTP error from VictoriaLogs"
                    );
                    let delay = backoff_delay_with_jitter(attempt);
                    log_reconnection_attempt(rule_name, vl_source, attempt, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                Err(e) => {
                    // Connection error (DNS, timeout, refused, ...). Same
                    // debounce gate as the HTTP-error branch above.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if should_report_source_down(consecutive_failures) {
                        metrics::gauge!(
                            "valerter_vl_source_up",
                            "vl_source" => vl_source.to_string(),
                        )
                        .set(0.0);
                    }

                    had_failure = true;
                    warn!(
                        rule_name = %rule_name,
                        vl_source = %vl_source,
                        error = %e,
                        "Connection failed"
                    );
                    let delay = backoff_delay_with_jitter(attempt);
                    log_reconnection_attempt(rule_name, vl_source, attempt, delay);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
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
                                "rule_name" => rule_name.to_string(),
                                "vl_source" => vl_source.to_string(),
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
                            "rule_name" => rule_name.to_string(),
                            "vl_source" => vl_source.to_string(),
                        )
                        .set(now);

                        let lines =
                            process_chunk_logged(&mut self.buffer, &chunk, rule_name, vl_source);
                        for line in lines {
                            line_handler(line).await?;
                        }
                    }
                    Err(e) => {
                        // Mid-stream error (EOF, broken pipe, ...). Same
                        // debounce gate as the connect branches above.
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if should_report_source_down(consecutive_failures) {
                            metrics::gauge!(
                                "valerter_vl_source_up",
                                "vl_source" => vl_source.to_string(),
                            )
                            .set(0.0);
                        }

                        had_failure = true;
                        warn!(
                            rule_name = %rule_name,
                            vl_source = %vl_source,
                            error = %e,
                            "Stream read error"
                        );
                        let delay = backoff_delay_with_jitter(attempt);
                        log_reconnection_attempt(rule_name, vl_source, attempt, delay);
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        break; // Break inner loop to reconnect
                    }
                }
            }

            // Stream ended cleanly (server closed the connection with no
            // error). This is not a failure: `had_failure` stays false so the
            // throttle cache is NOT reset on the next connect (a benign
            // disconnect used to let duplicate alert bursts through). It is
            // still rate-limited: a proxy or VL closing tails immediately
            // would otherwise spin in a tight connect/EOF loop.
            if had_failure {
                continue; // mid-stream error path already slept
            }
            // ~1s after a connection that received data; ~1s, 2s, 4s... for
            // consecutive empty EOFs.
            if first_chunk_received {
                empty_eof_streak = 0;
            } else {
                empty_eof_streak = empty_eof_streak.saturating_add(1);
            }
            let delay = backoff_delay_with_jitter(empty_eof_streak.saturating_sub(1));
            debug!(
                rule_name = %rule_name,
                vl_source = %vl_source,
                empty_eof_streak = empty_eof_streak,
                delay_ms = delay.as_millis(),
                "Stream ended, reconnecting"
            );
            // A clean end is not a failure: `valerter_reconnections_total`
            // only counts reconnections after a failure.
            metrics::counter!(
                "valerter_stream_ends_total",
                "rule_name" => rule_name.to_string(),
                "vl_source" => vl_source.to_string(),
            )
            .increment(1);
            tokio::time::sleep(delay).await;
        }
    }
}

/// Build the request headers once: defaults, then Basic Auth, then custom
/// headers. Custom headers are inserted last (sorted by name for a
/// deterministic result) so they replace a default or Basic Auth header of the
/// same name (case-insensitive) instead of duplicating it.
///
/// Invalid header names or values are normally rejected when the configuration
/// is loaded; this is a defensive guard so such a header fails the task at
/// startup instead of looping on reconnection without ever sending a request.
fn build_headers(client: &Client, config: &TailConfig) -> Result<HeaderMap, StreamError> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/x-ndjson"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    if let Some(ref auth) = config.basic_auth {
        // Let reqwest encode the credentials (same encoding as before).
        let request = client
            .get("http://localhost/")
            .basic_auth(&auth.username, Some(auth.password.expose()))
            .build()
            .map_err(|_| invalid_header_error(AUTHORIZATION.as_str()))?;
        if let Some(mut value) = request.headers().get(AUTHORIZATION).cloned() {
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
    }

    if let Some(ref custom) = config.headers {
        let mut custom: Vec<_> = custom.iter().collect();
        custom.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in custom {
            let header_name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid_header_error(name))?;
            let mut header_value =
                HeaderValue::from_str(value.expose()).map_err(|_| invalid_header_error(name))?;
            header_value.set_sensitive(true);
            headers.insert(header_name, header_value);
        }
    }

    Ok(headers)
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
///
/// Exposed `pub(crate)` only: production callers must go through
/// [`backoff_delay_with_jitter`] so the jitter clamp is always applied. Direct
/// use bypasses that safety net.
pub(crate) fn backoff_delay_default(attempt: u32) -> Duration {
    backoff_delay(attempt, BACKOFF_BASE, BACKOFF_MAX)
}

/// Minimum reconnect delay floor in milliseconds (post-jitter clamp).
///
/// The exponential backoff base is 1s = 1000ms, so a -10% jitter on attempt
/// 0 produces 900ms which is well above this floor; the clamp is a defensive
/// safety net for any future change that lowers `BACKOFF_BASE`.
pub const MIN_RECONNECT_DELAY_MS: u64 = 100;

/// Compute the backoff delay with `±10%` uniform jitter applied per call.
///
/// Multi-source observability (v2.0.0 part 2): when N sources behind a flapping
/// load balancer all reconnect at the same exponential cadence they form a
/// thundering herd. Per-task uniform jitter spreads attempts in a `[0.9·D,
/// 1.1·D]` window so the herd dissolves over a few cycles without changing
/// the overall reconnect rate.
///
/// The jitter is uniform over `[-0.10, +0.10]` (inclusive) and the resulting
/// delay is clamped to [`MIN_RECONNECT_DELAY_MS`] so a negative jitter never
/// produces a sub-100ms hot loop.
pub fn backoff_delay_with_jitter(attempt: u32) -> Duration {
    use rand::Rng;

    let base = backoff_delay_default(attempt);
    let jitter: f64 = rand::thread_rng().gen_range(-0.10..=0.10);
    apply_jitter_floor(base.as_millis() as u64, jitter)
}

/// Apply a `(1 + jitter)` multiplier to a millisecond base and clamp the
/// result to [`MIN_RECONNECT_DELAY_MS`]. Pure helper so the clamp branch is
/// directly exercisable from unit tests with synthetic small bases.
fn apply_jitter_floor(base_ms: u64, jitter: f64) -> Duration {
    let effective_ms = ((base_ms as f64) * (1.0 + jitter)).max(MIN_RECONNECT_DELAY_MS as f64);
    Duration::from_millis(effective_ms as u64)
}

/// Trait for reconnection callbacks.
///
/// Implementors receive notification when a connection is restored after failure.
/// This is used to reset throttle caches as per FR7.
pub trait ReconnectCallback: Send + Sync {
    /// Called when connection is restored after failure.
    ///
    /// Receives both the rule name AND the source name so implementors can
    /// scope their reaction (e.g. throttle reset) per `(rule, source)` task
    /// rather than fan-out across all sources of the same rule.
    fn on_reconnect(&self, rule_name: &str, vl_source: &str);
}

/// Log the reconnection attempt with proper tracing.
///
/// # Arguments
///
/// * `rule_name` - Name of the rule for the tracing span
/// * `vl_source` - Name of the VictoriaLogs source for the tracing span
/// * `attempt` - Current retry attempt number
/// * `delay` - Delay before next retry
pub fn log_reconnection_attempt(rule_name: &str, vl_source: &str, attempt: u32, delay: Duration) {
    warn!(
        rule_name = %rule_name,
        vl_source = %vl_source,
        attempt = attempt,
        delay_ms = delay.as_millis() as u64,
        "Connection failed, retrying"
    );

    // Increment reconnection metric (now per-(rule, source) for multi-source
    // observability — v2.0.0 part 2).
    metrics::counter!(
        "valerter_reconnections_total",
        "rule_name" => rule_name.to_string(),
        "vl_source" => vl_source.to_string(),
    )
    .increment(1);
}

/// Log successful reconnection after failure.
///
/// # Arguments
///
/// * `rule_name` - Name of the rule for the tracing span
/// * `vl_source` - Name of the VictoriaLogs source for the tracing span
pub fn log_reconnection_success(rule_name: &str, vl_source: &str) {
    info!(
        rule_name = %rule_name,
        vl_source = %vl_source,
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

    // ==========================================================================
    // Multi-source observability v2.0.0: jitter on reconnect backoff.
    // The intent is to break thundering-herd alignment on flapping load
    // balancers; we cannot prove statistical independence in a unit test, but
    // we can prove the bounds and the floor clamp.
    // ==========================================================================

    #[test]
    fn jitter_stays_within_plus_minus_ten_percent_of_base_for_attempt_3() {
        // Attempt 3 → base 8s = 8000ms. Jittered value must lie in [7200, 8800].
        let base = backoff_delay_default(3);
        assert_eq!(base, Duration::from_secs(8));
        let lo = (base.as_millis() as f64 * 0.90).floor() as u128;
        let hi = (base.as_millis() as f64 * 1.10).ceil() as u128;
        for _ in 0..200 {
            let d = backoff_delay_with_jitter(3);
            let ms = d.as_millis();
            assert!(
                ms >= lo && ms <= hi,
                "jittered delay {}ms outside [{}, {}]",
                ms,
                lo,
                hi
            );
        }
    }

    #[test]
    fn jitter_caps_below_min_reconnect_delay_floor() {
        // Directly exercise the floor branch via the pure helper. With
        // base_ms=50 and jitter=-0.5, the natural product (25ms) is far
        // below MIN_RECONNECT_DELAY_MS (100ms) and must be clamped up.
        let clamped = apply_jitter_floor(50, -0.5);
        assert_eq!(
            clamped.as_millis() as u64,
            MIN_RECONNECT_DELAY_MS,
            "small base + heavy negative jitter must be clamped to the floor"
        );

        // Edge: jitter that would land exactly at the floor still pegs to it.
        let exact = apply_jitter_floor(100, 0.0);
        assert_eq!(exact.as_millis() as u64, MIN_RECONNECT_DELAY_MS);

        // The default-base path remains unaffected (probabilistic check).
        for _ in 0..50 {
            let d = backoff_delay_with_jitter(0);
            assert!(
                d.as_millis() >= MIN_RECONNECT_DELAY_MS as u128,
                "default-base jitter must not drop below floor: {}ms",
                d.as_millis()
            );
        }
    }

    #[test]
    fn jitter_at_capped_attempt_stays_within_window_around_max() {
        // Attempt 100 → backoff is capped to BACKOFF_MAX = 60s.
        // Jitter window is computed from the cap, not from 2^100.
        let base = backoff_delay_default(100);
        assert_eq!(base, BACKOFF_MAX);
        let lo = (base.as_millis() as f64 * 0.90).floor() as u128;
        let hi = (base.as_millis() as f64 * 1.10).ceil() as u128;
        for _ in 0..50 {
            let d = backoff_delay_with_jitter(100);
            let ms = d.as_millis();
            assert!(
                ms >= lo && ms <= hi,
                "jittered capped delay {}ms outside [{}, {}]",
                ms,
                lo,
                hi
            );
        }
    }

    #[test]
    fn test_client_creation_success() {
        let config = test_config("http://localhost:9428", "test", None);

        let result = TailClient::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn should_report_source_down_debounces_until_threshold() {
        // Threshold-1 failures in a row must not flip the gauge; the Nth does.
        for below in 0..VL_SOURCE_UP_FAILURE_THRESHOLD {
            assert!(
                !should_report_source_down(below),
                "{} consecutive failures must not report the source as down (threshold is {})",
                below,
                VL_SOURCE_UP_FAILURE_THRESHOLD
            );
        }
        assert!(
            should_report_source_down(VL_SOURCE_UP_FAILURE_THRESHOLD),
            "{} consecutive failures must report the source as down",
            VL_SOURCE_UP_FAILURE_THRESHOLD
        );
        assert!(
            should_report_source_down(VL_SOURCE_UP_FAILURE_THRESHOLD + 5),
            "sustained failures past the threshold must keep reporting down"
        );
    }

    #[test]
    fn test_process_chunk_logged_simulates_vl_chunks() {
        let mut buffer = StreamBuffer::new();

        // Simulate receiving chunked JSON lines like VictoriaLogs sends
        assert!(process_chunk_logged(&mut buffer, br#"{"_msg":"partial"#, "r", "s").is_empty());
        let lines = process_chunk_logged(&mut buffer, b"\"}\n{\"_msg\":\"test2\"}\n", "r", "s");
        assert_eq!(lines, vec![r#"{"_msg":"partial"}"#, r#"{"_msg":"test2"}"#]);
    }

    #[test]
    fn test_process_chunk_logged_counts_discarded_lines_per_line() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let lines = metrics::with_local_recorder(&recorder, || {
            let mut buffer = StreamBuffer::new();
            let mut lines = process_chunk_logged(
                &mut buffer,
                b"ok1\n\xff\n\xfe\nok2\n\x80\n",
                "rule1",
                "src1",
            );
            // Two oversized lines: one complete, one pending then finished.
            let mut chunk = vec![b'x'; MAX_LINE_SIZE + 1];
            chunk.extend_from_slice(b"\nok3\n");
            chunk.extend(vec![b'y'; MAX_LINE_SIZE + 1]);
            lines.extend(process_chunk_logged(&mut buffer, &chunk, "rule1", "src1"));
            lines.extend(process_chunk_logged(
                &mut buffer,
                b"yyy\nok4\n",
                "rule1",
                "src1",
            ));
            lines
        });

        assert_eq!(lines, vec!["ok1", "ok2", "ok3", "ok4"]);
        let rendered = handle.render();
        for series in [
            r#"valerter_lines_discarded_total{rule_name="rule1",vl_source="src1",reason="invalid_utf8"} 3"#,
            r#"valerter_lines_discarded_total{rule_name="rule1",vl_source="src1",reason="oversized"} 2"#,
        ] {
            assert!(
                rendered.contains(series),
                "missing {series} in:\n{rendered}"
            );
        }
    }

    // ==========================================================================
    // URL normalization and request headers
    // ==========================================================================

    #[test]
    fn test_build_url_strips_trailing_slashes() {
        for (base, expected) in [
            (
                "http://vl:9428/",
                "http://vl:9428/select/logsql/tail?query=q",
            ),
            (
                "https://proxy.example.com/vl//",
                "https://proxy.example.com/vl/select/logsql/tail?query=q",
            ),
            (
                "http://vl:9428",
                "http://vl:9428/select/logsql/tail?query=q",
            ),
        ] {
            let client = TailClient::new(test_config(base, "q", None)).unwrap();
            assert_eq!(client.build_url(), expected, "base_url {base}");
        }
    }

    fn custom_headers(pairs: &[(&str, &str)]) -> Option<HashMap<String, SecretString>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), SecretString::new(v.to_string())))
                .collect(),
        )
    }

    fn basic_auth() -> Option<BasicAuthConfig> {
        Some(BasicAuthConfig {
            username: "user".to_string(),
            password: SecretString::new("pass".to_string()),
        })
    }

    #[test]
    fn test_custom_authorization_overrides_basic_auth_predicate() {
        let mut config = test_config("http://vl:9428", "q", None);
        assert!(!config.custom_authorization_overrides_basic_auth());

        config.headers = custom_headers(&[("Authorization", "Bearer abc")]);
        assert!(!config.custom_authorization_overrides_basic_auth());

        config.basic_auth = basic_auth();
        assert!(config.custom_authorization_overrides_basic_auth());

        config.headers = custom_headers(&[("authorization", "Bearer abc")]);
        assert!(config.custom_authorization_overrides_basic_auth());

        config.headers = custom_headers(&[("Authorization-Token", "Bearer abc")]);
        assert!(!config.custom_authorization_overrides_basic_auth());

        config.headers = None;
        assert!(!config.custom_authorization_overrides_basic_auth());
    }

    #[test]
    fn test_headers_defaults_and_basic_auth() {
        let mut config = test_config("http://vl:9428", "q", None);
        config.basic_auth = basic_auth();
        let client = TailClient::new(config).unwrap();

        assert_eq!(client.headers[ACCEPT], "application/x-ndjson");
        assert_eq!(client.headers[CONNECTION], "keep-alive");
        // base64("user:pass")
        assert_eq!(client.headers[AUTHORIZATION], "Basic dXNlcjpwYXNz");
        assert!(client.headers[AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn test_custom_headers_replace_defaults_and_basic_auth() {
        let mut config = test_config("http://vl:9428", "q", None);
        config.basic_auth = basic_auth();
        config.headers = custom_headers(&[
            ("accept", "application/json"),
            ("Authorization", "Bearer abc"),
            ("X-Tenant", "t1"),
        ]);
        let client = TailClient::new(config).unwrap();

        assert_eq!(client.headers.get_all(ACCEPT).iter().count(), 1);
        assert_eq!(client.headers[ACCEPT], "application/json");
        assert_eq!(client.headers.get_all(AUTHORIZATION).iter().count(), 1);
        assert_eq!(client.headers[AUTHORIZATION], "Bearer abc");
        assert_eq!(client.headers["x-tenant"], "t1");
        assert!(client.headers["x-tenant"].is_sensitive());
    }

    #[test]
    fn test_custom_headers_case_duplicates_are_deterministic() {
        let mut config = test_config("http://vl:9428", "q", None);
        // Sorted by name: "X-Tenant" < "x-tenant", so the latter wins.
        config.headers = custom_headers(&[("x-tenant", "lower"), ("X-Tenant", "upper")]);
        let client = TailClient::new(config).unwrap();

        assert_eq!(client.headers.get_all("x-tenant").iter().count(), 1);
        assert_eq!(client.headers["x-tenant"], "lower");
    }

    #[test]
    fn test_invalid_header_value_fails_without_leaking_value() {
        let mut config = test_config("http://vl:9428", "q", None);
        config.headers = custom_headers(&[("X-Token", "secret\nvalue")]);

        let err = TailClient::new(config)
            .err()
            .expect("invalid header must fail");
        let msg = err.to_string();
        assert!(msg.contains("'X-Token'"), "{msg}");
        assert!(!msg.contains("secret"), "{msg}");
    }

    #[test]
    fn test_invalid_header_name_is_truncated() {
        let long_name = format!("bad name {}", "n".repeat(100));
        let mut config = test_config("http://vl:9428", "q", None);
        config.headers = custom_headers(&[(long_name.as_str(), "secret")]);

        let err = TailClient::new(config)
            .err()
            .expect("invalid header must fail");
        let msg = err.to_string();
        let expected: String = long_name.chars().take(HEADER_NAME_MAX_CHARS).collect();
        assert!(msg.contains(&format!("'{expected}'")), "{msg}");
        assert!(!msg.contains(&long_name), "{msg}");
        assert!(!msg.contains("secret"), "{msg}");
    }
}
