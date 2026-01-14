//! Prometheus metrics exposition server.
//!
//! This module provides an HTTP server that exposes valerter metrics
//! in Prometheus format on a configurable port.

use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Global flag to track if recorder is installed (for tests)
static RECORDER_INSTALLED: OnceLock<()> = OnceLock::new();

/// Register all metric descriptions for Prometheus.
///
/// This should be called once at startup after the recorder is installed.
/// Descriptions provide HELP text in the Prometheus output.
pub fn register_metric_descriptions() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};

    // Counters
    describe_counter!(
        "valerter_logs_matched_total",
        "Total number of log lines successfully matched by rules (before throttling)"
    );
    describe_counter!(
        "valerter_alerts_failed_total",
        "Total number of alerts that permanently failed after all retries exhausted"
    );
    describe_counter!(
        "valerter_alerts_sent_total",
        "Total number of alerts successfully sent to notification channels"
    );
    describe_counter!(
        "valerter_alerts_throttled_total",
        "Total number of alerts blocked by throttling"
    );
    describe_counter!(
        "valerter_alerts_passed_total",
        "Total number of alerts that passed throttling (not blocked)"
    );
    describe_counter!(
        "valerter_alerts_dropped_total",
        "Total number of alerts dropped due to full queue"
    );
    describe_counter!(
        "valerter_notify_errors_total",
        "Total number of notification errors after retries exhausted"
    );
    describe_counter!(
        "valerter_parse_errors_total",
        "Total number of log parsing errors (regex no-match or invalid JSON)"
    );
    describe_counter!(
        "valerter_reconnections_total",
        "Total number of VictoriaLogs reconnections"
    );
    describe_counter!(
        "valerter_rule_panics_total",
        "Total number of rule task panics"
    );
    describe_counter!(
        "valerter_rule_errors_total",
        "Total number of fatal rule errors (non-recoverable)"
    );

    // Gauges
    describe_gauge!(
        "valerter_queue_size",
        "Current number of alerts in the notification queue"
    );
    describe_gauge!(
        "valerter_last_query_timestamp",
        "Unix timestamp of last successful VictoriaLogs query chunk received"
    );
    describe_gauge!(
        "valerter_victorialogs_up",
        "VictoriaLogs connection status (1=connected, 0=disconnected)"
    );
    describe_gauge!(
        "valerter_uptime_seconds",
        "Time in seconds since valerter started"
    );

    // Histograms
    describe_histogram!(
        "valerter_query_duration_seconds",
        "Time to receive first chunk from VictoriaLogs after sending request"
    );
}

/// Metrics server for Prometheus exposition.
///
/// Starts an HTTP server that serves metrics on `/metrics` and
/// a health check on `/health`.
pub struct MetricsServer {
    port: u16,
}

impl MetricsServer {
    /// Create a new metrics server bound to the given port.
    ///
    /// Use port 0 to let the OS assign an available port (useful for testing).
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Returns the configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Run the metrics server until cancelled.
    ///
    /// This method installs the global metrics recorder and starts
    /// an HTTP server. It will block until the cancellation token
    /// is triggered.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start or encounters
    /// a fatal error during operation.
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        let addr: SocketAddr = ([0, 0, 0, 0], self.port).into();

        // Build the Prometheus exporter with HTTP server
        // Note: The recorder can only be installed once per process
        let builder = PrometheusBuilder::new();
        builder
            .with_http_listener(addr)
            .install()
            .map_err(|e| anyhow::anyhow!("Failed to install Prometheus exporter: {}", e))?;

        // Mark that the recorder is installed
        let _ = RECORDER_INSTALLED.set(());

        // Register descriptions after recorder is installed
        register_metric_descriptions();

        info!(port = self.port, "Metrics server started on /metrics");

        // Wait for cancellation
        cancel.cancelled().await;

        info!("Metrics server shutting down");

        Ok(())
    }
}

/// Check if the metrics recorder has been installed.
///
/// This is useful for tests to know if metrics will be recorded.
pub fn is_recorder_installed() -> bool {
    RECORDER_INSTALLED.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::time::Duration;

    // Use OnceLock to safely store the test port (no unsafe needed)
    static TEST_PORT: OnceLock<u16> = OnceLock::new();

    fn get_test_port() -> u16 {
        *TEST_PORT.get_or_init(|| {
            let port = portpicker::pick_unused_port().expect("No free port");

            // Start the metrics server in a background task
            let cancel = CancellationToken::new();
            let server = MetricsServer::new(port);

            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let _ = server.run(cancel).await;
                });
            });

            // Wait for server to be ready
            std::thread::sleep(Duration::from_millis(500));

            port
        })
    }

    // Test 6.1: Server starts and responds on /metrics
    #[tokio::test]
    async fn metrics_server_starts_and_responds() {
        let port = get_test_port();

        // Make request to /metrics
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/metrics", port))
            .send()
            .await
            .expect("Request should succeed");

        assert!(resp.status().is_success(), "Should return 200 OK");
    }

    // Test 6.2: Format Prometheus valide
    #[tokio::test]
    async fn metrics_format_is_valid_prometheus() {
        let port = get_test_port();

        // Increment a counter to have data
        metrics::counter!("valerter_alerts_sent_total", "rule_name" => "test_rule").increment(1);

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/metrics", port))
            .send()
            .await
            .expect("Request should succeed");

        let body = resp.text().await.expect("Should have body");

        // Prometheus format checks:
        // - Lines are either comments (#) or metrics
        // - Metrics have format: name{labels} value
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Valid Prometheus lines start with # or a metric name (letter or underscore)
            let first_char = line.chars().next().unwrap_or(' ');
            assert!(
                first_char == '#' || first_char.is_alphabetic() || first_char == '_',
                "Invalid Prometheus line: {}",
                line
            );
        }
    }

    // Test 6.4: Metrics incremented appear in /metrics
    #[tokio::test]
    async fn metrics_incremented_appear_in_output() {
        let port = get_test_port();

        // Increment counters with labels
        metrics::counter!("valerter_alerts_sent_total", "rule_name" => "cpu_alert").increment(42);
        metrics::counter!("valerter_alerts_throttled_total", "rule_name" => "cpu_alert")
            .increment(10);
        metrics::gauge!("valerter_queue_size").set(5.0);

        // Fetch metrics
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/metrics", port))
            .send()
            .await
            .expect("Request should succeed");

        let body = resp.text().await.expect("Should have body");

        // Verify our metrics appear
        assert!(
            body.contains("valerter_alerts_sent_total"),
            "Should contain alerts_sent metric. Body: {}",
            body
        );
        assert!(
            body.contains("cpu_alert"),
            "Should contain rule_name label. Body: {}",
            body
        );
    }

    // Test: MetricsServer::new creates server with correct port
    #[test]
    fn new_creates_server_with_port() {
        let server = MetricsServer::new(9090);
        assert_eq!(server.port(), 9090);
    }

    // Test: MetricsServer with port 0 is allowed (OS assigns)
    #[test]
    fn new_with_port_zero_allowed() {
        let server = MetricsServer::new(0);
        assert_eq!(server.port(), 0);
    }
}
