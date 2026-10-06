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

use crate::config::RuntimeConfig;
use crate::notify::NotifierRegistry;

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
        "Total number of alerts that permanently failed for a notifier, once per alert and notifier"
    );
    describe_counter!(
        "valerter_alerts_sent_total",
        "Total number of alerts delivered by a notifier, once per alert and notifier"
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
        "Total number of deliveries dropped because a destination queue was full \
         (sum over every destination; an alert routed to two destinations counts twice)"
    );
    describe_counter!(
        "valerter_destination_alerts_dropped_total",
        "Number of alerts dropped because the queue of this destination was full"
    );
    describe_counter!(
        "valerter_notify_errors_total",
        "Total number of permanent notification failures (retries exhausted, \
         non-retryable response or render error), once per alert and notifier"
    );
    describe_counter!(
        "valerter_email_recipient_errors_total",
        "Number of email recipients an alert could not be delivered to"
    );
    describe_counter!(
        "valerter_telegram_chat_errors_total",
        "Number of Telegram chats an alert could not be delivered to"
    );
    describe_counter!(
        "valerter_alerts_truncated_total",
        "Total number of alerts whose message body was truncated to fit the notifier length limit"
    );
    describe_counter!(
        "valerter_parse_errors_total",
        "Total number of log parsing errors (regex no-match or invalid JSON)"
    );
    describe_counter!(
        "valerter_lines_discarded_total",
        "Total number of streamed lines discarded before parsing (oversized or invalid UTF-8)"
    );
    describe_counter!(
        "valerter_reconnections_total",
        "Total number of VictoriaLogs reconnections after a failure"
    );
    describe_counter!(
        "valerter_stream_ends_total",
        "Total number of clean VictoriaLogs stream ends (EOF without error), each followed by a reconnection"
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
        "Current number of pending deliveries across every destination queue \
         (up to 100 per destination)"
    );
    describe_gauge!(
        "valerter_destination_queue_size",
        "Current number of alerts pending in the queue of this destination (at most 100)"
    );
    describe_gauge!(
        "valerter_last_query_timestamp",
        "Unix timestamp of last successful VictoriaLogs query chunk received"
    );
    describe_gauge!(
        "valerter_vl_source_up",
        "Per-source VictoriaLogs reachability (1=connected, 0=disconnected). \
         Replaces the v1.x per-rule `valerter_victorialogs_up`."
    );
    describe_gauge!(
        "valerter_uptime_seconds",
        "Time in seconds since valerter started"
    );
    describe_gauge!(
        "valerter_build_info",
        "Build information with version label (always 1)"
    );

    // Histograms
    describe_histogram!(
        "valerter_query_duration_seconds",
        "Time to receive first chunk from VictoriaLogs after sending request"
    );
}

/// Metrics server for Prometheus exposition.
///
/// Starts an HTTP server that serves metrics on `/metrics`, the only
/// documented path. The listener comes from `metrics-exporter-prometheus`:
/// it does no routing of its own beyond a built-in `/health` reply and serves
/// the metrics on any other path; valerter documents neither behavior.
pub struct MetricsServer {
    port: u16,
    /// Optional channel to signal when the recorder is ready.
    /// This allows callers to wait for the recorder to be installed
    /// before emitting metrics (avoiding the race condition where
    /// metrics are lost if emitted before the recorder is ready).
    ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MetricsServer {
    /// Create a new metrics server bound to the given port.
    ///
    /// Use port 0 to let the OS assign an available port (useful for testing).
    pub fn new(port: u16) -> Self {
        Self {
            port,
            ready_tx: None,
        }
    }

    /// Create a new metrics server with a ready signal channel.
    ///
    /// The channel will be signaled once the Prometheus recorder is installed
    /// and ready to receive metrics. This prevents the race condition where
    /// metrics emitted before the recorder is ready are silently lost.
    pub fn with_ready_signal(port: u16, ready_tx: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            port,
            ready_tx: Some(ready_tx),
        }
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
    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
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

        // Signal that the recorder is ready (if a channel was provided)
        if let Some(tx) = self.ready_tx {
            let _ = tx.send(());
        }

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

/// One `(rule, source)` pair the engine runs a task for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceSeries {
    pub rule_name: String,
    pub vl_source: String,
    /// Whether the rule uses a regex parser (it can then emit
    /// `error_type="regex_no_match"`).
    pub regex_parser: bool,
}

/// One `(rule, source, destination)` triplet an alert can be delivered to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySeries {
    pub rule_name: String,
    pub vl_source: String,
    pub notifier_name: String,
    pub notifier_type: String,
}

/// A registered notifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifierSeries {
    pub name: String,
    pub notifier_type: String,
}

/// Every label combination [`initialize_metrics`] seeds at startup.
///
/// Built by [`build_metrics_inventory`] from the enabled rules (same source
/// fan-out as the engine), their destinations and the notifier registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsInventory {
    /// Every `vl_source` targeted by at least one enabled rule, sorted.
    pub sources: Vec<String>,
    /// Every `(enabled rule, resolved source)` pair.
    pub rule_sources: Vec<RuleSourceSeries>,
    /// Every `(enabled rule, resolved source, rule destination)` triplet.
    pub deliveries: Vec<DeliverySeries>,
    /// Every registered notifier, used or not.
    pub notifiers: Vec<NotifierSeries>,
}

/// Build the metric series inventory seeded at startup.
///
/// Multi-source observability (v2.0.0 part 2): every per-rule metric also
/// carries `vl_source`, so one pair per `(enabled rule, resolved source)`, with
/// the same fan-out as the engine: empty `vl_sources` means every configured
/// source, a non-empty list restricts to the named, declared sources. Each
/// pair is crossed with the rule destinations, typed through the registry.
/// `sources` holds the sources targeted by at least one enabled rule (sorted,
/// without duplicates): a source no task tails gets no `vl_source_up` series.
pub fn build_metrics_inventory(
    config: &RuntimeConfig,
    registry: &NotifierRegistry,
) -> MetricsInventory {
    let mut inventory = MetricsInventory::default();

    for rule in config.rules.iter().filter(|r| r.enabled) {
        let rule_sources = config
            .victorialogs
            .keys()
            .filter(|s| rule.vl_sources.is_empty() || rule.vl_sources.contains(s));
        for vl_source in rule_sources {
            inventory.rule_sources.push(RuleSourceSeries {
                rule_name: rule.name.clone(),
                vl_source: vl_source.clone(),
                regex_parser: rule.parser.regex.is_some(),
            });
            // Destinations missing from the registry were rejected by the
            // preflight checks.
            for (notifier_name, notifier) in rule
                .notify
                .destinations
                .iter()
                .filter_map(|d| registry.get(d).map(|n| (d, n)))
            {
                inventory.deliveries.push(DeliverySeries {
                    rule_name: rule.name.clone(),
                    vl_source: vl_source.clone(),
                    notifier_name: notifier_name.clone(),
                    notifier_type: notifier.notifier_type().to_string(),
                });
            }
        }
    }

    let mut sources: Vec<String> = inventory
        .rule_sources
        .iter()
        .map(|p| p.vl_source.clone())
        .collect();
    sources.sort_unstable();
    sources.dedup();
    inventory.sources = sources;

    let mut notifiers: Vec<NotifierSeries> = registry
        .names()
        .filter_map(|name| {
            registry.get(name).map(|n| NotifierSeries {
                name: name.to_string(),
                notifier_type: n.notifier_type().to_string(),
            })
        })
        .collect();
    notifiers.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    inventory.notifiers = notifiers;
    inventory
}

/// Initialize all known metrics to their default values.
///
/// Call it right after the Prometheus recorder is installed so that every
/// series is visible in `/metrics` from startup, before any event. Each series
/// gets exactly the labels (names and order) it is emitted with, so that the
/// seeded series is the one later incremented.
pub fn initialize_metrics(inventory: &MetricsInventory) {
    use metrics::{counter, gauge};

    // Initialize gauges with their initial values
    gauge!("valerter_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
    gauge!("valerter_uptime_seconds").set(0.0);
    gauge!("valerter_queue_size").set(0.0);

    // Initialize per-source `vl_source_up` gauge to 0 for every source an
    // enabled rule targets. The engine flips it to 1 on the first successful
    // tail connect.
    for source_name in &inventory.sources {
        gauge!("valerter_vl_source_up", "vl_source" => source_name.clone()).set(0.0);
    }

    // Initialize counters without labels (global counters)
    counter!("valerter_alerts_dropped_total").absolute(0);

    // Per-(rule, source) series. Every per-rule metric also carries
    // `vl_source` (v2.0.0 multi-source observability).
    for pair in &inventory.rule_sources {
        let rule_name = &pair.rule_name;
        let vl_source = &pair.vl_source;
        for name in [
            "valerter_logs_matched_total",
            "valerter_alerts_throttled_total",
            "valerter_alerts_passed_total",
            "valerter_rule_panics_total",
            "valerter_rule_errors_total",
            "valerter_reconnections_total",
            "valerter_stream_ends_total",
        ] {
            counter!(
                name,
                "rule_name" => rule_name.clone(),
                "vl_source" => vl_source.clone(),
            )
            .absolute(0);
        }
        for reason in ["oversized", "invalid_utf8"] {
            counter!(
                "valerter_lines_discarded_total",
                "rule_name" => rule_name.clone(),
                "vl_source" => vl_source.clone(),
                "reason" => reason,
            )
            .absolute(0);
        }
        // The VictoriaLogs envelope is always parsed as JSON; only a regex
        // parser can fail to match.
        let error_types: &[&'static str] = if pair.regex_parser {
            &["invalid_json", "regex_no_match"]
        } else {
            &["invalid_json"]
        };
        for error_type in error_types {
            counter!(
                "valerter_parse_errors_total",
                "rule_name" => rule_name.clone(),
                "vl_source" => vl_source.clone(),
                "error_type" => *error_type,
            )
            .absolute(0);
        }
        // Histograms can't be `absolute(0)` but referencing the handle here
        // registers the series so it appears in /metrics from startup.
        let _ = metrics::histogram!(
            "valerter_query_duration_seconds",
            "rule_name" => rule_name.clone(),
            "vl_source" => vl_source.clone(),
        );
        gauge!(
            "valerter_last_query_timestamp",
            "rule_name" => rule_name.clone(),
            "vl_source" => vl_source.clone(),
        )
        .set(0.0);
    }

    // Per-(rule, source, destination) notification series, plus the
    // per-target error counter of email and telegram destinations.
    for delivery in &inventory.deliveries {
        for name in [
            "valerter_alerts_sent_total",
            "valerter_notify_errors_total",
            "valerter_alerts_failed_total",
        ] {
            counter!(
                name,
                "rule_name" => delivery.rule_name.clone(),
                "vl_source" => delivery.vl_source.clone(),
                "notifier_name" => delivery.notifier_name.clone(),
                "notifier_type" => delivery.notifier_type.clone(),
            )
            .absolute(0);
        }
        let target_errors = match delivery.notifier_type.as_str() {
            "email" => Some("valerter_email_recipient_errors_total"),
            "telegram" => Some("valerter_telegram_chat_errors_total"),
            _ => None,
        };
        if let Some(name) = target_errors {
            counter!(
                name,
                "rule_name" => delivery.rule_name.clone(),
                "vl_source" => delivery.vl_source.clone(),
                "notifier_name" => delivery.notifier_name.clone(),
            )
            .absolute(0);
        }
    }

    // Truncation is only emitted by telegram notifiers, without rule labels.
    for notifier in inventory
        .notifiers
        .iter()
        .filter(|n| n.notifier_type == "telegram")
    {
        counter!(
            "valerter_alerts_truncated_total",
            "notifier_type" => "telegram",
            "notifier_name" => notifier.name.clone()
        )
        .absolute(0);
    }

    tracing::info!(
        rule_source_pair_count = inventory.rule_sources.len(),
        source_count = inventory.sources.len(),
        notifier_count = inventory.notifiers.len(),
        "Metrics initialized to zero"
    );
}

/// Initialize the per-destination queue metrics to zero.
///
/// Call it right after [`initialize_metrics`] so that
/// `valerter_destination_queue_size` and
/// `valerter_destination_alerts_dropped_total` are visible for every notifier
/// from startup.
///
/// # Arguments
///
/// * `destinations` - `(notifier_name, notifier_type)` of every notifier.
pub fn initialize_destination_metrics(destinations: &[(&str, &str)]) {
    use metrics::{counter, gauge};

    for (notifier_name, notifier_type) in destinations {
        gauge!(
            "valerter_destination_queue_size",
            "notifier_name" => notifier_name.to_string(),
            "notifier_type" => notifier_type.to_string(),
        )
        .set(0.0);
        counter!(
            "valerter_destination_alerts_dropped_total",
            "notifier_name" => notifier_name.to_string(),
            "notifier_type" => notifier_type.to_string(),
        )
        .absolute(0);
    }
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

    // initialize_metrics: label sets seeded from a synthetic inventory

    fn synthetic_inventory() -> MetricsInventory {
        let delivery = |rule: &str, source: &str, name: &str, kind: &str| DeliverySeries {
            rule_name: rule.to_string(),
            vl_source: source.to_string(),
            notifier_name: name.to_string(),
            notifier_type: kind.to_string(),
        };
        let notifier = |name: &str, kind: &str| NotifierSeries {
            name: name.to_string(),
            notifier_type: kind.to_string(),
        };
        MetricsInventory {
            sources: vec!["vlprod".to_string(), "vldev".to_string()],
            rule_sources: vec![
                RuleSourceSeries {
                    rule_name: "re".to_string(),
                    vl_source: "vlprod".to_string(),
                    regex_parser: true,
                },
                RuleSourceSeries {
                    rule_name: "js".to_string(),
                    vl_source: "vldev".to_string(),
                    regex_parser: false,
                },
            ],
            deliveries: vec![
                delivery("re", "vlprod", "hook", "webhook"),
                delivery("re", "vlprod", "mail", "email"),
                delivery("js", "vldev", "tg", "telegram"),
            ],
            notifiers: vec![
                notifier("hook", "webhook"),
                notifier("mail", "email"),
                notifier("tg", "telegram"),
                notifier("tg-idle", "telegram"),
                notifier("idle", "mattermost"),
            ],
        }
    }

    /// Initialize `inventory` under a local recorder and return the
    /// non-comment lines of the rendering.
    fn initialized_series(inventory: &MetricsInventory) -> Vec<String> {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || initialize_metrics(inventory));
        handle
            .render()
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    fn assert_has(series: &[String], expected: &str) {
        assert!(
            series.iter().any(|l| l == expected),
            "missing `{expected}` in:\n{}",
            series.join("\n")
        );
    }

    #[test]
    fn initialize_metrics_seeds_emission_label_sets_at_zero() {
        let series = initialized_series(&synthetic_inventory());

        for expected in [
            r#"valerter_vl_source_up{vl_source="vldev"} 0"#,
            r#"valerter_stream_ends_total{rule_name="re",vl_source="vlprod"} 0"#,
            r#"valerter_reconnections_total{rule_name="js",vl_source="vldev"} 0"#,
            r#"valerter_lines_discarded_total{rule_name="re",vl_source="vlprod",reason="oversized"} 0"#,
            r#"valerter_lines_discarded_total{rule_name="re",vl_source="vlprod",reason="invalid_utf8"} 0"#,
            r#"valerter_parse_errors_total{rule_name="re",vl_source="vlprod",error_type="invalid_json"} 0"#,
            r#"valerter_parse_errors_total{rule_name="re",vl_source="vlprod",error_type="regex_no_match"} 0"#,
            r#"valerter_parse_errors_total{rule_name="js",vl_source="vldev",error_type="invalid_json"} 0"#,
            r#"valerter_alerts_sent_total{rule_name="re",vl_source="vlprod",notifier_name="hook",notifier_type="webhook"} 0"#,
            r#"valerter_notify_errors_total{rule_name="re",vl_source="vlprod",notifier_name="mail",notifier_type="email"} 0"#,
            r#"valerter_alerts_failed_total{rule_name="js",vl_source="vldev",notifier_name="tg",notifier_type="telegram"} 0"#,
            r#"valerter_email_recipient_errors_total{rule_name="re",vl_source="vlprod",notifier_name="mail"} 0"#,
            r#"valerter_telegram_chat_errors_total{rule_name="js",vl_source="vldev",notifier_name="tg"} 0"#,
            r#"valerter_alerts_truncated_total{notifier_type="telegram",notifier_name="tg"} 0"#,
            r#"valerter_alerts_truncated_total{notifier_type="telegram",notifier_name="tg-idle"} 0"#,
        ] {
            assert_has(&series, expected);
        }
    }

    #[test]
    fn initialize_metrics_creates_no_impossible_or_reduced_series() {
        let series = initialized_series(&synthetic_inventory());
        let with_prefix = |prefix: &str| -> Vec<&String> {
            series.iter().filter(|l| l.starts_with(prefix)).collect()
        };

        // No regex_no_match for a JSON-only rule.
        assert!(
            with_prefix(r#"valerter_parse_errors_total{rule_name="js""#)
                .iter()
                .all(|l| !l.contains("regex_no_match"))
        );
        // Every notification series carries the four labels.
        for name in [
            "valerter_alerts_sent_total",
            "valerter_notify_errors_total",
            "valerter_alerts_failed_total",
        ] {
            let lines = with_prefix(&format!("{name}{{"));
            assert_eq!(lines.len(), 3, "{name}: {lines:?}");
            assert!(
                lines
                    .iter()
                    .all(|l| l.contains("notifier_name=") && l.contains("notifier_type=")),
                "{name}: {lines:?}"
            );
        }
        // Per-target error counters only for destinations of the right type.
        assert_eq!(
            with_prefix("valerter_email_recipient_errors_total").len(),
            1
        );
        assert_eq!(with_prefix("valerter_telegram_chat_errors_total").len(), 1);
        // Unused notifiers get no notification series.
        assert!(
            series
                .iter()
                .all(|l| !l.contains(r#"notifier_name="idle""#))
        );
        assert!(
            series
                .iter()
                .all(|l| !l.contains("notifier=") && !l.contains("notifier_config_errors"))
        );
    }

    #[test]
    fn emission_after_initialize_metrics_updates_the_seeded_series() {
        use crate::error::ParseError;
        use crate::notify::{AlertPayload, record_permanent_failure};
        use crate::parser::record_parse_error;

        let alert = AlertPayload {
            mattermost_channel: None,
            message: crate::template::RenderedMessage {
                title: String::new(),
                body: String::new(),
                email_body_html: None,
                accent_color: None,
                ..Default::default()
            },
            rule_name: "re".to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec!["hook".to_string()],
            log_timestamp: String::new(),
            log_timestamp_formatted: String::new(),
            log: AlertPayload::log_from_fields(&serde_json::json!({})),
        };
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            initialize_metrics(&synthetic_inventory());
            record_parse_error("re", "vlprod", &ParseError::NoMatch);
            record_permanent_failure(&alert, "hook", "webhook");
        });
        let rendered = handle.render();

        for (prefix, expected) in [
            (
                r#"valerter_parse_errors_total{rule_name="re",vl_source="vlprod",error_type="regex_no_match"}"#,
                1,
            ),
            (
                r#"valerter_alerts_failed_total{rule_name="re",vl_source="vlprod",notifier_name="hook""#,
                1,
            ),
        ] {
            let lines: Vec<_> = rendered.lines().filter(|l| l.starts_with(prefix)).collect();
            assert_eq!(lines.len(), expected, "one series for {prefix}: {lines:?}");
            assert!(lines[0].ends_with(" 1"), "{lines:?}");
        }
    }

    // build_metrics_inventory

    /// Notifier stub: only its name and type matter to the inventory.
    struct StubNotifier(&'static str, &'static str);

    #[async_trait::async_trait]
    impl crate::Notifier for StubNotifier {
        fn name(&self) -> &str {
            self.0
        }
        fn notifier_type(&self) -> &str {
            self.1
        }
        fn output_format(&self) -> crate::config::OutputFormat {
            crate::config::OutputFormat::Plain
        }
        async fn send(
            &self,
            _alert: &crate::AlertPayload,
        ) -> Result<(), crate::error::NotifyError> {
            Ok(())
        }
    }

    fn inventory_rule(
        name: &str,
        enabled: bool,
        vl_sources: &[&str],
        destinations: &[&str],
        regex: Option<&str>,
    ) -> crate::config::CompiledRule {
        use crate::config::{CompiledParser, CompiledRule, JsonParserConfig, NotifyConfig};
        CompiledRule {
            name: name.to_string(),
            enabled,
            query: "_stream:test".to_string(),
            parser: CompiledParser {
                regex: regex.map(|r| regex::Regex::new(r).unwrap()),
                json: regex.is_none().then(|| JsonParserConfig {
                    fields: vec!["_msg".to_string()],
                }),
            },
            throttle: None,
            notify: NotifyConfig {
                template: "tpl".to_string(),
                mattermost_channel: None,
                destinations: destinations.iter().map(|d| d.to_string()).collect(),
            },
            vl_sources: vl_sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn inventory_config(rules: Vec<crate::config::CompiledRule>) -> RuntimeConfig {
        use crate::config::{
            DEFAULT_MAX_STREAMS, DefaultsConfig, MetricsConfig, ThrottleConfig, VlSourceConfig,
        };
        let source = |url: &str| VlSourceConfig {
            url: url.to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        };
        RuntimeConfig {
            victorialogs: [
                ("vldev".to_string(), source("http://vldev:9428")),
                ("vlprod".to_string(), source("http://vlprod:9428")),
                ("vlstaging".to_string(), source("http://vlstaging:9428")),
            ]
            .into_iter()
            .collect(),
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                timestamp_timezone: "UTC".to_string(),
                max_streams: DEFAULT_MAX_STREAMS,
            },
            templates: std::collections::HashMap::new(),
            rules,
            metrics: MetricsConfig::default(),
            notifiers: None,
            config_dir: std::path::PathBuf::from("."),
        }
    }

    #[test]
    fn metrics_inventory_crosses_rule_sources_with_typed_destinations() {
        let config = inventory_config(vec![
            inventory_rule(
                "errors",
                true,
                &["vlprod", "vldev"],
                &["hook", "mail"],
                Some(r"(?P<x>.*)"),
            ),
            inventory_rule("off", false, &[], &["idle"], None),
        ]);
        let mut registry = NotifierRegistry::new();
        for (name, kind) in [("hook", "webhook"), ("mail", "email"), ("idle", "telegram")] {
            registry
                .register(std::sync::Arc::new(StubNotifier(name, kind)))
                .unwrap();
        }

        let inventory = build_metrics_inventory(&config, &registry);

        assert_eq!(
            inventory.sources,
            ["vldev", "vlprod"],
            "vlstaging, targeted by no enabled rule, gets no vl_source_up series"
        );
        let pairs: Vec<_> = inventory
            .rule_sources
            .iter()
            .map(|p| (p.rule_name.as_str(), p.vl_source.as_str(), p.regex_parser))
            .collect();
        assert_eq!(
            pairs,
            [("errors", "vldev", true), ("errors", "vlprod", true)],
            "the disabled rule gets no series"
        );
        let deliveries: Vec<_> = inventory
            .deliveries
            .iter()
            .map(|d| {
                (
                    d.vl_source.as_str(),
                    d.notifier_name.as_str(),
                    d.notifier_type.as_str(),
                )
            })
            .collect();
        assert_eq!(
            deliveries,
            [
                ("vldev", "hook", "webhook"),
                ("vldev", "mail", "email"),
                ("vlprod", "hook", "webhook"),
                ("vlprod", "mail", "email"),
            ]
        );
        assert!(
            inventory
                .deliveries
                .iter()
                .all(|d| d.notifier_name != "idle"),
            "a notifier used by no enabled rule gets no delivery series"
        );
        let notifiers: Vec<_> = inventory
            .notifiers
            .iter()
            .map(|n| (n.name.as_str(), n.notifier_type.as_str()))
            .collect();
        assert_eq!(
            notifiers,
            [("hook", "webhook"), ("idle", "telegram"), ("mail", "email")]
        );
    }

    #[test]
    fn metrics_inventory_fans_out_empty_vl_sources_to_every_source() {
        let config = inventory_config(vec![inventory_rule("all", true, &[], &[], None)]);

        let inventory = build_metrics_inventory(&config, &NotifierRegistry::new());

        let pairs: Vec<_> = inventory
            .rule_sources
            .iter()
            .map(|p| (p.vl_source.as_str(), p.regex_parser))
            .collect();
        assert_eq!(
            pairs,
            [("vldev", false), ("vlprod", false), ("vlstaging", false)]
        );
        assert!(inventory.deliveries.is_empty());
        assert_eq!(inventory.sources, ["vldev", "vlprod", "vlstaging"]);
    }

    #[test]
    fn metrics_inventory_sources_exclude_untargeted_and_disabled_rule_sources() {
        let config = inventory_config(vec![
            inventory_rule("prod", true, &["vlprod"], &[], None),
            inventory_rule("prod2", true, &["vlprod"], &[], None),
            inventory_rule("off", false, &["vlstaging"], &[], None),
        ]);

        let inventory = build_metrics_inventory(&config, &NotifierRegistry::new());

        assert_eq!(inventory.sources, ["vlprod"]);
    }
}
