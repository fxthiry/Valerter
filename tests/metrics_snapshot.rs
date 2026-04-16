//! `/metrics` snapshot test for the multi-source observability work
//! (v2.0.0 part 2).
//!
//! Spins up a 2-source 1-rule engine plus the real Prometheus metrics
//! exporter on an ephemeral port, exercises every per-rule metric path
//! once (alert sent, alert throttled, parse error, log matched), then
//! scrapes `/metrics` and asserts the **set of metric names + label keys**
//! against an inline expected list. Values and timestamps are intentionally
//! ignored — the test catches accidental metric rename/relabel in future PRs
//! without coupling to runtime numbers.
//!
//! ## Why a separate integration test binary
//!
//! `metrics-exporter-prometheus` installs a global recorder via
//! `PrometheusBuilder::install()`, which can only run once per process. Each
//! integration test binary gets its own process, so this file owns the
//! recorder for its run and does not race with `src/metrics.rs` unit tests
//! or other integration suites.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use valerter::config::{
    CompiledParser, CompiledRule, CompiledTemplate, DEFAULT_MAX_STREAMS, DefaultsConfig,
    JsonParserConfig, MetricsConfig, NotifyConfig, RuntimeConfig, ThrottleConfig, VlSourceConfig,
};
use valerter::notify::{AlertPayload, NotificationQueue};
use valerter::{MetricsServer, RuleEngine};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Re-serialize a JSON value into NDJSON (one event + trailing newline).
fn ndjson_body(events: &[&Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for ev in events {
        out.extend_from_slice(
            serde_json::to_vec(ev)
                .expect("fixture is valid JSON")
                .as_slice(),
        );
        out.push(b'\n');
    }
    out
}

async fn mount_ndjson(server: &MockServer, events: &[&Value]) {
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(ndjson_body(events), "application/x-ndjson"),
        )
        .mount(server)
        .await;
}

fn rule(name: &str, vl_sources: Vec<String>, throttle_count: u32) -> CompiledRule {
    CompiledRule {
        name: name.to_string(),
        enabled: true,
        query: "_stream:test".to_string(),
        parser: CompiledParser {
            regex: None,
            json: Some(JsonParserConfig {
                fields: vec!["_msg".to_string()],
            }),
        },
        throttle: Some(valerter::config::CompiledThrottle {
            key_template: None,
            count: throttle_count,
            window: Duration::from_secs(60),
        }),
        notify: NotifyConfig {
            template: "tpl".to_string(),
            mattermost_channel: None,
            destinations: vec!["dest".to_string()],
        },
        vl_sources,
    }
}

fn vl_source(uri: &str) -> VlSourceConfig {
    VlSourceConfig {
        url: uri.to_string(),
        basic_auth: None,
        headers: None,
        tls: None,
    }
}

fn runtime(sources: BTreeMap<String, VlSourceConfig>, rules: Vec<CompiledRule>) -> RuntimeConfig {
    let mut templates = std::collections::HashMap::new();
    templates.insert(
        "tpl".to_string(),
        CompiledTemplate {
            title: "{{ rule_name }}@{{ vl_source }}".to_string(),
            body: "{{ _msg }}".to_string(),
            email_body_html: None,
            accent_color: None,
        },
    );

    RuntimeConfig {
        victorialogs: sources,
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: DEFAULT_MAX_STREAMS,
        },
        templates,
        rules,
        metrics: MetricsConfig::default(),
        notifiers: None,
        config_dir: std::path::PathBuf::from("."),
    }
}

async fn drain(rx: &mut broadcast::Receiver<AlertPayload>, max: usize, deadline: Duration) {
    let mut got = 0;
    let _ = tokio::time::timeout(deadline, async {
        while got < max {
            match rx.recv().await {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
    })
    .await;
}

/// Parse a Prometheus exposition body and return the set of `name{labelkeys}`
/// strings. Label *values* and metric *values* are stripped; only the metric
/// identifier and the **sorted set of label keys** are kept. This is exactly
/// what we want to catch accidental rename/relabel without coupling to
/// counter values, timestamps, or how many label-value combinations exist.
fn extract_name_label_keys(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Extract name and (optional) labels block. Format: `name{k="v",...} value`
        // or `name value`.
        let (head, _) = match line.split_once(' ') {
            Some(parts) => parts,
            None => continue,
        };
        let (name, label_keys) = if let Some(brace) = head.find('{') {
            let name = &head[..brace];
            let labels_str = &head[brace + 1..head.len() - 1];
            let mut keys: Vec<&str> = labels_str
                .split(',')
                .filter_map(|kv| kv.split_once('=').map(|(k, _)| k))
                .collect();
            keys.sort();
            keys.dedup();
            (name.to_string(), keys.join(","))
        } else {
            (head.to_string(), String::new())
        };
        if label_keys.is_empty() {
            out.insert(name);
        } else {
            out.insert(format!("{}{{{}}}", name, label_keys));
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_snapshot_two_sources_one_rule() {
    // 1) Mock 2 VL sources. Source `vlprod` serves a parseable event so the
    //    engine drives the throttle + alert path. Source `vldev` serves a
    //    line that fails JSON parsing, exercising the parse-error path.
    let vlprod = MockServer::start().await;
    let vldev = MockServer::start().await;

    let good_event: Value = serde_json::json!({
        "_time": "2026-04-15T10:00:00Z",
        "_stream": "{}",
        "_msg": "ok",
    });
    mount_ndjson(&vlprod, &[&good_event, &good_event, &good_event]).await;

    // For vldev, serve raw garbage so the parser increments
    // `valerter_parse_errors_total{rule_name, vl_source, error_type}`.
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"this is not json\n".to_vec(), "application/x-ndjson"),
        )
        .mount(&vldev)
        .await;

    let mut sources = BTreeMap::new();
    sources.insert("vlprod".to_string(), vl_source(&vlprod.uri()));
    sources.insert("vldev".to_string(), vl_source(&vldev.uri()));

    // Throttle count=1 on the only rule so the second event on `vlprod`
    // also exercises the throttled path.
    let rules = vec![rule("snapshot_rule", Vec::new(), 1)];
    let cfg = runtime(sources, rules);

    // 2) Boot the metrics server on an ephemeral port. The recorder install
    //    is a one-shot global; subsequent tests in this same binary cannot
    //    install it again, which is why this file is a dedicated integration
    //    test.
    let port = portpicker::pick_unused_port().expect("free port");
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let metrics_cancel = cancel.clone();
    let metrics_handle = tokio::spawn(async move {
        let server = MetricsServer::with_ready_signal(port, ready_tx);
        let _ = server.run(metrics_cancel).await;
    });
    ready_rx.await.expect("metrics server should signal ready");

    // 3) Initialize all known metric series so the snapshot is deterministic
    //    even before counters tick. Mirrors the call valerter's main does.
    let rule_source_pairs: Vec<(&str, &str)> =
        vec![("snapshot_rule", "vlprod"), ("snapshot_rule", "vldev")];
    let source_names: Vec<&str> = vec!["vlprod", "vldev"];
    // Pass at least one notifier so the per-notifier sentinel counters
    // (`alerts_failed_total{notifier}` / `notify_errors_total{notifier}`)
    // are seeded and the snapshot can assert their presence.
    let notifier_names: Vec<&str> = vec!["sentinel"];
    valerter::initialize_metrics(&rule_source_pairs, &source_names, &notifier_names);

    // 4) Run the engine briefly so each metric path fires at least once.
    let queue = NotificationQueue::new(64);
    let mut rx = queue.subscribe();
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), queue.clone());
    let cancel_for_engine = cancel.clone();
    let engine_handle = tokio::spawn(async move { engine.run(cancel_for_engine).await });

    // Drain a few alerts to make sure the throttle/passed/sent paths run.
    drain(&mut rx, 5, Duration::from_secs(2)).await;

    // 5) Scrape /metrics.
    let url = format!("http://127.0.0.1:{}/metrics", port);
    let body = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("scrape should succeed")
        .text()
        .await
        .expect("body should decode");

    // 6) Tear down. The engine task runs forever until cancelled.
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), engine_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), metrics_handle).await;

    // 7) Assert the snapshot. We check that *every expected* metric series
    //    (name + label-key set) is present. The actual output may carry
    //    additional series from per-(rule, source) initialization that we
    //    explicitly seeded, so we tolerate supersets.
    let actual = extract_name_label_keys(&body);

    // Inline expected snapshot. Sorted alphabetically for stable diffs.
    // Each entry is `metric_name{label_keys_csv_sorted}` or just
    // `metric_name` when unlabeled.
    let expected: Arc<[&'static str]> = Arc::from([
        // Per-(rule, source) counters seeded by initialize_metrics.
        "valerter_alerts_passed_total{rule_name,vl_source}",
        "valerter_alerts_sent_total{rule_name,vl_source}",
        "valerter_alerts_throttled_total{rule_name,vl_source}",
        "valerter_logs_matched_total{rule_name,vl_source}",
        "valerter_parse_errors_total{rule_name,vl_source}",
        "valerter_reconnections_total{rule_name,vl_source}",
        "valerter_rule_errors_total{rule_name,vl_source}",
        "valerter_rule_panics_total{rule_name,vl_source}",
        // Per-(rule, source) discarded counter (3-label, reason="oversized").
        "valerter_lines_discarded_total{reason,rule_name,vl_source}",
        // Per-(rule, source) gauge for last query timestamp.
        "valerter_last_query_timestamp{rule_name,vl_source}",
        // Per-(rule, source) histogram exported as a Prometheus summary by
        // metrics-exporter-prometheus: emits the metric with `quantile` label
        // plus `_sum` and `_count` companion series.
        "valerter_query_duration_seconds{quantile,rule_name,vl_source}",
        "valerter_query_duration_seconds_count{rule_name,vl_source}",
        "valerter_query_duration_seconds_sum{rule_name,vl_source}",
        // Per-notifier sentinel counters.
        "valerter_alerts_failed_total{notifier}",
        "valerter_notify_errors_total{notifier}",
        // Global / shared counters & gauges.
        "valerter_alerts_dropped_total",
        "valerter_queue_size",
        "valerter_uptime_seconds",
        // Per-source reachability gauge (replaces the old per-rule
        // valerter_victorialogs_up).
        "valerter_vl_source_up{vl_source}",
        // Build info carries only the version label.
        "valerter_build_info{version}",
    ]);

    let mut missing: Vec<String> = Vec::new();
    for want in expected.iter() {
        if !actual.contains(*want) {
            missing.push((*want).to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "metrics snapshot missing expected series:\n  missing = {:#?}\n\n  actual = {:#?}\n\n  raw body =\n{}",
        missing,
        actual,
        body
    );

    // Hard regression: the v1.x per-rule gauge MUST be gone in v2.0.0.
    assert!(
        !actual
            .iter()
            .any(|s| s.starts_with("valerter_victorialogs_up")),
        "valerter_victorialogs_up must be removed in v2.0.0 (replaced by valerter_vl_source_up). Found in /metrics:\n{}",
        body
    );
}
