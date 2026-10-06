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
use tokio_util::sync::CancellationToken;
use valerter::config::{
    CompiledParser, CompiledRule, CompiledTemplate, DEFAULT_MAX_STREAMS, DefaultsConfig,
    JsonParserConfig, MetricsConfig, NotifyConfig, RuntimeConfig, SecretString, ThrottleConfig,
    VlSourceConfig, WebhookNotifierConfig,
};
use valerter::notify::WebhookNotifier;
use valerter::{
    DEFAULT_QUEUE_CAPACITY, MetricsServer, NotificationQueue, NotificationWorker, NotifierRegistry,
    RuleEngine,
};
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
            body_format: valerter::config::BodyFormat::Text,
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

/// Real webhook notifier posting to `server`.
fn webhook(name: &str, server: &MockServer) -> Arc<WebhookNotifier> {
    let config = WebhookNotifierConfig {
        url: SecretString::new(format!("{}/hook", server.uri())),
        method: "POST".to_string(),
        headers: std::collections::HashMap::new(),
        body_template: None,
        format: None,
    };
    Arc::new(WebhookNotifier::from_config(name, &config, reqwest::Client::new()).unwrap())
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
    // Declared but targeted by no rule: never tailed, so no vl_source_up.
    sources.insert(
        "vlarchive".to_string(),
        vl_source("http://vlarchive.invalid:9428"),
    );

    // Throttle count=1 on the only rule so the second event on `vlprod`
    // also exercises the throttled path.
    let rules = vec![rule(
        "snapshot_rule",
        vec!["vldev".to_string(), "vlprod".to_string()],
        1,
    )];
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

    // 3) Real delivery path: `dest` is a webhook notifier posting to a
    //    wiremock endpoint, `idle` is declared but used by no rule.
    let hook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook_server)
        .await;
    let mut registry = NotifierRegistry::new();
    registry.register(webhook("dest", &hook_server)).unwrap();
    registry.register(webhook("idle", &hook_server)).unwrap();
    let registry = Arc::new(registry);

    // 4) Initialize all known metric series so the snapshot is deterministic
    //    even before counters tick, from the inventory valerter's main
    //    builds: one pair per (rule, source), one triplet per destination.
    let inventory = valerter::build_metrics_inventory(&cfg, &registry);
    assert_eq!(inventory.sources, ["vldev", "vlprod"]);
    valerter::initialize_metrics(&inventory);
    // Per-destination queue series, seeded for every notifier. `idle` never
    // receives an alert, so its series must stay at their initial zero.
    let destinations: Vec<(&str, &str)> = inventory
        .notifiers
        .iter()
        .map(|n| (n.name.as_str(), n.notifier_type.as_str()))
        .collect();
    assert_eq!(destinations, [("dest", "webhook"), ("idle", "webhook")]);
    valerter::initialize_destination_metrics(&destinations);

    // Scrape before any event: every seeded series is at 0.
    let url = format!("http://127.0.0.1:{}/metrics", port);
    let initial = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("scrape should succeed")
        .text()
        .await
        .expect("body should decode");

    // 5) Run the engine briefly so each metric path fires at least once.
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY, &registry);
    let mut worker = NotificationWorker::new(&queue, registry.clone());
    let worker_cancel = CancellationToken::new();
    let worker_cancel_clone = worker_cancel.clone();
    let worker_handle = tokio::spawn(async move { worker.run(worker_cancel_clone).await });
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), queue.clone());
    let cancel_for_engine = cancel.clone();
    let engine_handle = tokio::spawn(async move { engine.run(cancel_for_engine).await });

    // Wait until the webhook delivered at least one alert, so the
    // throttle/passed/sent paths ran.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hook_server.received_requests().await.unwrap().is_empty()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Let the worker record the metrics of the delivered alerts.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6) Scrape /metrics.
    let body = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("scrape should succeed")
        .text()
        .await
        .expect("body should decode");

    // 7) Tear down. The engine task runs forever until cancelled.
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), engine_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), metrics_handle).await;
    worker_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), worker_handle).await;

    // 8) Assert the snapshot. We check that *every expected* metric series
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
        "valerter_alerts_throttled_total{rule_name,vl_source}",
        "valerter_logs_matched_total{rule_name,vl_source}",
        "valerter_reconnections_total{rule_name,vl_source}",
        "valerter_rule_errors_total{rule_name,vl_source}",
        "valerter_rule_panics_total{rule_name,vl_source}",
        "valerter_stream_ends_total{rule_name,vl_source}",
        // Per-(rule, source) counters carrying their emission label.
        "valerter_lines_discarded_total{reason,rule_name,vl_source}",
        "valerter_parse_errors_total{error_type,rule_name,vl_source}",
        // Per-(rule, source) gauge for last query timestamp.
        "valerter_last_query_timestamp{rule_name,vl_source}",
        // Per-(rule, source) histogram exported as a Prometheus summary by
        // metrics-exporter-prometheus: emits the metric with `quantile` label
        // plus `_sum` and `_count` companion series.
        "valerter_query_duration_seconds{quantile,rule_name,vl_source}",
        "valerter_query_duration_seconds_count{rule_name,vl_source}",
        "valerter_query_duration_seconds_sum{rule_name,vl_source}",
        // Per-(rule, source, destination) notification counters.
        "valerter_alerts_failed_total{notifier_name,notifier_type,rule_name,vl_source}",
        "valerter_alerts_sent_total{notifier_name,notifier_type,rule_name,vl_source}",
        "valerter_notify_errors_total{notifier_name,notifier_type,rule_name,vl_source}",
        // Global / shared counters & gauges.
        "valerter_alerts_dropped_total",
        "valerter_queue_size",
        // Per-destination queue series seeded by initialize_destination_metrics.
        "valerter_destination_alerts_dropped_total{notifier_name,notifier_type}",
        "valerter_destination_queue_size{notifier_name,notifier_type}",
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

    // Before any event, every seeded series is present at 0, with the
    // label values of its emission.
    for series in [
        "valerter_alerts_sent_total{rule_name=\"snapshot_rule\",vl_source=\"vlprod\",notifier_name=\"dest\",notifier_type=\"webhook\"} 0",
        "valerter_alerts_failed_total{rule_name=\"snapshot_rule\",vl_source=\"vldev\",notifier_name=\"dest\",notifier_type=\"webhook\"} 0",
        "valerter_parse_errors_total{rule_name=\"snapshot_rule\",vl_source=\"vldev\",error_type=\"invalid_json\"} 0",
        "valerter_lines_discarded_total{rule_name=\"snapshot_rule\",vl_source=\"vlprod\",reason=\"invalid_utf8\"} 0",
        "valerter_stream_ends_total{rule_name=\"snapshot_rule\",vl_source=\"vlprod\"} 0",
    ] {
        assert!(
            initial.lines().any(|l| l == series),
            "missing `{}` in the initial /metrics:\n{}",
            series,
            initial
        );
    }

    // The seeded series is the one incremented: a single alerts_sent series
    // for (snapshot_rule, vlprod), now above 0.
    let sent_prod: Vec<&str> = body
        .lines()
        .filter(|l| {
            l.starts_with("valerter_alerts_sent_total{") && l.contains("vl_source=\"vlprod\"")
        })
        .collect();
    assert_eq!(
        sent_prod.len(),
        1,
        "one alerts_sent series: {:?}",
        sent_prod
    );
    assert!(
        sent_prod[0].starts_with(
            "valerter_alerts_sent_total{rule_name=\"snapshot_rule\",vl_source=\"vlprod\",notifier_name=\"dest\",notifier_type=\"webhook\"} "
        ) && !sent_prod[0].ends_with(" 0"),
        "unexpected alerts_sent series: {:?}",
        sent_prod
    );

    // The per-destination series exist at 0 for a notifier that never
    // received anything.
    for series in [
        "valerter_destination_queue_size{notifier_name=\"idle\",notifier_type=\"webhook\"} 0",
        "valerter_destination_alerts_dropped_total{notifier_name=\"idle\",notifier_type=\"webhook\"} 0",
    ] {
        assert!(
            body.lines().any(|l| l == series),
            "missing `{}` in /metrics:\n{}",
            series,
            body
        );
    }

    // A notifier used by no rule gets no notification series.
    assert!(
        !body
            .lines()
            .any(|l| l.starts_with("valerter_alerts_") && l.contains("notifier_name=\"idle\"")),
        "no notification series for the unused notifier:\n{}",
        body
    );

    // Reduced label sets are gone: no `{notifier}` series, no alerts_sent
    // without notifier_name, no parse_errors without error_type, and no
    // notifier config error counter.
    for forbidden in [
        "valerter_alerts_failed_total{notifier}",
        "valerter_notify_errors_total{notifier}",
        "valerter_alerts_sent_total{rule_name,vl_source}",
        "valerter_parse_errors_total{rule_name,vl_source}",
    ] {
        assert!(
            !actual.contains(forbidden),
            "series `{}` must not exist:\n{}",
            forbidden,
            body
        );
    }
    assert!(
        !body.contains("notifier=\""),
        "no series may carry a `notifier` label:\n{}",
        body
    );
    assert!(
        !body.contains("valerter_notifier_config_errors_total"),
        "valerter_notifier_config_errors_total must be removed:\n{}",
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

    // A declared source no enabled rule targets has no vl_source_up series.
    for scrape in [&initial, &body] {
        assert!(
            !scrape.contains(r#"valerter_vl_source_up{vl_source="vlarchive"}"#),
            "untargeted source must not get valerter_vl_source_up:\n{}",
            scrape
        );
        assert!(!scrape.contains("vlarchive"), "{}", scrape);
    }
}
