//! End-to-end integration test for the v2.0.0 multi-source VL core.
//!
//! Spins up **two** wiremock `MockServer` instances to stand in for two
//! VictoriaLogs sources (`vlprod`, `vldev`), serves distinct fixture events
//! on each, runs `RuleEngine` against the pair, and inspects the alert
//! payloads delivered through the notification queue to prove:
//!
//! 1. A rule with `vl_sources: [vlprod]` spawns exactly one task and its
//!    payloads carry `vl_source == "vlprod"`.
//! 2. A rule with empty `vl_sources` fans out across every source and
//!    payloads arrive tagged with each source name.
//! 3. The synthetic `vl_source` field is rendered in template output
//!    (layer 1) and survives in `AlertPayload` for layer 2 notifiers.
//! 4. Per-source default throttle buckets are isolated: two sources sending
//!    identical events both pass through on first delivery rather than the
//!    second being dropped as a duplicate.
//! 5. The throttle cache is shared by a rule's sources: a custom key without
//!    `vl_source` dedups across them, one with `vl_source` keeps them apart.
//!
//! The fixture corpus from `tests/fixtures/vl_events/` (chore/vl-fixtures-corpus)
//! is consumed via `common::vl_events::load_fixture`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use valerter::config::{
    CompiledParser, CompiledRule, CompiledTemplate, CompiledThrottle, DefaultsConfig,
    JsonParserConfig, MetricsConfig, NotifyConfig, RuntimeConfig, ThrottleConfig, VlSourceConfig,
};
use valerter::notify::AlertPayload;
use valerter::{RuleEngine, TemplateEngine};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::recording::RecordingDelivery;
use common::vl_events::load_fixture;

/// Re-serialize a JSON fixture (which in the corpus is a single object) into
/// an NDJSON response body — one JSON object followed by a trailing newline.
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

/// Build an NDJSON mock that replies once with the given events.
async fn mount_ndjson(server: &MockServer, events: &[&Value]) {
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(ndjson_body(events), "application/x-ndjson"),
        )
        .mount(server)
        .await;
}

fn rule(name: &str, vl_sources: Vec<String>) -> CompiledRule {
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
        throttle: None,
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
            title: "[{{ vl_source }}] {{ rule_name }}".to_string(),
            body: "source={{ vl_source }} msg={{ _msg }}".to_string(),
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
            max_streams: valerter::config::DEFAULT_MAX_STREAMS,
        },
        templates,
        rules,
        metrics: MetricsConfig::default(),
        notifiers: None,
        config_dir: std::path::PathBuf::from("."),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_rule_with_vl_sources_list_targets_single_source() {
    let vlprod = MockServer::start().await;
    let vldev = MockServer::start().await;

    let ev_prod = load_fixture("nginx_http_400.json");
    let ev_dev = load_fixture("nginx_http_500.json");

    mount_ndjson(&vlprod, &[&ev_prod]).await;
    mount_ndjson(&vldev, &[&ev_dev]).await;

    let mut sources = BTreeMap::new();
    sources.insert("vlprod".to_string(), vl_source(&vlprod.uri()));
    sources.insert("vldev".to_string(), vl_source(&vldev.uri()));

    // Rule pinned to vlprod only. vldev's stream must never produce an alert
    // via this rule.
    let rules = vec![rule("prod_only", vec!["vlprod".to_string()])];

    let mut delivery = RecordingDelivery::start(&["dest"]);

    let cfg = runtime(sources, rules);
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), delivery.queue.clone());

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

    let alerts = delivery.drain(1, Duration::from_secs(3)).await;
    // Negative-evidence proof: vldev MUST NOT have served any tail request,
    // since the only rule is pinned to vlprod. Catches regressions where the
    // resolve_sources filter is bypassed and the rule fans out anyway.
    let vldev_hits = vldev.received_requests().await.unwrap_or_default();
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    delivery.shutdown().await;

    assert!(
        !alerts.is_empty(),
        "rule pinned to vlprod should have produced at least one alert"
    );
    for a in &alerts {
        assert_eq!(
            a.vl_source, "vlprod",
            "payload carried wrong vl_source: {}",
            a.vl_source
        );
        assert!(
            a.message.title.contains("vlprod"),
            "layer 1 title must contain rendered vl_source, got: {}",
            a.message.title
        );
    }
    assert!(
        vldev_hits.is_empty(),
        "vldev served {} request(s) for a rule pinned to vlprod (negative-evidence assertion)",
        vldev_hits.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_rule_without_vl_sources_fans_out_across_all() {
    let vlprod = MockServer::start().await;
    let vldev = MockServer::start().await;

    let ev = load_fixture("k8s_pod_oom.json");
    mount_ndjson(&vlprod, &[&ev]).await;
    mount_ndjson(&vldev, &[&ev]).await;

    let mut sources = BTreeMap::new();
    sources.insert("vlprod".to_string(), vl_source(&vlprod.uri()));
    sources.insert("vldev".to_string(), vl_source(&vldev.uri()));

    // vl_sources empty = fan out across all sources.
    let rules = vec![rule("fan_out", Vec::new())];

    let mut delivery = RecordingDelivery::start(&["dest"]);
    let cfg = runtime(sources, rules);
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), delivery.queue.clone());

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

    // Drain a fixed time window with a high `max` so we don't exit before
    // the slower of the two parallel source tasks delivers its first alert.
    let alerts = delivery.drain(200, Duration::from_secs(2)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    delivery.shutdown().await;

    let mut sources_seen: std::collections::HashSet<String> = Default::default();
    for a in &alerts {
        sources_seen.insert(a.vl_source.clone());
    }

    assert!(
        sources_seen.contains("vlprod"),
        "expected vlprod alert, got sources: {:?}",
        sources_seen
    );
    assert!(
        sources_seen.contains("vldev"),
        "expected vldev alert, got sources: {:?}",
        sources_seen
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_default_throttle_buckets_are_isolated_per_source() {
    // The same event delivered twice on two different sources must not be
    // deduped as a single bucket when the rule uses the default throttle
    // (no custom key). The throttle cache is shared by the rule's sources,
    // but the default key `{rule}-{source}:global` differs per source, so
    // each source counts in its own bucket and both alerts should land.
    let vlprod = MockServer::start().await;
    let vldev = MockServer::start().await;

    // Low count (=1) would cause a cross-source collision under v1 default.
    let ev = load_fixture("nginx_http_500.json");
    mount_ndjson(&vlprod, &[&ev]).await;
    mount_ndjson(&vldev, &[&ev]).await;

    let mut sources = BTreeMap::new();
    sources.insert("vlprod".to_string(), vl_source(&vlprod.uri()));
    sources.insert("vldev".to_string(), vl_source(&vldev.uri()));

    // Tight throttle count=1: if both sources rendered the same key the
    // second one would be blocked.
    let mut cfg = runtime(sources, vec![rule("isolate", Vec::new())]);
    cfg.defaults.throttle.count = 1;

    let mut delivery = RecordingDelivery::start(&["dest"]);
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), delivery.queue.clone());

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

    // Drain for a fixed window long enough for both sources' first stream
    // to land. With throttle count=1 each per-source key allows only one
    // alert through, but the two keys are distinct so both sources deliver.
    // Use a high `max` so we don't exit early before both sources land.
    let alerts = delivery.drain(100, Duration::from_secs(2)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    delivery.shutdown().await;

    let sources_seen: std::collections::HashSet<String> =
        alerts.iter().map(|a| a.vl_source.clone()).collect();

    assert!(
        sources_seen.contains("vlprod") && sources_seen.contains("vldev"),
        "per-source default throttle buckets must be isolated; saw: {:?} (alerts: {})",
        sources_seen,
        alerts.len()
    );
}

/// Run a fan-out rule with the given throttle key and `count: 1` against two
/// sources serving the same event, and return the alerts drained.
async fn run_shared_event_with_throttle_key(rule_name: &str, key: &str) -> Vec<AlertPayload> {
    let vlprod = MockServer::start().await;
    let vldev = MockServer::start().await;

    let ev = load_fixture("nginx_http_500.json");
    mount_ndjson(&vlprod, &[&ev]).await;
    mount_ndjson(&vldev, &[&ev]).await;

    let mut sources = BTreeMap::new();
    sources.insert("vlprod".to_string(), vl_source(&vlprod.uri()));
    sources.insert("vldev".to_string(), vl_source(&vldev.uri()));

    // Long window: the mocks re-serve the event on every reconnection, all
    // of which must land in the same window.
    let mut r = rule(rule_name, Vec::new());
    r.throttle = Some(CompiledThrottle {
        key_template: Some(key.to_string()),
        count: 1,
        window: Duration::from_secs(3600),
    });
    let cfg = runtime(sources, vec![r]);

    let mut delivery = RecordingDelivery::start(&["dest"]);
    let engine = RuleEngine::new(cfg, reqwest::Client::new(), delivery.queue.clone());

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

    // Fixed drain window with a high `max`: we must observe that no extra
    // alert arrives, not just that the first one did.
    let alerts = delivery.drain(100, Duration::from_secs(2)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    delivery.shutdown().await;
    alerts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_rule_name_key_dedups_across_sources() {
    // `{{ rule_name }}` renders the same key on both sources, and the rule's
    // throttle cache is shared: only the first event of either source passes.
    let alerts = run_shared_event_with_throttle_key("dedup", "{{ rule_name }}").await;

    let sources: Vec<&str> = alerts.iter().map(|a| a.vl_source.as_str()).collect();
    assert_eq!(
        alerts.len(),
        1,
        "a key shared across sources must dedup to one alert; got sources {:?}",
        sources
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_vl_source_key_isolates_sources() {
    // Adding `{{ vl_source }}` to the key gives each source its own counter.
    let alerts =
        run_shared_event_with_throttle_key("isolate_key", "{{ vl_source }}-{{ _msg }}").await;

    let count = |source: &str| alerts.iter().filter(|a| a.vl_source == source).count();
    assert_eq!(
        (count("vlprod"), count("vldev")),
        (1, 1),
        "a key with vl_source must let exactly one alert per source through (alerts: {})",
        alerts.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_source_event_field_named_vl_source_is_masked_by_synthetic() {
    // If an event literally carries a `vl_source` field, the synthetic
    // value wins in layer 1 and in the AlertPayload (collision policy
    // matches rule_name, v1.2.1).
    let server = MockServer::start().await;

    // Build an event with a hostile literal vl_source value. Use a minimal
    // VL shape: _time, _stream, _msg, plus the collision field.
    let hostile: Value = serde_json::json!({
        "_time": "2026-04-15T10:00:00Z",
        "_stream": "{}",
        "_msg": "hostile",
        "vl_source": "evil"
    });
    mount_ndjson(&server, &[&hostile]).await;

    let mut sources = BTreeMap::new();
    sources.insert("real_source".to_string(), vl_source(&server.uri()));

    let rules = vec![rule("collision", Vec::new())];

    let mut delivery = RecordingDelivery::start(&["dest"]);
    let engine = RuleEngine::new(
        runtime(sources, rules),
        reqwest::Client::new(),
        delivery.queue.clone(),
    );

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

    let alerts = delivery.drain(1, Duration::from_secs(3)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    delivery.shutdown().await;

    assert!(!alerts.is_empty(), "expected at least one alert");
    for a in &alerts {
        assert_eq!(
            a.vl_source, "real_source",
            "AlertPayload.vl_source must be synthetic, not event-literal 'evil'"
        );
        assert!(
            a.message.title.contains("real_source"),
            "layer 1 title must show synthetic vl_source, got: {}",
            a.message.title
        );
        assert!(
            !a.message.title.contains("evil"),
            "title must not leak event-literal 'evil' into rendered output: {}",
            a.message.title
        );
    }
}

#[tokio::test]
async fn template_engine_renders_vl_source_directly_without_http() {
    // Smoke test the template-level contract independently of the engine
    // so that if the integration tests above time out in CI under load we
    // still have a fast unit-level guarantee that vl_source threads through
    // layer 1. This also doubles as an assertion that the fixture corpus is
    // consumable from template rendering (guards against future shape drift).
    let mut templates = std::collections::HashMap::new();
    templates.insert(
        "tpl".to_string(),
        CompiledTemplate {
            title: "[{{ vl_source }}] {{ rule_name }} {{ _msg }}".to_string(),
            body: "b".to_string(),
            email_body_html: None,
            accent_color: None,
        },
    );
    let engine = Arc::new(TemplateEngine::new(templates));

    let ev = load_fixture("nginx_http_400.json");
    let rendered = engine.render_with_fallback("tpl", &ev, "nginx_rule", "vlprod");

    assert!(
        rendered.title.starts_with("[vlprod] nginx_rule "),
        "expected title to include synthetic vl_source, got: {}",
        rendered.title
    );
}
