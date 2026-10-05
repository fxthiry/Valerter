//! Unit tests for notify module.

use super::*;
use async_trait::async_trait;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use tokio::sync::mpsc;

use crate::config::{
    EmailNotifierConfig, MattermostNotifierConfig, NotifierConfig, SecretString, SmtpConfig,
    TelegramNotifierConfig, TlsMode, WebhookNotifierConfig,
};
use crate::error::NotifyError;
use crate::template::RenderedMessage;

fn test_config_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn make_payload(rule_name: &str) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body".to_string(),
            email_body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: rule_name.to_string(),
        vl_source: "vlprod".to_string(),
        destinations: vec![], // Uses default notifier
        log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
    }
}

fn make_payload_with_destinations(rule_name: &str, destinations: Vec<String>) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body".to_string(),
            email_body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: rule_name.to_string(),
        vl_source: "vlprod".to_string(),
        destinations,
        log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
    }
}

struct TestNotifier {
    name: String,
    notifier_type: String,
    should_fail: bool,
}

#[async_trait]
impl Notifier for TestNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        &self.notifier_type
    }

    async fn send(&self, _alert: &AlertPayload) -> Result<(), NotifyError> {
        if self.should_fail {
            Err(NotifyError::SendFailed("test failure".to_string()))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn notifier_trait_methods() {
    let notifier = TestNotifier {
        name: "test-notifier".to_string(),
        notifier_type: "test".to_string(),
        should_fail: false,
    };

    assert_eq!(notifier.name(), "test-notifier");
    assert_eq!(notifier.notifier_type(), "test");

    let payload = make_payload("test_rule");
    assert!(notifier.send(&payload).await.is_ok());
}

#[tokio::test]
async fn notifier_trait_failure() {
    let notifier = TestNotifier {
        name: "failing-notifier".to_string(),
        notifier_type: "test".to_string(),
        should_fail: true,
    };

    let payload = make_payload("test_rule");
    assert!(notifier.send(&payload).await.is_err());
}

#[test]
fn registry_register_and_get() {
    let mut registry = NotifierRegistry::new();
    let notifier = Arc::new(TestNotifier {
        name: "test-1".to_string(),
        notifier_type: "test".to_string(),
        should_fail: false,
    });

    assert!(registry.register(notifier).is_ok());
    assert!(registry.get("test-1").is_some());
    assert!(registry.get("nonexistent").is_none());
}

#[test]
fn registry_duplicate_name_error() {
    let mut registry = NotifierRegistry::new();
    let notifier1 = Arc::new(TestNotifier {
        name: "same-name".to_string(),
        notifier_type: "test".to_string(),
        should_fail: false,
    });
    let notifier2 = Arc::new(TestNotifier {
        name: "same-name".to_string(),
        notifier_type: "test".to_string(),
        should_fail: false,
    });

    assert!(registry.register(notifier1).is_ok());
    assert!(registry.register(notifier2).is_err());
}

#[test]
fn registry_names() {
    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(TestNotifier {
            name: "alpha".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();
    registry
        .register(Arc::new(TestNotifier {
            name: "beta".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();

    let names: Vec<_> = registry.names().collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));
}

#[test]
fn registry_validate_destinations_success() {
    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(TestNotifier {
            name: "notifier-a".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();
    registry
        .register(Arc::new(TestNotifier {
            name: "notifier-b".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();

    let result =
        registry.validate_destinations(&["notifier-a".to_string(), "notifier-b".to_string()]);
    assert!(result.is_ok());
}

#[test]
fn registry_validate_destinations_failure() {
    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(TestNotifier {
            name: "exists".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();

    let result = registry.validate_destinations(&[
        "exists".to_string(),
        "unknown1".to_string(),
        "unknown2".to_string(),
    ]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown1"));
    assert!(msg.contains("unknown2"));
}

#[test]
fn registry_is_empty_and_len() {
    let mut registry = NotifierRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    registry
        .register(Arc::new(TestNotifier {
            name: "test".to_string(),
            notifier_type: "test".to_string(),
            should_fail: false,
        }))
        .unwrap();

    assert!(!registry.is_empty());
    assert_eq!(registry.len(), 1);
}

#[test]
#[serial]
fn registry_from_config_creates_mattermost_notifiers() {
    // Use temp_env for safe env var handling (Fix M3)
    temp_env::with_var(
        "TEST_MM_WEBHOOK",
        Some("https://mm.example.com/hooks/test123"),
        || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "mattermost-infra".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new("${TEST_MM_WEBHOOK}".to_string()),
                    channel: Some("infra-alerts".to_string()),
                    username: Some("valerter".to_string()),
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "mattermost-ops".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new(
                        "https://static.example.com/hooks/static".to_string(),
                    ),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(
                result.is_ok(),
                "from_config should succeed: {:?}",
                result.err()
            );
            let registry = result.unwrap();

            assert_eq!(registry.len(), 2);
            assert!(registry.get("mattermost-infra").is_some());
            assert!(registry.get("mattermost-ops").is_some());

            // Check types
            let infra = registry.get("mattermost-infra").unwrap();
            assert_eq!(infra.name(), "mattermost-infra");
            assert_eq!(infra.notifier_type(), "mattermost");
        },
    );
}

#[test]
#[serial]
fn registry_from_config_fails_on_undefined_env_var() {
    // Use temp_env to ensure env var doesn't exist (Fix M3)
    temp_env::with_var("UNDEFINED_WEBHOOK_VAR", None::<&str>, || {
        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "bad-notifier".to_string(),
            NotifierConfig::Mattermost(MattermostNotifierConfig {
                webhook_url: SecretString::new("${UNDEFINED_WEBHOOK_VAR}".to_string()),
                channel: None,
                username: None,
                icon_url: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);

        match &errors[0] {
            crate::error::ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-notifier");
                assert!(
                    message.contains("UNDEFINED_WEBHOOK_VAR"),
                    "Error should mention the undefined var: {}",
                    message
                );
            }
            other => panic!("Expected InvalidNotifier, got {:?}", other),
        }
    });
}

#[test]
#[serial]
fn registry_from_config_collects_all_errors() {
    // Use temp_env to ensure env vars don't exist (Fix M3)
    temp_env::with_vars(
        [
            ("UNDEFINED_VAR_1", None::<&str>),
            ("UNDEFINED_VAR_2", None::<&str>),
        ],
        || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "bad-notifier-1".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new("${UNDEFINED_VAR_1}".to_string()),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "bad-notifier-2".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new("${UNDEFINED_VAR_2}".to_string()),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(
                errors.len(),
                2,
                "Should collect all errors, not stop at first"
            );
        },
    );
}

#[test]
fn registry_from_config_empty_config_returns_empty_registry() {
    let notifiers_config = HashMap::new();
    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    assert!(result.is_ok());
    let registry = result.unwrap();
    assert!(registry.is_empty());
}

#[test]
#[serial]
fn registry_from_config_creates_webhook_notifiers() {
    temp_env::with_var("TEST_WEBHOOK_TOKEN", Some("secret-token-abc123"), || {
        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "webhook-alerts".to_string(),
            NotifierConfig::Webhook(WebhookNotifierConfig {
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "POST".to_string(),
                headers: {
                    let mut h = std::collections::HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        SecretString::new("Bearer ${TEST_WEBHOOK_TOKEN}".to_string()),
                    );
                    h.insert(
                        "Content-Type".to_string(),
                        SecretString::new("application/json".to_string()),
                    );
                    h
                },
                body_template: Some(r#"{"alert": "{{ title }}"}"#.to_string()),
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(
            result.is_ok(),
            "Should successfully create webhook notifier: {:?}",
            result
        );
        let registry = result.unwrap();
        assert_eq!(registry.len(), 1);

        let notifier = registry.get("webhook-alerts");
        assert!(notifier.is_some());
        let notifier = notifier.unwrap();
        assert_eq!(notifier.name(), "webhook-alerts");
        assert_eq!(notifier.notifier_type(), "webhook");
    });
}

#[test]
fn registry_from_config_webhook_with_defaults() {
    let mut notifiers_config = HashMap::new();
    notifiers_config.insert(
        "simple-webhook".to_string(),
        NotifierConfig::Webhook(WebhookNotifierConfig {
            url: SecretString::new("https://api.example.com/hook".to_string()),
            method: "POST".to_string(),
            headers: std::collections::HashMap::new(),
            body_template: None,
        }),
    );

    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    assert!(result.is_ok());
    let registry = result.unwrap();
    assert_eq!(registry.len(), 1);

    let notifier = registry.get("simple-webhook");
    assert!(notifier.is_some());
    assert_eq!(notifier.unwrap().notifier_type(), "webhook");
}

#[test]
#[serial]
fn registry_from_config_webhook_fails_on_undefined_env_var() {
    temp_env::with_var("UNDEFINED_WEBHOOK_TOKEN", None::<&str>, || {
        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "bad-webhook".to_string(),
            NotifierConfig::Webhook(WebhookNotifierConfig {
                url: SecretString::new("https://api.example.com/alerts".to_string()),
                method: "POST".to_string(),
                headers: {
                    let mut h = std::collections::HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        SecretString::new("Bearer ${UNDEFINED_WEBHOOK_TOKEN}".to_string()),
                    );
                    h
                },
                body_template: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);

        match &errors[0] {
            crate::error::ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-webhook");
                assert!(message.contains("Authorization"));
                assert!(message.contains("UNDEFINED_WEBHOOK_TOKEN"));
            }
            other => panic!("Expected InvalidNotifier, got {:?}", other),
        }
    });
}

#[test]
#[serial]
fn registry_from_config_mixed_notifiers() {
    temp_env::with_vars(
        [
            (
                "TEST_MM_WEBHOOK_MIXED",
                Some("https://mm.example.com/hooks/abc"),
            ),
            ("TEST_WH_TOKEN_MIXED", Some("token-xyz")),
        ],
        || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "mattermost-1".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new("${TEST_MM_WEBHOOK_MIXED}".to_string()),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "webhook-1".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: SecretString::new("https://api.example.com/alerts".to_string()),
                    method: "POST".to_string(),
                    headers: {
                        let mut h = std::collections::HashMap::new();
                        h.insert(
                            "X-API-Key".to_string(),
                            SecretString::new("${TEST_WH_TOKEN_MIXED}".to_string()),
                        );
                        h
                    },
                    body_template: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(
                result.is_ok(),
                "Should create mixed notifiers: {:?}",
                result
            );
            let registry = result.unwrap();
            assert_eq!(registry.len(), 2);

            let mm = registry.get("mattermost-1");
            assert!(mm.is_some());
            assert_eq!(mm.unwrap().notifier_type(), "mattermost");

            let wh = registry.get("webhook-1");
            assert!(wh.is_some());
            assert_eq!(wh.unwrap().notifier_type(), "webhook");
        },
    );
}

// ============================================================================
// Notification queue: one queue and one delivery task per destination
// ============================================================================

/// Registry of `TestNotifier`s that always succeed.
fn make_ok_registry(names: &[&str]) -> NotifierRegistry {
    let mut registry = NotifierRegistry::new();
    for name in names {
        registry
            .register(Arc::new(TestNotifier {
                name: name.to_string(),
                notifier_type: "test".to_string(),
                should_fail: false,
            }))
            .unwrap();
    }
    registry
}

fn to(rule_name: &str, destinations: &[&str]) -> AlertPayload {
    make_payload_with_destinations(
        rule_name,
        destinations.iter().map(|d| d.to_string()).collect(),
    )
}

/// Notifier recording the rule name of every alert it delivers.
///
/// Optionally panics on its first alert, or waits on `gate` after recording
/// each alert (to keep a send in flight).
struct RecordingTestNotifier {
    name: String,
    tx: mpsc::UnboundedSender<String>,
    panic_on_first: AtomicBool,
    gate: Option<Arc<tokio::sync::Semaphore>>,
}

impl RecordingTestNotifier {
    fn new(name: &str, tx: mpsc::UnboundedSender<String>) -> Self {
        Self {
            name: name.to_string(),
            tx,
            panic_on_first: AtomicBool::new(false),
            gate: None,
        }
    }
}

#[async_trait]
impl Notifier for RecordingTestNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "test"
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        if self.panic_on_first.swap(false, AtomicOrdering::SeqCst) {
            panic!("scripted notifier panic");
        }
        let _ = self.tx.send(alert.rule_name.clone());
        if let Some(gate) = &self.gate {
            gate.acquire().await.unwrap().forget();
        }
        Ok(())
    }
}

fn registry_of(notifiers: Vec<RecordingTestNotifier>) -> Arc<NotifierRegistry> {
    let mut registry = NotifierRegistry::new();
    for n in notifiers {
        registry.register(Arc::new(n)).unwrap();
    }
    Arc::new(registry)
}

async fn recv_n(rx: &mut mpsc::UnboundedReceiver<String>, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < n {
        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
            Ok(Some(name)) => out.push(name),
            _ => break,
        }
    }
    out
}

/// Run `f` with a local Prometheus recorder on a current-thread runtime, so
/// every task it spawns records into that recorder. Returns the rendering.
fn with_recorder<F: std::future::Future<Output = ()>>(f: impl FnOnce() -> F) -> String {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    metrics::with_local_recorder(&recorder, || rt.block_on(f()));
    handle.render()
}

fn assert_series(rendered: &str, series: &str) {
    assert!(
        rendered.lines().any(|l| l == series),
        "missing `{series}` in:\n{rendered}"
    );
}

#[test]
fn send_to_queue_is_non_blocking() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&["test-1"]));

    let result = queue.send(to("test_rule", &["test-1"]));

    assert!(result.is_ok());
    assert_eq!(queue.len(), 1);
}

#[test]
fn send_routes_to_each_destination() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&["mm-ops", "mm-infra", "other"]));

    queue.send(to("cpu", &["mm-ops", "mm-infra"])).unwrap();

    assert_eq!(queue.destination_len("mm-ops"), Some(1));
    assert_eq!(queue.destination_len("mm-infra"), Some(1));
    assert_eq!(queue.destination_len("other"), Some(0));
    assert_eq!(queue.destination_len("missing"), None);
    assert_eq!(queue.len(), 2);
}

#[test]
fn send_skips_and_counts_unknown_destination() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&["mm-ops"]));

    let rendered = with_recorder(|| async {
        assert!(queue.send(to("cpu", &["ghost", "mm-ops"])).is_ok());
    });

    assert_eq!(queue.destination_len("mm-ops"), Some(1));
    assert_eq!(queue.len(), 1);
    assert_series(
        &rendered,
        "valerter_notify_errors_total{notifier_name=\"ghost\",notifier_type=\"unknown\",rule_name=\"cpu\",vl_source=\"vlprod\"} 1",
    );
}

#[test]
fn send_without_known_destination_is_not_an_error() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&["mm-ops"]));
    assert!(queue.send(to("cpu", &["ghost"])).is_ok());
    assert!(queue.is_empty());
}

#[tokio::test]
async fn send_after_worker_stopped_returns_closed() {
    let registry = Arc::new(make_ok_registry(&["test-1"]));
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    // Pending alerts are accepted before the worker starts.
    assert!(queue.send(to("before", &["test-1"])).is_ok());

    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    worker.run(cancel).await;

    let result = queue.send(to("after", &["test-1"]));
    assert_eq!(result, Err(crate::error::QueueError::Closed));
    assert_eq!(result.unwrap_err().to_string(), "notification queue closed");
}

#[test]
fn drop_oldest_is_per_destination() {
    let queue = NotificationQueue::new(5, &make_ok_registry(&["slow", "fast"]));

    for i in 0..10 {
        queue.send(to(&format!("rule_{i}"), &["slow"])).unwrap();
    }
    queue.send(to("fast_rule", &["fast"])).unwrap();

    assert_eq!(queue.destination_len("slow"), Some(5));
    assert_eq!(queue.destination_len("fast"), Some(1));
    assert_eq!(queue.len(), 6);
}

#[test]
fn queue_capacity_is_exact_per_destination() {
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY, &make_ok_registry(&["a", "b"]));

    for i in 0..200 {
        queue.send(to(&format!("rule_{i}"), &["a", "b"])).unwrap();
    }

    assert_eq!(queue.destination_len("a"), Some(DEFAULT_QUEUE_CAPACITY));
    assert_eq!(queue.destination_len("b"), Some(DEFAULT_QUEUE_CAPACITY));
    assert_eq!(queue.len(), 2 * DEFAULT_QUEUE_CAPACITY);
}

#[test]
fn queue_size_updates_on_send() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&["test-1"]));

    assert_eq!(queue.len(), 0);
    assert!(queue.is_empty());

    queue.send(to("rule_1", &["test-1"])).unwrap();
    assert_eq!(queue.len(), 1);

    queue.send(to("rule_2", &["test-1"])).unwrap();
    assert_eq!(queue.len(), 2);
}

#[test]
fn queue_metrics_sum_destinations_and_count_drops_per_destination() {
    let queue = NotificationQueue::new(3, &make_ok_registry(&["mm-ops", "mm-infra"]));

    let rendered = with_recorder(|| async {
        // Two alerts to two destinations: 2 + 2 pending deliveries.
        queue.send(to("cpu", &["mm-ops", "mm-infra"])).unwrap();
        queue.send(to("cpu", &["mm-ops", "mm-infra"])).unwrap();
        // Overflow mm-ops only: 2 more alerts, capacity 3 -> 1 dropped.
        queue.send(to("disk", &["mm-ops"])).unwrap();
        queue.send(to("disk", &["mm-ops"])).unwrap();
    });

    assert_series(
        &rendered,
        "valerter_destination_queue_size{notifier_name=\"mm-ops\",notifier_type=\"test\"} 3",
    );
    assert_series(
        &rendered,
        "valerter_destination_queue_size{notifier_name=\"mm-infra\",notifier_type=\"test\"} 2",
    );
    assert_series(&rendered, "valerter_queue_size 5");
    assert_series(&rendered, "valerter_alerts_dropped_total 1");
    assert_series(
        &rendered,
        "valerter_destination_alerts_dropped_total{notifier_name=\"mm-ops\",notifier_type=\"test\"} 1",
    );
    assert!(
        !rendered.contains("valerter_destination_alerts_dropped_total{notifier_name=\"mm-infra\""),
        "mm-infra dropped nothing:\n{rendered}"
    );
}

#[test]
fn queue_gauges_follow_worker_consumption() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let registry = registry_of(vec![
        RecordingTestNotifier::new("mm-ops", tx.clone()),
        RecordingTestNotifier::new("mm-infra", tx),
    ]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let rendered = with_recorder(|| async {
        queue.send(to("cpu", &["mm-ops", "mm-infra"])).unwrap();
        queue.send(to("cpu", &["mm-ops", "mm-infra"])).unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(async move { worker.run(run_cancel).await });
        assert_eq!(recv_n(&mut rx, 4).await.len(), 4);
        cancel.cancel();
        run.await.unwrap();
    });

    assert_series(&rendered, "valerter_queue_size 0");
    assert_series(
        &rendered,
        "valerter_destination_queue_size{notifier_name=\"mm-ops\",notifier_type=\"test\"} 0",
    );
    assert!(queue.is_empty());
}

#[tokio::test]
async fn worker_delivers_each_destination_in_fifo_order() {
    let (tx_a, mut rx_a) = mpsc::unbounded_channel();
    let (tx_b, mut rx_b) = mpsc::unbounded_channel();
    let registry = registry_of(vec![
        RecordingTestNotifier::new("a", tx_a),
        RecordingTestNotifier::new("b", tx_b),
    ]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    for i in 0..5 {
        queue.send(to(&format!("rule_{i}"), &["a", "b"])).unwrap();
    }
    queue.send(to("only_b", &["b"])).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let run_cancel = cancel.clone();
    let run = tokio::spawn(async move { worker.run(run_cancel).await });

    // Alerts queued while the worker runs are delivered too.
    let a = recv_n(&mut rx_a, 5).await;
    queue.send(to("late", &["a"])).unwrap();
    let a_late = recv_n(&mut rx_a, 1).await;
    let b = recv_n(&mut rx_b, 6).await;
    cancel.cancel();
    run.await.unwrap();

    assert_eq!(a, vec!["rule_0", "rule_1", "rule_2", "rule_3", "rule_4"]);
    assert_eq!(a_late, vec!["late"]);
    assert_eq!(
        b,
        vec!["rule_0", "rule_1", "rule_2", "rule_3", "rule_4", "only_b"]
    );
}

/// `RecordingTestNotifier` that waits on the returned gate after recording
/// each alert, keeping that send in flight until a permit is added.
fn gated_notifier(
    name: &str,
    tx: mpsc::UnboundedSender<String>,
) -> (RecordingTestNotifier, Arc<tokio::sync::Semaphore>) {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut notifier = RecordingTestNotifier::new(name, tx);
    notifier.gate = Some(Arc::clone(&gate));
    (notifier, gate)
}

fn drain_rx(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

#[tokio::test]
async fn drain_sends_pending_alerts_in_fifo_order() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let registry = registry_of(vec![RecordingTestNotifier::new("mm-ops", tx)]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    for i in 0..3 {
        queue.send(to(&format!("rule_{i}"), &["mm-ops"])).unwrap();
    }

    // Shutdown requested while the three alerts are still queued.
    let drain = tokio_util::sync::CancellationToken::new();
    drain.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), worker.run(drain))
        .await
        .expect("worker should stop once its queue is drained");

    assert_eq!(drain_rx(&mut rx), vec!["rule_0", "rule_1", "rule_2"]);
    assert!(queue.is_empty());
    assert_eq!(
        queue.send(to("after", &["mm-ops"])),
        Err(crate::error::QueueError::Closed)
    );
}

#[tokio::test]
async fn drain_of_a_destination_is_not_held_by_a_blocked_one() {
    let (tx_blocked, mut rx_blocked) = mpsc::unbounded_channel();
    let (tx_ok, mut rx_ok) = mpsc::unbounded_channel();
    let (blocked, gate) = gated_notifier("blocked", tx_blocked);
    let registry = registry_of(vec![blocked, RecordingTestNotifier::new("ok", tx_ok)]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    for i in 0..3 {
        queue
            .send(to(&format!("rule_{i}"), &["blocked", "ok"]))
            .unwrap();
    }

    let drain = tokio_util::sync::CancellationToken::new();
    drain.cancel();
    let run = tokio::spawn(async move { worker.run(drain).await });

    assert_eq!(
        recv_n(&mut rx_ok, 3).await,
        vec!["rule_0", "rule_1", "rule_2"]
    );
    assert_eq!(recv_n(&mut rx_blocked, 1).await, vec!["rule_0"]);
    assert_eq!(queue.destination_len("ok"), Some(0));
    assert_eq!(queue.destination_len("blocked"), Some(2));
    assert!(!run.is_finished(), "blocked destination is still draining");

    gate.add_permits(10);
    tokio::time::timeout(std::time::Duration::from_secs(2), run)
        .await
        .expect("worker should stop once every queue is drained")
        .unwrap();
    assert_eq!(drain_rx(&mut rx_blocked), vec!["rule_1", "rule_2"]);
    assert!(queue.is_empty());
}

#[tokio::test]
async fn drain_of_empty_queues_returns_immediately() {
    let registry = Arc::new(make_ok_registry(&["a", "b"]));
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let drain = tokio_util::sync::CancellationToken::new();
    let run_drain = drain.clone();
    let run = tokio::spawn(async move { worker.run(run_drain).await });
    tokio::task::yield_now().await;
    drain.cancel();

    tokio::time::timeout(std::time::Duration::from_millis(500), run)
        .await
        .expect("an empty queue must not delay the shutdown")
        .unwrap();
}

#[tokio::test]
async fn drain_requested_during_send_finishes_it_then_sends_the_rest() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (notifier, gate) = gated_notifier("mm-ops", tx);
    let registry = registry_of(vec![notifier]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    for i in 0..3 {
        queue.send(to(&format!("rule_{i}"), &["mm-ops"])).unwrap();
    }

    let drain = tokio_util::sync::CancellationToken::new();
    let run_drain = drain.clone();
    let run = tokio::spawn(async move { worker.run(run_drain).await });

    // First alert in flight, then shutdown is requested.
    assert_eq!(recv_n(&mut rx, 1).await, vec!["rule_0"]);
    drain.cancel();
    gate.add_permits(10);
    tokio::time::timeout(std::time::Duration::from_secs(2), run)
        .await
        .expect("worker should stop once its queue is drained")
        .unwrap();

    assert_eq!(drain_rx(&mut rx), vec!["rule_1", "rule_2"]);
    assert!(queue.is_empty());
    assert_eq!(
        queue.send(to("after", &["mm-ops"])),
        Err(crate::error::QueueError::Closed)
    );
}

#[tokio::test(start_paused = true)]
async fn await_worker_drain_reports_drained_worker() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let registry = registry_of(vec![RecordingTestNotifier::new("mm-ops", tx)]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);
    for i in 0..3 {
        queue.send(to(&format!("rule_{i}"), &["mm-ops"])).unwrap();
    }

    let drain = tokio_util::sync::CancellationToken::new();
    drain.cancel();
    let handle = tokio::spawn(async move { worker.run(drain).await });
    let start = tokio::time::Instant::now();

    let outcome = await_worker_drain(handle, &queue, SHUTDOWN_DRAIN_TIMEOUT).await;

    assert_eq!(outcome, DrainOutcome::Drained);
    assert!(start.elapsed() < SHUTDOWN_DRAIN_TIMEOUT);
    assert_eq!(drain_rx(&mut rx).len(), 3);
}

#[tokio::test(start_paused = true)]
async fn await_worker_drain_aborts_worker_after_timeout() {
    assert_eq!(SHUTDOWN_DRAIN_TIMEOUT, std::time::Duration::from_secs(20));

    let (tx, mut rx) = mpsc::unbounded_channel();
    // The gate never gets a permit: the first send blocks forever.
    let (notifier, _gate) = gated_notifier("mm-ops", tx);
    let registry = registry_of(vec![notifier]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);
    for i in 0..3 {
        queue.send(to(&format!("rule_{i}"), &["mm-ops"])).unwrap();
    }

    let drain = tokio_util::sync::CancellationToken::new();
    let run_drain = drain.clone();
    let handle = tokio::spawn(async move { worker.run(run_drain).await });
    let abort_handle = handle.abort_handle();
    assert_eq!(recv_n(&mut rx, 1).await, vec!["rule_0"]);
    drain.cancel();
    let start = tokio::time::Instant::now();

    let outcome = await_worker_drain(handle, &queue, SHUTDOWN_DRAIN_TIMEOUT).await;

    assert_eq!(outcome, DrainOutcome::TimedOut { undelivered: 2 });
    assert_eq!(start.elapsed(), SHUTDOWN_DRAIN_TIMEOUT);
    assert!(abort_handle.is_finished(), "worker task must be aborted");
}

#[test]
fn notifier_panic_is_isolated_and_counted() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (tx_other, mut rx_other) = mpsc::unbounded_channel();
    let panicky = RecordingTestNotifier::new("webhook-x", tx);
    panicky.panic_on_first.store(true, AtomicOrdering::SeqCst);
    let registry = registry_of(vec![
        panicky,
        RecordingTestNotifier::new("mm-ops", tx_other),
    ]);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let rendered = with_recorder(|| async {
        queue.send(to("cpu", &["webhook-x", "mm-ops"])).unwrap();
        queue.send(to("disk", &["webhook-x", "mm-ops"])).unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(async move { worker.run(run_cancel).await });

        // The alert after the panic is delivered normally.
        assert_eq!(recv_n(&mut rx, 1).await, vec!["disk"]);
        assert_eq!(recv_n(&mut rx_other, 2).await, vec!["cpu", "disk"]);

        // The destination still accepts and delivers alerts.
        queue.send(to("mem", &["webhook-x"])).unwrap();
        assert_eq!(recv_n(&mut rx, 1).await, vec!["mem"]);
        cancel.cancel();
        run.await.unwrap();
    });

    for name in [
        "valerter_notify_errors_total",
        "valerter_alerts_failed_total",
    ] {
        assert_series(
            &rendered,
            &format!(
                "{name}{{rule_name=\"cpu\",vl_source=\"vlprod\",notifier_name=\"webhook-x\",notifier_type=\"test\"}} 1"
            ),
        );
    }
}

#[test]
fn backoff_delay_calculation() {
    use std::time::Duration;

    let base = Duration::from_millis(500);
    let max = Duration::from_secs(5);

    assert_eq!(backoff_delay(0, base, max), Duration::from_millis(500));
    assert_eq!(backoff_delay(1, base, max), Duration::from_millis(1000));
    assert_eq!(backoff_delay(2, base, max), Duration::from_millis(2000));
    assert_eq!(backoff_delay(3, base, max), Duration::from_millis(4000));
    assert_eq!(backoff_delay(4, base, max), Duration::from_secs(5));
    assert_eq!(backoff_delay(10, base, max), Duration::from_secs(5));
}

#[test]
fn backoff_delay_handles_overflow() {
    use std::time::Duration;

    let base = Duration::from_secs(1);
    let max = Duration::from_secs(60);
    assert_eq!(backoff_delay(100, base, max), max);
}

#[test]
fn alert_payload_clone_works() {
    let payload = AlertPayload {
        message: RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            email_body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: "my_rule".to_string(),
        vl_source: "vlprod".to_string(),
        destinations: vec!["mattermost-infra".to_string()],
        log_timestamp: "2026-01-15T10:00:00Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:00:00 UTC".to_string(),
    };

    let cloned = payload.clone();
    assert_eq!(cloned.rule_name, payload.rule_name);
    assert_eq!(cloned.vl_source, payload.vl_source);
    assert_eq!(cloned.message.title, payload.message.title);
    assert_eq!(cloned.destinations, payload.destinations);
    assert_eq!(cloned.log_timestamp, payload.log_timestamp);
    assert_eq!(
        cloned.log_timestamp_formatted,
        payload.log_timestamp_formatted
    );
}

#[test]
fn queue_is_clone() {
    let queue1 = NotificationQueue::new(10, &make_ok_registry(&["test-1"]));
    let queue2 = queue1.clone();

    queue1.send(to("rule_1", &["test-1"])).unwrap();
    assert_eq!(queue2.len(), 1);
}

#[test]
fn queue_debug_format() {
    let queue = NotificationQueue::new(10, &make_ok_registry(&[]));
    let debug = format!("{:?}", queue);
    assert!(debug.contains("NotificationQueue"));
}

#[test]
fn alert_payload_with_empty_destinations_uses_default() {
    let payload = make_payload("test_rule");
    assert!(payload.destinations.is_empty());
}

#[test]
fn alert_payload_with_destinations() {
    let payload = make_payload_with_destinations(
        "test_rule",
        vec!["dest-a".to_string(), "dest-b".to_string()],
    );
    assert_eq!(payload.destinations.len(), 2);
    assert_eq!(payload.destinations[0], "dest-a");
    assert_eq!(payload.destinations[1], "dest-b");
}

#[test]
fn registry_from_config_creates_email_notifiers() {
    let mut notifiers_config = HashMap::new();
    notifiers_config.insert(
        "email-ops".to_string(),
        NotifierConfig::Email(EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "valerter@example.com".to_string(),
            to: vec!["ops@example.com".to_string()],
            subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
            body_template: None,
            body_template_file: None,
        }),
    );

    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    assert!(result.is_ok(), "Should create email notifier: {:?}", result);
    let registry = result.unwrap();
    assert_eq!(registry.len(), 1);

    let notifier = registry.get("email-ops");
    assert!(notifier.is_some());
    let notifier = notifier.unwrap();
    assert_eq!(notifier.name(), "email-ops");
    assert_eq!(notifier.notifier_type(), "email");
}

#[test]
#[serial]
fn registry_from_config_email_with_auth() {
    temp_env::with_vars(
        [
            ("TEST_SMTP_USER_REG", Some("testuser")),
            ("TEST_SMTP_PASS_REG", Some("testpass")),
        ],
        || {
            let mut notifiers_config = HashMap::new();
            notifiers_config.insert(
                "email-auth".to_string(),
                NotifierConfig::Email(EmailNotifierConfig {
                    smtp: SmtpConfig {
                        host: "smtp.example.com".to_string(),
                        port: 587,
                        username: Some("${TEST_SMTP_USER_REG}".to_string()),
                        password: Some(SecretString::new("${TEST_SMTP_PASS_REG}".to_string())),
                        tls: TlsMode::Starttls,
                        tls_verify: true,
                    },
                    from: "valerter@example.com".to_string(),
                    to: vec!["ops@example.com".to_string()],
                    subject_template: "{{ title }}".to_string(),
                    body_template: None,
                    body_template_file: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(
                result.is_ok(),
                "Should resolve env vars for email auth: {:?}",
                result
            );
            let registry = result.unwrap();
            assert_eq!(registry.get("email-auth").unwrap().notifier_type(), "email");
        },
    );
}

#[test]
#[serial]
fn registry_from_config_email_fails_on_undefined_env_var() {
    temp_env::with_var("UNDEFINED_SMTP_VAR_REG", None::<&str>, || {
        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "bad-email".to_string(),
            NotifierConfig::Email(EmailNotifierConfig {
                smtp: SmtpConfig {
                    host: "smtp.example.com".to_string(),
                    port: 587,
                    username: Some("${UNDEFINED_SMTP_VAR_REG}".to_string()),
                    password: Some(SecretString::new("somepass".to_string())),
                    tls: TlsMode::Starttls,
                    tls_verify: true,
                },
                from: "valerter@example.com".to_string(),
                to: vec!["ops@example.com".to_string()],
                subject_template: "{{ title }}".to_string(),
                body_template: None,
                body_template_file: None,
            }),
        );

        let client = reqwest::Client::new();
        let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);

        match &errors[0] {
            crate::error::ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-email");
                assert!(message.contains("UNDEFINED_SMTP_VAR_REG"));
            }
            other => panic!("Expected InvalidNotifier, got {:?}", other),
        }
    });
}

#[test]
fn registry_from_config_email_fails_on_invalid_from_address() {
    let mut notifiers_config = HashMap::new();
    notifiers_config.insert(
        "bad-from-email".to_string(),
        NotifierConfig::Email(EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "not-an-email".to_string(),
            to: vec!["ops@example.com".to_string()],
            subject_template: "{{ title }}".to_string(),
            body_template: None,
            body_template_file: None,
        }),
    );

    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);

    match &errors[0] {
        crate::error::ConfigError::InvalidNotifier { name, message } => {
            assert_eq!(name, "bad-from-email");
            assert!(message.contains("from"));
        }
        other => panic!("Expected InvalidNotifier, got {:?}", other),
    }
}

#[test]
#[serial]
fn registry_from_config_all_three_notifier_types() {
    temp_env::with_var(
        "TEST_MM_ALL_TYPES",
        Some("https://mm.example.com/hooks/abc"),
        || {
            let mut notifiers_config = HashMap::new();

            // Mattermost
            notifiers_config.insert(
                "mattermost".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: SecretString::new("${TEST_MM_ALL_TYPES}".to_string()),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );

            // Webhook
            notifiers_config.insert(
                "webhook".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: SecretString::new("https://api.example.com/alerts".to_string()),
                    method: "POST".to_string(),
                    headers: std::collections::HashMap::new(),
                    body_template: None,
                }),
            );

            // Email
            notifiers_config.insert(
                "email".to_string(),
                NotifierConfig::Email(EmailNotifierConfig {
                    smtp: SmtpConfig {
                        host: "smtp.example.com".to_string(),
                        port: 587,
                        username: None,
                        password: None,
                        tls: TlsMode::Starttls,
                        tls_verify: true,
                    },
                    from: "valerter@example.com".to_string(),
                    to: vec!["ops@example.com".to_string()],
                    subject_template: "{{ title }}".to_string(),
                    body_template: None,
                    body_template_file: None,
                }),
            );

            let client = reqwest::Client::new();
            let result =
                NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

            assert!(
                result.is_ok(),
                "Should create all three notifier types: {:?}",
                result
            );
            let registry = result.unwrap();
            assert_eq!(registry.len(), 3);

            assert_eq!(
                registry.get("mattermost").unwrap().notifier_type(),
                "mattermost"
            );
            assert_eq!(registry.get("webhook").unwrap().notifier_type(), "webhook");
            assert_eq!(registry.get("email").unwrap().notifier_type(), "email");
        },
    );
}

#[test]
#[serial]
fn registry_from_config_creates_telegram_notifier() {
    let mut notifiers_config = HashMap::new();
    notifiers_config.insert(
        "telegram-infra".to_string(),
        NotifierConfig::Telegram(TelegramNotifierConfig {
            bot_token: SecretString::new("fake-token-123".to_string()),
            chat_ids: vec!["-100123".to_string(), "-100456".to_string()],
            parse_mode: Some("HTML".to_string()),
            disable_notification: None,
            disable_web_page_preview: Some(true),
            body_template: None,
        }),
    );

    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    assert!(
        result.is_ok(),
        "Telegram notifier registration should succeed: {:?}",
        result.err()
    );
    let registry = result.unwrap();
    assert_eq!(registry.len(), 1);

    let notifier = registry
        .get("telegram-infra")
        .expect("should be registered");
    assert_eq!(notifier.name(), "telegram-infra");
    assert_eq!(notifier.notifier_type(), "telegram");
}

#[test]
#[serial]
fn registry_from_config_propagates_telegram_validation_errors() {
    let mut notifiers_config = HashMap::new();
    notifiers_config.insert(
        "telegram-broken".to_string(),
        NotifierConfig::Telegram(TelegramNotifierConfig {
            bot_token: SecretString::new("fake-token".to_string()),
            chat_ids: vec![],
            parse_mode: None,
            disable_notification: None,
            disable_web_page_preview: None,
            body_template: None,
        }),
    );

    let client = reqwest::Client::new();
    let result = NotifierRegistry::from_config(&notifiers_config, client, &test_config_dir());

    let errs = result.unwrap_err();
    assert!(errs.iter().any(|e| e.to_string().contains("chat_ids")));
}

fn mattermost_registry_errors(env_value: &str) -> String {
    temp_env::with_var("HCV_MM_WEBHOOK", Some(env_value), || {
        let mut notifiers_config = HashMap::new();
        notifiers_config.insert(
            "mm".to_string(),
            NotifierConfig::Mattermost(MattermostNotifierConfig {
                webhook_url: SecretString::new("${HCV_MM_WEBHOOK}".to_string()),
                channel: None,
                username: None,
                icon_url: None,
            }),
        );
        match NotifierRegistry::from_config(
            &notifiers_config,
            reqwest::Client::new(),
            &test_config_dir(),
        ) {
            Ok(_) => String::new(),
            Err(errors) => errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    })
}

#[test]
#[serial]
fn registry_rejects_resolved_mattermost_url_with_bad_scheme() {
    let msg = mattermost_registry_errors("htps://mm.example.com/hooks/SECRET");
    assert!(
        msg.contains("invalid notifier 'mm': webhook_url: invalid URL:"),
        "{msg}"
    );
    assert!(!msg.contains("SECRET"), "{msg}");
}

#[test]
#[serial]
fn registry_rejects_resolved_mattermost_url_that_does_not_parse() {
    let msg = mattermost_registry_errors("not a url SECRET");
    assert!(
        msg.contains("invalid notifier 'mm': webhook_url: invalid URL:"),
        "{msg}"
    );
    assert!(!msg.contains("SECRET"), "{msg}");
}

#[test]
#[serial]
fn registry_accepts_resolved_mattermost_url() {
    assert_eq!(
        mattermost_registry_errors("https://mm.example.com/hooks/abc"),
        ""
    );
}
