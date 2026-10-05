//! `log` in notifier templates, end to end: a VictoriaLogs line goes through
//! the engine (parse, throttle, rule template), the notification queue and a
//! webhook notifier whose `body_template` reads the event fields.
//!
//! Kept in its own test binary: `capture_logs` asserts on log lines emitted by
//! shared callsites (the delivery worker), which other tests running in
//! parallel in the same binary could register while no capturing subscriber
//! exists, hiding them from the capture.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use common::logs::capture_logs;
use tokio_util::sync::CancellationToken;
use valerter::RuleEngine;
use valerter::config::{
    CompiledParser, CompiledRule, CompiledTemplate, DefaultsConfig, MetricsConfig, NotifyConfig,
    RuntimeConfig, SecretString, ThrottleConfig, VlSourceConfig, WebhookNotifierConfig,
};
use valerter::notify::{NotificationQueue, NotificationWorker, NotifierRegistry, WebhookNotifier};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create client")
}

/// Webhook notifier `name` posting to `url` with `body_template`.
fn make_webhook_notifier(name: &str, url: &str, body_template: &str) -> WebhookNotifier {
    let config = WebhookNotifierConfig {
        url: SecretString::new(url.to_string()),
        method: "POST".to_string(),
        headers: HashMap::new(),
        body_template: Some(body_template.to_string()),
    };
    WebhookNotifier::from_config(name, &config, make_client()).unwrap()
}

/// Wait until `server` received `count` requests or `deadline` passed.
async fn wait_for_requests(server: &MockServer, count: usize, deadline: Duration) -> usize {
    let start = tokio::time::Instant::now();
    loop {
        let received = server.received_requests().await.unwrap_or_default().len();
        if received >= count || start.elapsed() >= deadline {
            return received;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Mock webhook answering `status` to every POST on `/api/alerts`.
async fn start_webhook(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

/// Run a `RuleEngine` tailing `event` from a mocked VictoriaLogs, whose rule
/// sends to a webhook notifier `hook` (POST to `webhook_url`, `body_template`
/// = `template`), until the webhook received `expected` requests or `deadline`
/// passed. The engine runs on the current thread, so `capture_logs` sees the
/// logs of every task.
async fn run_engine_to_webhook(
    event: serde_json::Value,
    template: &str,
    webhook: &MockServer,
    expected: usize,
    deadline: Duration,
) {
    let vl = MockServer::start().await;
    let mut line = serde_json::to_vec(&event).unwrap();
    line.push(b'\n');
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(line, "application/x-ndjson"))
        .up_to_n_times(1)
        .mount(&vl)
        .await;

    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(make_webhook_notifier(
            "hook",
            &format!("{}/api/alerts", webhook.uri()),
            template,
        )))
        .unwrap();
    let registry = Arc::new(registry);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let config = RuntimeConfig {
        victorialogs: BTreeMap::from([(
            "vlprod".to_string(),
            VlSourceConfig {
                url: vl.uri(),
                basic_auth: None,
                headers: None,
                tls: None,
            },
        )]),
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: valerter::config::DEFAULT_MAX_STREAMS,
        },
        templates: HashMap::from([(
            "tpl".to_string(),
            CompiledTemplate {
                title: "Alert on {{ host }}".to_string(),
                body: "pod {{ k8s.pod }}".to_string(),
                email_body_html: None,
                accent_color: None,
            },
        )]),
        rules: vec![CompiledRule {
            name: "log_rule".to_string(),
            enabled: true,
            query: "_stream:test".to_string(),
            parser: CompiledParser {
                regex: None,
                json: None,
            },
            throttle: None,
            notify: NotifyConfig {
                template: "tpl".to_string(),
                mattermost_channel: None,
                destinations: vec!["hook".to_string()],
            },
            vl_sources: vec![],
        }],
        metrics: MetricsConfig::default(),
        notifiers: None,
        config_dir: std::path::PathBuf::from("."),
    };
    let engine = RuleEngine::new(config, make_client(), queue);

    let cancel = CancellationToken::new();
    let engine_handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { engine.run(cancel).await }
    });
    let worker_handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { worker.run(cancel).await }
    });

    wait_for_requests(webhook, expected, deadline).await;
    // Let the worker log the outcome of the last request.
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), engine_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
}

#[tokio::test]
async fn test_engine_log_fields_reach_webhook_body_template() {
    let webhook = start_webhook(200).await;

    run_engine_to_webhook(
        serde_json::json!({
            "_time": "2026-01-15T10:49:35Z",
            "_stream": "{}",
            "_msg": "upstream error",
            "host": "web-01",
            "k8s.pod": "api-7f"
        }),
        r#"{"host": {{ log.host | tojson }}, "pod": {{ log["k8s.pod"] | tojson }}, "nested": {{ log.k8s.pod | tojson }}, "title": {{ title | tojson }}, "body": {{ body | tojson }}}"#,
        &webhook,
        1,
        Duration::from_secs(5),
    )
    .await;

    let requests = webhook.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let parsed: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!({
            "host": "web-01",
            "pod": "api-7f",
            "nested": "api-7f",
            "title": "Alert on web-01",
            "body": "pod api-7f"
        })
    );
}

#[tokio::test]
async fn test_engine_failed_delivery_never_logs_log_fields() {
    let webhook = start_webhook(500).await;
    let (logs, _guard) = capture_logs(tracing::Level::TRACE);

    run_engine_to_webhook(
        serde_json::json!({
            "_time": "2026-01-15T10:49:35Z",
            "_stream": "{}",
            "_msg": "login token=s3cr3t",
            "host": "web-01",
            "k8s.pod": "auth-1",
            "token": "s3cr3t"
        }),
        r#"{"token": {{ log.token | tojson }}, "msg": {{ log._msg | tojson }}}"#,
        &webhook,
        3,
        Duration::from_secs(10),
    )
    .await;

    let requests = webhook.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "the webhook should be retried");
    assert!(String::from_utf8_lossy(&requests[0].body).contains("s3cr3t"));
    let text = logs.text();
    assert!(
        text.contains("Failed to send notification after all retries"),
        "{text}"
    );
    assert!(
        !text.contains("s3cr3t"),
        "a log line leaks a log field:\n{text}"
    );
}
