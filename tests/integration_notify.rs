//! Integration tests for notification sending.
//!
//! Uses wiremock to simulate webhook endpoints for Mattermost and generic webhooks.

mod common;

use common::logs::capture_logs;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use valerter::config::{SecretString, WebhookNotifierConfig};
use valerter::notify::{
    AlertPayload, MattermostNotifier, NotificationQueue, NotificationWorker, NotifierRegistry,
    WebhookNotifier,
};
use valerter::template::RenderedMessage;
use wiremock::matchers::{body_partial_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_payload(rule_name: &str) -> AlertPayload {
    make_payload_with_destinations(rule_name, vec!["default".to_string()])
}

fn make_payload_with_destinations(rule_name: &str, destinations: Vec<String>) -> AlertPayload {
    AlertPayload {
        mattermost_channel: None,
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body content".to_string(),
            email_body_html: None,
            accent_color: Some("#ff0000".to_string()),
            ..Default::default()
        },
        rule_name: rule_name.to_string(),
        vl_source: "vlprod".to_string(),
        destinations,
        log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
        log: AlertPayload::log_from_fields(&serde_json::json!({})),
    }
}

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create client")
}

/// Create a test registry with a default Mattermost notifier pointing to the mock server.
fn make_test_registry(client: reqwest::Client, webhook_url: &str) -> Arc<NotifierRegistry> {
    let mut registry = NotifierRegistry::new();
    let notifier = MattermostNotifier::new(
        "default".to_string(),
        SecretString::new(webhook_url.to_string()),
        client,
    );
    registry.register(Arc::new(notifier)).unwrap();
    Arc::new(registry)
}

// ============================================================================
// Task 4.1: Test envoi reussi au premier essai
// ============================================================================

#[tokio::test]
async fn test_send_success_first_attempt() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/test-webhook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/test-webhook", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload("test_rule");
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Give worker time to process
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Verify mock was called exactly once
    mock_server.verify().await;
}

// ============================================================================
// Task 4.2: Test retry sur erreur 500 (puis succes)
// ============================================================================

#[tokio::test]
async fn test_retry_on_server_error_then_success() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let mock_server = MockServer::start().await;

    // Use a counter to track request number and return different responses
    let request_count = Arc::new(AtomicU32::new(0));
    let request_count_clone = request_count.clone();

    Mock::given(method("POST"))
        .and(path("/hooks/retry-test"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = request_count_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First request: fail with 500
                ResponseTemplate::new(500)
            } else {
                // Second request: succeed
                ResponseTemplate::new(200)
            }
        })
        .expect(2) // Expect exactly 2 calls (1 fail + 1 success)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/retry-test", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload("retry_rule");
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Wait for retry (500ms base backoff + processing time)
    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Verify exactly 2 attempts were made
    mock_server.verify().await;
}

// ============================================================================
// Task 4.3: Test echec apres 3 tentatives
// ============================================================================

#[tokio::test]
async fn test_failure_after_max_retries() {
    let mock_server = MockServer::start().await;

    // All calls return 500 - should fail after 3 attempts
    Mock::given(method("POST"))
        .and(path("/hooks/always-fail"))
        .respond_with(ResponseTemplate::new(500))
        .expect(3) // Exactly 3 attempts
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/always-fail", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload("fail_rule");
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Wait for all retries (500ms + 1s = 1.5s backoff + processing time)
    tokio::time::sleep(Duration::from_millis(5000)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Verify exactly 3 attempts were made
    mock_server.verify().await;
}

// ============================================================================
// Task 4.5: Test format payload Mattermost (structure attachments)
// ============================================================================

#[tokio::test]
async fn test_mattermost_payload_format() {
    let mock_server = MockServer::start().await;

    // Verify the JSON body contains expected structure using partial match
    Mock::given(method("POST"))
        .and(path("/hooks/format-test"))
        .and(body_partial_json(serde_json::json!({
            "attachments": [{
                "fallback": "Alert from format_rule",
                "title": "Alert from format_rule",
                "text": "Test body content",
                "footer": "valerter | format_rule | vlprod | 15/01/2026 10:49:35 UTC"
            }]
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/format-test", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload("format_rule");
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // If mock matches, format is correct
    mock_server.verify().await;
}

// ============================================================================
// Test 4xx errors are NOT retried
// ============================================================================

#[tokio::test]
async fn test_client_error_no_retry() {
    let mock_server = MockServer::start().await;

    // 400 errors should NOT be retried
    Mock::given(method("POST"))
        .and(path("/hooks/bad-request"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1) // Only 1 attempt, no retry
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/bad-request", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload("bad_rule");
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Verify only 1 attempt (no retry on 4xx)
    mock_server.verify().await;
}

// ============================================================================
// Test multiple messages processed in sequence
// ============================================================================

#[tokio::test]
async fn test_multiple_messages_in_sequence() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/multi-test"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3) // Expect 3 messages
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/multi-test", mock_server.uri());
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    // Send 3 messages
    queue.send(make_payload("rule_1")).unwrap();
    queue.send(make_payload("rule_2")).unwrap();
    queue.send(make_payload("rule_3")).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    mock_server.verify().await;
}

// ============================================================================
// Story 6.3: Test fan-out to multiple destinations in parallel
// ============================================================================

/// Create a test registry with multiple notifiers pointing to different mock servers.
fn make_multi_notifier_registry(
    client: reqwest::Client,
    notifiers: Vec<(&str, &str)>, // (name, webhook_url)
) -> Arc<NotifierRegistry> {
    let mut registry = NotifierRegistry::new();
    for (name, url) in notifiers {
        let notifier = MattermostNotifier::new(
            name.to_string(),
            SecretString::new(url.to_string()),
            client.clone(),
        );
        registry.register(Arc::new(notifier)).unwrap();
    }
    Arc::new(registry)
}

#[tokio::test]
async fn test_fanout_to_multiple_destinations() {
    // Create two separate mock servers to simulate different notifiers
    let mock_server_infra = MockServer::start().await;
    let mock_server_ops = MockServer::start().await;

    // Both servers expect exactly 1 call each
    Mock::given(method("POST"))
        .and(path("/hooks/infra"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server_infra)
        .await;

    Mock::given(method("POST"))
        .and(path("/hooks/ops"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server_ops)
        .await;

    let webhook_infra = format!("{}/hooks/infra", mock_server_infra.uri());
    let webhook_ops = format!("{}/hooks/ops", mock_server_ops.uri());

    let client = make_client();
    let registry = make_multi_notifier_registry(
        client,
        vec![
            ("mattermost-infra", &webhook_infra),
            ("mattermost-ops", &webhook_ops),
        ],
    );

    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    // Send one alert with two destinations
    let payload = make_payload_with_destinations(
        "critical_alert",
        vec!["mattermost-infra".to_string(), "mattermost-ops".to_string()],
    );
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Give worker time to process
    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Verify BOTH mock servers were called exactly once
    mock_server_infra.verify().await;
    mock_server_ops.verify().await;
}

#[tokio::test]
async fn test_fanout_partial_failure_continues() {
    // One server succeeds, one fails - both should be attempted
    let mock_server_success = MockServer::start().await;
    let mock_server_fail = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/success"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server_success)
        .await;

    // This one returns 500 - will fail after retries
    Mock::given(method("POST"))
        .and(path("/hooks/fail"))
        .respond_with(ResponseTemplate::new(500))
        .expect(3) // 3 retry attempts
        .mount(&mock_server_fail)
        .await;

    let webhook_success = format!("{}/hooks/success", mock_server_success.uri());
    let webhook_fail = format!("{}/hooks/fail", mock_server_fail.uri());

    let client = make_client();
    let registry = make_multi_notifier_registry(
        client,
        vec![
            ("notifier-success", &webhook_success),
            ("notifier-fail", &webhook_fail),
        ],
    );

    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    // Send alert to both destinations
    let payload = make_payload_with_destinations(
        "partial_fail_test",
        vec!["notifier-success".to_string(), "notifier-fail".to_string()],
    );
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Wait for retries on failing server (3 attempts with backoff)
    tokio::time::sleep(Duration::from_millis(5000)).await;
    cancel.cancel();

    worker_handle.await.unwrap();

    // Both servers should have been called - failure on one doesn't stop the other
    mock_server_success.verify().await;
    mock_server_fail.verify().await;
}

// ============================================================================
// Story 6.5: WebhookNotifier Integration Tests
// ============================================================================

/// Create a WebhookNotifier for testing with the given configuration.
fn make_webhook_notifier(
    name: &str,
    url: &str,
    method_str: &str,
    headers: HashMap<String, String>,
    body_template: Option<String>,
) -> WebhookNotifier {
    let config = WebhookNotifierConfig {
        url: SecretString::new(url.to_string()),
        method: method_str.to_string(),
        headers: headers
            .into_iter()
            .map(|(k, v)| (k, SecretString::new(v)))
            .collect(),
        body_template,
        format: None,
    };
    let client = make_client();
    WebhookNotifier::from_config(name, &config, client).unwrap()
}

/// Create a test registry with a WebhookNotifier.
fn make_webhook_registry(
    name: &str,
    url: &str,
    method_str: &str,
    headers: HashMap<String, String>,
    body_template: Option<String>,
) -> Arc<NotifierRegistry> {
    let mut registry = NotifierRegistry::new();
    let notifier = make_webhook_notifier(name, url, method_str, headers, body_template);
    registry.register(Arc::new(notifier)).unwrap();
    Arc::new(registry)
}

#[tokio::test]
async fn test_webhook_send_with_body_template() {
    let mock_server = MockServer::start().await;

    // Expect custom JSON body from template
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .and(body_string_contains(
            "\"alert_title\": \"Alert from template_rule\"",
        ))
        .and(body_string_contains(
            "\"alert_body\": \"Test body content\"",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());
    let body_template = Some(
        r#"{"alert_title": "{{ title }}", "alert_body": "{{ body }}", "rule": "{{ rule_name }}"}"#
            .to_string(),
    );

    let registry = make_webhook_registry(
        "test-webhook",
        &webhook_url,
        "POST",
        HashMap::new(),
        body_template,
    );
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload_with_destinations("template_rule", vec!["test-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_send_with_default_body() {
    let mock_server = MockServer::start().await;

    // Expect default JSON payload structure (DefaultWebhookPayload)
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .and(body_partial_json(serde_json::json!({
            "alert_name": "default-webhook",
            "rule_name": "default_rule",
            "title": "Alert from default_rule",
            "body": "Test body content"
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());

    // No body_template = uses DefaultWebhookPayload
    let registry = make_webhook_registry(
        "default-webhook",
        &webhook_url,
        "POST",
        HashMap::new(),
        None,
    );
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload =
        make_payload_with_destinations("default_rule", vec!["default-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_with_custom_headers() {
    let mock_server = MockServer::start().await;

    // Expect custom headers
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .and(header("Authorization", "Bearer test-token-123"))
        .and(header("X-Custom-Header", "custom-value"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer test-token-123".to_string(),
    );
    headers.insert("X-Custom-Header".to_string(), "custom-value".to_string());

    let registry = make_webhook_registry("header-webhook", &webhook_url, "POST", headers, None);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload_with_destinations("header_rule", vec!["header-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_retry_on_500_then_success() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let mock_server = MockServer::start().await;
    let request_count = Arc::new(AtomicU32::new(0));
    let request_count_clone = request_count.clone();

    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = request_count_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                ResponseTemplate::new(500) // First: fail
            } else {
                ResponseTemplate::new(200) // Second: success
            }
        })
        .expect(2) // 1 fail + 1 success
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());

    let registry =
        make_webhook_registry("retry-webhook", &webhook_url, "POST", HashMap::new(), None);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload_with_destinations("retry_rule", vec!["retry-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    // Wait for retry (500ms backoff + processing)
    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_retry_on_429_then_success() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let mock_server = MockServer::start().await;
    let request_count = Arc::new(AtomicU32::new(0));
    let request_count_clone = request_count.clone();

    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = request_count_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                ResponseTemplate::new(429) // rate limited: must be retried
            } else {
                ResponseTemplate::new(200)
            }
        })
        .expect(2)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());

    let registry = make_webhook_registry(
        "retry-429-webhook",
        &webhook_url,
        "POST",
        HashMap::new(),
        None,
    );
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload =
        make_payload_with_destinations("retry_rule", vec!["retry-429-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_no_retry_on_400() {
    let mock_server = MockServer::start().await;

    // 400 should NOT be retried
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1) // Only 1 attempt
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());

    let registry = make_webhook_registry(
        "no-retry-webhook",
        &webhook_url,
        "POST",
        HashMap::new(),
        None,
    );
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload =
        make_payload_with_destinations("no_retry_rule", vec!["no-retry-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

#[tokio::test]
async fn test_webhook_put_method() {
    let mock_server = MockServer::start().await;

    // Expect PUT method
    Mock::given(method("PUT"))
        .and(path("/api/alerts"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/api/alerts", mock_server.uri());

    let registry = make_webhook_registry("put-webhook", &webhook_url, "PUT", HashMap::new(), None);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let payload = make_payload_with_destinations("put_rule", vec!["put-webhook".to_string()]);
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();

    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    mock_server.verify().await;
}

// ============================================================================
// Per-destination delivery: a slow destination does not affect the others
// ============================================================================

/// Webhook client timeout used for the unresponsive endpoint.
const SHORT_TIMEOUT: Duration = Duration::from_millis(200);

/// Shortest time the webhook notifier needs to exhaust its 3 attempts
/// against an endpoint that never answers within `SHORT_TIMEOUT`:
/// 3 timeouts + 500 ms + 1 s of backoff.
const WEBHOOK_RETRY_FLOOR: Duration = Duration::from_millis(3 * 200 + 500 + 1000);

/// Registry with a webhook notifier `webhook-down` (short client timeout)
/// and a Mattermost notifier `mm-ops`.
fn make_isolation_registry(webhook_url: &str, mattermost_url: &str) -> Arc<NotifierRegistry> {
    let short_client = reqwest::Client::builder()
        .timeout(SHORT_TIMEOUT)
        .build()
        .unwrap();
    let config = WebhookNotifierConfig {
        url: SecretString::new(webhook_url.to_string()),
        method: "POST".to_string(),
        headers: HashMap::new(),
        body_template: None,
        format: None,
    };
    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(
            WebhookNotifier::from_config("webhook-down", &config, short_client).unwrap(),
        ))
        .unwrap();
    registry
        .register(Arc::new(MattermostNotifier::new(
            "mm-ops".to_string(),
            SecretString::new(mattermost_url.to_string()),
            make_client(),
        )))
        .unwrap();
    Arc::new(registry)
}

/// Mount an endpoint that answers 200 only after `delay`.
async fn mount_endpoint(server: &MockServer, delay: Duration) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(delay))
        .mount(server)
        .await;
}

/// Wait until `server` has received `count` requests, or `deadline` expires.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_unresponsive_destination_does_not_delay_others() {
    let webhook_server = MockServer::start().await;
    let mm_server = MockServer::start().await;
    mount_endpoint(&webhook_server, Duration::from_secs(5)).await;
    mount_endpoint(&mm_server, Duration::ZERO).await;

    let registry = make_isolation_registry(&webhook_server.uri(), &mm_server.uri());
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let worker_handle = tokio::spawn(async move { worker.run(cancel_clone).await });

    let start = tokio::time::Instant::now();
    queue
        .send(make_payload_with_destinations(
            "both",
            vec!["webhook-down".to_string(), "mm-ops".to_string()],
        ))
        .unwrap();
    for i in 0..5 {
        queue
            .send(make_payload_with_destinations(
                &format!("mm_only_{i}"),
                vec!["mm-ops".to_string()],
            ))
            .unwrap();
    }

    let delivered = wait_for_requests(&mm_server, 6, WEBHOOK_RETRY_FLOOR).await;
    let elapsed = start.elapsed();
    let webhook_attempts = webhook_server
        .received_requests()
        .await
        .unwrap_or_default()
        .len();

    cancel.cancel();
    worker_handle.abort();

    assert_eq!(delivered, 6, "mm-ops must receive all its alerts");
    assert!(
        elapsed < Duration::from_secs(1),
        "mm-ops alerts took {elapsed:?}, they must not wait for webhook-down retries"
    );
    assert!(
        webhook_attempts < 3,
        "webhook-down retries should still be running, saw {webhook_attempts} attempts"
    );
}

#[test]
fn test_saturated_destination_drops_only_its_own_alerts() {
    const BURST: usize = valerter::DEFAULT_QUEUE_CAPACITY + 50;

    // Local recorder on a current-thread runtime: the queue and the workers
    // run on this thread, so their metrics land in this recorder.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let healthy_received = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let webhook_server = MockServer::start().await;
            let mm_server = MockServer::start().await;
            mount_endpoint(&webhook_server, Duration::from_secs(5)).await;
            mount_endpoint(&mm_server, Duration::ZERO).await;

            let registry = make_isolation_registry(&webhook_server.uri(), &mm_server.uri());
            let queue = NotificationQueue::new(valerter::DEFAULT_QUEUE_CAPACITY, &registry);
            let mut worker = NotificationWorker::new(&queue, registry);
            let cancel = tokio_util::sync::CancellationToken::new();
            let cancel_clone = cancel.clone();
            let worker_handle = tokio::spawn(async move { worker.run(cancel_clone).await });

            // A burst well within the healthy endpoint's throughput, but far
            // beyond what the unresponsive one can absorb.
            for i in 0..BURST {
                queue
                    .send(make_payload_with_destinations(
                        &format!("burst_{i}"),
                        vec!["webhook-down".to_string(), "mm-ops".to_string()],
                    ))
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }

            let received = wait_for_requests(&mm_server, BURST, Duration::from_secs(10)).await;
            cancel.cancel();
            worker_handle.abort();
            received
        })
    });

    assert_eq!(healthy_received, BURST, "mm-ops must receive every alert");

    let rendered = handle.render();
    let dropped = |notifier: &str, kind: &str| -> u64 {
        let prefix = format!(
            "valerter_destination_alerts_dropped_total{{notifier_name=\"{notifier}\",notifier_type=\"{kind}\"}} "
        );
        rendered
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .map(|v| v.parse().unwrap())
            .unwrap_or(0)
    };
    assert!(
        dropped("webhook-down", "webhook") > 0,
        "webhook-down must have dropped alerts:\n{rendered}"
    );
    assert_eq!(
        dropped("mm-ops", "mattermost"),
        0,
        "mm-ops must not drop anything:\n{rendered}"
    );
}

// ============================================================================
// Webhook payload hardening: default Content-Type, tojson, invalid JSON warning
// ============================================================================

/// Send one alert through a webhook notifier and return the requests received
/// by the mock server (which always answers 200).
async fn send_webhook_once(
    headers: HashMap<String, String>,
    body_template: Option<String>,
    body: &str,
) -> Vec<wiremock::Request> {
    use valerter::notify::Notifier;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let url = format!("{}/api/alerts", mock_server.uri());
    let notifier = make_webhook_notifier("payload-webhook", &url, "POST", headers, body_template);
    let mut payload =
        make_payload_with_destinations("payload_rule", vec!["payload-webhook".to_string()]);
    payload.message.body = body.to_string();

    notifier.send(&payload).await.unwrap();
    mock_server.received_requests().await.unwrap()
}

fn content_types(request: &wiremock::Request) -> Vec<String> {
    request
        .headers
        .get_all("content-type")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn test_webhook_default_body_has_json_content_type() {
    let requests = send_webhook_once(HashMap::new(), None, "Test body content").await;

    assert_eq!(requests.len(), 1);
    assert_eq!(content_types(&requests[0]), vec!["application/json"]);
}

#[tokio::test]
async fn test_webhook_body_template_has_json_content_type() {
    let requests = send_webhook_once(
        HashMap::new(),
        Some(r#"{"text": {{ body | tojson }}}"#.to_string()),
        "Test body content",
    )
    .await;

    assert_eq!(requests.len(), 1);
    assert_eq!(content_types(&requests[0]), vec!["application/json"]);
}

#[tokio::test]
async fn test_webhook_configured_content_type_not_duplicated() {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/plain".to_string());
    let requests = send_webhook_once(headers, Some("{{ body }}".to_string()), "plain").await;

    assert_eq!(requests.len(), 1);
    assert_eq!(content_types(&requests[0]), vec!["text/plain"]);
}

#[tokio::test]
async fn test_webhook_invalid_json_body_still_sent() {
    // Unescaped quote: the notifier warns but still sends the request.
    let (logs, _guard) = capture_logs(tracing::Level::WARN);
    let requests = send_webhook_once(
        HashMap::new(),
        Some(r#"{"text": "{{ body }}"}"#.to_string()),
        r#"say "hi""#,
    )
    .await;

    assert_eq!(requests.len(), 1);
    assert_eq!(
        String::from_utf8(requests[0].body.clone()).unwrap(),
        r#"{"text": "say "hi""}"#
    );
    let logs = logs.text();
    let warn = logs
        .lines()
        .find(|l| l.contains("Webhook body is not valid JSON"))
        .unwrap_or_else(|| panic!("missing invalid JSON warning in:\n{logs}"));
    assert!(warn.contains("WARN"), "{warn}");
    // The rendered body may carry event data: it is never logged.
    assert!(!logs.contains(r#"say "hi""#), "{logs}");
}

#[tokio::test]
async fn test_webhook_non_json_content_type_body_sent() {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/plain".to_string());
    let requests = send_webhook_once(headers, Some("{{ body }}".to_string()), "not json").await;

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"not json");
}

#[tokio::test]
async fn test_webhook_tojson_body_is_valid_json() {
    let original = "say \"hi\"\npath C:\\tmp";
    let requests = send_webhook_once(
        HashMap::new(),
        Some(r#"{"text": {{ body | tojson }}}"#.to_string()),
        original,
    )
    .await;

    assert_eq!(requests.len(), 1);
    let parsed: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(parsed["text"], original);
}

// ============================================================================
// `${VAR}` in the webhook body_template: resolved in the source only
// ============================================================================

/// Send one alert through an already built webhook notifier and return the
/// requests received by the mock server (which always answers 200).
async fn send_with_notifier(
    server: &MockServer,
    notifier: &WebhookNotifier,
    body: &str,
) -> Vec<wiremock::Request> {
    use valerter::notify::Notifier;

    let mut payload =
        make_payload_with_destinations("payload_rule", vec!["payload-webhook".to_string()]);
    payload.message.body = body.to_string();
    notifier.send(&payload).await.unwrap();
    server.received_requests().await.unwrap()
}

async fn start_ok_server() -> MockServer {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;
    mock_server
}

#[tokio::test]
#[serial_test::serial]
async fn test_webhook_env_var_in_body_template_is_resolved() {
    let mock_server = start_ok_server().await;
    let url = format!("{}/api/alerts", mock_server.uri());
    // Only the notifier construction reads the environment.
    let notifier = temp_env::with_var("ROUTING_KEY", Some("abc123"), || {
        make_webhook_notifier(
            "payload-webhook",
            &url,
            "POST",
            HashMap::new(),
            Some(r#"{"routing_key": "${ROUTING_KEY}"}"#.to_string()),
        )
    });

    let requests = send_with_notifier(&mock_server, &notifier, "body").await;

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, br#"{"routing_key": "abc123"}"#);
}

#[tokio::test]
#[serial_test::serial]
async fn test_webhook_env_var_syntax_in_alert_body_sent_literally() {
    let mock_server = start_ok_server().await;
    let url = format!("{}/api/alerts", mock_server.uri());
    let notifier = temp_env::with_var("HOME", Some("/home/secret"), || {
        make_webhook_notifier(
            "payload-webhook",
            &url,
            "POST",
            HashMap::new(),
            Some(r#"{"text": {{ body | tojson }}}"#.to_string()),
        )
    });

    let requests = send_with_notifier(&mock_server, &notifier, "path is ${HOME}").await;

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, br#"{"text": "path is ${HOME}"}"#);
}

// ============================================================================
// `log`: event fields in the webhook body_template
// ============================================================================

/// Send one alert carrying the event `fields` through a webhook notifier
/// whose `body_template` is `template`, against a server answering
/// `statuses` per request (the last one repeats). Returns the request bodies.
async fn send_with_log_fields(
    template: &str,
    fields: serde_json::Value,
    statuses: &'static [u16],
) -> Vec<String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use valerter::notify::Notifier;

    let mock_server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/api/alerts"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(statuses[n.min(statuses.len() - 1)])
        })
        .mount(&mock_server)
        .await;
    let url = format!("{}/api/alerts", mock_server.uri());
    let notifier = make_webhook_notifier(
        "log-webhook",
        &url,
        "POST",
        HashMap::new(),
        Some(template.to_string()),
    );
    let mut payload = make_payload_with_destinations("log_rule", vec!["log-webhook".to_string()]);
    payload.log = AlertPayload::log_from_fields(&fields);

    notifier.send(&payload).await.unwrap();
    mock_server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect()
}

#[tokio::test]
async fn test_webhook_body_template_reads_log_fields() {
    let bodies = send_with_log_fields(
        r#"{"host": {{ log.host | tojson }}, "pod": {{ log["k8s.pod"] | tojson }}}"#,
        serde_json::json!({"host": "web-01", "k8s.pod": "api-7f", "_msg": "m"}),
        &[200],
    )
    .await;

    assert_eq!(bodies, vec![r#"{"host": "web-01", "pod": "api-7f"}"#]);
}

#[tokio::test]
async fn test_webhook_body_template_whole_log_is_valid_json() {
    let bodies = send_with_log_fields(
        r#"{"details": {{ log | tojson }}}"#,
        serde_json::json!({
            "_msg": "say \"hi\"\nnext",
            "_time": "2026-01-15T10:49:35Z",
            "k8s.pod": "api-7f"
        }),
        &[200],
    )
    .await;

    assert_eq!(bodies.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    let details = &parsed["details"];
    assert_eq!(details["_msg"], "say \"hi\"\nnext");
    assert_eq!(details["_time"], "2026-01-15T10:49:35Z");
    // Flat and unflattened views of a dotted key.
    assert_eq!(details["k8s.pod"], "api-7f");
    assert_eq!(details["k8s"]["pod"], "api-7f");
}

#[tokio::test]
async fn test_webhook_env_var_syntax_in_log_field_sent_literally() {
    // `${VAR}` is resolved in the template source when the notifier is built,
    // never in rendered values: an undefined variable in a field is no error.
    let bodies = send_with_log_fields(
        r#"{"key": {{ log.key | tojson }}}"#,
        serde_json::json!({"key": "${ROUTING_KEY_NEVER_DEFINED}"}),
        &[200],
    )
    .await;

    assert_eq!(bodies, vec![r#"{"key": "${ROUTING_KEY_NEVER_DEFINED}"}"#]);
}

#[tokio::test]
async fn test_webhook_log_body_identical_across_retries() {
    let bodies = send_with_log_fields(
        r#"{"host": {{ log.host | tojson }}, "msg": {{ log._msg | tojson }}}"#,
        serde_json::json!({"host": "web-01", "_msg": "boom"}),
        &[500, 200],
    )
    .await;

    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[0], r#"{"host": "web-01", "msg": "boom"}"#);
}

// ============================================================================
// Mattermost: rule-level mattermost_channel override and fallback
// ============================================================================

#[tokio::test]
async fn test_mattermost_rule_channel_override_falls_back_to_notifier_channel() {
    let mock_server = MockServer::start().await;
    // Webhook locked to its own channel: the override is rejected once.
    Mock::given(method("POST"))
        .and(path("/hooks/locked"))
        .and(body_partial_json(serde_json::json!({"channel": "alerts"})))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hooks/locked"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut registry = NotifierRegistry::new();
    registry
        .register(Arc::new(MattermostNotifier::with_options(
            "default".to_string(),
            SecretString::new(format!("{}/hooks/locked", mock_server.uri())),
            Some("ops".to_string()),
            None,
            None,
            make_client(),
        )))
        .unwrap();
    let registry = Arc::new(registry);
    let queue = NotificationQueue::new(10, &registry);
    let mut worker = NotificationWorker::new(&queue, registry);

    let mut payload = make_payload("override_rule");
    payload.mattermost_channel = Some("alerts".to_string());
    queue.send(payload).unwrap();

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let worker_handle = tokio::spawn(async move {
        worker.run(cancel_clone).await;
    });
    wait_for_requests(&mock_server, 2, Duration::from_secs(5)).await;
    cancel.cancel();
    worker_handle.await.unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let first: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(first["channel"], "alerts");
    // Resent once to the notifier's own channel.
    assert_eq!(second["channel"], "ops");
    mock_server.verify().await;
}
