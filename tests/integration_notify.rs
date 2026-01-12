//! Integration tests for Mattermost notification sending.
//!
//! Uses wiremock to simulate Mattermost webhook endpoints.

use std::sync::Arc;
use std::time::Duration;
use valerter::config::SecretString;
use valerter::notify::{AlertPayload, MattermostNotifier, NotificationQueue, NotificationWorker, NotifierRegistry};
use valerter::template::RenderedMessage;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_payload(rule_name: &str) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body content".to_string(),
            color: Some("#ff0000".to_string()),
            icon: None,
        },
        rule_name: rule_name.to_string(),
        destinations: vec![], // Empty = use default notifier (Story 6.3)
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
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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
                "footer": "valerter | format_rule"
            }]
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hooks/format-test", mock_server.uri());
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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
    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_test_registry(client, &webhook_url);
    let mut worker = NotificationWorker::new(&queue, registry, "default".to_string());

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

fn make_payload_with_destinations(rule_name: &str, destinations: Vec<String>) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body content".to_string(),
            color: Some("#ff0000".to_string()),
            icon: None,
        },
        rule_name: rule_name.to_string(),
        destinations,
    }
}

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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_multi_notifier_registry(
        client,
        vec![
            ("mattermost-infra", &webhook_infra),
            ("mattermost-ops", &webhook_ops),
        ],
    );

    let mut worker = NotificationWorker::new(&queue, registry, "mattermost-infra".to_string());

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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let registry = make_multi_notifier_registry(
        client,
        vec![
            ("notifier-success", &webhook_success),
            ("notifier-fail", &webhook_fail),
        ],
    );

    let mut worker = NotificationWorker::new(&queue, registry, "notifier-success".to_string());

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
