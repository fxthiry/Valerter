//! Integration tests for Mattermost notification sending.
//!
//! Uses wiremock to simulate Mattermost webhook endpoints.

use std::time::Duration;
use valerter::notify::{AlertPayload, NotificationQueue, NotificationWorker};
use valerter::template::RenderedMessage;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_payload(rule_name: &str, webhook_url: &str) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body content".to_string(),
            color: Some("#ff0000".to_string()),
            icon: None,
        },
        rule_name: rule_name.to_string(),
        webhook_url: webhook_url.to_string(),
    }
}

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create client")
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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/test-webhook", mock_server.uri());
    let payload = make_payload("test_rule", &webhook_url);
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
    use std::sync::Arc;

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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/retry-test", mock_server.uri());
    let payload = make_payload("retry_rule", &webhook_url);
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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/always-fail", mock_server.uri());
    let payload = make_payload("fail_rule", &webhook_url);
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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/format-test", mock_server.uri());
    let payload = make_payload("format_rule", &webhook_url);
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

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/bad-request", mock_server.uri());
    let payload = make_payload("bad_rule", &webhook_url);
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
// Test 403 Forbidden (invalid webhook) is NOT retried
// ============================================================================

#[tokio::test]
async fn test_forbidden_no_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/forbidden"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&mock_server)
        .await;

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/forbidden", mock_server.uri());
    let payload = make_payload("forbidden_rule", &webhook_url);
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

// ============================================================================
// Test multiple alerts processed sequentially
// ============================================================================

#[tokio::test]
async fn test_multiple_alerts_processed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hooks/multi"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3) // 3 alerts
        .mount(&mock_server)
        .await;

    let queue = NotificationQueue::new(10);
    let client = make_client();
    let mut worker = NotificationWorker::new(&queue, client);

    let webhook_url = format!("{}/hooks/multi", mock_server.uri());

    // Send 3 alerts
    for i in 0..3 {
        let payload = make_payload(&format!("rule_{}", i), &webhook_url);
        queue.send(payload).unwrap();
    }

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
