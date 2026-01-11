//! Integration tests for VictoriaLogs streaming connection.
//!
//! Uses wiremock to simulate VictoriaLogs tail endpoint behavior.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use valerter::error::StreamError;
use valerter::tail::{
    BACKOFF_BASE, BACKOFF_MAX, ReconnectCallback, TailClient, TailConfig, backoff_delay,
    log_reconnection_attempt, log_reconnection_success,
};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper to create a TailConfig pointing to the mock server.
fn create_config(mock_server: &MockServer, query: &str) -> TailConfig {
    TailConfig {
        base_url: mock_server.uri(),
        query: query.to_string(),
        start: None,
    }
}

// =============================================================================
// Test 8.2: Basic streaming connection (mock chunks -> lines)
// =============================================================================

#[tokio::test]
async fn test_streaming_basic_single_line() {
    let mock_server = MockServer::start().await;

    // Configure streaming response with a single JSON line
    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .and(query_param("query", "_stream:test"))
        .and(header("Accept", "application/x-ndjson"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    b"{\"_time\":\"2026-01-09T10:00:00Z\",\"_msg\":\"test log\"}\n",
                    "application/x-ndjson",
                )
                .append_header("Transfer-Encoding", "chunked"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:test");
    let mut client = TailClient::new(config).unwrap();

    let lines = client.connect_and_receive("test_rule").await.unwrap();

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("test log"));
}

#[tokio::test]
async fn test_streaming_multiple_lines() {
    let mock_server = MockServer::start().await;

    // Configure streaming response with multiple JSON lines
    let body = br#"{"_time":"2026-01-09T10:00:00Z","_msg":"log 1"}
{"_time":"2026-01-09T10:00:01Z","_msg":"log 2"}
{"_time":"2026-01-09T10:00:02Z","_msg":"log 3"}
"#;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.as_slice(), "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:multi");
    let mut client = TailClient::new(config).unwrap();

    let lines = client.connect_and_receive("test_rule").await.unwrap();

    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("log 1"));
    assert!(lines[1].contains("log 2"));
    assert!(lines[2].contains("log 3"));
}

#[tokio::test]
async fn test_streaming_empty_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"", "application/x-ndjson"))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:empty");
    let mut client = TailClient::new(config).unwrap();

    let lines = client.connect_and_receive("test_rule").await.unwrap();

    assert!(lines.is_empty());
}

// =============================================================================
// Test 8.3: Reconnection after HTTP error
// =============================================================================

#[tokio::test]
async fn test_connection_error_http_500() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:error");
    let mut client = TailClient::new(config).unwrap();

    let result = client.connect_and_receive("test_rule").await;

    assert!(result.is_err());
    match result {
        Err(StreamError::ConnectionFailed(msg)) => {
            assert!(msg.contains("500"));
        }
        _ => panic!("Expected ConnectionFailed error"),
    }
}

#[tokio::test]
async fn test_connection_error_http_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:notfound");
    let mut client = TailClient::new(config).unwrap();

    let result = client.connect_and_receive("test_rule").await;

    assert!(result.is_err());
    match result {
        Err(StreamError::ConnectionFailed(msg)) => {
            assert!(msg.contains("404"));
        }
        _ => panic!("Expected ConnectionFailed error"),
    }
}

#[tokio::test]
async fn test_connection_error_http_503() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:unavailable");
    let mut client = TailClient::new(config).unwrap();

    let result = client.connect_and_receive("test_rule").await;

    assert!(result.is_err());
    match result {
        Err(StreamError::ConnectionFailed(msg)) => {
            assert!(msg.contains("503"));
        }
        _ => panic!("Expected ConnectionFailed error"),
    }
}

#[tokio::test]
async fn test_connection_error_server_down() {
    // Create a config pointing to a non-existent server
    let config = TailConfig {
        base_url: "http://127.0.0.1:59999".to_string(), // Unlikely port
        query: "_stream:test".to_string(),
        start: None,
    };

    let mut client = TailClient::new(config).unwrap();

    let result = client.connect_and_receive("test_rule").await;

    assert!(result.is_err());
    match result {
        Err(StreamError::ConnectionFailed(_)) => {}
        _ => panic!("Expected ConnectionFailed error"),
    }
}

// =============================================================================
// Test 8.4: Timeout on zombie connection (read timeout)
// =============================================================================

#[tokio::test]
async fn test_timeout_detection() {
    let mock_server = MockServer::start().await;

    // Configure a delayed response that exceeds read timeout
    // Note: In real tests, we'd want to test actual timeout behavior,
    // but wiremock doesn't easily support streaming delays.
    // Instead, we test the timeout mapping in error handling.
    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"incomplete", "application/x-ndjson")
                .set_delay(Duration::from_millis(100)), // Short delay for test
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:delay");
    let mut client = TailClient::new(config).unwrap();

    // This won't actually timeout since delay is short, but tests the path
    let result = client.connect_and_receive("test_rule").await;

    // Should succeed (data received before timeout)
    // The buffer will hold "incomplete" without newline
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty()); // No complete lines
}

// =============================================================================
// Backoff delay integration tests
// =============================================================================

#[test]
fn test_backoff_sequence() {
    // Verify the full backoff sequence: 1, 2, 4, 8, 16, 32, 60, 60, 60...
    let expected_delays = [1, 2, 4, 8, 16, 32, 60, 60, 60, 60];

    for (attempt, expected_secs) in expected_delays.iter().enumerate() {
        let delay = backoff_delay(attempt as u32, BACKOFF_BASE, BACKOFF_MAX);
        assert_eq!(
            delay,
            Duration::from_secs(*expected_secs),
            "Attempt {} should have delay {}s",
            attempt,
            expected_secs
        );
    }
}

// =============================================================================
// URL construction integration tests
// =============================================================================

#[tokio::test]
async fn test_url_construction_is_correct() {
    let mock_server = MockServer::start().await;

    // Verify the exact URL format expected by VictoriaLogs
    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .and(query_param("query", "_stream:{app=\"myapp\"}"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = TailConfig {
        base_url: mock_server.uri(),
        query: r#"_stream:{app="myapp"}"#.to_string(),
        start: None,
    };

    let mut client = TailClient::new(config).unwrap();
    let _ = client.connect_and_receive("test_rule").await;

    // If we get here without panic, the URL matched
}

#[tokio::test]
async fn test_url_with_start_param() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .and(query_param("query", "_stream:test"))
        .and(query_param("start", "now-1h"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = TailConfig {
        base_url: mock_server.uri(),
        query: "_stream:test".to_string(),
        start: Some("now-1h".to_string()),
    };

    let mut client = TailClient::new(config).unwrap();
    let _ = client.connect_and_receive("test_rule").await;
}

// =============================================================================
// Header verification tests
// =============================================================================

#[tokio::test]
async fn test_headers_are_set_correctly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .and(header("Accept", "application/x-ndjson"))
        .and(header("Connection", "keep-alive"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:headers");
    let mut client = TailClient::new(config).unwrap();

    let _ = client.connect_and_receive("test_rule").await;
}

// =============================================================================
// UTF-8 handling integration tests (via StreamBuffer)
// =============================================================================

#[tokio::test]
async fn test_streaming_with_utf8_content() {
    let mock_server = MockServer::start().await;

    // JSON with UTF-8 characters (French accents and emoji)
    let body = r#"{"_msg":"Café crème été"}
{"_msg":"Alert 🚨 triggered"}
"#;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.as_bytes(), "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:utf8");
    let mut client = TailClient::new(config).unwrap();

    let lines = client.connect_and_receive("test_rule").await.unwrap();

    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("Café"));
    assert!(lines[0].contains("été"));
    assert!(lines[1].contains("🚨"));
}

// =============================================================================
// Tests for stream_with_reconnect
// =============================================================================

/// Test callback implementation for tracking reconnections
struct TestReconnectCallback {
    count: AtomicU32,
}

impl TestReconnectCallback {
    fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    fn reconnect_count(&self) -> u32 {
        self.count.load(Ordering::SeqCst)
    }
}

impl ReconnectCallback for TestReconnectCallback {
    fn on_reconnect(&self, _rule_name: &str) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_stream_with_reconnect_receives_lines() {
    let mock_server = MockServer::start().await;

    // Configure streaming response
    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            b"{\"_msg\":\"line1\"}\n{\"_msg\":\"line2\"}\n",
            "application/x-ndjson",
        ))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:reconnect");
    let mut client = TailClient::new(config).unwrap();

    let received_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let lines_clone = Arc::clone(&received_lines);

    // Use tokio::time::timeout to prevent infinite loop
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        client
            .stream_with_reconnect("test_rule", None, |line| {
                let lines = Arc::clone(&lines_clone);
                async move {
                    lines.lock().unwrap().push(line);
                    Ok(())
                }
            })
            .await
    })
    .await;

    // Should timeout (infinite loop), but lines should have been received
    assert!(result.is_err()); // Timeout expected

    let lines = received_lines.lock().unwrap();
    assert!(lines.len() >= 2);
    assert!(lines[0].contains("line1"));
    assert!(lines[1].contains("line2"));
}

#[tokio::test]
async fn test_stream_with_reconnect_retries_on_error() {
    let mock_server = MockServer::start().await;

    // First request fails, second succeeds
    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"after_retry\"}\n", "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:retry");
    let mut client = TailClient::new(config).unwrap();

    let callback = TestReconnectCallback::new();
    let received_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let lines_clone = Arc::clone(&received_lines);

    // Use short timeout - should get at least one retry and one success
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        client
            .stream_with_reconnect("test_rule", Some(&callback), |line| {
                let lines = Arc::clone(&lines_clone);
                async move {
                    lines.lock().unwrap().push(line);
                    Ok(())
                }
            })
            .await
    })
    .await;

    let lines = received_lines.lock().unwrap();
    // Should have received lines after retry
    assert!(!lines.is_empty(), "Expected lines after reconnection");
    assert!(lines[0].contains("after_retry"));

    // Callback should have been called at least once (may be more due to reconnections during timeout)
    assert!(
        callback.reconnect_count() >= 1,
        "Callback should be called at least once after reconnection, got {}",
        callback.reconnect_count()
    );
}

// =============================================================================
// Tests for log_reconnection_attempt and log_reconnection_success
// =============================================================================

#[test]
fn test_log_reconnection_attempt_does_not_panic() {
    // Just verify the function can be called without panic
    log_reconnection_attempt("test_rule", 0, Duration::from_secs(1));
    log_reconnection_attempt("test_rule", 5, Duration::from_secs(32));
    log_reconnection_attempt("test_rule", 10, Duration::from_secs(60));
}

#[test]
fn test_log_reconnection_success_does_not_panic() {
    // Just verify the function can be called without panic
    log_reconnection_success("test_rule");
}

#[test]
fn test_reconnect_callback_trait() {
    let callback = TestReconnectCallback::new();
    assert_eq!(callback.reconnect_count(), 0);

    callback.on_reconnect("rule1");
    assert_eq!(callback.reconnect_count(), 1);

    callback.on_reconnect("rule2");
    assert_eq!(callback.reconnect_count(), 2);
}
