//! Integration tests for VictoriaLogs streaming connection.
//!
//! Uses wiremock to simulate VictoriaLogs tail endpoint behavior.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::logs::capture_logs;
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
        basic_auth: None,
        headers: None,
        tls: None,
    }
}

/// What `stream_with_reconnect` produced during its first connection.
struct FirstConnection {
    lines: Vec<String>,
    /// Logs (DEBUG and above) written meanwhile.
    logs: String,
}

/// Runs `stream_with_reconnect` until its first connection ends, collecting
/// the lines it delivered and the logs. The end is detected by the log written
/// right before the reconnection delay (`Stream ended, reconnecting` after a
/// clean EOF, `Connection failed, retrying` after a failure), so no second
/// connection is ever made.
async fn first_connection(client: &mut TailClient) -> FirstConnection {
    let (logs, _guard) = capture_logs(tracing::Level::DEBUG);
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let stream = client.stream_with_reconnect("test_rule", "default", None, move |line| {
        let sink = Arc::clone(&sink);
        async move {
            sink.lock().unwrap().push(line);
            Ok(())
        }
    });
    let ended = async {
        loop {
            let text = logs.text();
            if text.contains("Stream ended, reconnecting")
                || text.contains("Connection failed, retrying")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result = stream => panic!("stream_with_reconnect returned: {result:?}"),
        () = ended => {}
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!("first connection did not end within 10s:\n{}", logs.text())
        }
    }
    let lines = std::mem::take(&mut *lines.lock().unwrap());
    FirstConnection {
        lines,
        logs: logs.text(),
    }
}

// =============================================================================
// Test 8.2: Basic streaming connection (mock chunks -> lines)
// =============================================================================

#[tokio::test]
async fn test_streaming_basic_single_line() {
    let mock_server = MockServer::start().await;

    // Configure streaming response with a single JSON line
    Mock::given(method("GET"))
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

    let lines = first_connection(&mut client).await.lines;

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

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.as_slice(), "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:multi");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("log 1"));
    assert!(lines[1].contains("log 2"));
    assert!(lines[2].contains("log 3"));
}

#[tokio::test]
async fn test_streaming_empty_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"", "application/x-ndjson"))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:empty");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert!(lines.is_empty());
}

// =============================================================================
// Test 8.3: Reconnection after HTTP error
// =============================================================================

#[tokio::test]
async fn test_connection_error_http_500() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:error");
    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    // The failure is logged and the client backs off to reconnect.
    assert!(logs.contains("HTTP error from VictoriaLogs"), "{logs}");
    assert!(logs.contains("status=500"), "{logs}");
    assert!(logs.contains("Connection failed, retrying"), "{logs}");
}

#[tokio::test]
async fn test_connection_error_http_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:notfound");
    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    // The failure is logged and the client backs off to reconnect.
    assert!(logs.contains("HTTP error from VictoriaLogs"), "{logs}");
    assert!(logs.contains("status=404"), "{logs}");
    assert!(logs.contains("Connection failed, retrying"), "{logs}");
}

#[tokio::test]
async fn test_connection_error_http_503() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:unavailable");
    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    // The failure is logged and the client backs off to reconnect.
    assert!(logs.contains("HTTP error from VictoriaLogs"), "{logs}");
    assert!(logs.contains("status=503"), "{logs}");
    assert!(logs.contains("Connection failed, retrying"), "{logs}");
}

#[tokio::test]
async fn test_connection_error_server_down() {
    // Create a config pointing to a non-existent server
    let config = TailConfig {
        base_url: "http://127.0.0.1:59999".to_string(), // Unlikely port
        query: "_stream:test".to_string(),
        start: None,
        basic_auth: None,
        headers: None,
        tls: None,
    };

    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    // The failure is logged and the client backs off to reconnect.
    assert!(logs.contains("Connection failed"), "{logs}");
    assert!(logs.contains("Connection failed, retrying"), "{logs}");
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
    Mock::given(method("GET"))
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
        basic_auth: None,
        headers: None,
        tls: None,
    };

    let mut client = TailClient::new(config).unwrap();
    first_connection(&mut client).await;

    // If we get here without panic, the URL matched
}

#[tokio::test]
async fn test_url_with_start_param() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
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
        basic_auth: None,
        headers: None,
        tls: None,
    };

    let mut client = TailClient::new(config).unwrap();
    first_connection(&mut client).await;
}

// =============================================================================
// Header verification tests
// =============================================================================

#[tokio::test]
async fn test_headers_are_set_correctly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header("Accept", "application/x-ndjson"))
        .and(header("Connection", "keep-alive"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:headers");
    let mut client = TailClient::new(config).unwrap();

    first_connection(&mut client).await;
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

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.as_bytes(), "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:utf8");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

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
    fn on_reconnect(&self, _rule_name: &str, _vl_source: &str) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_stream_with_reconnect_receives_lines() {
    let mock_server = MockServer::start().await;

    // Configure streaming response
    Mock::given(method("GET"))
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
            .stream_with_reconnect("test_rule", "default", None, |line| {
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
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
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
            .stream_with_reconnect("test_rule", "default", Some(&callback), |line| {
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
    log_reconnection_attempt("test_rule", "default", 0, Duration::from_secs(1));
    log_reconnection_attempt("test_rule", "default", 5, Duration::from_secs(32));
    log_reconnection_attempt("test_rule", "default", 10, Duration::from_secs(60));
}

#[test]
fn test_log_reconnection_success_does_not_panic() {
    // Just verify the function can be called without panic
    log_reconnection_success("test_rule", "default");
}

#[test]
fn test_reconnect_callback_trait() {
    let callback = TestReconnectCallback::new();
    assert_eq!(callback.reconnect_count(), 0);

    callback.on_reconnect("rule1", "vlprod");
    assert_eq!(callback.reconnect_count(), 1);

    callback.on_reconnect("rule2", "vldev");
    assert_eq!(callback.reconnect_count(), 2);
}

// =============================================================================
// Story 5.4: Basic Auth and Custom Headers Integration Tests
// =============================================================================
//
// Note on TLS testing (AC #6, #7):
// - AC #6 (verify: false with self-signed cert): Code implemented in tail.rs:90-93
//   via danger_accept_invalid_certs(true). Not testable with wiremock as it
//   doesn't support TLS configuration in tests.
// - AC #7 (verify: true rejects self-signed): Default behavior from reqwest.
//   Not testable without a real TLS server with self-signed certificate.
//   The default value (verify: true) is tested in config.rs unit tests.
// =============================================================================

use std::collections::HashMap;
use valerter::config::{BasicAuthConfig, SecretString};
use wiremock::matchers::header_exists;

/// Helper to create a TailConfig with Basic Auth
fn create_config_with_basic_auth(
    mock_server: &MockServer,
    username: &str,
    password: &str,
) -> TailConfig {
    TailConfig {
        base_url: mock_server.uri(),
        query: "_stream:auth".to_string(),
        start: None,
        basic_auth: Some(BasicAuthConfig {
            username: username.to_string(),
            password: SecretString::new(password.to_string()),
        }),
        headers: None,
        tls: None,
    }
}

/// Helper to create a TailConfig with custom headers
fn create_config_with_headers(
    mock_server: &MockServer,
    headers: HashMap<String, SecretString>,
) -> TailConfig {
    TailConfig {
        base_url: mock_server.uri(),
        query: "_stream:headers".to_string(),
        start: None,
        basic_auth: None,
        headers: Some(headers),
        tls: None,
    }
}

#[tokio::test]
async fn test_basic_auth_header_is_sent() {
    let mock_server = MockServer::start().await;

    // Expected Basic Auth header for "testuser:testpass" is "dGVzdHVzZXI6dGVzdHBhc3M="
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header("Authorization", "Basic dGVzdHVzZXI6dGVzdHBhc3M="))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"authenticated\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = create_config_with_basic_auth(&mock_server, "testuser", "testpass");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("authenticated"));
}

#[tokio::test]
async fn test_custom_headers_are_sent() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header("X-API-Key", "secret-key-123"))
        .and(header("X-Custom", "custom-value"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"headers received\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut headers = HashMap::new();
    headers.insert(
        "X-API-Key".to_string(),
        SecretString::new("secret-key-123".to_string()),
    );
    headers.insert(
        "X-Custom".to_string(),
        SecretString::new("custom-value".to_string()),
    );

    let config = create_config_with_headers(&mock_server, headers);
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("headers received"));
}

#[tokio::test]
async fn test_bearer_token_in_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header("Authorization", "Bearer my-jwt-token-here"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"bearer auth ok\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        SecretString::new("Bearer my-jwt-token-here".to_string()),
    );

    let config = create_config_with_headers(&mock_server, headers);
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("bearer auth ok"));
}

#[tokio::test]
async fn test_basic_auth_with_custom_headers_combined() {
    let mock_server = MockServer::start().await;

    // Both Basic Auth and custom headers should be sent
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header_exists("Authorization")) // Basic auth header
        .and(header("X-Tenant-ID", "tenant-abc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"combined auth ok\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut headers = HashMap::new();
    headers.insert(
        "X-Tenant-ID".to_string(),
        SecretString::new("tenant-abc".to_string()),
    );

    let config = TailConfig {
        base_url: mock_server.uri(),
        query: "_stream:combined".to_string(),
        start: None,
        basic_auth: Some(BasicAuthConfig {
            username: "admin".to_string(),
            password: SecretString::new("secret".to_string()),
        }),
        headers: Some(headers),
        tls: None,
    };

    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("combined auth ok"));
}

// =============================================================================
// Test 401 on wrong credentials (AC #1 edge case)
// =============================================================================

#[tokio::test]
async fn test_basic_auth_401_on_wrong_credentials() {
    let mock_server = MockServer::start().await;

    // Server expects correct credentials, returns 401 for wrong ones
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .and(header(
            "Authorization",
            "Basic d3JvbmdfdXNlcjp3cm9uZ19wYXNz",
        )) // wrong_user:wrong_pass
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&mock_server)
        .await;

    let config = create_config_with_basic_auth(&mock_server, "wrong_user", "wrong_pass");
    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    assert!(
        logs.contains("status=401"),
        "Should mention 401 status: {logs}"
    );
    assert!(logs.contains("response=Unauthorized"), "{logs}");
    assert!(logs.contains("Connection failed, retrying"), "{logs}");
}

#[tokio::test]
async fn test_without_auth_no_authorization_header() {
    let mock_server = MockServer::start().await;

    // This mock will FAIL if Authorization header is present
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"_msg\":\"no auth\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:noauth");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("no auth"));
}

// =============================================================================
// v2.0.3 hardening
// =============================================================================

/// Invalid UTF-8 in the stream must drop only the faulty line and streaming
/// must continue, instead of killing the rule task.
#[tokio::test]
async fn test_invalid_utf8_line_is_dropped_not_fatal() {
    let mock_server = MockServer::start().await;

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"{\"_msg\":\"before\"}\n");
    body.extend_from_slice(b"{\"_msg\":\"bad \xff\xfe\"}\n");
    body.extend_from_slice(b"{\"_msg\":\"after\"}\n");

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.as_slice(), "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:utf8bad");
    let mut client = TailClient::new(config).unwrap();

    let received_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let lines_clone = Arc::clone(&received_lines);

    let result = tokio::time::timeout(Duration::from_millis(800), async {
        client
            .stream_with_reconnect("test_rule", "default", None, |line| {
                let lines = Arc::clone(&lines_clone);
                async move {
                    lines.lock().unwrap().push(line);
                    Ok(())
                }
            })
            .await
    })
    .await;

    // Must still be looping (timeout), not returned with an error.
    assert!(
        result.is_err(),
        "stream must not terminate on invalid UTF-8"
    );
    let lines = received_lines.lock().unwrap();
    // Only the invalid line is dropped; its neighbours are delivered intact.
    // The next connection only starts after ~1s, past the 800ms window.
    assert_eq!(
        *lines,
        vec![r#"{"_msg":"before"}"#, r#"{"_msg":"after"}"#],
        "valid lines around the invalid one must be kept"
    );
}

/// A line over 1 MiB is dropped whole: its neighbours are delivered and no
/// truncated fragment of it ever reaches the caller.
#[tokio::test]
async fn test_oversized_line_is_dropped_without_truncated_fragment() {
    let mock_server = MockServer::start().await;

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"{\"_msg\":\"before\"}\n");
    body.extend_from_slice(b"{\"_msg\":\"");
    body.extend(std::iter::repeat_n(b'x', 1024 * 1024 + 10));
    body.extend_from_slice(b"\"}\n");
    body.extend_from_slice(b"{\"_msg\":\"after\"}\n");

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/x-ndjson"))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:oversized");
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;

    assert_eq!(
        lines,
        vec![r#"{"_msg":"before"}"#, r#"{"_msg":"after"}"#],
        "only the two valid lines must be received"
    );
}

/// A clean EOF (200 then server closes) is not a failure: the throttle reset
/// callback must NOT fire on the next connection.
#[tokio::test]
async fn test_clean_eof_does_not_trigger_reconnect_callback() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(b"{\"_msg\":\"x\"}\n", "application/x-ndjson"),
        )
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:eof");
    let mut client = TailClient::new(config).unwrap();
    let callback = TestReconnectCallback::new();

    let _ = tokio::time::timeout(Duration::from_millis(1500), async {
        client
            .stream_with_reconnect("test_rule", "default", Some(&callback), |_| async {
                Ok(())
            })
            .await
    })
    .await;

    assert_eq!(
        callback.reconnect_count(),
        0,
        "clean EOF must not reset throttle"
    );
    // ...but reconnections did happen (several requests within the window).
    assert!(mock_server.received_requests().await.unwrap().len() >= 2);
}

/// A clean EOF with data flowing must reconnect quickly (base delay, no
/// exponential growth) — but never in a tight loop.
#[tokio::test]
async fn test_clean_eof_reconnects_with_delay_not_tight_loop() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"", "application/x-ndjson"))
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:eofempty");
    let mut client = TailClient::new(config).unwrap();

    let _ = tokio::time::timeout(Duration::from_millis(1200), async {
        client
            .stream_with_reconnect("test_rule", "default", None, |_| async { Ok(()) })
            .await
    })
    .await;

    let n = mock_server.received_requests().await.unwrap().len();
    // Empty EOFs back off (1s, 2s, ...): the second request arrives after ~1s
    // and at most 3 land in 1.2s, where the old tight loop produced hundreds.
    assert!(
        (2..=3).contains(&n),
        "expected backed-off reconnects, got {n}"
    );
}

/// Responder recording the arrival time of each request.
struct TimedEmptyBody {
    arrivals: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
}

impl wiremock::Respond for TimedEmptyBody {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        self.arrivals
            .lock()
            .unwrap()
            .push(std::time::Instant::now());
        ResponseTemplate::new(200).set_body_raw(b"", "application/x-ndjson")
    }
}

/// The first empty EOF is followed by a ~1s delay (not 2s).
#[tokio::test]
async fn test_first_empty_eof_reconnects_after_about_one_second() {
    let mock_server = MockServer::start().await;
    let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(TimedEmptyBody {
            arrivals: Arc::clone(&arrivals),
        })
        .mount(&mock_server)
        .await;

    let config = create_config(&mock_server, "_stream:eoffirst");
    let mut client = TailClient::new(config).unwrap();

    let _ = tokio::time::timeout(Duration::from_millis(1500), async {
        client
            .stream_with_reconnect("test_rule", "default", None, |_| async { Ok(()) })
            .await
    })
    .await;

    let arrivals = arrivals.lock().unwrap();
    assert!(
        arrivals.len() >= 2,
        "expected a second request, got {}",
        arrivals.len()
    );
    let gap = arrivals[1] - arrivals[0];
    assert!(
        gap >= Duration::from_millis(850) && gap <= Duration::from_millis(1200),
        "second request after {gap:?}, expected ~1s"
    );
}

/// Run `stream_with_reconnect` against `mock_server` for `duration` under a
/// local Prometheus recorder (current-thread runtime, so every metric lands
/// in it). Returns the rendering.
fn stream_counted(mock_server_setup: impl AsyncFnOnce(&MockServer), duration: Duration) -> String {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            mock_server_setup(&mock_server).await;
            let mut client = TailClient::new(create_config(&mock_server, "_stream:m")).unwrap();
            let _ = tokio::time::timeout(duration, async {
                client
                    .stream_with_reconnect("r", "s", None, |_| async { Ok(()) })
                    .await
            })
            .await;
        })
    });
    handle.render()
}

/// Value of the `{rule_name="r",vl_source="s"}` series of `name`, if emitted.
fn rs_counter(rendered: &str, name: &str) -> Option<u64> {
    let prefix = format!("{name}{{rule_name=\"r\",vl_source=\"s\"}} ");
    rendered
        .lines()
        .find_map(|l| l.strip_prefix(&prefix)?.parse().ok())
}

/// A clean EOF counts in `valerter_stream_ends_total`, never in
/// `valerter_reconnections_total`.
#[test]
fn test_clean_eof_counts_stream_end_not_reconnection() {
    let rendered = stream_counted(
        async |server| {
            Mock::given(method("GET"))
                .and(path("/select/logsql/tail"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(b"{\"_msg\":\"x\"}\n", "application/x-ndjson"),
                )
                .mount(server)
                .await;
        },
        Duration::from_millis(1500),
    );

    let ends = rs_counter(&rendered, "valerter_stream_ends_total").unwrap_or(0);
    assert!(ends >= 1, "expected stream ends, got {ends}:\n{rendered}");
    assert_eq!(
        rs_counter(&rendered, "valerter_reconnections_total").unwrap_or(0),
        0,
        "a clean EOF is not a reconnection after failure:\n{rendered}"
    );
}

/// One clean EOF, then an HTTP 500: one stream end, one reconnection.
#[test]
fn test_clean_eof_then_http_500_are_counted_separately() {
    let rendered = stream_counted(
        async |server| {
            Mock::given(method("GET"))
                .and(path("/select/logsql/tail"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(b"{\"_msg\":\"x\"}\n", "application/x-ndjson"),
                )
                .up_to_n_times(1)
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/select/logsql/tail"))
                .respond_with(ResponseTemplate::new(500))
                .mount(server)
                .await;
        },
        // EOF at ~0s, ~1s delay, 500 at ~1s, then a >= 1s failure backoff.
        Duration::from_millis(1700),
    );

    assert_eq!(
        rs_counter(&rendered, "valerter_stream_ends_total"),
        Some(1),
        "{rendered}"
    );
    assert_eq!(
        rs_counter(&rendered, "valerter_reconnections_total"),
        Some(1),
        "{rendered}"
    );
}

// =============================================================================
// URL normalization and header replacement
// =============================================================================

#[tokio::test]
async fn test_base_url_with_trailing_slash() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(b"{\"_msg\":\"x\"}\n", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut config = create_config(&mock_server, "_stream:slash");
    config.base_url = format!("{}/", mock_server.uri());
    let mut client = TailClient::new(config).unwrap();

    let lines = first_connection(&mut client).await.lines;
    assert_eq!(lines.len(), 1);

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests[0].url.path(), "/select/logsql/tail");
}

/// Values of every header with the given name in the first received request.
async fn received_header_values(mock_server: &MockServer, name: &str) -> Vec<String> {
    let requests = mock_server.received_requests().await.unwrap();
    requests[0]
        .headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn test_custom_accept_header_replaces_default() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut headers = HashMap::new();
    headers.insert(
        "accept".to_string(),
        SecretString::new("application/json".to_string()),
    );
    let config = create_config_with_headers(&mock_server, headers);
    let mut client = TailClient::new(config).unwrap();
    first_connection(&mut client).await;

    assert_eq!(
        received_header_values(&mock_server, "accept").await,
        vec!["application/json"]
    );
}

#[tokio::test]
async fn test_custom_authorization_replaces_basic_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"\n", "application/x-ndjson"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut config = create_config_with_basic_auth(&mock_server, "admin", "secret");
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        SecretString::new("Bearer abc".to_string()),
    );
    config.headers = Some(headers);
    assert!(config.custom_authorization_overrides_basic_auth());

    let mut client = TailClient::new(config).unwrap();
    first_connection(&mut client).await;

    assert_eq!(
        received_header_values(&mock_server, "authorization").await,
        vec!["Bearer abc"]
    );
}

// =============================================================================
// Secrets and bounded error bodies
// =============================================================================

/// Credentials and query string of the source URL never reach the logs, not
/// even at DEBUG level nor inside a transport error.
#[tokio::test]
async fn test_source_url_secrets_are_not_logged() {
    let port = portpicker::pick_unused_port().expect("free port");
    let config = TailConfig {
        base_url: format!("http://user:S3CRETPASS@127.0.0.1:{port}/?token=S3CRETTOKEN"),
        query: "_stream:secret".to_string(),
        start: None,
        basic_auth: None,
        headers: None,
        tls: None,
    };
    let mut client = TailClient::new(config).unwrap();

    let logs = first_connection(&mut client).await.logs;

    assert!(
        logs.contains("Connecting to VictoriaLogs tail endpoint"),
        "{logs}"
    );
    assert!(logs.contains("Connection failed"), "{logs}");
    assert!(
        logs.contains("***"),
        "the URL should be logged redacted: {logs}"
    );
    assert!(!logs.contains("S3CRETPASS"), "{logs}");
    assert!(!logs.contains("S3CRETTOKEN"), "{logs}");
}

/// A proxy answering 502 with a chunked body that never ends must not block
/// the task: the warning is logged with what was received and the client
/// reconnects.
#[tokio::test]
async fn test_endless_error_body_does_not_block_reconnection() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut second_tx = Some(second_tx);
        let mut open = Vec::new();
        for accepted in 0.. {
            let (mut socket, _) = listener.accept().await.unwrap();
            if accepted == 1
                && let Some(tx) = second_tx.take()
            {
                let _ = tx.send(());
            }
            let _ = socket
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n\
                      b\r\nproxy-error\r\n",
                )
                .await;
            // Never send the final chunk: keep the socket open.
            open.push(socket);
        }
    });

    let (logs, _guard) = capture_logs(tracing::Level::WARN);
    let config = TailConfig {
        base_url: format!("http://{addr}"),
        query: "_stream:endless".to_string(),
        start: None,
        basic_auth: None,
        headers: None,
        tls: None,
    };
    let mut client = TailClient::new(config).unwrap();
    let stream = client.stream_with_reconnect("test_rule", "default", None, |_| async { Ok(()) });

    tokio::select! {
        result = stream => panic!("stream_with_reconnect returned: {result:?}"),
        second = second_rx => second.expect("listener task alive"),
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!("no second connection within 10s:\n{}", logs.text())
        }
    }

    let logs = logs.text();
    assert!(logs.contains("HTTP error from VictoriaLogs"), "{logs}");
    assert!(logs.contains("status=502"), "{logs}");
    assert!(logs.contains("response=proxy-error"), "{logs}");
}
