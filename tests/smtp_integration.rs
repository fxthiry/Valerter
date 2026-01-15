//! SMTP Integration tests with Mailhog (Story 7.2)
//!
//! These tests require a running Mailhog instance.
//!
//! # Running locally
//!
//! ```bash
//! # Start Mailhog with Docker
//! docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
//!
//! # Run the integration tests
//! TEST_SMTP_HOST=localhost TEST_SMTP_PORT=1025 cargo test --test smtp_integration -- --ignored
//! ```
//!
//! # Environment Variables
//!
//! - `TEST_SMTP_HOST`: SMTP server host (default: localhost)
//! - `TEST_SMTP_PORT`: SMTP server port (default: 1025)
//!
//! # In CI
//!
//! The GitHub Actions workflow configures Mailhog as a service container
//! and sets the environment variables automatically.

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use valerter::config::{EmailNotifierConfig, SmtpConfig, TlsMode};
use valerter::notify::email::EmailNotifier;
use valerter::notify::{AlertPayload, Notifier};
use valerter::template::RenderedMessage;

// =============================================================================
// Mailhog API types
// =============================================================================

/// Response from Mailhog API v2 /messages endpoint.
#[derive(Debug, Deserialize)]
struct MailhogResponse {
    /// Total number of messages in inbox.
    total: u32,
    /// Number of messages returned in this response.
    #[allow(dead_code)]
    count: u32,
    /// List of messages.
    items: Vec<MailhogMessage>,
}

/// A single message from Mailhog.
#[derive(Debug, Deserialize)]
struct MailhogMessage {
    /// Message ID.
    #[serde(rename = "ID")]
    id: String,
    /// Raw message content.
    #[serde(rename = "Content")]
    content: MailhogContent,
    /// MIME data (parsed headers).
    #[serde(rename = "MIME")]
    #[allow(dead_code)]
    mime: Option<MailhogMime>,
}

/// Content section of a Mailhog message.
#[derive(Debug, Deserialize)]
struct MailhogContent {
    /// Headers as key-value pairs.
    #[serde(rename = "Headers")]
    headers: std::collections::HashMap<String, Vec<String>>,
    /// Message body.
    #[serde(rename = "Body")]
    body: String,
}

/// MIME section of a Mailhog message.
#[derive(Debug, Deserialize)]
struct MailhogMime {
    /// Parsed parts (for multipart messages).
    #[serde(rename = "Parts")]
    #[allow(dead_code)]
    parts: Option<Vec<serde_json::Value>>,
}

// =============================================================================
// Mailhog helper functions
// =============================================================================

/// Decode quoted-printable soft line breaks for assertion purposes.
/// This removes `=\r\n` sequences that split words in quoted-printable encoding.
fn decode_qp_soft_breaks(input: &str) -> String {
    input.replace("=\r\n", "").replace("=\n", "")
}

/// Get the Mailhog API base URL from environment variables.
fn mailhog_api_url() -> String {
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    format!("http://{}:8025", host)
}

/// Get all messages from Mailhog inbox.
async fn get_mailhog_messages(client: &Client) -> Result<MailhogResponse, reqwest::Error> {
    let url = format!("{}/api/v2/messages", mailhog_api_url());
    client.get(&url).send().await?.json().await
}

/// Clear all messages from Mailhog inbox.
async fn clear_mailhog_inbox(client: &Client) -> Result<(), reqwest::Error> {
    let url = format!("{}/api/v1/messages", mailhog_api_url());
    client.delete(&url).send().await?;
    Ok(())
}

/// Delete a specific message from Mailhog by ID.
#[allow(dead_code)]
async fn delete_mailhog_message(client: &Client, id: &str) -> Result<(), reqwest::Error> {
    let url = format!("{}/api/v1/messages/{}", mailhog_api_url(), id);
    client.delete(&url).send().await?;
    Ok(())
}

/// Wait for a message to appear in Mailhog (with timeout).
async fn wait_for_message(
    client: &Client,
    timeout: Duration,
) -> Result<MailhogMessage, &'static str> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for message in Mailhog");
        }

        match get_mailhog_messages(client).await {
            Ok(response) => {
                if !response.items.is_empty() {
                    return Ok(response.items.into_iter().next().unwrap());
                }
            }
            Err(e) => {
                // Log connection errors to help debug Mailhog connectivity issues
                eprintln!("Mailhog API error (retrying): {}", e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// =============================================================================
// Test helpers
// =============================================================================

/// Create an EmailNotifier configured for Mailhog.
fn create_mailhog_notifier(name: &str) -> EmailNotifier {
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("TEST_SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse()
        .unwrap_or(1025);

    let config = EmailNotifierConfig {
        smtp: SmtpConfig {
            host,
            port,
            username: None,
            password: None,
            tls: TlsMode::None, // Mailhog doesn't support TLS
            tls_verify: false,
        },
        from: "valerter-test@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
        body_template: None,
        body_template_file: None,
    };

    let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    EmailNotifier::from_config(name, &config, &config_dir)
        .expect("Failed to create EmailNotifier for Mailhog")
}

/// Create an EmailNotifier with multiple recipients.
fn create_mailhog_notifier_multi_recipient(name: &str, recipients: Vec<&str>) -> EmailNotifier {
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("TEST_SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse()
        .unwrap_or(1025);

    let config = EmailNotifierConfig {
        smtp: SmtpConfig {
            host,
            port,
            username: None,
            password: None,
            tls: TlsMode::None,
            tls_verify: false,
        },
        from: "valerter-test@example.com".to_string(),
        to: recipients.into_iter().map(String::from).collect(),
        subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
        body_template: None,
        body_template_file: None,
    };

    let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    EmailNotifier::from_config(name, &config, &config_dir)
        .expect("Failed to create EmailNotifier for Mailhog")
}

/// Create a test alert payload.
fn make_alert_payload(rule_name: &str, title: &str, body: &str) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: title.to_string(),
            body: body.to_string(),
            body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: rule_name.to_string(),
        destinations: vec![],
        log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
    }
}

// =============================================================================
// Integration tests (AC #3, #4, #5, #6)
// =============================================================================

/// Test basic email sending to Mailhog.
/// AC #3: Send real emails to Mailhog on localhost:1025
/// AC #4: Verify via Mailhog API
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_to_mailhog() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier and send alert
    let notifier = create_mailhog_notifier("mailhog-test");
    let alert = make_alert_payload("cpu_high", "CPU Alert", "CPU usage is above 90%");

    let result = notifier.send(&alert).await;
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());

    // Wait for message to appear in Mailhog
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Message not received in Mailhog");

    // Verify content (AC #4)
    let headers = &message.content.headers;

    // Verify From
    let from = headers.get("From").and_then(|v| v.first());
    assert!(
        from.is_some(),
        "From header missing. Headers: {:?}",
        headers
    );
    assert!(
        from.unwrap().contains("valerter-test@example.com"),
        "From should contain sender address, got: {:?}",
        from
    );

    // Verify To
    let to = headers.get("To").and_then(|v| v.first());
    assert!(to.is_some(), "To header missing");
    assert!(
        to.unwrap().contains("recipient@example.com"),
        "To should contain recipient address, got: {:?}",
        to
    );

    // Verify Subject
    let subject = headers.get("Subject").and_then(|v| v.first());
    assert!(subject.is_some(), "Subject header missing");
    assert!(
        subject.unwrap().contains("cpu_high"),
        "Subject should contain rule_name, got: {:?}",
        subject
    );
    assert!(
        subject.unwrap().contains("CPU Alert"),
        "Subject should contain title, got: {:?}",
        subject
    );

    // Verify Body
    assert!(
        message.content.body.contains("CPU usage is above 90%"),
        "Body should contain alert message, got: {}",
        message.content.body
    );
}

/// Test sending email to multiple recipients.
/// AC #4: Verify content for multiple recipients
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_multiple_recipients() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier with multiple recipients
    let notifier = create_mailhog_notifier_multi_recipient(
        "multi-recipient-test",
        vec![
            "alice@example.com",
            "bob@example.com",
            "charlie@example.com",
        ],
    );

    let alert = make_alert_payload("disk_full", "Disk Alert", "Disk usage is critical");

    let result = notifier.send(&alert).await;
    assert!(result.is_ok(), "Failed to send email: {:?}", result.err());

    // Wait a bit for all messages to arrive
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Get all messages
    let response = get_mailhog_messages(&client)
        .await
        .expect("Failed to get messages from Mailhog");

    // Should have 3 messages (one per recipient)
    assert_eq!(
        response.total, 3,
        "Should have 3 messages, got {}",
        response.total
    );

    // Verify each recipient received an email
    let mut recipients_found = [false, false, false];
    for message in &response.items {
        let to = message
            .content
            .headers
            .get("To")
            .and_then(|v| v.first())
            .unwrap_or(&String::new())
            .to_string();

        if to.contains("alice@example.com") {
            recipients_found[0] = true;
        }
        if to.contains("bob@example.com") {
            recipients_found[1] = true;
        }
        if to.contains("charlie@example.com") {
            recipients_found[2] = true;
        }
    }

    assert!(
        recipients_found[0],
        "alice@example.com should have received email"
    );
    assert!(
        recipients_found[1],
        "bob@example.com should have received email"
    );
    assert!(
        recipients_found[2],
        "charlie@example.com should have received email"
    );
}

/// Test sending HTML formatted email with body_html (pre-escaped HTML content).
/// AC #4: Verify body_html content is included in email
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_html_format() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier with HTML format
    let notifier = create_mailhog_notifier("html-test");

    // body_html is used for pre-rendered HTML content (from TemplateEngine)
    // This simulates what TemplateEngine produces when rendering body_html
    let alert = AlertPayload {
        message: RenderedMessage {
            title: "HTML Alert".to_string(),
            body: "Fallback plain text".to_string(),
            body_html: Some(
                "<h1>Alert!</h1><p>Something <strong>important</strong> happened.</p>".to_string(),
            ),
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: "html_rule".to_string(),
        destinations: vec![],
        log_timestamp: "2026-01-15T10:49:35.799Z".to_string(),
        log_timestamp_formatted: "15/01/2026 10:49:35 UTC".to_string(),
    };

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Failed to send HTML email: {:?}",
        result.err()
    );

    // Wait for message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("HTML message not received in Mailhog");

    // Verify Content-Type is HTML
    let content_type = message
        .content
        .headers
        .get("Content-Type")
        .and_then(|v| v.first());

    assert!(content_type.is_some(), "Content-Type header missing");
    assert!(
        content_type.unwrap().contains("text/html"),
        "Content-Type should be text/html, got: {:?}",
        content_type
    );

    // Verify HTML content from body_html is in the email body
    // body_html is injected as safe (pre-escaped) into the default template
    // Check for content that appears in body_html (may be quoted-printable encoded)
    assert!(
        message.content.body.contains("Alert!"),
        "Body should contain the alert content from body_html"
    );
    assert!(
        message.content.body.contains("important"),
        "Body should contain content from body_html"
    );
}

/// Test sending email with plain text body (no body_html).
/// AC #4: Verify plain text body is included in HTML email template
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_text_format() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier - all emails are now HTML with the default template
    let notifier = create_mailhog_notifier("text-test");

    // No body_html - the plain text body will be used in the HTML template
    let alert = make_alert_payload(
        "text_rule",
        "Plain Text Alert",
        "This is a plain text message.",
    );

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Failed to send text email: {:?}",
        result.err()
    );

    // Wait for message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Text message not received in Mailhog");

    // All emails are now HTML (using the default body template)
    let content_type = message
        .content
        .headers
        .get("Content-Type")
        .and_then(|v| v.first());

    assert!(content_type.is_some(), "Content-Type header missing");
    assert!(
        content_type.unwrap().contains("text/html"),
        "Content-Type should be text/html (all emails use HTML template), got: {:?}",
        content_type
    );

    // Verify body content is included in the HTML email
    assert!(
        message.content.body.contains("plain text message"),
        "Body should contain the message content"
    );
}

/// Test that TLS mode none works with Mailhog.
/// AC #6: Validate mode none (Mailhog only supports none)
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_tls_mode_none_with_mailhog() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier with TLS mode none (explicitly)
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("TEST_SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse()
        .unwrap_or(1025);

    let config = EmailNotifierConfig {
        smtp: SmtpConfig {
            host,
            port,
            username: None,
            password: None,
            tls: TlsMode::None, // Explicitly test TLS mode none
            tls_verify: false,
        },
        from: "tls-test@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject_template: "{{ title }}".to_string(),
        body_template: None,
        body_template_file: None,
    };

    let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let notifier = EmailNotifier::from_config("tls-none-test", &config, &config_dir)
        .expect("Failed to create notifier");

    let alert = make_alert_payload("tls_test", "TLS None Test", "Testing TLS mode none");

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Should successfully send with TLS mode none: {:?}",
        result.err()
    );

    // Verify message was received
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Message not received with TLS mode none");

    assert!(
        message.content.body.contains("Testing TLS mode none"),
        "Body should match"
    );
}

/// Test Mailhog API helper functions work correctly.
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_mailhog_api_helpers() {
    let client = Client::new();

    // Test clear inbox
    let clear_result = clear_mailhog_inbox(&client).await;
    assert!(
        clear_result.is_ok(),
        "Should be able to clear inbox: {:?}",
        clear_result.err()
    );

    // Test get messages on empty inbox
    let messages = get_mailhog_messages(&client)
        .await
        .expect("Failed to get messages");

    assert_eq!(messages.total, 0, "Inbox should be empty after clear");

    // Send a test email
    let notifier = create_mailhog_notifier("api-test");
    let alert = make_alert_payload("api_test", "API Test", "Testing API helpers");
    notifier.send(&alert).await.expect("Failed to send");

    // Test wait_for_message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Should find message");

    assert!(!message.id.is_empty(), "Message should have an ID");

    // Verify final count
    let final_messages = get_mailhog_messages(&client)
        .await
        .expect("Failed to get final messages");

    assert_eq!(final_messages.total, 1, "Should have exactly 1 message");
}

// =============================================================================
// Body template integration tests (Task 13/M4 - Tech Spec email-body-template)
// =============================================================================

/// Test sending HTML email with inline body_template.
/// Verifies that body_template is rendered and sent correctly.
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_with_body_template_inline() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier with inline body_template
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("TEST_SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse()
        .unwrap_or(1025);

    let config = EmailNotifierConfig {
        smtp: SmtpConfig {
            host,
            port,
            username: None,
            password: None,
            tls: TlsMode::None,
            tls_verify: false,
        },
        from: "template-test@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
        body_template: Some(
            r#"<html>
<body>
<h1>CUSTOM TEMPLATE</h1>
<p>Title: {{ title }}</p>
<p>Body: {{ body }}</p>
<p>Rule: {{ rule_name }}</p>
<p>Color: {{ color }}</p>
</body>
</html>"#
                .to_string(),
        ),
        body_template_file: None,
    };

    let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let notifier = EmailNotifier::from_config("body-template-test", &config, &config_dir)
        .expect("Failed to create notifier with body_template");

    let alert = make_alert_payload("template_rule", "Template Test", "Testing body template");

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Failed to send email with body_template: {:?}",
        result.err()
    );

    // Wait for message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Message with body_template not received");

    // Verify Content-Type is HTML
    let content_type = message
        .content
        .headers
        .get("Content-Type")
        .and_then(|v| v.first());

    assert!(content_type.is_some(), "Content-Type header missing");
    assert!(
        content_type.unwrap().contains("text/html"),
        "Content-Type should be text/html"
    );

    // Verify body contains rendered template markers
    assert!(
        message.content.body.contains("CUSTOM TEMPLATE"),
        "Body should contain custom template marker"
    );
    assert!(
        message.content.body.contains("Title: Template Test"),
        "Body should contain rendered title"
    );
    assert!(
        message.content.body.contains("Rule: template_rule"),
        "Body should contain rendered rule_name"
    );
}

/// Test sending HTML email with body_template_file.
/// Verifies that external template file is loaded and rendered correctly.
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_with_body_template_file() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier with body_template_file pointing to default template
    let host = std::env::var("TEST_SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port: u16 = std::env::var("TEST_SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse()
        .unwrap_or(1025);

    let config = EmailNotifierConfig {
        smtp: SmtpConfig {
            host,
            port,
            username: None,
            password: None,
            tls: TlsMode::None,
            tls_verify: false,
        },
        from: "file-template@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject_template: "{{ title }}".to_string(),
        body_template: None,
        body_template_file: Some("templates/default-email.html.j2".to_string()),
    };

    let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let notifier = EmailNotifier::from_config("file-template-test", &config, &config_dir)
        .expect("Failed to create notifier with body_template_file");

    let alert = make_alert_payload("file_rule", "File Template Test", "Testing file template");

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Failed to send email with body_template_file: {:?}",
        result.err()
    );

    // Wait for message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Message with body_template_file not received");

    // Decode quoted-printable soft breaks for reliable assertions
    let body = decode_qp_soft_breaks(&message.content.body);

    // Verify body contains default template structure
    assert!(
        body.contains("<!DOCTYPE html>"),
        "Body should contain HTML doctype from file template"
    );
    assert!(
        body.contains("File Template Test"),
        "Body should contain rendered title"
    );
    assert!(
        body.contains("file_rule"),
        "Body should contain rendered rule_name"
    );
    assert!(
        body.contains("Valerter"),
        "Body should contain Valerter branding from default template"
    );
}

/// Test default body template is used when neither body_template nor body_template_file specified.
#[tokio::test]
#[ignore] // Requires running Mailhog
async fn test_send_email_with_default_body_template() {
    let client = Client::new();

    // Clear inbox before test
    clear_mailhog_inbox(&client)
        .await
        .expect("Failed to clear Mailhog inbox");

    // Create notifier WITHOUT body_template - should use embedded default
    let notifier = create_mailhog_notifier("default-body-test");

    let alert = make_alert_payload(
        "default_body_rule",
        "Default Body Test",
        "Testing default body template",
    );

    let result = notifier.send(&alert).await;
    assert!(
        result.is_ok(),
        "Failed to send email with default body template: {:?}",
        result.err()
    );

    // Wait for message
    let message = wait_for_message(&client, Duration::from_secs(5))
        .await
        .expect("Message with default body template not received");

    // Decode quoted-printable soft breaks for reliable assertions
    let body = decode_qp_soft_breaks(&message.content.body);

    // Verify body contains default template structure (embedded default-email.html.j2)
    assert!(
        body.contains("<!DOCTYPE html>"),
        "Body should contain HTML doctype from embedded default template"
    );
    assert!(
        body.contains("Default Body Test"),
        "Body should contain rendered title"
    );
    assert!(
        body.contains("default_body_rule"),
        "Body should contain rendered rule_name"
    );
}
