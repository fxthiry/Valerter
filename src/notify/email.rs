//! Email notifier implementation (Story 6.6).
//!
//! Implements the `Notifier` trait for sending alerts via SMTP
//! with exponential backoff retry.
//!
//! # Testability (Story 7.2)
//!
//! The `EmailNotifier` supports transport injection for testing:
//! - Production: Uses `AsyncSmtpTransport<Tokio1Executor>`
//! - Testing: Uses `MockEmailTransport` for unit tests without SMTP server

use crate::config::{EmailNotifierConfig, TlsMode, resolve_body_template, resolve_env_vars};
use crate::error::{ConfigError, NotifyError};
use crate::notify::{AlertPayload, Notifier, backoff_delay};
use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use minijinja::{Environment, context};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Default HTML template for email body, embedded at compile time.
const DEFAULT_BODY_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/templates/default-email.html.j2"
));

/// Backoff base delay for email retries (AD-07).
/// Longer than HTTP because SMTP connections are slower.
const EMAIL_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Maximum backoff delay for email retries (AD-07).
const EMAIL_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Maximum number of retry attempts for email (AD-07).
const EMAIL_MAX_RETRIES: u32 = 3;

// =============================================================================
// EmailTransport Trait (Story 7.2)
// =============================================================================

/// Async email transport abstraction for testability (Story 7.2).
///
/// This trait allows injecting mock transports in tests while using
/// the real `AsyncSmtpTransport` in production.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    /// Send an email message.
    ///
    /// # Arguments
    ///
    /// * `message` - The email message to send
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Email sent successfully
    /// * `Err(String)` - Error message describing the failure
    async fn send_email(&self, message: Message) -> Result<(), String>;
}

/// Real SMTP transport wrapper implementing `EmailTransport`.
///
/// Wraps `AsyncSmtpTransport<Tokio1Executor>` for production use.
pub struct SmtpTransport {
    inner: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpTransport {
    /// Create a new SMTP transport wrapper.
    pub fn new(transport: AsyncSmtpTransport<Tokio1Executor>) -> Self {
        Self { inner: transport }
    }
}

#[async_trait]
impl EmailTransport for SmtpTransport {
    async fn send_email(&self, message: Message) -> Result<(), String> {
        self.inner
            .send(message)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Email notifier implementation (Story 6.6).
///
/// Sends alerts via SMTP with:
/// - Configurable TLS modes (none, starttls, tls)
/// - Certificate verification options
/// - Environment variable substitution for credentials
/// - Custom subject templates
/// - Exponential backoff retry (AD-07)
///
/// # Retry Policy
///
/// - **Connection errors**: Retry (timeout, connection refused)
/// - **Authentication errors**: Do NOT retry (invalid credentials)
/// - **Transient SMTP errors**: Retry (4xx responses)
/// - **Permanent SMTP errors**: Do NOT retry (5xx responses)
///
/// # Testability (Story 7.2)
///
/// The transport can be injected via `with_transport()` for testing:
/// ```ignore
/// let mock = Arc::new(MockEmailTransport::new());
/// let notifier = EmailNotifier::with_transport(name, mock, from, to, subject, format);
/// ```
pub struct EmailNotifier {
    /// Unique name for this notifier instance.
    name: String,
    /// Email transport for sending emails (abstracted for testability).
    transport: Arc<dyn EmailTransport>,
    /// Sender email address.
    from: Mailbox,
    /// Recipient email addresses.
    to: Vec<Mailbox>,
    /// Subject line template source.
    subject_template_source: String,
    /// Body template source (always has a value - defaults to embedded template).
    body_template_source: String,
}

impl EmailNotifier {
    /// Create a new EmailNotifier from configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this notifier instance
    /// * `config` - Email notifier configuration
    /// * `config_dir` - Directory containing the config file (for relative path resolution)
    ///
    /// # Returns
    ///
    /// * `Ok(EmailNotifier)` - Configured notifier ready to send
    /// * `Err(ConfigError)` - If configuration validation fails
    pub fn from_config(
        name: &str,
        config: &EmailNotifierConfig,
        config_dir: &Path,
    ) -> Result<Self, ConfigError> {
        // 1. Resolve environment variables for credentials
        let username = config
            .smtp
            .username
            .as_ref()
            .map(|u| resolve_env_vars(u))
            .transpose()
            .map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("smtp.username: {}", e),
            })?;

        let password = config
            .smtp
            .password
            .as_ref()
            .map(|p| resolve_env_vars(p))
            .transpose()
            .map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("smtp.password: {}", e),
            })?;

        // 2. Build the transport based on TLS mode
        let transport = Self::build_transport(name, config, username, password)?;

        // 3. Parse the 'from' email address
        let from: Mailbox = config
            .from
            .parse()
            .map_err(|e| ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("invalid 'from' address '{}': {}", config.from, e),
            })?;

        // 4. Parse the 'to' email addresses
        let to: Vec<Mailbox> = config
            .to
            .iter()
            .map(|addr| {
                addr.parse().map_err(|e| ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: format!("invalid 'to' address '{}': {}", addr, e),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if to.is_empty() {
            return Err(ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: "'to' must contain at least one email address".to_string(),
            });
        }

        // 5. Validate the subject template (syntax)
        Self::validate_template(&config.subject_template).map_err(|e| {
            ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("subject_template: {}", e),
            }
        })?;

        // 5b. Validate the subject template (render test for unknown filters)
        crate::config::validate_template_render(&config.subject_template).map_err(|e| {
            ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("subject_template render: {}", e),
            }
        })?;

        // 6. Resolve body template (file > inline > embedded default)
        let body_template_source = match resolve_body_template(config, config_dir)? {
            Some(template) => template,
            None => DEFAULT_BODY_TEMPLATE.to_string(),
        };

        // 7. Validate the body template
        Self::validate_template(&body_template_source).map_err(|e| {
            ConfigError::InvalidNotifier {
                name: name.to_string(),
                message: format!("body_template: {}", e),
            }
        })?;

        Ok(Self {
            name: name.to_string(),
            transport: Arc::new(SmtpTransport::new(transport)),
            from,
            to,
            subject_template_source: config.subject_template.clone(),
            body_template_source,
        })
    }

    /// Create an EmailNotifier with a custom transport (Story 7.2).
    ///
    /// This constructor enables dependency injection for testing.
    /// In production, use `from_config()` instead.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this notifier instance
    /// * `transport` - The email transport implementation
    /// * `from` - Sender email address
    /// * `to` - Recipient email addresses
    /// * `subject_template_source` - Subject line template
    /// * `body_template_source` - Optional body template (uses default if None)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For testing with mock transport
    /// let mock = Arc::new(MockEmailTransport::new());
    /// let notifier = EmailNotifier::with_transport(
    ///     "test-email",
    ///     mock,
    ///     "sender@test.com".parse().unwrap(),
    ///     vec!["dest@test.com".parse().unwrap()],
    ///     "[{{ rule_name }}] {{ title }}",
    ///     None, // Use default body template
    /// );
    /// ```
    #[cfg(test)]
    pub fn with_transport(
        name: &str,
        transport: Arc<dyn EmailTransport>,
        from: Mailbox,
        to: Vec<Mailbox>,
        subject_template_source: &str,
        body_template_source: Option<&str>,
    ) -> Self {
        Self {
            name: name.to_string(),
            transport,
            from,
            to,
            subject_template_source: subject_template_source.to_string(),
            body_template_source: body_template_source
                .map(|s| s.to_string())
                .unwrap_or_else(|| DEFAULT_BODY_TEMPLATE.to_string()),
        }
    }

    /// Build SMTP transport based on TLS mode, credentials, and tls_verify setting.
    fn build_transport(
        name: &str,
        config: &EmailNotifierConfig,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, ConfigError> {
        let host = &config.smtp.host;
        let port = config.smtp.port;
        let tls_verify = config.smtp.tls_verify;

        // Build TLS parameters with optional certificate verification (AC5)
        let tls_parameters = if config.smtp.tls != TlsMode::None {
            let mut tls_builder = TlsParameters::builder(host.clone());
            if !tls_verify {
                // Disable certificate verification for self-signed certs
                tls_builder = tls_builder.dangerous_accept_invalid_certs(true);
            }
            Some(
                tls_builder
                    .build()
                    .map_err(|e| ConfigError::InvalidNotifier {
                        name: name.to_string(),
                        message: format!("TLS configuration error: {}", e),
                    })?,
            )
        } else {
            None
        };

        // Build transport based on TLS mode
        let builder = match config.smtp.tls {
            TlsMode::None => {
                // No encryption - dangerous but allowed
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port)
            }
            TlsMode::Starttls => {
                // STARTTLS - upgrade connection to TLS with custom parameters
                let tls_params = tls_parameters.expect("TLS parameters required for STARTTLS");
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                    .port(port)
                    .tls(Tls::Required(tls_params))
            }
            TlsMode::Tls => {
                // Direct TLS connection with custom parameters
                let tls_params = tls_parameters.expect("TLS parameters required for TLS");
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                    .port(port)
                    .tls(Tls::Wrapper(tls_params))
            }
        };

        // Add credentials if provided
        let builder = match (username, password) {
            (Some(u), Some(p)) => builder.credentials(Credentials::new(u, p)),
            (Some(_), None) => {
                return Err(ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: "smtp.password required when smtp.username is set".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::InvalidNotifier {
                    name: name.to_string(),
                    message: "smtp.username required when smtp.password is set".to_string(),
                });
            }
            (None, None) => builder, // No auth
        };

        Ok(builder.build())
    }

    /// Validate a minijinja template syntax.
    fn validate_template(source: &str) -> Result<(), String> {
        let mut env = Environment::new();
        env.add_template("_validate", source)
            .map_err(|e| e.to_string())?;
        Ok(())
    }


    /// Render the subject template with alert context.
    fn render_subject(&self, alert: &AlertPayload) -> Result<String, NotifyError> {
        let mut env = Environment::new();
        env.add_template("subject", &self.subject_template_source)
            .map_err(|e| NotifyError::TemplateError(format!("template error: {}", e)))?;

        let tmpl = env
            .get_template("subject")
            .map_err(|e| NotifyError::TemplateError(format!("template error: {}", e)))?;

        tmpl.render(context! {
            title => &alert.message.title,
            body => &alert.message.body,
            rule_name => &alert.rule_name,
            color => &alert.message.color,
            icon => &alert.message.icon,
        })
        .map_err(|e| NotifyError::TemplateError(format!("template render error: {}", e)))
    }

    /// Render the body template with alert context.
    ///
    /// Uses `body_html` from the template engine (already HTML-escaped) if available,
    /// otherwise falls back to `body`. The body is marked as "safe" (pre-escaped) so
    /// the template doesn't need `| safe` filter - this prevents user errors if they
    /// edit the email template and accidentally remove the filter.
    fn render_body(&self, alert: &AlertPayload) -> Result<String, NotifyError> {
        let mut env = Environment::new();
        // HTML auto-escape for title/rule_name/etc
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        env.add_template("body", &self.body_template_source)
            .map_err(|e| NotifyError::TemplateError(format!("body template error: {}", e)))?;

        let tmpl = env
            .get_template("body")
            .map_err(|e| NotifyError::TemplateError(format!("body template error: {}", e)))?;

        // Use body_html if available (already HTML-escaped), otherwise fall back to body
        let body_content = alert
            .message
            .body_html
            .as_ref()
            .unwrap_or(&alert.message.body);

        // Mark body as pre-escaped (safe) so template doesn't need | safe filter
        let body_safe = minijinja::Value::from_safe_string(body_content.clone());

        tmpl.render(context! {
            title => &alert.message.title,
            body => body_safe,
            rule_name => &alert.rule_name,
            color => &alert.message.color,
            icon => &alert.message.icon,
        })
        .map_err(|e| NotifyError::TemplateError(format!("body template render error: {}", e)))
    }

    /// Build the email message for a specific recipient.
    ///
    /// Sends to a single recipient per message to allow partial success
    /// when one recipient is rejected by the SMTP server (AC7 compliance).
    fn build_message_for_recipient(
        &self,
        subject: &str,
        body: &str,
        recipient: &Mailbox,
    ) -> Result<Message, NotifyError> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(recipient.clone())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())
            .map_err(|e| NotifyError::SendFailed(format!("failed to build email: {}", e)))?;

        Ok(message)
    }

    /// Send email to a single recipient with retry logic.
    ///
    /// Returns Ok if the email was sent successfully, Err otherwise.
    async fn send_to_recipient(
        &self,
        subject: &str,
        body: &str,
        recipient: &Mailbox,
    ) -> Result<(), NotifyError> {
        let message = self.build_message_for_recipient(subject, body, recipient)?;

        for attempt in 0..EMAIL_MAX_RETRIES {
            match self.transport.send_email(message.clone()).await {
                Ok(()) => {
                    tracing::debug!(
                        recipient = %recipient,
                        "Email sent to recipient"
                    );
                    return Ok(());
                }
                Err(error_str) => {
                    // Check for permanent errors (don't retry)
                    if Self::is_permanent_error(&error_str) {
                        tracing::warn!(
                            recipient = %recipient,
                            error = %error_str,
                            "Permanent SMTP error, not retrying for this recipient"
                        );
                        return Err(NotifyError::SendFailed(format!(
                            "permanent error for {}: {}",
                            recipient, error_str
                        )));
                    }

                    tracing::debug!(
                        attempt = attempt,
                        recipient = %recipient,
                        error = %error_str,
                        "Failed to send email, retrying"
                    );

                    if attempt < EMAIL_MAX_RETRIES - 1 {
                        let delay = backoff_delay(attempt, EMAIL_BACKOFF_BASE, EMAIL_BACKOFF_MAX);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(NotifyError::MaxRetriesExceeded)
    }

    /// Check if an SMTP error is permanent and should not be retried.
    ///
    /// Uses word boundary matching to avoid false positives when SMTP codes
    /// appear in email addresses or other contexts.
    fn is_permanent_error(error_str: &str) -> bool {
        // Helper to check if a code appears as a word boundary (not part of email/text)
        let contains_smtp_code = |code: &str| {
            error_str
                .split(|c: char| !c.is_ascii_digit())
                .any(|segment| segment == code)
        };

        // Authentication failures
        error_str.to_lowercase().contains("authentication")
            || contains_smtp_code("535")
            || error_str.to_lowercase().contains("invalid credentials")
            // Mailbox/recipient permanent errors (5xx)
            || contains_smtp_code("550") // Mailbox unavailable
            || contains_smtp_code("551") // User not local
            || contains_smtp_code("552") // Message size exceeded
            || contains_smtp_code("553") // Mailbox name invalid
            || contains_smtp_code("554") // Transaction failed
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "email"
    }

    /// Send alert to all configured recipients.
    ///
    /// Implements per-recipient sending (AC7 compliant):
    /// - Each recipient gets a separate email
    /// - If one recipient fails, others can still succeed
    /// - Logs warning for failed recipients, continues to next
    /// - Returns Ok if at least one recipient succeeded
    /// - Returns Err only if ALL recipients failed
    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        let span = tracing::info_span!(
            "send_email",
            rule_name = %alert.rule_name,
            notifier_name = %self.name
        );
        let _guard = span.enter();

        // Render templates once for all recipients
        let subject = self.render_subject(alert)?;
        let body = self.render_body(alert)?;

        // Track success/failure per recipient
        let mut success_count = 0;
        let mut failure_count = 0;

        // Send to each recipient individually (AC7: continue on rejection)
        for recipient in &self.to {
            match self.send_to_recipient(&subject, &body, recipient).await {
                Ok(()) => {
                    success_count += 1;
                }
                Err(e) => {
                    failure_count += 1;
                    tracing::warn!(
                        recipient = %recipient,
                        error = %e,
                        "Failed to send email to recipient, continuing to next"
                    );
                    // Metrics for per-recipient failures
                    metrics::counter!(
                        "valerter_email_recipient_errors_total",
                        "rule_name" => alert.rule_name.clone(),
                        "notifier_name" => self.name.clone()
                    )
                    .increment(1);
                }
            }
        }

        // Log summary
        tracing::info!(
            success = success_count,
            failed = failure_count,
            total = self.to.len(),
            "Email send complete"
        );

        // Determine overall result
        if success_count > 0 {
            // At least one recipient succeeded
            metrics::counter!(
                "valerter_alerts_sent_total",
                "rule_name" => alert.rule_name.clone(),
                "notifier_name" => self.name.clone(),
                "notifier_type" => "email"
            )
            .increment(1);
            Ok(())
        } else {
            // All recipients failed
            metrics::counter!(
                "valerter_notify_errors_total",
                "rule_name" => alert.rule_name.clone(),
                "notifier_name" => self.name.clone(),
                "notifier_type" => "email"
            )
            .increment(1);
            // Permanent failure - all recipients failed
            metrics::counter!(
                "valerter_alerts_failed_total",
                "rule_name" => alert.rule_name.clone(),
                "notifier_name" => self.name.clone(),
                "notifier_type" => "email"
            )
            .increment(1);
            Err(NotifyError::SendFailed(format!(
                "all {} recipients failed",
                failure_count
            )))
        }
    }
}

impl std::fmt::Debug for EmailNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NFR9: Never expose credentials in debug output
        f.debug_struct("EmailNotifier")
            .field("name", &self.name)
            .field("from", &self.from.to_string())
            .field("to_count", &self.to.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EmailNotifierConfig, SmtpConfig, TlsMode};
    use crate::template::RenderedMessage;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ===================================================================
    // MockEmailTransport for testing (Story 7.2)
    // ===================================================================

    /// Mock email transport for unit testing without SMTP server.
    ///
    /// Records all sent emails and can be configured to succeed or fail.
    pub struct MockEmailTransport {
        /// Sent messages (thread-safe for async tests).
        sent_messages: Mutex<Vec<SentEmail>>,
        /// Number of times send was called.
        send_count: AtomicU32,
        /// If Some, returns this error on next send.
        fail_next_n: AtomicU32,
        /// Error message to return when failing.
        error_message: Mutex<String>,
    }

    /// Captured email for verification.
    #[derive(Debug, Clone)]
    pub struct SentEmail {
        pub from: String,
        pub to: String,
        pub subject: String,
        pub body: String,
    }

    impl MockEmailTransport {
        /// Create a new mock transport that succeeds by default.
        pub fn new() -> Self {
            Self {
                sent_messages: Mutex::new(Vec::new()),
                send_count: AtomicU32::new(0),
                fail_next_n: AtomicU32::new(0),
                error_message: Mutex::new("mock failure".to_string()),
            }
        }

        /// Configure the mock to fail the next n sends.
        pub fn fail_next(&self, count: u32, error: &str) {
            self.fail_next_n.store(count, Ordering::SeqCst);
            *self.error_message.lock().unwrap() = error.to_string();
        }

        /// Get the number of times send was called.
        pub fn send_count(&self) -> u32 {
            self.send_count.load(Ordering::SeqCst)
        }

        /// Get all sent emails.
        pub fn sent_emails(&self) -> Vec<SentEmail> {
            self.sent_messages.lock().unwrap().clone()
        }

        /// Clear sent emails.
        #[allow(dead_code)]
        pub fn clear(&self) {
            self.sent_messages.lock().unwrap().clear();
            self.send_count.store(0, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl EmailTransport for MockEmailTransport {
        async fn send_email(&self, message: Message) -> Result<(), String> {
            self.send_count.fetch_add(1, Ordering::SeqCst);

            // Check if we should fail
            let fail_count = self.fail_next_n.load(Ordering::SeqCst);
            if fail_count > 0 {
                self.fail_next_n.fetch_sub(1, Ordering::SeqCst);
                return Err(self.error_message.lock().unwrap().clone());
            }

            // Extract email details from the message
            let from = message
                .headers()
                .get_raw("From")
                .map(|v| v.to_string())
                .unwrap_or_default();

            let to = message
                .headers()
                .get_raw("To")
                .map(|v| v.to_string())
                .unwrap_or_default();

            let subject = message
                .headers()
                .get_raw("Subject")
                .map(|v| v.to_string())
                .unwrap_or_default();

            // Get body from message (simplified extraction)
            let body = String::from_utf8_lossy(&message.formatted()).to_string();

            self.sent_messages.lock().unwrap().push(SentEmail {
                from,
                to,
                subject,
                body,
            });

            Ok(())
        }
    }

    fn make_test_config() -> EmailNotifierConfig {
        EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "test@example.com".to_string(),
            to: vec!["dest@example.com".to_string()],
            subject_template: "[{{ rule_name }}] {{ title }}".to_string(),
            body_template: None,
            body_template_file: None,
        }
    }

    fn test_config_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn make_alert_payload(rule_name: &str) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: "Test Alert".to_string(),
                body: "Something happened".to_string(),
                body_html: None,
                color: Some("#ff0000".to_string()),
                icon: Some(":warning:".to_string()),
            },
            rule_name: rule_name.to_string(),
            destinations: vec![],
        }
    }

    // ===================================================================
    // EmailNotifier construction tests
    // ===================================================================

    #[test]
    fn from_config_with_valid_config() {
        let config = make_test_config();
        let result = EmailNotifier::from_config("test-email", &config, &test_config_dir());

        assert!(result.is_ok(), "Should create notifier: {:?}", result.err());
        let notifier = result.unwrap();
        assert_eq!(notifier.name(), "test-email");
        assert_eq!(notifier.notifier_type(), "email");
    }

    #[test]
    fn from_config_with_invalid_from_address() {
        let mut config = make_test_config();
        config.from = "not-an-email".to_string();

        let result = EmailNotifier::from_config("bad-from", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-from");
                assert!(message.contains("from"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_with_invalid_to_address() {
        let mut config = make_test_config();
        config.to = vec!["not-an-email".to_string()];

        let result = EmailNotifier::from_config("bad-to", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-to");
                assert!(message.contains("to"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_with_empty_to_list() {
        let mut config = make_test_config();
        config.to = vec![];

        let result = EmailNotifier::from_config("empty-to", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "empty-to");
                assert!(message.contains("at least one"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_with_invalid_subject_template() {
        let mut config = make_test_config();
        config.subject_template = "{% if unclosed".to_string();

        let result = EmailNotifier::from_config("bad-template", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-template");
                assert!(message.contains("subject_template"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_with_multiple_recipients() {
        let mut config = make_test_config();
        config.to = vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "charlie@example.com".to_string(),
        ];

        let result = EmailNotifier::from_config("multi-to", &config, &test_config_dir());

        assert!(result.is_ok());
        let notifier = result.unwrap();
        assert_eq!(notifier.to.len(), 3);
    }

    #[test]
    fn from_config_fails_with_username_without_password() {
        let mut config = make_test_config();
        config.smtp.username = Some("user".to_string());
        config.smtp.password = None;

        let result = EmailNotifier::from_config("no-password", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "no-password");
                assert!(message.contains("password required"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_fails_with_password_without_username() {
        let mut config = make_test_config();
        config.smtp.username = None;
        config.smtp.password = Some("pass".to_string());

        let result = EmailNotifier::from_config("no-username", &config, &test_config_dir());

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "no-username");
                assert!(message.contains("username required"));
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_resolves_env_vars_for_credentials() {
        temp_env::with_vars(
            [
                ("TEST_SMTP_USER", Some("testuser")),
                ("TEST_SMTP_PASS", Some("testpass")),
            ],
            || {
                let mut config = make_test_config();
                config.smtp.username = Some("${TEST_SMTP_USER}".to_string());
                config.smtp.password = Some("${TEST_SMTP_PASS}".to_string());

                let result = EmailNotifier::from_config("env-creds", &config, &test_config_dir());

                // Should not fail due to env var resolution
                // (May fail later due to actual SMTP connection, but that's OK)
                assert!(
                    result.is_ok(),
                    "Should resolve env vars: {:?}",
                    result.err()
                );
            },
        );
    }

    #[test]
    fn from_config_fails_on_undefined_env_var() {
        temp_env::with_var("UNDEFINED_SMTP_VAR", None::<&str>, || {
            let mut config = make_test_config();
            config.smtp.username = Some("${UNDEFINED_SMTP_VAR}".to_string());
            config.smtp.password = Some("somepass".to_string());

            let result = EmailNotifier::from_config("bad-env", &config, &test_config_dir());

            assert!(result.is_err());
            let err = result.unwrap_err();
            match err {
                ConfigError::InvalidNotifier { name, message } => {
                    assert_eq!(name, "bad-env");
                    assert!(message.contains("smtp.username"));
                    assert!(message.contains("UNDEFINED_SMTP_VAR"));
                }
                _ => panic!("Expected InvalidNotifier, got {:?}", err),
            }
        });
    }

    // ===================================================================
    // TLS verify configuration tests (AC5)
    // ===================================================================

    #[test]
    fn from_config_with_tls_verify_false() {
        let mut config = make_test_config();
        config.smtp.tls_verify = false;

        let result = EmailNotifier::from_config("insecure-email", &config, &test_config_dir());

        // Should successfully create notifier with disabled cert verification
        assert!(
            result.is_ok(),
            "Should create notifier with tls_verify=false: {:?}",
            result.err()
        );
    }

    #[test]
    fn from_config_with_tls_verify_true() {
        let mut config = make_test_config();
        config.smtp.tls_verify = true;

        let result = EmailNotifier::from_config("secure-email-tls", &config, &test_config_dir());

        assert!(
            result.is_ok(),
            "Should create notifier with tls_verify=true: {:?}",
            result.err()
        );
    }

    #[test]
    fn from_config_tls_none_ignores_tls_verify() {
        let mut config = make_test_config();
        config.smtp.tls = TlsMode::None;
        config.smtp.tls_verify = false; // Should be ignored for TlsMode::None

        let result = EmailNotifier::from_config("no-tls", &config, &test_config_dir());

        assert!(
            result.is_ok(),
            "Should create notifier with tls=none: {:?}",
            result.err()
        );
    }

    // ===================================================================
    // Subject template rendering tests
    // ===================================================================

    #[test]
    fn render_subject_with_all_fields() {
        let config = make_test_config();
        let notifier = EmailNotifier::from_config("test", &config, &test_config_dir()).unwrap();

        let alert = make_alert_payload("cpu_alert");
        let subject = notifier.render_subject(&alert).unwrap();

        assert_eq!(subject, "[cpu_alert] Test Alert");
    }

    #[test]
    fn render_subject_with_complex_template() {
        let mut config = make_test_config();
        config.subject_template = "[{{ rule_name | upper }}] {{ title }} ({{ color }})".to_string();

        let notifier = EmailNotifier::from_config("test", &config, &test_config_dir()).unwrap();
        let alert = make_alert_payload("my_rule");
        let subject = notifier.render_subject(&alert).unwrap();

        assert!(subject.contains("MY_RULE"));
        assert!(subject.contains("Test Alert"));
        assert!(subject.contains("#ff0000"));
    }

    // ===================================================================
    // Message building tests
    // ===================================================================

    #[test]
    fn build_message_text_format() {
        let config = make_test_config();
        let notifier = EmailNotifier::from_config("test", &config, &test_config_dir()).unwrap();
        let recipient: Mailbox = "test@example.com".parse().unwrap();

        let message = notifier
            .build_message_for_recipient("Test Subject", "Test body content", &recipient)
            .unwrap();

        // Just verify it doesn't panic and returns a valid message
        assert!(message.headers().get_raw("From").is_some());
        assert!(message.headers().get_raw("To").is_some());
        assert!(message.headers().get_raw("Subject").is_some());
    }

    #[test]
    fn build_message_html_format() {
        let config = make_test_config();

        let notifier = EmailNotifier::from_config("test", &config, &test_config_dir()).unwrap();
        let recipient: Mailbox = "test@example.com".parse().unwrap();
        let message = notifier
            .build_message_for_recipient("Test Subject", "<p>HTML content</p>", &recipient)
            .unwrap();

        assert!(message.headers().get_raw("Content-Type").is_some());
    }

    // ===================================================================
    // Notifier trait tests
    // ===================================================================

    #[test]
    fn notifier_properties() {
        let config = make_test_config();
        let notifier = EmailNotifier::from_config("my-email", &config, &test_config_dir()).unwrap();

        assert_eq!(notifier.name(), "my-email");
        assert_eq!(notifier.notifier_type(), "email");
    }

    #[tokio::test]
    async fn notifier_trait_is_object_safe() {
        let config = make_test_config();
        let notifier: Box<dyn Notifier> =
            Box::new(EmailNotifier::from_config("test", &config, &test_config_dir()).unwrap());

        assert_eq!(notifier.name(), "test");
        assert_eq!(notifier.notifier_type(), "email");
    }

    // ===================================================================
    // Debug output security tests (NFR9)
    // ===================================================================

    #[test]
    fn debug_output_does_not_expose_transport_details() {
        let config = make_test_config();
        let notifier =
            EmailNotifier::from_config("secure-email", &config, &test_config_dir()).unwrap();

        let debug = format!("{:?}", notifier);

        // Name is OK to show
        assert!(debug.contains("secure-email"));
        // From address is OK
        assert!(debug.contains("test@example.com"));
        // Should NOT expose SMTP host, credentials, etc.
        // The debug impl only shows name, from, to_count
        assert!(debug.contains("to_count"));
    }

    #[test]
    fn debug_output_with_credentials_does_not_leak() {
        temp_env::with_vars(
            [
                ("TEST_DBG_USER", Some("secretuser")),
                ("TEST_DBG_PASS", Some("secretpassword")),
            ],
            || {
                let mut config = make_test_config();
                config.smtp.username = Some("${TEST_DBG_USER}".to_string());
                config.smtp.password = Some("${TEST_DBG_PASS}".to_string());

                let notifier =
                    EmailNotifier::from_config("cred-email", &config, &test_config_dir()).unwrap();
                let debug = format!("{:?}", notifier);

                // Credentials must NOT appear
                assert!(!debug.contains("secretuser"));
                assert!(!debug.contains("secretpassword"));
            },
        );
    }

    // ===================================================================
    // MockTransport tests (Story 7.2 - AC #1, #2)
    // ===================================================================

    /// Helper to create a notifier with mock transport.
    fn make_notifier_with_mock(mock: Arc<MockEmailTransport>) -> EmailNotifier {
        EmailNotifier::with_transport(
            "test-mock",
            mock,
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "[{{ rule_name }}] {{ title }}",
            None, // Use default body template
        )
    }

    #[tokio::test]
    async fn mock_transport_records_sent_email() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = make_notifier_with_mock(mock.clone());

        let alert = make_alert_payload("test_rule");
        let result = notifier.send(&alert).await;

        assert!(result.is_ok(), "Send should succeed with mock transport");
        assert_eq!(mock.send_count(), 1, "Should have called send once");

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1, "Should have recorded one email");
    }

    #[tokio::test]
    async fn mock_transport_validates_email_from_address() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = make_notifier_with_mock(mock.clone());

        let alert = make_alert_payload("test_rule");
        notifier.send(&alert).await.unwrap();

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        assert!(
            emails[0].from.contains("sender@test.com"),
            "From should contain sender address, got: {}",
            emails[0].from
        );
    }

    #[tokio::test]
    async fn mock_transport_validates_email_to_address() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = make_notifier_with_mock(mock.clone());

        let alert = make_alert_payload("test_rule");
        notifier.send(&alert).await.unwrap();

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        assert!(
            emails[0].to.contains("dest@test.com"),
            "To should contain destination address, got: {}",
            emails[0].to
        );
    }

    #[tokio::test]
    async fn mock_transport_validates_email_subject() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = make_notifier_with_mock(mock.clone());

        let alert = make_alert_payload("cpu_alert");
        notifier.send(&alert).await.unwrap();

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        // Subject template is "[{{ rule_name }}] {{ title }}"
        assert!(
            emails[0].subject.contains("cpu_alert"),
            "Subject should contain rule_name, got: {}",
            emails[0].subject
        );
        assert!(
            emails[0].subject.contains("Test Alert"),
            "Subject should contain title, got: {}",
            emails[0].subject
        );
    }

    #[tokio::test]
    async fn mock_transport_validates_email_body() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = make_notifier_with_mock(mock.clone());

        let alert = make_alert_payload("test_rule");
        notifier.send(&alert).await.unwrap();

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        // Body from make_alert_payload is "Something happened"
        assert!(
            emails[0].body.contains("Something happened"),
            "Body should contain alert body, got: {}",
            emails[0].body
        );
    }

    #[tokio::test]
    async fn mock_transport_sends_to_multiple_recipients() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = EmailNotifier::with_transport(
            "multi-recipient",
            mock.clone(),
            "sender@test.com".parse().unwrap(),
            vec![
                "alice@test.com".parse().unwrap(),
                "bob@test.com".parse().unwrap(),
                "charlie@test.com".parse().unwrap(),
            ],
            "{{ title }}",
            None, // Use default body template
        );

        let alert = make_alert_payload("test_rule");
        let result = notifier.send(&alert).await;

        assert!(result.is_ok());
        assert_eq!(mock.send_count(), 3, "Should send to each recipient");

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 3, "Should record 3 emails");

        // Verify each recipient received an email
        let recipients: Vec<&str> = emails.iter().map(|e| e.to.as_str()).collect();
        assert!(recipients.iter().any(|r| r.contains("alice@test.com")));
        assert!(recipients.iter().any(|r| r.contains("bob@test.com")));
        assert!(recipients.iter().any(|r| r.contains("charlie@test.com")));
    }

    #[tokio::test]
    async fn mock_transport_html_format_sends_correctly() {
        let mock = Arc::new(MockEmailTransport::new());
        let notifier = EmailNotifier::with_transport(
            "html-test",
            mock.clone(),
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "{{ title }}",
            None, // Use default body template
        );

        let mut alert = make_alert_payload("html_test");
        // body_html is pre-escaped by TemplateEngine, injected with | safe
        // Using pre-escaped content simulates what TemplateEngine produces
        alert.message.body_html =
            Some("&lt;h1&gt;Alert!&lt;/h1&gt;&lt;p&gt;Something happened&lt;/p&gt;".to_string());

        let result = notifier.send(&alert).await;

        assert!(result.is_ok());
        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        // body_html content (pre-escaped) is injected directly with | safe
        assert!(
            emails[0].body.contains("&lt;h1&gt;Alert!&lt;"),
            "Pre-escaped body_html should be in email, got: {}",
            emails[0].body
        );
        assert!(
            !emails[0].body.contains("<h1>Alert!</h1>"),
            "Raw HTML should NOT be present (XSS prevention)"
        );
    }

    // ===================================================================
    // Retry behavior tests with mock (Story 7.2 - AC #1)
    // ===================================================================

    #[tokio::test(start_paused = true)]
    async fn mock_transport_retry_on_transient_error() {
        // start_paused = true: Time is paused, tokio::time::sleep completes instantly
        // This allows testing retry logic without waiting for real backoff delays (AC#2: <1s)
        let mock = Arc::new(MockEmailTransport::new());
        // Fail first 2 attempts with transient error, succeed on 3rd
        mock.fail_next(2, "connection timeout");

        let notifier = make_notifier_with_mock(mock.clone());
        let alert = make_alert_payload("retry_test");

        let result = notifier.send(&alert).await;

        assert!(result.is_ok(), "Should succeed after retries");
        assert_eq!(mock.send_count(), 3, "Should have tried 3 times");
    }

    #[tokio::test(start_paused = true)]
    async fn mock_transport_fails_after_max_retries() {
        // start_paused = true: Time is paused, tokio::time::sleep completes instantly
        // This allows testing retry logic without waiting for real backoff delays (AC#2: <1s)
        let mock = Arc::new(MockEmailTransport::new());
        // Fail all 3 attempts
        mock.fail_next(3, "connection timeout");

        let notifier = make_notifier_with_mock(mock.clone());
        let alert = make_alert_payload("fail_test");

        let result = notifier.send(&alert).await;

        assert!(result.is_err(), "Should fail after max retries");
        assert_eq!(
            mock.send_count(),
            3,
            "Should have tried EMAIL_MAX_RETRIES times"
        );
    }

    #[tokio::test]
    async fn mock_transport_no_retry_on_permanent_error() {
        let mock = Arc::new(MockEmailTransport::new());
        // Fail with authentication error (permanent)
        mock.fail_next(1, "535 authentication failed");

        let notifier = make_notifier_with_mock(mock.clone());
        let alert = make_alert_payload("auth_fail_test");

        let result = notifier.send(&alert).await;

        assert!(result.is_err(), "Should fail immediately");
        assert_eq!(mock.send_count(), 1, "Should NOT retry on permanent error");
    }

    #[tokio::test]
    async fn mock_transport_no_retry_on_550_mailbox_unavailable() {
        let mock = Arc::new(MockEmailTransport::new());
        mock.fail_next(1, "550 mailbox unavailable");

        let notifier = make_notifier_with_mock(mock.clone());
        let alert = make_alert_payload("mailbox_fail");

        let result = notifier.send(&alert).await;

        assert!(result.is_err());
        assert_eq!(mock.send_count(), 1, "Should NOT retry on 550 error");
    }

    #[tokio::test]
    async fn mock_transport_partial_success_with_multiple_recipients() {
        // Test that if one recipient fails permanently, others still succeed
        let mock = Arc::new(MockEmailTransport::new());
        // First send fails permanently, others succeed
        mock.fail_next(1, "550 mailbox unavailable");

        let notifier = EmailNotifier::with_transport(
            "partial-success",
            mock.clone(),
            "sender@test.com".parse().unwrap(),
            vec![
                "bad@test.com".parse().unwrap(),
                "good1@test.com".parse().unwrap(),
                "good2@test.com".parse().unwrap(),
            ],
            "{{ title }}",
            None, // Use default body template
        );

        let alert = make_alert_payload("partial_test");
        let result = notifier.send(&alert).await;

        // Should succeed overall because at least one recipient succeeded
        assert!(result.is_ok(), "Should succeed with partial delivery");
        assert_eq!(mock.send_count(), 3, "Should have tried all 3 recipients");

        // 2 successful, 1 failed
        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 2, "Should have recorded 2 successful emails");
    }

    #[tokio::test]
    async fn mock_transport_all_recipients_fail_returns_error() {
        let mock = Arc::new(MockEmailTransport::new());
        // All sends fail permanently
        mock.fail_next(3, "550 all mailboxes unavailable");

        let notifier = EmailNotifier::with_transport(
            "all-fail",
            mock.clone(),
            "sender@test.com".parse().unwrap(),
            vec![
                "bad1@test.com".parse().unwrap(),
                "bad2@test.com".parse().unwrap(),
                "bad3@test.com".parse().unwrap(),
            ],
            "{{ title }}",
            None, // Use default body template
        );

        let alert = make_alert_payload("all_fail_test");
        let result = notifier.send(&alert).await;

        assert!(result.is_err(), "Should fail when all recipients fail");
    }

    // ===================================================================
    // Body template tests (Task 13 - Tech Spec email-body-template)
    // ===================================================================

    #[test]
    fn render_body_with_all_variables() {
        // Task 13: Test render_body with all variables (title, body, rule_name, color, icon)
        let mock = Arc::new(MockEmailTransport::new());
        let custom_template = r#"Title: {{ title }}
Body: {{ body }}
Rule: {{ rule_name }}
Color: {{ color }}
Icon: {{ icon }}"#;

        let notifier = EmailNotifier::with_transport(
            "body-test",
            mock,
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "{{ title }}",
            Some(custom_template),
        );

        let alert = make_alert_payload("test_rule");
        let body = notifier.render_body(&alert).unwrap();

        assert!(body.contains("Title: Test Alert"), "Should contain title");
        assert!(
            body.contains("Body: Something happened"),
            "Should contain body"
        );
        assert!(body.contains("Rule: test_rule"), "Should contain rule_name");
        assert!(body.contains("Color: #ff0000"), "Should contain color");
        assert!(body.contains("Icon: :warning:"), "Should contain icon");
    }

    #[test]
    fn render_body_with_custom_template() {
        // Task 13: Test render_body with custom template
        let mock = Arc::new(MockEmailTransport::new());
        let custom_template = "<div class=\"alert\">{{ title }}: {{ body }}</div>";

        let notifier = EmailNotifier::with_transport(
            "custom-body-test",
            mock,
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "{{ title }}",
            Some(custom_template),
        );

        let alert = make_alert_payload("custom_rule");
        let body = notifier.render_body(&alert).unwrap();

        assert_eq!(
            body,
            "<div class=\"alert\">Test Alert: Something happened</div>"
        );
    }

    #[test]
    fn body_template_validation_fails_on_invalid() {
        // Task 13: Test that invalid body template fails at notifier creation
        let config = EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "test@example.com".to_string(),
            to: vec!["dest@example.com".to_string()],
            subject_template: "{{ title }}".to_string(),
            body_template: Some("{% if unclosed".to_string()), // Invalid template
            body_template_file: None,
        };

        let result = EmailNotifier::from_config("invalid-body", &config, &test_config_dir());

        assert!(result.is_err(), "Invalid body template should fail");
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "invalid-body");
                assert!(
                    message.contains("body_template"),
                    "Error should mention body_template: {}",
                    message
                );
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn mock_transport_validates_rendered_body() {
        // Task 13: Test that rendered body appears in sent email
        let mock = Arc::new(MockEmailTransport::new());
        let custom_template = "RENDERED: {{ title }} - {{ rule_name }}";

        let notifier = EmailNotifier::with_transport(
            "rendered-body-test",
            mock.clone(),
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "{{ title }}",
            Some(custom_template),
        );

        let alert = make_alert_payload("render_test");
        notifier.send(&alert).await.unwrap();

        let emails = mock.sent_emails();
        assert_eq!(emails.len(), 1);
        // The body should contain the RENDERED template, not raw alert.message.body
        assert!(
            emails[0]
                .body
                .contains("RENDERED: Test Alert - render_test"),
            "Body should contain rendered template, got: {}",
            emails[0].body
        );
    }

    #[test]
    fn default_body_template_used_when_none_specified() {
        // Task 13: Test fallback to embedded default template
        let mock = Arc::new(MockEmailTransport::new());

        let notifier = EmailNotifier::with_transport(
            "default-template-test",
            mock,
            "sender@test.com".parse().unwrap(),
            vec!["dest@test.com".parse().unwrap()],
            "{{ title }}",
            None, // No custom template - should use DEFAULT_BODY_TEMPLATE
        );

        let alert = make_alert_payload("default_test");
        let body = notifier.render_body(&alert).unwrap();

        // Default template is HTML with specific structure
        assert!(
            body.contains("<!DOCTYPE html>"),
            "Default template should be HTML"
        );
        assert!(
            body.contains("Test Alert"),
            "Default template should render title"
        );
        assert!(
            body.contains("default_test"),
            "Default template should render rule_name"
        );
        assert!(
            body.contains("Valerter"),
            "Default template should contain Valerter branding"
        );
    }

    // ===================================================================
    // Task 9: Tests subject_template render validation (unknown filters)
    // ===================================================================

    #[test]
    fn from_config_fails_on_subject_template_unknown_filter() {
        // AC6: subject_template with unknown filter should fail at config time
        let config = EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "test@example.com".to_string(),
            to: vec!["dest@example.com".to_string()],
            subject_template: "[TEST] {{ _msg | truncate(50) }}".to_string(), // Unknown filter
            body_template: None,
            body_template_file: None,
        };

        let result = EmailNotifier::from_config("bad-subject", &config, &test_config_dir());

        assert!(result.is_err(), "Unknown filter should fail validation");
        let err = result.unwrap_err();
        match err {
            ConfigError::InvalidNotifier { name, message } => {
                assert_eq!(name, "bad-subject");
                assert!(
                    message.contains("subject_template render"),
                    "Error should mention subject_template render: {}",
                    message
                );
                assert!(
                    message.contains("truncate"),
                    "Error should mention truncate filter: {}",
                    message
                );
            }
            _ => panic!("Expected InvalidNotifier, got {:?}", err),
        }
    }

    #[test]
    fn from_config_allows_builtin_filters_in_subject() {
        // Built-in filters should pass validation
        let config = EmailNotifierConfig {
            smtp: SmtpConfig {
                host: "smtp.example.com".to_string(),
                port: 587,
                username: None,
                password: None,
                tls: TlsMode::Starttls,
                tls_verify: true,
            },
            from: "test@example.com".to_string(),
            to: vec!["dest@example.com".to_string()],
            subject_template: "[{{ rule_name | upper }}] {{ title | default('Alert') }}"
                .to_string(),
            body_template: None,
            body_template_file: None,
        };

        let result = EmailNotifier::from_config("good-subject", &config, &test_config_dir());

        assert!(
            result.is_ok(),
            "Built-in filters should pass: {:?}",
            result.err()
        );
    }
}
