//! Unit tests for notify module.

use super::*;
use async_trait::async_trait;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::config::{
    EmailNotifierConfig, MattermostNotifierConfig, NotifierConfig, SmtpConfig, TlsMode,
    WebhookNotifierConfig,
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
            body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: rule_name.to_string(),
        destinations: vec![], // Uses default notifier
    }
}

fn make_payload_with_destinations(rule_name: &str, destinations: Vec<String>) -> AlertPayload {
    AlertPayload {
        message: RenderedMessage {
            title: format!("Alert from {}", rule_name),
            body: "Test body".to_string(),
            body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: rule_name.to_string(),
        destinations,
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
                    webhook_url: "${TEST_MM_WEBHOOK}".to_string(),
                    channel: Some("infra-alerts".to_string()),
                    username: Some("valerter".to_string()),
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "mattermost-ops".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: "https://static.example.com/hooks/static".to_string(),
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
                webhook_url: "${UNDEFINED_WEBHOOK_VAR}".to_string(),
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
                    webhook_url: "${UNDEFINED_VAR_1}".to_string(),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "bad-notifier-2".to_string(),
                NotifierConfig::Mattermost(MattermostNotifierConfig {
                    webhook_url: "${UNDEFINED_VAR_2}".to_string(),
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
                url: "https://api.example.com/alerts".to_string(),
                method: "POST".to_string(),
                headers: {
                    let mut h = std::collections::HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        "Bearer ${TEST_WEBHOOK_TOKEN}".to_string(),
                    );
                    h.insert("Content-Type".to_string(), "application/json".to_string());
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
            url: "https://api.example.com/hook".to_string(),
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
                url: "https://api.example.com/alerts".to_string(),
                method: "POST".to_string(),
                headers: {
                    let mut h = std::collections::HashMap::new();
                    h.insert(
                        "Authorization".to_string(),
                        "Bearer ${UNDEFINED_WEBHOOK_TOKEN}".to_string(),
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
                    webhook_url: "${TEST_MM_WEBHOOK_MIXED}".to_string(),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );
            notifiers_config.insert(
                "webhook-1".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: "https://api.example.com/alerts".to_string(),
                    method: "POST".to_string(),
                    headers: {
                        let mut h = std::collections::HashMap::new();
                        h.insert(
                            "X-API-Key".to_string(),
                            "${TEST_WH_TOKEN_MIXED}".to_string(),
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

#[test]
fn send_to_queue_is_non_blocking() {
    let queue = NotificationQueue::new(10);
    let _rx = queue.subscribe();

    let payload = make_payload("test_rule");
    let result = queue.send(payload);

    assert!(result.is_ok());
    assert_eq!(queue.len(), 1);
}

#[test]
fn send_without_receiver_returns_error() {
    let queue = NotificationQueue::new(10);

    let payload = make_payload("test_rule");
    let result = queue.send(payload);

    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::QueueError::Closed => {}
    }
}

#[tokio::test]
async fn drop_oldest_when_queue_full() {
    let queue = NotificationQueue::new(5);
    let mut rx = queue.subscribe();

    for i in 0..10 {
        let payload = make_payload(&format!("rule_{}", i));
        let _ = queue.send(payload);
    }

    match rx.recv().await {
        Err(broadcast::error::RecvError::Lagged(n)) => {
            assert!(n >= 1, "Expected at least 1 lagged message, got {}", n);
            assert!(n <= 10, "Cannot drop more messages than sent");
        }
        Ok(_) => panic!("Expected Lagged error when queue overflows"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn queue_size_updates_on_send() {
    let queue = NotificationQueue::new(10);
    let _rx = queue.subscribe();

    assert_eq!(queue.len(), 0);
    assert!(queue.is_empty());

    queue.send(make_payload("rule_1")).unwrap();
    assert_eq!(queue.len(), 1);

    queue.send(make_payload("rule_2")).unwrap();
    assert_eq!(queue.len(), 2);
}

#[test]
fn queue_capacity_is_respected() {
    let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY);
    let _rx = queue.subscribe();

    for i in 0..DEFAULT_QUEUE_CAPACITY {
        let payload = make_payload(&format!("rule_{}", i));
        queue.send(payload).unwrap();
    }

    assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);
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
            body_html: None,
            accent_color: Some("#ff0000".to_string()),
        },
        rule_name: "my_rule".to_string(),
        destinations: vec!["mattermost-infra".to_string()],
    };

    let cloned = payload.clone();
    assert_eq!(cloned.rule_name, payload.rule_name);
    assert_eq!(cloned.message.title, payload.message.title);
    assert_eq!(cloned.destinations, payload.destinations);
}

#[test]
fn queue_is_clone() {
    let queue1 = NotificationQueue::new(10);
    let queue2 = queue1.clone();

    let _rx = queue1.subscribe();

    queue1.send(make_payload("rule_1")).unwrap();
    assert_eq!(queue2.len(), 1);
}

#[test]
fn queue_debug_format() {
    let queue = NotificationQueue::new(10);
    let debug = format!("{:?}", queue);
    assert!(debug.contains("NotificationQueue"));
}

#[tokio::test]
async fn multiple_messages_consumed_in_order() {
    let queue = NotificationQueue::new(10);
    let mut rx = queue.subscribe();

    for i in 0..3 {
        queue.send(make_payload(&format!("rule_{}", i))).unwrap();
    }

    let msg0 = rx.recv().await.unwrap();
    assert_eq!(msg0.rule_name, "rule_0");

    let msg1 = rx.recv().await.unwrap();
    assert_eq!(msg1.rule_name, "rule_1");

    let msg2 = rx.recv().await.unwrap();
    assert_eq!(msg2.rule_name, "rule_2");
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
                        password: Some("${TEST_SMTP_PASS_REG}".to_string()),
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
                    password: Some("somepass".to_string()),
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
                    webhook_url: "${TEST_MM_ALL_TYPES}".to_string(),
                    channel: None,
                    username: None,
                    icon_url: None,
                }),
            );

            // Webhook
            notifiers_config.insert(
                "webhook".to_string(),
                NotifierConfig::Webhook(WebhookNotifierConfig {
                    url: "https://api.example.com/alerts".to_string(),
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
