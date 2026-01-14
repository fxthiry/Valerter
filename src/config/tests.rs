//! Integration tests for Config loading, validation, and compilation.

use super::*;
use std::path::PathBuf;
use std::time::Duration;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ============================================================
// Config Loading Tests
// ============================================================

#[test]
fn load_valid_config() {
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();

    // VictoriaLogs settings
    assert_eq!(config.victorialogs.url, "http://victorialogs:9428");

    // Defaults
    assert_eq!(config.defaults.throttle.count, 5);
    assert_eq!(config.defaults.throttle.window, Duration::from_secs(60));
    assert_eq!(config.defaults.notify.template, "default_alert");

    // Templates
    assert!(config.templates.contains_key("default_alert"));
    assert!(config.templates.contains_key("custom_template"));
    let default_template = config.templates.get("default_alert").unwrap();
    assert_eq!(default_template.accent_color, Some("#ff0000".to_string()));

    // Rules count
    assert_eq!(config.rules.len(), 3);

    // First rule: high_cpu_alert
    let rule1 = &config.rules[0];
    assert_eq!(rule1.name, "high_cpu_alert");
    assert!(rule1.enabled);
    assert!(rule1.parser.json.is_some());
    let throttle = rule1.throttle.as_ref().unwrap();
    assert_eq!(throttle.count, 3);
    assert_eq!(throttle.window, Duration::from_secs(300)); // 5m = 300s
    let notify = rule1.notify.as_ref().unwrap();
    assert_eq!(notify.channel, Some("alerts".to_string()));

    // Second rule: error_log_alert (uses regex parser)
    let rule2 = &config.rules[1];
    assert_eq!(rule2.name, "error_log_alert");
    assert!(rule2.parser.regex.is_some());
    assert!(rule2.throttle.is_none()); // uses defaults

    // Third rule: disabled
    let rule3 = &config.rules[2];
    assert!(!rule3.enabled);
}

#[test]
fn load_nonexistent_file_returns_load_error() {
    let result = Config::load(std::path::Path::new("/nonexistent/path/config.yaml"));
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::ConfigError::LoadError(msg) => {
            assert!(msg.contains("/nonexistent/path/config.yaml"));
        }
        e => panic!("Expected LoadError, got {:?}", e),
    }
}

#[test]
fn load_invalid_yaml_returns_validation_error() {
    let result = Config::load(&fixture_path("config_invalid_yaml.yaml"));
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::ConfigError::ValidationError(_) => {}
        e => panic!("Expected ValidationError, got {:?}", e),
    }
}

#[test]
fn load_webhook_from_explicit_value() {
    let config = Config::load_with_webhook(
        &fixture_path("config_valid.yaml"),
        Some("https://mattermost.example.com/hooks/xxx".to_string()),
    )
    .unwrap();

    assert!(config.mattermost_webhook.is_some());
    assert_eq!(
        config.mattermost_webhook.as_ref().unwrap().expose(),
        "https://mattermost.example.com/hooks/xxx"
    );
}

#[test]
fn load_webhook_from_environment_variable() {
    temp_env::with_var(
        "MATTERMOST_WEBHOOK",
        Some("https://test.webhook.url/hook"),
        || {
            let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
            assert!(config.mattermost_webhook.is_some());
            assert_eq!(
                config.mattermost_webhook.as_ref().unwrap().expose(),
                "https://test.webhook.url/hook"
            );
        },
    );
}

#[test]
fn mattermost_webhook_in_yaml_is_ignored_due_to_serde_skip() {
    // This test verifies that #[serde(skip)] on mattermost_webhook works:
    // even if mattermost_webhook appears in YAML, it should be None after deserialization
    // (it can only be set via load_with_webhook or MATTERMOST_WEBHOOK env var)
    let yaml = r#"
        victorialogs:
          url: http://localhost:9428
        defaults:
          throttle:
            count: 5
            window: 1m
          notify:
            template: default_alert
        templates:
          default_alert:
            title: "Alert"
            body: "{{ body }}"
        rules:
          - name: test_rule
            query: "*"
            parser:
              regex: ".*"
        mattermost_webhook: "https://should-be-ignored.com/hooks/secret"
    "#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();
    // The mattermost_webhook field should be None because #[serde(skip)] ignores it
    assert!(
        config.mattermost_webhook.is_none(),
        "mattermost_webhook should be None due to #[serde(skip)], but it was set from YAML"
    );
}

#[test]
fn rule_enabled_defaults_to_true() {
    let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();
    assert!(config.rules[0].enabled);
}

#[test]
fn default_config_path_is_correct() {
    assert_eq!(DEFAULT_CONFIG_PATH, "/etc/valerter/config.yaml");
}

#[test]
fn config_example_yaml_is_valid() {
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("config.example.yaml");

    let config = Config::load(&example_path).expect("config.example.yaml should be valid");
    assert!(!config.victorialogs.url.is_empty());
    assert!(!config.templates.is_empty());
    assert!(!config.rules.is_empty());
}

// ============================================================
// Validation Tests
// ============================================================

#[test]
fn validate_valid_config_passes() {
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_invalid_regex_returns_error_with_rule_name() {
    let config = Config::load(&fixture_path("config_invalid_regex.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_err());

    let errors = result.unwrap_err();
    let has_invalid_regex_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::InvalidRegex { rule, .. } if rule == "invalid_regex_rule")
    });
    assert!(has_invalid_regex_error);
}

#[test]
fn validate_disabled_rule_with_invalid_regex_still_fails() {
    let config = Config::load(&fixture_path("config_disabled_invalid.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn validate_invalid_template_returns_error() {
    let config = Config::load(&fixture_path("config_invalid_template.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_err());

    let errors = result.unwrap_err();
    let has_template_error = errors
        .iter()
        .any(|e| matches!(e, crate::error::ConfigError::InvalidTemplate { .. }));
    assert!(has_template_error);
}

// ============================================================
// Compilation Tests
// ============================================================

#[test]
fn compile_creates_runtime_config_with_compiled_regex() {
    let path = fixture_path("config_valid.yaml");
    let config = Config::load(&path).unwrap();
    config.validate().expect("Valid config should validate");

    let runtime = config.compile(&path).expect("Valid config should compile");

    assert_eq!(runtime.rules.len(), 3);

    let error_rule = runtime
        .rules
        .iter()
        .find(|r| r.name == "error_log_alert")
        .unwrap();
    assert!(error_rule.parser.regex.is_some());

    let regex = error_rule.parser.regex.as_ref().unwrap();
    let captures = regex
        .captures("2026-01-09T10:00:00 ERROR something failed")
        .unwrap();
    assert_eq!(captures.name("level").unwrap().as_str(), "ERROR");
}

#[test]
fn compile_preserves_config_values() {
    let path = fixture_path("config_valid.yaml");
    let config = Config::load(&path).unwrap();
    config.validate().unwrap();

    let runtime = config.compile(&path).unwrap();

    assert_eq!(runtime.victorialogs.url, "http://victorialogs:9428");
    assert_eq!(runtime.defaults.throttle.count, 5);
    assert!(runtime.templates.contains_key("default_alert"));
}

// ============================================================
// Auth Options Tests
// ============================================================

#[test]
fn load_config_with_basic_auth() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    assert!(config.victorialogs.basic_auth.is_some());
    let basic_auth = config.victorialogs.basic_auth.as_ref().unwrap();
    assert_eq!(basic_auth.username, "testuser");
    assert_eq!(basic_auth.password.expose(), "testpassword");
}

#[test]
fn load_config_with_headers() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    assert!(config.victorialogs.headers.is_some());
    let headers = config.victorialogs.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(
        headers.get("X-API-Key").unwrap().expose(),
        "secret-api-key-12345"
    );
}

#[test]
fn load_config_with_tls_verify_false() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    assert!(config.victorialogs.tls.is_some());
    assert!(!config.victorialogs.tls.as_ref().unwrap().verify);
}

#[test]
fn basic_auth_debug_redacts_password() {
    let basic_auth = BasicAuthConfig {
        username: "admin".to_string(),
        password: SecretString::new("super-secret-password".to_string()),
    };

    let debug_output = format!("{:?}", basic_auth);

    assert!(debug_output.contains("admin"));
    assert!(!debug_output.contains("super-secret-password"));
    assert!(debug_output.contains("[REDACTED]"));
}

#[test]
fn config_debug_does_not_leak_webhook() {
    let config = Config::load_with_webhook(
        &fixture_path("config_valid.yaml"),
        Some("secret-webhook-url".to_string()),
    )
    .unwrap();

    let debug_output = format!("{:?}", config);

    assert!(!debug_output.contains("secret-webhook-url"));
    assert!(debug_output.contains("[REDACTED]"));
}

// ============================================================
// Notifiers Tests
// ============================================================

#[test]
fn load_config_with_notifiers_section() {
    let config = Config::load(&fixture_path("config_with_notifiers.yaml")).unwrap();

    assert!(config.notifiers.is_some());
    let notifiers = config.notifiers.as_ref().unwrap();
    assert_eq!(notifiers.len(), 5);
}

#[test]
fn load_config_without_notifiers_section_is_valid() {
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
    assert!(config.notifiers.is_none());
}

// ============================================================
// RuntimeConfig Destination Validation Tests
// ============================================================

fn make_runtime_config_with_destinations(destinations: Option<Vec<String>>) -> RuntimeConfig {
    RuntimeConfig {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "default".to_string(),
            },
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                CompiledTemplate {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    body_html: None,
                    accent_color: None,
                },
            );
            t
        },
        rules: vec![CompiledRule {
            name: "test_rule".to_string(),
            enabled: true,
            query: "test".to_string(),
            parser: CompiledParser {
                regex: None,
                json: None,
            },
            throttle: None,
            notify: Some(NotifyConfig {
                template: None,
                channel: None,
                destinations,
            }),
        }],
        metrics: MetricsConfig::default(),
        notifiers: Some(std::collections::HashMap::new()),
        mattermost_webhook: None,
        config_dir: std::path::PathBuf::from("."),
    }
}

#[test]
fn collect_rule_destinations_returns_configured_destinations() {
    let config = make_runtime_config_with_destinations(Some(vec![
        "mattermost-infra".to_string(),
        "mattermost-ops".to_string(),
    ]));

    let destinations = config.collect_rule_destinations();
    assert_eq!(destinations.len(), 1);
    assert_eq!(destinations[0].0, "test_rule");
    assert_eq!(destinations[0].1, &["mattermost-infra", "mattermost-ops"]);
}

#[test]
fn validate_rule_destinations_passes_for_valid_destinations() {
    let config = make_runtime_config_with_destinations(Some(vec![
        "notifier-a".to_string(),
        "notifier-b".to_string(),
    ]));

    let valid_notifiers = vec!["notifier-a", "notifier-b", "notifier-c"];
    let result = config.validate_rule_destinations(&valid_notifiers);
    assert!(result.is_ok());
}

#[test]
fn validate_rule_destinations_fails_for_unknown_destination() {
    let config = make_runtime_config_with_destinations(Some(vec![
        "notifier-a".to_string(),
        "unknown-notifier".to_string(),
    ]));

    let valid_notifiers = vec!["notifier-a", "notifier-b"];
    let result = config.validate_rule_destinations(&valid_notifiers);

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].to_string().contains("unknown-notifier"));
}

#[test]
fn load_without_webhook() {
    let config = Config::load_with_webhook(&fixture_path("config_valid.yaml"), None).unwrap();
    assert!(config.mattermost_webhook.is_none());
}

#[test]
fn rules_use_defaults_when_not_specified() {
    let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();
    assert_eq!(config.rules.len(), 1);
    let rule = &config.rules[0];
    assert!(rule.throttle.is_none());
    assert!(rule.notify.is_none());
    assert_eq!(config.defaults.throttle.count, 10);
    assert_eq!(config.defaults.notify.template, "simple");
}

#[test]
fn validate_collects_all_errors() {
    let config = Config {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "default".to_string(),
            },
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                TemplateConfig {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    body_html: None,
                    accent_color: None,
                },
            );
            t
        },
        rules: vec![
            RuleConfig {
                name: "rule1_invalid".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: ParserConfig {
                    regex: Some("[invalid(".to_string()),
                    json: None,
                },
                throttle: None,
                notify: None,
            },
            RuleConfig {
                name: "rule2_invalid".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: ParserConfig {
                    regex: Some("(?P<unclosed".to_string()),
                    json: None,
                },
                throttle: None,
                notify: None,
            },
        ],
        metrics: MetricsConfig::default(),
        notifiers: None,
        mattermost_webhook: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 2, "Should collect all regex errors");
}

#[test]
fn validate_throttle_key_template() {
    let config = Config {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "default".to_string(),
            },
        },
        templates: std::collections::HashMap::new(),
        rules: vec![RuleConfig {
            name: "rule_with_invalid_throttle_key".to_string(),
            enabled: true,
            query: "test".to_string(),
            parser: ParserConfig {
                regex: None,
                json: None,
            },
            throttle: Some(ThrottleConfig {
                key: Some("{% if host %}{{ host".to_string()),
                count: 5,
                window: Duration::from_secs(60),
            }),
            notify: None,
        }],
        metrics: MetricsConfig::default(),
        notifiers: None,
        mattermost_webhook: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    let has_template_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::InvalidTemplate { rule, message }
            if rule == "rule_with_invalid_throttle_key" && message.contains("throttle.key"))
    });
    assert!(has_template_error);
}

#[test]
fn validate_nonexistent_notify_template_fails() {
    let config = Config {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "existing_template".to_string(),
            },
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "existing_template".to_string(),
                TemplateConfig {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    body_html: None,
                    accent_color: None,
                },
            );
            t
        },
        rules: vec![RuleConfig {
            name: "rule_with_missing_template".to_string(),
            enabled: true,
            query: "test".to_string(),
            parser: ParserConfig {
                regex: None,
                json: None,
            },
            throttle: None,
            notify: Some(NotifyConfig {
                template: Some("nonexistent_template".to_string()),
                channel: None,
                destinations: None,
            }),
        }],
        metrics: MetricsConfig::default(),
        notifiers: None,
        mattermost_webhook: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    let has_missing_template_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::InvalidTemplate { rule, message }
            if rule == "rule_with_missing_template"
            && message.contains("nonexistent_template"))
    });
    assert!(has_missing_template_error);
}

#[test]
fn validate_nonexistent_default_template_fails() {
    let config = Config {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "missing_default".to_string(),
            },
        },
        templates: std::collections::HashMap::new(),
        rules: vec![],
        metrics: MetricsConfig::default(),
        notifiers: None,
        mattermost_webhook: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    let has_default_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::InvalidTemplate { rule, message }
            if rule == "defaults.notify" && message.contains("missing_default"))
    });
    assert!(has_default_error);
}

#[test]
fn security_audit_full_config_debug_safe() {
    let config = Config::load_with_webhook(
        &fixture_path("config_valid.yaml"),
        Some("https://secret.webhook.url/hooks/supersecret123".to_string()),
    )
    .unwrap();

    let debug_output = format!("{:?}", config);
    let forbidden = ["secret.webhook.url", "supersecret123", "hooks/"];

    for pattern in &forbidden {
        assert!(
            !debug_output.contains(pattern),
            "SECURITY VIOLATION: Config debug leaked '{}'",
            pattern
        );
    }
    assert!(debug_output.contains("[REDACTED]"));
}

#[test]
fn load_config_without_auth_options() {
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
    assert!(config.victorialogs.basic_auth.is_none());
    assert!(config.victorialogs.headers.is_none());
    assert!(config.victorialogs.tls.is_none());
}

#[test]
fn headers_with_secret_values_are_redacted_in_debug() {
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        SecretString::new("Bearer secret-token".to_string()),
    );
    headers.insert(
        "X-API-Key".to_string(),
        SecretString::new("api-key-12345".to_string()),
    );

    let debug_output = format!("{:?}", headers);

    assert!(!debug_output.contains("secret-token"));
    assert!(!debug_output.contains("Bearer"));
    assert!(!debug_output.contains("api-key-12345"));
    assert!(debug_output.contains("Authorization"));
    assert!(debug_output.contains("X-API-Key"));
}

#[test]
fn full_config_with_auth_debug_redacts_all_secrets() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();
    let debug_output = format!("{:?}", config);

    assert!(!debug_output.contains("testpassword"));
    assert!(!debug_output.contains("secret-api-key-12345"));
    assert!(debug_output.contains("testuser"));
}

#[test]
fn tls_verify_defaults_to_true() {
    let tls: TlsConfig = serde_yaml::from_str("{}").unwrap();
    assert!(tls.verify);
}

#[test]
fn tls_verify_can_be_set_to_false() {
    let tls: TlsConfig = serde_yaml::from_str("verify: false").unwrap();
    assert!(!tls.verify);
}

#[test]
fn load_config_with_incomplete_basic_auth_fails() {
    let result = Config::load(&fixture_path("config_invalid_basic_auth.yaml"));
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::ConfigError::ValidationError(msg) => {
            assert!(msg.contains("password") || msg.contains("missing"));
        }
        e => panic!("Expected ValidationError, got {:?}", e),
    }
}

#[test]
fn validate_config_with_auth_passes() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn load_config_with_unknown_notifier_type_fails() {
    let result = Config::load(&fixture_path("config_invalid_notifier_type.yaml"));
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::error::ConfigError::ValidationError(msg) => {
            assert!(msg.contains("unknown") || msg.contains("variant") || msg.contains("type"));
        }
        e => panic!("Expected ValidationError, got {:?}", e),
    }
}

#[test]
fn collect_rule_destinations_skips_rules_without_destinations() {
    let config = make_runtime_config_with_destinations(None);
    let destinations = config.collect_rule_destinations();
    assert!(destinations.is_empty());
}

#[test]
fn collect_rule_destinations_skips_empty_destinations() {
    let config = make_runtime_config_with_destinations(Some(vec![]));
    let destinations = config.collect_rule_destinations();
    assert!(destinations.is_empty());
}

#[test]
fn validate_rule_destinations_fails_for_empty_destinations_when_notifiers_configured() {
    let config = make_runtime_config_with_destinations(Some(vec![]));
    let valid_notifiers = vec!["notifier-a"];
    let result = config.validate_rule_destinations(&valid_notifiers);

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].to_string().contains("cannot be empty"));
}

#[test]
fn validate_rule_destinations_passes_for_none_destinations_backward_compat() {
    let config = make_runtime_config_with_destinations(None);
    let valid_notifiers = vec!["notifier-a"];
    let result = config.validate_rule_destinations(&valid_notifiers);
    assert!(result.is_ok());
}

#[test]
fn validate_body_html_syntax_error_detected() {
    let yaml = r#"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "Test"
    body: "Test body"
    body_html: "{% if unclosed"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        if let crate::error::ConfigError::InvalidTemplate { message, .. } = e {
            message.contains("body_html")
        } else {
            false
        }
    }));
}

#[test]
fn validate_config_with_invalid_accent_color_fails() {
    let yaml = r#"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "Test"
    body: "Body"
    accent_color: "red"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg) if msg.contains("invalid hex color"))
    }));
}

#[test]
fn validate_config_with_short_hex_fails() {
    let yaml = r##"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "Test"
    body: "Body"
    accent_color: "#fff"
rules: []
"##;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg) if msg.contains("#rrggbb"))
    }));
}

#[test]
fn validate_config_with_valid_accent_color_passes() {
    let yaml = r##"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "Test"
    body: "Body"
    accent_color: "#ff5500"
rules: []
"##;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn validate_template_render_in_body_detects_unknown_filter() {
    let yaml = r#"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "Test"
    body: "{{ _msg | truncate(50) }}"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        if let crate::error::ConfigError::InvalidTemplate { message, .. } = e {
            message.contains("body render") && message.contains("truncate")
        } else {
            false
        }
    }));
}

#[test]
fn validate_valid_templates_pass() {
    let yaml = r#"
victorialogs:
  url: http://localhost:9428
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: test
templates:
  test:
    title: "{{ title | upper }}"
    body: "{{ body | default('N/A') }}"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn validate_rule_destinations_collects_all_errors() {
    let config = RuntimeConfig {
        victorialogs: VictoriaLogsConfig {
            url: "http://localhost:9428".to_string(),
            basic_auth: None,
            headers: None,
            tls: None,
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            notify: NotifyDefaults {
                template: "default".to_string(),
            },
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                CompiledTemplate {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    body_html: None,
                    accent_color: None,
                },
            );
            t
        },
        rules: vec![
            CompiledRule {
                name: "rule_1".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: CompiledParser {
                    regex: None,
                    json: None,
                },
                throttle: None,
                notify: Some(NotifyConfig {
                    template: None,
                    channel: None,
                    destinations: Some(vec!["unknown-1".to_string()]),
                }),
            },
            CompiledRule {
                name: "rule_2".to_string(),
                enabled: true,
                query: "test".to_string(),
                parser: CompiledParser {
                    regex: None,
                    json: None,
                },
                throttle: None,
                notify: Some(NotifyConfig {
                    template: None,
                    channel: None,
                    destinations: Some(vec!["unknown-2".to_string()]),
                }),
            },
        ],
        metrics: MetricsConfig::default(),
        notifiers: Some(std::collections::HashMap::new()),
        mattermost_webhook: None,
        config_dir: std::path::PathBuf::from("."),
    };

    let valid_notifiers = vec!["valid-notifier"];
    let result = config.validate_rule_destinations(&valid_notifiers);

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 2, "Should collect all destination errors");
}
