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

    // VictoriaLogs settings (multi-source map — single `default` source)
    assert_eq!(config.victorialogs.len(), 1);
    assert_eq!(
        config.victorialogs.get("default").unwrap().url,
        "http://victorialogs:9428"
    );

    // Defaults
    assert_eq!(config.defaults.throttle.count, 5);
    assert_eq!(config.defaults.throttle.window, Duration::from_secs(60));

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
    assert_eq!(rule1.notify.mattermost_channel, Some("alerts".to_string()));

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
    assert!(!config.victorialogs.is_empty());
    for source in config.victorialogs.values() {
        assert!(!source.url.is_empty());
    }
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

#[test]
fn validate_no_rules_fails() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  test:
    title: "Test"
    body: "Body"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_err());

    let errors = result.unwrap_err();
    let has_no_rules_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg) if msg.contains("no rules defined"))
    });
    assert!(has_no_rules_error);
}

#[test]
fn validate_no_notifiers_fails() {
    let config = Config::load(&fixture_path("config_no_notifier.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_err());

    let errors = result.unwrap_err();
    let has_no_notifiers_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg) if msg.contains("no notifiers configured"))
    });
    assert!(
        has_no_notifiers_error,
        "Expected 'no notifiers configured' error, got: {:?}",
        errors
    );
}

#[test]
fn validate_no_templates_fails() {
    let config = Config::load(&fixture_path("config_no_template.yaml")).unwrap();
    let result = config.validate();
    assert!(result.is_err());

    let errors = result.unwrap_err();
    let has_no_templates_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg) if msg.contains("no templates defined"))
    });
    assert!(
        has_no_templates_error,
        "Expected 'no templates defined' error, got: {:?}",
        errors
    );
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

    assert_eq!(
        runtime.victorialogs.get("default").unwrap().url,
        "http://victorialogs:9428"
    );
    assert_eq!(runtime.defaults.throttle.count, 5);
    assert!(runtime.templates.contains_key("default_alert"));
}

// ============================================================
// Auth Options Tests
// ============================================================

#[test]
fn load_config_with_basic_auth() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    let source = config.victorialogs.get("default").unwrap();
    assert!(source.basic_auth.is_some());
    let basic_auth = source.basic_auth.as_ref().unwrap();
    assert_eq!(basic_auth.username, "testuser");
    assert_eq!(basic_auth.password.expose(), "testpassword");
}

#[test]
fn load_config_with_headers() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    let source = config.victorialogs.get("default").unwrap();
    assert!(source.headers.is_some());
    let headers = source.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(
        headers.get("X-API-Key").unwrap().expose(),
        "secret-api-key-12345"
    );
}

#[test]
fn load_config_with_tls_verify_false() {
    let config = Config::load(&fixture_path("config_with_auth.yaml")).unwrap();

    let source = config.victorialogs.get("default").unwrap();
    assert!(source.tls.is_some());
    assert!(!source.tls.as_ref().unwrap().verify);
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
fn load_config_without_notifiers_section_loads_none() {
    // config_no_notifier.yaml has no notifiers section
    let config = Config::load(&fixture_path("config_no_notifier.yaml")).unwrap();
    assert!(config.notifiers.is_none());
}

// ============================================================
// RuntimeConfig Destination Validation Tests
// ============================================================

fn make_runtime_config_with_destinations(destinations: Vec<String>) -> RuntimeConfig {
    RuntimeConfig {
        victorialogs: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "default".to_string(),
                VlSourceConfig {
                    url: "http://localhost:9428".to_string(),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
            m
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: super::DEFAULT_MAX_STREAMS,
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                CompiledTemplate {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    email_body_html: None,
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
            notify: NotifyConfig {
                template: "default".to_string(),
                mattermost_channel: None,
                destinations,
            },
            vl_sources: Vec::new(),
        }],
        metrics: MetricsConfig::default(),
        notifiers: Some(std::collections::HashMap::new()),
        config_dir: std::path::PathBuf::from("."),
    }
}

#[test]
fn collect_rule_destinations_returns_configured_destinations() {
    let config = make_runtime_config_with_destinations(vec![
        "mattermost-infra".to_string(),
        "mattermost-ops".to_string(),
    ]);

    let destinations = config.collect_rule_destinations();
    assert_eq!(destinations.len(), 1);
    assert_eq!(destinations[0].0, "test_rule");
    assert_eq!(destinations[0].1, &["mattermost-infra", "mattermost-ops"]);
}

#[test]
fn validate_rule_destinations_passes_for_valid_destinations() {
    let config = make_runtime_config_with_destinations(vec![
        "notifier-a".to_string(),
        "notifier-b".to_string(),
    ]);

    let valid_notifiers = vec!["notifier-a", "notifier-b", "notifier-c"];
    let result = config.validate_rule_destinations(&valid_notifiers);
    assert!(result.is_ok());
}

#[test]
fn validate_rule_destinations_fails_for_unknown_destination() {
    let config = make_runtime_config_with_destinations(vec![
        "notifier-a".to_string(),
        "unknown-notifier".to_string(),
    ]);

    let valid_notifiers = vec!["notifier-a", "notifier-b"];
    let result = config.validate_rule_destinations(&valid_notifiers);

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].to_string().contains("unknown-notifier"));
}

#[test]
fn rules_use_defaults_when_not_specified() {
    let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();
    assert_eq!(config.rules.len(), 1);
    let rule = &config.rules[0];
    // Rule doesn't override throttle, so it uses defaults
    assert!(rule.throttle.is_none());
    // config_minimal.yaml matches README example values
    assert_eq!(config.defaults.throttle.count, 5);
    // notify is now mandatory, so check rule has it
    assert_eq!(rule.notify.template, "default_alert");
    assert!(!rule.notify.destinations.is_empty());
}

#[test]
fn validate_collects_all_errors() {
    let config = Config {
        victorialogs: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "default".to_string(),
                VlSourceConfig {
                    url: "http://localhost:9428".to_string(),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
            m
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: super::DEFAULT_MAX_STREAMS,
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                TemplateConfig {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    email_body_html: None,
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
                notify: NotifyConfig {
                    template: "default".to_string(),
                    mattermost_channel: None,
                    destinations: vec!["test".to_string()],
                },
                vl_sources: Vec::new(),
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
                notify: NotifyConfig {
                    template: "default".to_string(),
                    mattermost_channel: None,
                    destinations: vec!["test".to_string()],
                },
                vl_sources: Vec::new(),
            },
        ],
        metrics: MetricsConfig::default(),
        notifiers: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    // 2 regex errors + 1 no notifiers error = 3 errors
    assert_eq!(
        errors.len(),
        3,
        "Should collect all errors (2 regex + 1 no notifiers)"
    );
}

#[test]
fn validate_throttle_key_template() {
    let config = Config {
        victorialogs: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "default".to_string(),
                VlSourceConfig {
                    url: "http://localhost:9428".to_string(),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
            m
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: super::DEFAULT_MAX_STREAMS,
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                TemplateConfig {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    email_body_html: None,
                    accent_color: None,
                },
            );
            t
        },
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
            notify: NotifyConfig {
                template: "default".to_string(),
                mattermost_channel: None,
                destinations: vec!["test".to_string()],
            },
            vl_sources: Vec::new(),
        }],
        metrics: MetricsConfig::default(),
        notifiers: None,
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
        victorialogs: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "default".to_string(),
                VlSourceConfig {
                    url: "http://localhost:9428".to_string(),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
            m
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: super::DEFAULT_MAX_STREAMS,
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "existing_template".to_string(),
                TemplateConfig {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    email_body_html: None,
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
            notify: NotifyConfig {
                template: "nonexistent_template".to_string(),
                mattermost_channel: None,
                destinations: vec!["test".to_string()],
            },
            vl_sources: Vec::new(),
        }],
        metrics: MetricsConfig::default(),
        notifiers: None,
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
fn load_config_without_auth_options() {
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
    assert!(
        config
            .victorialogs
            .get("default")
            .unwrap()
            .basic_auth
            .is_none()
    );
    assert!(
        config
            .victorialogs
            .get("default")
            .unwrap()
            .headers
            .is_none()
    );
    assert!(config.victorialogs.get("default").unwrap().tls.is_none());
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
fn validate_email_body_html_syntax_error_detected() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  test:
    title: "Test"
    body: "Test body"
    email_body_html: "{% if unclosed"
rules: []
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        if let crate::error::ConfigError::InvalidTemplate { message, .. } = e {
            message.contains("email_body_html")
        } else {
            false
        }
    }));
}

// Regression guard for the v1.2.0 rename of `body_html` → `email_body_html`.
// The old field name must be rejected at parse time with an error message that
// mentions both names, so users upgrading from 1.1.x get an actionable hint.
#[test]
fn parse_rejects_old_body_html_field_name() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  test:
    title: "Test"
    body: "Test body"
    body_html: "<p>legacy</p>"
rules: []
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "YAML with legacy `body_html` field must be rejected at parse time"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("body_html"),
        "Error should mention the legacy field name `body_html`, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("email_body_html"),
        "Error should list the new field name `email_body_html` among expected fields, got: {}",
        err_msg
    );
}

#[test]
fn validate_config_with_invalid_accent_color_fails() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
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
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
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
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  test:
    title: "Test"
    body: "Body"
    accent_color: "#ff5500"
rules:
  - name: test_rule
    query: "_msg:test"
    parser:
      regex: ".*"
    notify:
      template: "test"
      destinations:
        - "test"
"##;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn validate_template_render_in_body_detects_unknown_filter() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
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
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  test:
    title: "{{ title | upper }}"
    body: "{{ body | default('N/A') }}"
rules:
  - name: test_rule
    query: "_msg:test"
    parser:
      regex: ".*"
    notify:
      template: "test"
      destinations:
        - "test"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn validate_rule_destinations_collects_all_errors() {
    let config = RuntimeConfig {
        victorialogs: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "default".to_string(),
                VlSourceConfig {
                    url: "http://localhost:9428".to_string(),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
            m
        },
        defaults: DefaultsConfig {
            throttle: ThrottleConfig {
                key: None,
                count: 5,
                window: Duration::from_secs(60),
            },
            timestamp_timezone: "UTC".to_string(),
            max_streams: super::DEFAULT_MAX_STREAMS,
        },
        templates: {
            let mut t = std::collections::HashMap::new();
            t.insert(
                "default".to_string(),
                CompiledTemplate {
                    title: "{{ title }}".to_string(),
                    body: "{{ body }}".to_string(),
                    email_body_html: None,
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
                notify: NotifyConfig {
                    template: "default".to_string(),
                    mattermost_channel: None,
                    destinations: vec!["unknown-1".to_string()],
                },
                vl_sources: Vec::new(),
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
                notify: NotifyConfig {
                    template: "default".to_string(),
                    mattermost_channel: None,
                    destinations: vec!["unknown-2".to_string()],
                },
                vl_sources: Vec::new(),
            },
        ],
        metrics: MetricsConfig::default(),
        notifiers: Some(std::collections::HashMap::new()),
        config_dir: std::path::PathBuf::from("."),
    };

    let valid_notifiers = vec!["valid-notifier"];
    let result = config.validate_rule_destinations(&valid_notifiers);

    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 2, "Should collect all destination errors");
}

// ============================================================
// Multi-file Config Tests (rules.d/, templates.d/, notifiers.d/)
// ============================================================

#[test]
fn load_with_rules_d_merges_rules() {
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Should have 1 inline + 2 from rules.d/ = 3 rules
    assert_eq!(config.rules.len(), 3);

    let rule_names: Vec<&str> = config.rules.iter().map(|r| r.name.as_str()).collect();
    assert!(rule_names.contains(&"inline_rule"));
    assert!(rule_names.contains(&"extra_rule_from_dir"));
    assert!(rule_names.contains(&"another_dir_rule"));
}

#[test]
fn load_with_templates_d_merges_templates() {
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Should have 2 inline + 1 from templates.d/ = 3 templates
    assert_eq!(config.templates.len(), 3);

    assert!(config.templates.contains_key("default_alert"));
    assert!(config.templates.contains_key("inline_template"));
    assert!(config.templates.contains_key("template_from_dir"));

    // Verify the dir template content
    let dir_template = config.templates.get("template_from_dir").unwrap();
    assert_eq!(dir_template.accent_color, Some("#00ff00".to_string()));
}

#[test]
fn load_with_notifiers_d_merges_notifiers() {
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Should have 1 inline + 2 from notifiers.d/ = 3 notifiers
    let notifiers = config.notifiers.expect("notifiers should be Some");
    assert_eq!(notifiers.len(), 3);

    assert!(notifiers.contains_key("inline-mattermost"));
    assert!(notifiers.contains_key("dir-mattermost"));
    assert!(notifiers.contains_key("dir-webhook"));
}

#[test]
fn load_with_all_directories_merges_all() {
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Verify all merges happened
    assert_eq!(config.rules.len(), 3);
    assert_eq!(config.templates.len(), 3);
    assert_eq!(config.notifiers.as_ref().unwrap().len(), 3);

    // Verify validation still passes
    assert!(config.validate().is_ok());
}

#[test]
fn load_without_directories_works() {
    // config_valid.yaml has no .d/ directories - should work as before
    let config = Config::load(&fixture_path("config_valid.yaml")).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn load_with_empty_directories_works() {
    let config = Config::load(&fixture_path("multi-file-empty/config.yaml")).unwrap();

    // Only the inline rule should exist
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "only_inline_rule");
}

#[test]
fn load_with_empty_file_in_directory_works() {
    // multi-file-empty has an empty.yaml file in rules.d/ - should be skipped
    let config = Config::load(&fixture_path("multi-file-empty/config.yaml")).unwrap();
    assert_eq!(config.rules.len(), 1);
}

#[test]
fn load_with_collision_fails_with_sources() {
    let result = Config::load(&fixture_path("multi-file-collision/config.yaml"));
    assert!(result.is_err());

    match result.unwrap_err() {
        crate::error::ConfigError::DuplicateName {
            resource_type,
            name,
            source1,
            source2,
        } => {
            assert_eq!(resource_type, "rule");
            assert_eq!(name, "collision_rule");
            assert!(source1.contains("config.yaml"));
            assert!(source2.contains("conflict.yaml"));
        }
        e => panic!("Expected DuplicateName error, got {:?}", e),
    }
}

#[test]
fn load_with_cross_file_reference_validates() {
    let config = Config::load(&fixture_path("multi-file-cross-ref/config.yaml")).unwrap();

    // Verify cross-references are correct
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.templates.len(), 3);

    // Rule from .d/ references template from config.yaml
    let dir_rule = config
        .rules
        .iter()
        .find(|r| r.name == "dir_rule_uses_inline_template")
        .unwrap();
    assert_eq!(dir_rule.notify.template, "inline_template".to_string());

    // Rule from config.yaml references template from .d/
    let inline_rule = config
        .rules
        .iter()
        .find(|r| r.name == "inline_rule_uses_dir_template")
        .unwrap();
    assert_eq!(inline_rule.notify.template, "template_from_dir".to_string());

    // Validation should pass (cross-file references are valid)
    assert!(config.validate().is_ok());
}

#[test]
fn load_with_invalid_yaml_in_directory_fails_with_filename() {
    let result = Config::load(&fixture_path("multi-file-invalid/config.yaml"));
    assert!(result.is_err());

    match result.unwrap_err() {
        crate::error::ConfigError::ValidationError(msg) => {
            assert!(msg.contains("rules.d"));
            assert!(msg.contains("bad.yaml"));
        }
        e => panic!("Expected ValidationError, got {:?}", e),
    }
}

#[test]
fn load_ignores_hidden_files_in_directory() {
    // multi-file/rules.d/.hidden.yaml exists but should be ignored
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Should still have only 3 rules (1 inline + 2 from extra.yaml)
    // The hidden_rule_should_not_load from .hidden.yaml should not be present
    assert_eq!(config.rules.len(), 3);

    let rule_names: Vec<&str> = config.rules.iter().map(|r| r.name.as_str()).collect();
    assert!(!rule_names.contains(&"hidden_rule_should_not_load"));
}

#[test]
fn load_with_intra_directory_collision_fails() {
    // Two files in rules.d/ define the same rule name
    let result = Config::load(&fixture_path("multi-file-intra-collision/config.yaml"));
    assert!(result.is_err());

    match result.unwrap_err() {
        crate::error::ConfigError::DuplicateName {
            resource_type,
            name,
            source1,
            source2,
        } => {
            assert_eq!(resource_type, "rules");
            assert_eq!(name, "collision_rule");
            // Due to sorting, a.yaml comes before b.yaml
            assert!(source1.contains("a.yaml"));
            assert!(source2.contains("b.yaml"));
        }
        e => panic!("Expected DuplicateName error, got {:?}", e),
    }
}

#[test]
fn load_with_only_d_directories_no_inline_keys() {
    // Config without templates, rules, notifiers keys - all loaded from .d/
    let config = Config::load(&fixture_path("multi-file-only-d/config.yaml")).unwrap();

    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "only_dir_rule");

    assert_eq!(config.templates.len(), 1);
    assert!(config.templates.contains_key("dir_template"));

    let notifiers = config.notifiers.as_ref().expect("notifiers should be Some");
    assert_eq!(notifiers.len(), 1);
    assert!(notifiers.contains_key("dir-notifier"));

    // Validation should pass
    assert!(config.validate().is_ok());
}

#[test]
fn load_ignores_non_yaml_files_in_directory() {
    // multi-file/rules.d/ has .txt and .json files that should be ignored
    let config = Config::load(&fixture_path("multi-file/config.yaml")).unwrap();

    // Should still have only 3 rules (1 inline + 2 from extra.yaml)
    // Files ignored.txt and ignored.json should not be processed
    assert_eq!(config.rules.len(), 3);

    let rule_names: Vec<&str> = config.rules.iter().map(|r| r.name.as_str()).collect();
    assert!(!rule_names.contains(&"rule_from_txt"));
    assert!(!rule_names.contains(&"rule_from_json"));
}

#[test]
fn load_with_template_collision_fails() {
    let result = Config::load(&fixture_path("multi-file-template-collision/config.yaml"));
    assert!(result.is_err());

    match result.unwrap_err() {
        crate::error::ConfigError::DuplicateName {
            resource_type,
            name,
            source1,
            source2,
        } => {
            assert_eq!(resource_type, "template");
            assert_eq!(name, "collision_template");
            assert!(source1.contains("config.yaml"));
            assert!(source2.contains("conflict.yaml"));
        }
        e => panic!("Expected DuplicateName error, got {:?}", e),
    }
}

#[test]
fn load_with_notifier_collision_fails() {
    let result = Config::load(&fixture_path("multi-file-notifier-collision/config.yaml"));
    assert!(result.is_err());

    match result.unwrap_err() {
        crate::error::ConfigError::DuplicateName {
            resource_type,
            name,
            source1,
            source2,
        } => {
            assert_eq!(resource_type, "notifier");
            assert_eq!(name, "collision_notifier");
            assert!(source1.contains("config.yaml"));
            assert!(source2.contains("conflict.yaml"));
        }
        e => panic!("Expected DuplicateName error, got {:?}", e),
    }
}

#[test]
fn defaults_notify_is_rejected() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
  notify:
    template: "default"
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("notify"),
        "Error should mention 'notify': {}",
        err
    );
}

// ============================================================
// Strict Config Validation - Unknown Fields Rejected
// ============================================================

#[test]
fn unknown_field_rejected_in_config_root() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
unknown_root_field: "should fail"
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field at root level should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_root_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_victorialogs_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
    unknown_vl_field: "should fail"
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in victorialogs should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_vl_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_metrics_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
metrics:
  enabled: true
  port: 9090
  unknown_metrics_field: "should fail"
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in metrics should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_metrics_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_throttle_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
    unknown_throttle_field: "should fail"
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in throttle should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_throttle_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_template_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
    unknown_template_field: "should fail"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in template should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_template_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_rule_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    unknown_rule_field: "should fail"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Unknown field in rule should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_rule_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_parser_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      unknown_parser_field: "should fail"
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in parser should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_parser_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_json_parser_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
        unknown_json_field: "should fail"
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in json parser should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_json_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_mattermost_notifier() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
    unknown_mm_field: "should fail"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in mattermost notifier should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_mm_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_webhook_notifier() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: webhook
    url: "https://example.com/webhook"
    method: "POST"
    unknown_webhook_field: "should fail"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in webhook notifier should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_webhook_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_email_notifier() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: email
    smtp:
      host: "smtp.example.com"
      port: 587
    from: "test@example.com"
    to: ["recipient@example.com"]
    subject_template: "Alert"
    unknown_email_field: "should fail"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in email notifier should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_email_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

#[test]
fn unknown_field_rejected_in_smtp_config() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: email
    smtp:
      host: "smtp.example.com"
      port: 587
      unknown_smtp_field: "should fail"
    from: "test@example.com"
    to: ["recipient@example.com"]
    subject_template: "Alert"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let result: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Unknown field in smtp config should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown_smtp_field"),
        "Error should mention the unknown field: {}",
        err
    );
}

// ============================================================
// Strict Config Validation - Invalid URLs Rejected
// ============================================================

#[test]
fn invalid_url_rejected_in_victorialogs() {
    let yaml = r#"
victorialogs:
  default:
    url: "not-a-valid-url"
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(
        result.is_err(),
        "Invalid URL in victorialogs should be rejected"
    );
}

#[test]
fn invalid_url_rejected_in_webhook_notifier() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  test:
    type: webhook
    url: "not-a-valid-url"
    method: "POST"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["test"]
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(
        result.is_err(),
        "Invalid URL in webhook notifier should be rejected"
    );
}

#[test]
fn telegram_notifier_with_empty_chat_ids_fails_validation() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  telegram-broken:
    type: telegram
    bot_token: "token"
    chat_ids: []
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["telegram-broken"]
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let errors = config.validate().unwrap_err();
    let has_chat_ids_error = errors.iter().any(|e| {
        matches!(e, crate::error::ConfigError::ValidationError(msg)
            if msg.contains("telegram-broken") && msg.contains("chat_ids must not be empty"))
    });
    assert!(
        has_chat_ids_error,
        "Expected chat_ids validation error, got: {:?}",
        errors
    );
}

#[test]
fn telegram_notifier_with_populated_chat_ids_passes_validation() {
    let yaml = r#"
victorialogs:
  default:
    url: http://localhost:9428
notifiers:
  telegram-ok:
    type: telegram
    bot_token: "token"
    chat_ids:
      - "-100123"
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  default:
    title: "Test"
    body: "Test body"
rules:
  - name: test_rule
    query: "test"
    parser:
      json:
        fields: ["host"]
    notify:
      template: "default"
      destinations: ["telegram-ok"]
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(
        config.validate().is_ok(),
        "Telegram notifier with non-empty chat_ids should validate"
    );
}

// ============================================================
// v2.0.0: multi-source config schema tests
// ============================================================

/// Shared YAML tail reused by the multi-source validation suite. Isolates
/// source-shape changes from notifier / template / rule noise.
const MULTI_SOURCE_TAIL: &str = r#"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: r
    query: "*"
    parser: { json: { fields: [x] } }
    notify: { template: default, destinations: [mm] }
"#;

#[test]
fn schema_parses_map_with_single_source() {
    let yaml = format!(
        r#"
victorialogs:
  default:
    url: "http://localhost:9428"
{}"#,
        MULTI_SOURCE_TAIL
    );
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.victorialogs.len(), 1);
    assert!(config.victorialogs.contains_key("default"));
    assert!(config.validate().is_ok());
}

#[test]
fn schema_parses_map_with_multiple_sources() {
    let yaml = format!(
        r#"
victorialogs:
  vlprod:
    url: "https://vl.prod.example.com:9428"
  vldev:
    url: "http://vl.dev.internal:9428"
{}"#,
        MULTI_SOURCE_TAIL
    );
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.victorialogs.len(), 2);
    assert!(config.victorialogs.contains_key("vlprod"));
    assert!(config.victorialogs.contains_key("vldev"));
}

#[test]
fn schema_parses_rule_vl_sources_field() {
    let yaml = r#"
victorialogs:
  vlprod:
    url: "http://vlprod:9428"
  vldev:
    url: "http://vldev:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: prod_only
    query: "*"
    parser: { json: { fields: [x] } }
    vl_sources: [vlprod]
    notify: { template: default, destinations: [mm] }
  - name: fan_out
    query: "*"
    parser: { json: { fields: [x] } }
    notify: { template: default, destinations: [mm] }
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].vl_sources, vec!["vlprod".to_string()]);
    assert!(config.rules[1].vl_sources.is_empty()); // default = fan-out
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_zero_sources() {
    let yaml = format!(
        r#"
victorialogs: {{}}
{}"#,
        MULTI_SOURCE_TAIL
    );
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    let errors = config.validate().expect_err("zero sources must reject");
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("at least one source required")),
        "expected 'at least one source required' error, got: {:?}",
        errors
    );
}

#[test]
fn validate_rejects_unknown_vl_sources_ref() {
    let yaml = r#"
victorialogs:
  vlprod:
    url: "http://vlprod:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: bad_ref
    query: "*"
    parser: { json: { fields: [x] } }
    vl_sources: [vlprod, missing_source]
    notify: { template: default, destinations: [mm] }
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let errors = config
        .validate()
        .expect_err("unknown source ref must reject");
    let msg = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        msg.contains("unknown source 'missing_source'"),
        "msg: {}",
        msg
    );
    assert!(
        msg.contains("vlprod"),
        "error must list known sources; msg: {}",
        msg
    );
}

#[test]
fn validate_rejects_invalid_source_name() {
    // Source name with `-` would create ambiguity in the default throttle key
    // `{rule}-{source}:global`. Restricted to `^[a-zA-Z0-9_]+$`.
    let yaml = r#"
victorialogs:
  prod-eu:
    url: "http://vl:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: r
    query: "*"
    parser: { json: { fields: [x] } }
    notify: { template: default, destinations: [mm] }
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let errors = config
        .validate()
        .expect_err("source name with `-` must reject");
    let msg = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        msg.contains("source name 'prod-eu' is invalid"),
        "msg: {}",
        msg
    );
    assert!(
        msg.contains("[a-zA-Z0-9_]"),
        "msg must hint at allowed chars: {}",
        msg
    );
}

#[test]
fn validate_rejects_duplicate_vl_sources_entry() {
    let yaml = r#"
victorialogs:
  vlprod:
    url: "http://vl:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: dupe
    query: "*"
    parser: { json: { fields: [x] } }
    vl_sources: [vlprod, vlprod]
    notify: { template: default, destinations: [mm] }
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let errors = config
        .validate()
        .expect_err("duplicate vl_sources must reject");
    let msg = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        msg.contains("duplicate entry 'vlprod'"),
        "expected duplicate entry mention, got: {}",
        msg
    );
}

#[test]
fn load_rejects_legacy_single_url_shape_with_migration_message() {
    let legacy_yaml = r#"
victorialogs:
  url: "http://victorialogs:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: { count: 5, window: 60s }
templates:
  default:
    title: "t"
    body: "b"
rules:
  - name: r
    query: "*"
    parser: { json: { fields: [x] } }
    notify: { template: default, destinations: [mm] }
"#;
    let err = serde_yaml::from_str::<Config>(legacy_yaml)
        .expect_err("legacy single-URL shape must fail to parse");
    let err_str = err.to_string();
    assert!(
        err_str.contains("map of named sources"),
        "expected migration hint mentioning 'map of named sources', got: {}",
        err_str
    );
    assert!(
        err_str.contains("victorialogs:"),
        "expected migration YAML snippet in error, got: {}",
        err_str
    );
}

// ============================================================
// v2.0.0 part 2: defaults.max_streams cap (multi-source guardrail).
//
// Total fan-out is `sum_over_enabled_rules(if vl_sources.is_empty() then
// sources.len() else vl_sources.len())`. Disabled rules do not contribute.
// Breach is rejected at load with both numbers in the error.
// ============================================================

/// YAML helper: build a config with `n_sources` declared sources, `n_rules`
/// enabled rules each with empty `vl_sources` (full fan-out), and an explicit
/// `defaults.max_streams: cap`.
fn config_with_fan_out(n_sources: usize, n_rules: usize, cap: usize) -> String {
    let mut yaml = String::from("victorialogs:\n");
    for i in 0..n_sources {
        yaml.push_str(&format!("  src{}:\n    url: http://h{}:9428\n", i, i));
    }
    yaml.push_str(&format!(
        "defaults:\n  max_streams: {}\n  throttle:\n    count: 5\n    window: 1m\n",
        cap
    ));
    yaml.push_str("templates:\n  t:\n    title: x\n    body: y\n");
    yaml.push_str(
        "notifiers:\n  n:\n    type: mattermost\n    webhook_url: https://example.com/hooks/x\n",
    );
    yaml.push_str("rules:\n");
    for i in 0..n_rules {
        yaml.push_str(&format!(
            "  - name: r{}\n    query: 't'\n    parser:\n      json:\n        fields: [_msg]\n    notify:\n      template: t\n      destinations: [n]\n",
            i
        ));
    }
    yaml
}

#[test]
fn validate_max_streams_under_cap_passes() {
    // 3 sources × 4 fan-out rules = 12 streams ≤ 50.
    let yaml = config_with_fan_out(3, 4, 50);
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    config
        .validate()
        .expect("12 streams under cap of 50 should validate");
}

#[test]
fn validate_max_streams_at_exact_cap_passes() {
    // 5 × 10 = 50, exactly the cap — boundary case allowed.
    let yaml = config_with_fan_out(5, 10, 50);
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    config
        .validate()
        .expect("50 streams at cap of 50 should validate");
}

#[test]
fn validate_max_streams_breach_fails_with_actual_and_cap() {
    // 5 sources × 12 fan-out rules = 60 > 50.
    let yaml = config_with_fan_out(5, 12, 50);
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    let errors = config.validate().expect_err("60 streams > cap should fail");
    let has_max_streams_error = errors.iter().any(|e| match e {
        crate::error::ConfigError::ValidationError(msg) => {
            msg.contains("max_streams") && msg.contains("60") && msg.contains("50")
        }
        _ => false,
    });
    assert!(
        has_max_streams_error,
        "expected max_streams error mentioning actual=60 and cap=50, got: {:?}",
        errors
    );
}

#[test]
fn validate_max_streams_default_value_is_fifty() {
    // Omit `defaults.max_streams` entirely → DEFAULT_MAX_STREAMS (50). 51
    // streams must fail; the default is what the cap reads as.
    let mut yaml = String::from("victorialogs:\n");
    for i in 0..51 {
        yaml.push_str(&format!("  src{}:\n    url: http://h{}:9428\n", i, i));
    }
    yaml.push_str("defaults:\n  throttle:\n    count: 5\n    window: 1m\n");
    yaml.push_str("templates:\n  t:\n    title: x\n    body: y\n");
    yaml.push_str(
        "notifiers:\n  n:\n    type: mattermost\n    webhook_url: https://example.com/hooks/x\n",
    );
    yaml.push_str("rules:\n  - name: r0\n    query: 't'\n    parser:\n      json:\n        fields: [_msg]\n    notify:\n      template: t\n      destinations: [n]\n");
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    let errors = config
        .validate()
        .expect_err("51 streams under default cap of 50 should fail");
    assert!(
        errors.iter().any(|e| matches!(
            e,
            crate::error::ConfigError::ValidationError(m) if m.contains("max_streams")
        )),
        "expected max_streams error, got: {:?}",
        errors
    );
}

#[test]
fn validate_max_streams_disabled_rules_do_not_contribute() {
    // 5 sources × (1 enabled fan-out rule + 100 disabled fan-out rules) =
    // 5 enabled streams. Even though raw `vl_sources.len()` would sum to
    // hundreds if we counted disabled rules, the cap is on enabled only.
    let mut yaml = String::from("victorialogs:\n");
    for i in 0..5 {
        yaml.push_str(&format!("  src{}:\n    url: http://h{}:9428\n", i, i));
    }
    yaml.push_str("defaults:\n  max_streams: 5\n  throttle:\n    count: 5\n    window: 1m\n");
    yaml.push_str("templates:\n  t:\n    title: x\n    body: y\n");
    yaml.push_str(
        "notifiers:\n  n:\n    type: mattermost\n    webhook_url: https://example.com/hooks/x\n",
    );
    yaml.push_str("rules:\n");
    yaml.push_str("  - name: enabled_rule\n    query: 't'\n    parser:\n      json:\n        fields: [_msg]\n    notify:\n      template: t\n      destinations: [n]\n");
    for i in 0..100 {
        yaml.push_str(&format!(
            "  - name: disabled{}\n    enabled: false\n    query: 't'\n    parser:\n      json:\n        fields: [_msg]\n    notify:\n      template: t\n      destinations: [n]\n",
            i
        ));
    }
    let config: Config = serde_yaml::from_str(&yaml).unwrap();
    config
        .validate()
        .expect("disabled rules should not contribute to fan-out total");
}

#[test]
fn validate_max_streams_pinned_rule_counts_only_listed_sources() {
    // 5 sources, 2 pinned rules each `vl_sources: [src0]`, 3 fan-out rules.
    // total = 2*1 + 3*5 = 17, well under default cap.
    let yaml = r#"
victorialogs:
  src0: { url: http://h0:9428 }
  src1: { url: http://h1:9428 }
  src2: { url: http://h2:9428 }
  src3: { url: http://h3:9428 }
  src4: { url: http://h4:9428 }
defaults:
  throttle:
    count: 5
    window: 1m
templates:
  t: { title: x, body: y }
notifiers:
  n: { type: mattermost, webhook_url: https://example.com/hooks/x }
rules:
  - name: pinned1
    query: 't'
    parser: { json: { fields: [_msg] } }
    vl_sources: [src0]
    notify: { template: t, destinations: [n] }
  - name: pinned2
    query: 't'
    parser: { json: { fields: [_msg] } }
    vl_sources: [src0]
    notify: { template: t, destinations: [n] }
  - name: fan1
    query: 't'
    parser: { json: { fields: [_msg] } }
    notify: { template: t, destinations: [n] }
  - name: fan2
    query: 't'
    parser: { json: { fields: [_msg] } }
    notify: { template: t, destinations: [n] }
  - name: fan3
    query: 't'
    parser: { json: { fields: [_msg] } }
    notify: { template: t, destinations: [n] }
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    config
        .validate()
        .expect("17 streams under default cap of 50 should validate");
}

fn v203_yaml(rules: &str) -> String {
    format!(
        r#"
victorialogs:
  vlprod:
    url: "http://vl:9428"
notifiers:
  mm:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/test"
defaults:
  throttle: {{ count: 5, window: 60s }}
templates:
  default:
    title: "t"
    body: "b"
rules:
{rules}
"#
    )
}

fn v203_errors(yaml: &str) -> String {
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    match config.validate() {
        Ok(()) => String::new(),
        Err(errors) => errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

#[test]
fn validate_rejects_duplicate_inline_rule_names() {
    let yaml = v203_yaml(
        r#"
  - name: dupe
    query: "*"
    parser: { regex: "(?P<m>.*)" }
    notify: { template: default, destinations: [mm] }
  - name: dupe
    query: "error"
    parser: { regex: "(?P<m>.*)" }
    notify: { template: default, destinations: [mm] }
"#,
    );
    let msg = v203_errors(&yaml);
    assert!(msg.contains("duplicate rule name 'dupe'"), "{msg}");
}

#[test]
fn validate_rejects_zero_throttle_count_and_window() {
    let yaml = v203_yaml(
        r#"
  - name: r
    query: "*"
    parser: { regex: "(?P<m>.*)" }
    throttle: { count: 0, window: 0s }
    notify: { template: default, destinations: [mm] }
"#,
    );
    let msg = v203_errors(&yaml);
    assert!(msg.contains("throttle.count must be >= 1"), "{msg}");
    assert!(msg.contains("throttle.window must be > 0"), "{msg}");
}

#[test]
fn validate_accepts_env_placeholder_webhook_url() {
    let yaml = v203_yaml(
        r#"
  - name: r
    query: "*"
    parser: { regex: "(?P<m>.*)" }
    notify: { template: default, destinations: [mm] }
"#,
    )
    .replace(
        r#"webhook_url: "https://mattermost.example.com/hooks/test""#,
        r#"webhook_url: "${MATTERMOST_WEBHOOK}""#,
    );
    assert_eq!(v203_errors(&yaml), "");
}

#[test]
fn load_resolves_env_vars_in_victorialogs_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        v203_yaml(
            r#"
  - name: r
    query: "*"
    parser: { regex: "(?P<m>.*)" }
    notify: { template: default, destinations: [mm] }
"#,
        )
        .replace(
            r#"url: "http://vl:9428""#,
            r#"url: "${V203_VL_URL}"
    basic_auth: { username: "${V203_VL_USER}", password: "${V203_VL_PASS}" }
    headers: { Authorization: "Bearer ${V203_VL_TOKEN}" }"#,
        ),
    )
    .unwrap();
    // SAFETY: test-local variables with unique names; tests in this module do not read them concurrently.
    unsafe {
        std::env::set_var("V203_VL_URL", "http://resolved:9428");
        std::env::set_var("V203_VL_USER", "alice");
        std::env::set_var("V203_VL_PASS", "s3cret");
        std::env::set_var("V203_VL_TOKEN", "tok");
    }
    let config = Config::load(&path).expect("load");
    let src = &config.victorialogs["vlprod"];
    assert_eq!(src.url, "http://resolved:9428");
    let auth = src.basic_auth.as_ref().unwrap();
    assert_eq!(auth.username, "alice");
    assert_eq!(auth.password.expose(), "s3cret");
    assert_eq!(
        src.headers.as_ref().unwrap()["Authorization"].expose(),
        "Bearer tok"
    );
}

#[test]
fn load_fails_on_undefined_env_var_in_victorialogs_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        v203_yaml(
            r#"
  - name: r
    query: "*"
    parser: { regex: "(?P<m>.*)" }
    notify: { template: default, destinations: [mm] }
"#,
        )
        .replace(
            r#"url: "http://vl:9428""#,
            r#"url: "${V203_DEFINITELY_UNSET}""#,
        ),
    )
    .unwrap();
    let err = Config::load(&path).expect_err("must fail").to_string();
    assert!(
        err.contains("vlprod") && err.contains("V203_DEFINITELY_UNSET"),
        "{err}"
    );
}
