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

#[test]
fn validate_no_rules_fails() {
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
            timestamp_timezone: "UTC".to_string(),
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
fn rules_use_defaults_when_not_specified() {
    let config = Config::load(&fixture_path("config_minimal.yaml")).unwrap();
    assert_eq!(config.rules.len(), 1);
    let rule = &config.rules[0];
    // Rule doesn't override throttle or notify, so it uses defaults
    assert!(rule.throttle.is_none());
    assert!(rule.notify.is_none());
    // config_minimal.yaml matches README example values
    assert_eq!(config.defaults.throttle.count, 5);
    assert_eq!(config.defaults.notify.template, "default_alert");
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
            timestamp_timezone: "UTC".to_string(),
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
            timestamp_timezone: "UTC".to_string(),
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
            timestamp_timezone: "UTC".to_string(),
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
            timestamp_timezone: "UTC".to_string(),
        },
        templates: std::collections::HashMap::new(),
        rules: vec![],
        metrics: MetricsConfig::default(),
        notifiers: None,
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
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
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
rules:
  - name: test_rule
    query: "_msg:test"
    parser:
      regex: ".*"
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
notifiers:
  test:
    type: mattermost
    webhook_url: "https://example.com/hooks/test"
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
rules:
  - name: test_rule
    query: "_msg:test"
    parser:
      regex: ".*"
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
            timestamp_timezone: "UTC".to_string(),
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
    assert_eq!(
        dir_rule.notify.as_ref().unwrap().template,
        Some("inline_template".to_string())
    );

    // Rule from config.yaml references template from .d/
    let inline_rule = config
        .rules
        .iter()
        .find(|r| r.name == "inline_rule_uses_dir_template")
        .unwrap();
    assert_eq!(
        inline_rule.notify.as_ref().unwrap().template,
        Some("template_from_dir".to_string())
    );

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
