//! Notifier configurations (Mattermost, Webhook, Email).

use serde::Deserialize;
use std::collections::HashMap;

/// Map of named notifier configurations.
pub type NotifiersConfig = HashMap<String, NotifierConfig>;

/// Notifier configuration with type tag for deserialization.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum NotifierConfig {
    #[serde(rename = "mattermost")]
    Mattermost(MattermostNotifierConfig),
    #[serde(rename = "webhook")]
    Webhook(WebhookNotifierConfig),
    #[serde(rename = "email")]
    Email(EmailNotifierConfig),
}

/// Configuration for a Mattermost notifier instance.
#[derive(Debug, Clone, Deserialize)]
pub struct MattermostNotifierConfig {
    /// Webhook URL (supports `${ENV_VAR}` substitution).
    pub webhook_url: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
}

/// Configuration for a generic webhook notifier.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookNotifierConfig {
    /// Target URL (supports `${ENV_VAR}` substitution).
    pub url: String,
    #[serde(default = "default_post")]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body_template: Option<String>,
}

/// Configuration for an email notifier.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailNotifierConfig {
    pub smtp: SmtpConfig,
    pub from: String,
    pub to: Vec<String>,
    pub subject_template: String,
    #[serde(default)]
    pub body_template: Option<String>,
    #[serde(default)]
    pub body_template_file: Option<String>,
}

/// SMTP server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: TlsMode,
    #[serde(default = "default_true")]
    pub tls_verify: bool,
}

/// TLS mode for SMTP connections.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    None,
    #[default]
    Starttls,
    Tls,
}

fn default_post() -> String {
    "POST".to_string()
}

pub(crate) fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mattermost_notifier_config_parses() {
        let yaml = r#"
            type: mattermost
            webhook_url: "https://example.com/hooks/test"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Mattermost(cfg) => {
                assert_eq!(cfg.webhook_url, "https://example.com/hooks/test");
                assert!(cfg.channel.is_none());
            }
            _ => panic!("Expected Mattermost variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_defaults() {
        let yaml = r#"
            type: webhook
            url: https://api.example.com/alerts
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.method, "POST");
                assert!(cfg.headers.is_empty());
                assert!(cfg.body_template.is_none());
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn email_notifier_config_parses() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
            from: test@example.com
            to: [dest@example.com]
            subject_template: "{{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert_eq!(cfg.smtp.host, "smtp.example.com");
                assert_eq!(cfg.smtp.tls, TlsMode::Starttls);
                assert!(cfg.smtp.tls_verify);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn tls_mode_defaults_to_starttls() {
        let tls: TlsMode = serde_yaml::from_str("~").unwrap_or_default();
        assert_eq!(tls, TlsMode::Starttls);
    }

    #[test]
    fn notifiers_config_is_hashmap() {
        let yaml = r#"
            notifier-a:
              type: mattermost
              webhook_url: "https://a.example.com"
            notifier-b:
              type: mattermost
              webhook_url: "https://b.example.com"
        "#;
        let config: NotifiersConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.len(), 2);
        assert!(config.contains_key("notifier-a"));
        assert!(config.contains_key("notifier-b"));
    }

    #[test]
    fn mattermost_notifier_config_optional_fields_default() {
        let yaml = r#"
            type: mattermost
            webhook_url: "https://example.com/hooks/test"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Mattermost(cfg) => {
                assert!(cfg.channel.is_none());
                assert!(cfg.username.is_none());
                assert!(cfg.icon_url.is_none());
            }
            _ => panic!("Expected Mattermost variant"),
        }
    }

    #[test]
    fn mattermost_notifier_config_requires_webhook_url() {
        let yaml = r#"
            type: mattermost
            channel: "test"
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn webhook_notifier_config_parses_with_all_fields() {
        let yaml = r#"
            type: webhook
            url: https://api.example.com/alerts
            method: PUT
            headers:
              Authorization: Bearer token123
              Content-Type: application/json
            body_template: |
              {"alert": "{{ title }}", "message": "{{ body }}"}
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.url, "https://api.example.com/alerts");
                assert_eq!(cfg.method, "PUT");
                assert_eq!(cfg.headers.len(), 2);
                assert!(cfg.body_template.is_some());
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_requires_url() {
        let yaml = r#"
            type: webhook
            method: POST
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn webhook_notifier_config_method_defaults_to_post() {
        let yaml = r#"
            type: webhook
            url: https://example.com/hook
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert_eq!(cfg.method, "POST");
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn webhook_notifier_config_empty_headers_is_valid() {
        let yaml = r#"
            type: webhook
            url: https://example.com/hook
            headers: {}
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Webhook(cfg) => {
                assert!(cfg.headers.is_empty());
            }
            _ => panic!("Expected Webhook variant"),
        }
    }

    #[test]
    fn email_notifier_config_parses_with_all_fields() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
              username: "${SMTP_USER}"
              password: "${SMTP_PASSWORD}"
              tls: starttls
              tls_verify: true
            from: valerter@example.com
            to:
              - ops@example.com
              - admin@example.com
            subject_template: "[{{ rule_name | upper }}] {{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert_eq!(cfg.smtp.host, "smtp.example.com");
                assert_eq!(cfg.smtp.port, 587);
                assert!(cfg.smtp.username.is_some());
                assert!(cfg.smtp.password.is_some());
                assert_eq!(cfg.to.len(), 2);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn email_notifier_config_requires_from() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
            to: [dest@example.com]
            subject_template: "{{ title }}"
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn email_notifier_config_requires_to() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
            from: test@example.com
            subject_template: "{{ title }}"
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn email_notifier_config_requires_subject_template() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
            from: test@example.com
            to: [dest@example.com]
        "#;
        let result: Result<NotifierConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn email_notifier_config_multi_recipients() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 587
            from: test@example.com
            to:
              - alice@example.com
              - bob@example.com
              - charlie@example.com
            subject_template: "{{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert_eq!(cfg.to.len(), 3);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn email_notifier_config_tls_mode_none() {
        let yaml = r#"
            type: email
            smtp:
              host: localhost
              port: 25
              tls: none
            from: test@example.com
            to: [dest@example.com]
            subject_template: "{{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert_eq!(cfg.smtp.tls, TlsMode::None);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn email_notifier_config_tls_mode_tls() {
        let yaml = r#"
            type: email
            smtp:
              host: smtp.example.com
              port: 465
              tls: tls
            from: test@example.com
            to: [dest@example.com]
            subject_template: "{{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert_eq!(cfg.smtp.tls, TlsMode::Tls);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn email_notifier_config_tls_verify_false() {
        let yaml = r#"
            type: email
            smtp:
              host: internal.smtp
              port: 587
              tls: starttls
              tls_verify: false
            from: test@example.com
            to: [dest@example.com]
            subject_template: "{{ title }}"
        "#;
        let config: NotifierConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            NotifierConfig::Email(cfg) => {
                assert!(!cfg.smtp.tls_verify);
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn notify_config_parses_with_destinations() {
        use crate::config::types::NotifyConfig;
        let yaml = r#"
            template: custom_alert
            destinations:
              - mattermost-infra
              - mattermost-ops
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.template, Some("custom_alert".to_string()));
        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert_eq!(destinations.len(), 2);
    }

    #[test]
    fn notify_config_parses_without_destinations_for_backward_compat() {
        use crate::config::types::NotifyConfig;
        let yaml = r#"
            template: default_alert
            channel: alerts
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.template, Some("default_alert".to_string()));
        assert_eq!(config.channel, Some("alerts".to_string()));
        assert!(config.destinations.is_none());
    }

    #[test]
    fn notify_config_default_is_all_none() {
        use crate::config::types::NotifyConfig;
        let yaml = "{}";
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.template.is_none());
        assert!(config.channel.is_none());
        assert!(config.destinations.is_none());
    }

    #[test]
    fn notify_config_parses_with_single_destination() {
        use crate::config::types::NotifyConfig;
        let yaml = r#"
            destinations:
              - mattermost-infra
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0], "mattermost-infra");
    }

    #[test]
    fn notify_config_parses_empty_destinations_as_empty_vec() {
        use crate::config::types::NotifyConfig;
        let yaml = r#"
            destinations: []
        "#;
        let config: NotifyConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.destinations.is_some());
        let destinations = config.destinations.unwrap();
        assert!(destinations.is_empty());
    }
}
