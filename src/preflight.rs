//! Startup checks shared by the daemon and `--validate`.
//!
//! After the configuration is loaded, validated and compiled, the daemon must
//! still build every notifier, check that every rule destination exists and
//! that templates sent to email destinations define `email_body_html`. These
//! checks live here so that `valerter --validate` runs exactly the same code
//! as the daemon startup and the two paths cannot drift apart.
//!
//! None of these checks performs a network call.

use std::time::Duration;

use thiserror::Error;
use tracing::{error, info, warn};

use crate::config::{NotifiersConfig, RuntimeConfig};
use crate::error::ConfigError;
use crate::notify::NotifierRegistry;

/// Timeout applied to every request made by the shared HTTP client.
const HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of a successful preflight.
#[derive(Debug)]
pub struct PreflightReport {
    /// Registry holding every configured notifier.
    pub registry: NotifierRegistry,
}

/// First failed preflight stage, in the order notifiers → destinations →
/// email templates. Every error of every stage has already been logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PreflightError {
    #[error("Failed to create notifiers: {0} errors")]
    Notifiers(usize),
    #[error("Destination validation failed: {0} errors")]
    Destinations(usize),
    #[error("Email template validation failed: {0} errors")]
    EmailTemplates(usize),
}

/// Build the HTTP client shared by notifiers and VictoriaLogs tail tasks (AD-03).
pub fn build_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
}

/// Run every blocking startup check that depends on notifiers.
///
/// All stages are evaluated even when an earlier one fails, so that a single
/// run reports every error. Destinations and email templates are checked
/// against the notifiers *declared* in the configuration, so a notifier that
/// failed to build is not reported as an unknown destination.
pub fn run_preflight(
    config: &RuntimeConfig,
    http_client: reqwest::Client,
) -> Result<PreflightReport, PreflightError> {
    let no_notifiers = NotifiersConfig::new();
    // Config::validate() already rejects a configuration without notifiers.
    let declared = config.notifiers.as_ref().unwrap_or(&no_notifiers);
    let checks = PreflightChecks::run(config, declared, http_client);

    match &checks.registry {
        Ok(registry) => info!(
            notifier_count = registry.len(),
            "Created notifiers from config"
        ),
        Err(errors) => {
            for e in errors {
                error!(error = %e, "Notifier configuration error");
            }
        }
    }

    match &checks.destinations {
        Ok(()) => info!("All rule destinations validated successfully"),
        Err(errors) => {
            for e in errors {
                error!(error = %e, "Destination validation error");
            }
        }
    }

    match &checks.email_templates {
        Ok(()) => info!("All email templates validated successfully"),
        Err(errors) => {
            for e in errors {
                error!(error = %e, "Email template validation error");
            }
        }
    }

    let registry = match checks.registry {
        Ok(registry) => registry,
        Err(errors) => return Err(PreflightError::Notifiers(errors.len())),
    };
    if let Err(errors) = checks.destinations {
        return Err(PreflightError::Destinations(errors.len()));
    }
    if let Err(errors) = checks.email_templates {
        return Err(PreflightError::EmailTemplates(errors.len()));
    }

    // Warn if mattermost_channel is set but no Mattermost notifier in destinations
    warn_unused_mattermost_channels(config, declared);

    Ok(PreflightReport { registry })
}

/// Results of every preflight stage, before logging.
struct PreflightChecks {
    registry: Result<NotifierRegistry, Vec<ConfigError>>,
    destinations: Result<(), Vec<ConfigError>>,
    email_templates: Result<(), Vec<String>>,
}

impl PreflightChecks {
    fn run(
        config: &RuntimeConfig,
        declared: &NotifiersConfig,
        http_client: reqwest::Client,
    ) -> Self {
        // Create notifier registry (Story 6.2: named notifiers)
        let registry = NotifierRegistry::from_config(declared, http_client, &config.config_dir);

        // Validate rule destinations against declared notifiers (Story 6.3: fail-fast at startup)
        let declared_names: Vec<&str> = declared.keys().map(String::as_str).collect();
        let destinations = config.validate_rule_destinations(&declared_names);

        // Validate that templates used with email destinations have email_body_html (fail-fast)
        let email_templates = validate_email_templates(config, declared);

        Self {
            registry,
            destinations,
            email_templates,
        }
    }
}

/// Whether `name` is a declared notifier of type `type_name`.
fn is_notifier_type(notifiers: &NotifiersConfig, name: &str, type_name: &str) -> bool {
    notifiers
        .get(name)
        .is_some_and(|n| n.type_name() == type_name)
}

/// Validate that templates used with email destinations have email_body_html.
///
/// For each enabled rule, if any of its destinations is an email notifier,
/// the template must have email_body_html defined. This is a fail-fast validation
/// to prevent runtime errors.
fn validate_email_templates(
    config: &RuntimeConfig,
    notifiers: &NotifiersConfig,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    for rule in &config.rules {
        if !rule.enabled {
            continue;
        }

        let email_dests: Vec<&str> = rule
            .notify
            .destinations
            .iter()
            .map(String::as_str)
            .filter(|dest| is_notifier_type(notifiers, dest, "email"))
            .collect();

        if email_dests.is_empty() {
            continue;
        }

        // Get the template name for this rule
        let template_name = &rule.notify.template;

        // Check if template has email_body_html
        if let Some(template) = config.templates.get(template_name)
            && template.email_body_html.is_none()
        {
            errors.push(format!(
                "template '{}' requires email_body_html field when used with email destination{} {} (rule '{}')",
                template_name,
                if email_dests.len() > 1 { "s" } else { "" },
                email_dests
                    .iter()
                    .map(|s| format!("'{}'", s))
                    .collect::<Vec<_>>()
                    .join(", "),
                rule.name
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Warn if mattermost_channel is set but no Mattermost notifier is in destinations.
fn warn_unused_mattermost_channels(config: &RuntimeConfig, notifiers: &NotifiersConfig) {
    for rule in &config.rules {
        if !rule.enabled || rule.notify.mattermost_channel.is_none() {
            continue;
        }

        let has_mattermost = rule
            .notify
            .destinations
            .iter()
            .any(|dest| is_notifier_type(notifiers, dest, "mattermost"));

        if !has_mattermost {
            warn!(
                rule_name = %rule.name,
                "mattermost_channel ignored - no mattermost notifier in destinations"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    /// Env var guaranteed to be undefined in the test environment.
    const UNSET_VAR: &str = "VALERTER_PREFLIGHT_TEST_UNSET_VAR";

    const BASE: &str = r#"
victorialogs:
  default:
    url: "http://vl.invalid:9428"
defaults:
  throttle:
    count: 5
    window: 60s
templates:
  plain:
    title: "{{ title }}"
    body: "{{ body }}"
  html:
    title: "{{ title }}"
    body: "{{ body }}"
    email_body_html: "<p>{{ body }}</p>"
"#;

    const EMAIL_OK: &str = r#"
  email-ops:
    type: email
    smtp:
      host: smtp.invalid
      port: 587
    from: "alerts@example.com"
    to: ["ops@example.com"]
    subject_template: "{{ title }}"
"#;

    const MATTERMOST_OK: &str = r#"
  mm-ops:
    type: mattermost
    webhook_url: "https://mattermost.invalid/hooks/x"
"#;

    fn rule(name: &str, enabled: bool, template: &str, destinations: &[&str]) -> String {
        format!(
            r#"
  - name: "{name}"
    enabled: {enabled}
    query: "_stream:{{app=\"x\"}}"
    parser:
      json:
        fields: ["message"]
    notify:
      template: "{template}"
      destinations: [{dests}]
"#,
            dests = destinations
                .iter()
                .map(|d| format!("\"{}\"", d))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn runtime_config(notifiers: &[&str], rules: &[String]) -> RuntimeConfig {
        let yaml = format!(
            "{BASE}notifiers:{}\nrules:{}",
            notifiers.concat(),
            rules.concat()
        );
        let config: Config = serde_yaml::from_str(&yaml).expect("test config parses");
        config
            .validate()
            .expect("test config passes Config::validate()");
        config
            .compile(Path::new("/nonexistent-valerter-dir/config.yaml"))
            .expect("test config compiles")
    }

    fn checks(config: &RuntimeConfig) -> PreflightChecks {
        let declared = config
            .notifiers
            .as_ref()
            .expect("test config has notifiers");
        PreflightChecks::run(config, declared, build_http_client().unwrap())
    }

    #[test]
    fn valid_config_builds_registry_with_every_notifier() {
        let config = runtime_config(
            &[EMAIL_OK, MATTERMOST_OK],
            &[rule("r", true, "html", &["email-ops", "mm-ops"])],
        );

        let report =
            run_preflight(&config, build_http_client().unwrap()).expect("preflight should succeed");

        let mut names: Vec<&str> = report.registry.names().collect();
        names.sort_unstable();
        assert_eq!(names, ["email-ops", "mm-ops"]);
    }

    #[test]
    fn unknown_destination_fails_destinations_stage() {
        let config = runtime_config(&[MATTERMOST_OK], &[rule("r", true, "plain", &["nope"])]);

        let err = run_preflight(&config, build_http_client().unwrap()).err();
        assert_eq!(err, Some(PreflightError::Destinations(1)));
        assert_eq!(
            err.unwrap().to_string(),
            "Destination validation failed: 1 errors"
        );

        let errors = checks(&config).destinations.unwrap_err();
        assert_eq!(
            errors[0].to_string(),
            "invalid configuration: rule 'r': unknown notifier 'nope'"
        );
    }

    #[test]
    fn email_template_without_html_fails_email_stage() {
        let config = runtime_config(&[EMAIL_OK], &[rule("r", true, "plain", &["email-ops"])]);

        let err = run_preflight(&config, build_http_client().unwrap()).err();
        assert_eq!(err, Some(PreflightError::EmailTemplates(1)));
        assert_eq!(
            err.unwrap().to_string(),
            "Email template validation failed: 1 errors"
        );

        let errors = checks(&config).email_templates.unwrap_err();
        assert_eq!(
            errors,
            [
                "template 'plain' requires email_body_html field when used with email destination 'email-ops' (rule 'r')"
            ]
        );
    }

    #[test]
    fn disabled_rule_is_ignored_for_email_templates() {
        let config = runtime_config(
            &[EMAIL_OK],
            &[
                rule("off", false, "plain", &["email-ops"]),
                rule("on", true, "html", &["email-ops"]),
            ],
        );

        assert!(run_preflight(&config, build_http_client().unwrap()).is_ok());
    }

    #[test]
    fn failed_notifier_still_checks_email_templates_without_unknown_destination() {
        let failing_email = format!(
            r#"
  email-ops:
    type: email
    smtp:
      host: smtp.invalid
      port: 587
      username: "user"
      password: "${{{UNSET_VAR}}}"
    from: "alerts@example.com"
    to: ["ops@example.com"]
    subject_template: "{{{{ title }}}}"
"#
        );
        let config = runtime_config(
            &[&failing_email],
            &[rule("r", true, "plain", &["email-ops"])],
        );

        let err = run_preflight(&config, build_http_client().unwrap()).err();
        assert_eq!(err, Some(PreflightError::Notifiers(1)));

        let checks = checks(&config);
        let notifier_errors = checks.registry.unwrap_err();
        assert_eq!(notifier_errors.len(), 1);
        assert!(
            notifier_errors[0].to_string().contains(UNSET_VAR),
            "unexpected notifier error: {}",
            notifier_errors[0]
        );
        assert!(
            checks.destinations.is_ok(),
            "a declared notifier that failed to build must not be an unknown destination"
        );
        let email_errors = checks.email_templates.unwrap_err();
        assert_eq!(email_errors.len(), 1);
        assert!(email_errors[0].contains("requires email_body_html"));
    }

    #[test]
    fn missing_body_template_file_fails_notifiers_stage() {
        let email = r#"
  email-ops:
    type: email
    smtp:
      host: smtp.invalid
      port: 587
    from: "alerts@example.com"
    to: ["ops@example.com"]
    subject_template: "{{ title }}"
    body_template_file: "templates/missing.html.j2"
"#;
        let config = runtime_config(&[email], &[rule("r", true, "html", &["email-ops"])]);

        let err = run_preflight(&config, build_http_client().unwrap()).err();
        assert_eq!(err, Some(PreflightError::Notifiers(1)));

        let notifier_errors = checks(&config).registry.unwrap_err();
        assert!(
            notifier_errors[0]
                .to_string()
                .contains("body_template_file not found"),
            "unexpected notifier error: {}",
            notifier_errors[0]
        );
    }

    #[test]
    fn preflight_error_messages_match_startup_messages() {
        assert_eq!(
            PreflightError::Notifiers(2).to_string(),
            "Failed to create notifiers: 2 errors"
        );
        assert_eq!(
            PreflightError::Destinations(3).to_string(),
            "Destination validation failed: 3 errors"
        );
        assert_eq!(
            PreflightError::EmailTemplates(1).to_string(),
            "Email template validation failed: 1 errors"
        );
    }
}
