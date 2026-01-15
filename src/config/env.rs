//! Environment variable substitution and template resolution.

use super::notifiers::EmailNotifierConfig;
use crate::error::ConfigError;
use regex::Regex;
use std::path::Path;

/// Maximum size for body_template_file (1MB).
const MAX_BODY_TEMPLATE_SIZE: u64 = 1024 * 1024;

/// Resolves `${VAR_NAME}` patterns in a string.
pub fn resolve_env_vars(value: &str) -> Result<String, ConfigError> {
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("Invalid regex");

    let mut result = value.to_string();
    let mut errors = Vec::new();

    let matches: Vec<_> = re.captures_iter(value).collect();

    for cap in matches {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = &cap[1];

        match std::env::var(var_name) {
            Ok(var_value) => {
                result = result.replace(full_match, &var_value);
            }
            Err(_) => {
                errors.push(var_name.to_string());
            }
        }
    }

    if errors.is_empty() {
        Ok(result)
    } else {
        Err(ConfigError::ValidationError(format!(
            "undefined environment variable{}: {}",
            if errors.len() > 1 { "s" } else { "" },
            errors.join(", ")
        )))
    }
}

/// Resolves the body template for an email notifier.
/// Priority: body_template_file > body_template > None (embedded default).
pub fn resolve_body_template(
    config: &EmailNotifierConfig,
    config_dir: &Path,
) -> Result<Option<String>, ConfigError> {
    if config.body_template.is_some() && config.body_template_file.is_some() {
        tracing::warn!(
            "both body_template and body_template_file defined, using body_template_file"
        );
    }

    // Priority 1: body_template_file
    if let Some(ref file_path) = config.body_template_file {
        let path = if Path::new(file_path).is_absolute() {
            std::path::PathBuf::from(file_path)
        } else {
            config_dir.join(file_path)
        };

        if !path.exists() {
            return Err(ConfigError::ValidationError(format!(
                "body_template_file not found: {}",
                path.display()
            )));
        }

        let metadata = std::fs::metadata(&path).map_err(|e| {
            ConfigError::ValidationError(format!(
                "cannot read body_template_file '{}': {}",
                path.display(),
                e
            ))
        })?;

        if metadata.len() > MAX_BODY_TEMPLATE_SIZE {
            return Err(ConfigError::ValidationError(format!(
                "body_template_file '{}' exceeds maximum size of 1MB ({} bytes)",
                path.display(),
                metadata.len()
            )));
        }

        let content = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                ConfigError::ValidationError(format!(
                    "body_template_file '{}' must be valid UTF-8",
                    path.display()
                ))
            } else {
                ConfigError::ValidationError(format!(
                    "cannot read body_template_file '{}': {}",
                    path.display(),
                    e
                ))
            }
        })?;

        tracing::debug!("body template source: file");
        return Ok(Some(content));
    }

    // Priority 2: body_template (inline)
    if let Some(ref template) = config.body_template {
        tracing::debug!("body template source: inline");
        return Ok(Some(template.clone()));
    }

    // Priority 3: None (use embedded default)
    tracing::debug!("body template source: embedded");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::notifiers::{SmtpConfig, TlsMode};
    use serial_test::serial;

    #[test]
    #[serial]
    fn resolve_env_vars_substitutes_single_variable() {
        temp_env::with_var(
            "TEST_WEBHOOK_VAR",
            Some("https://example.com/hooks/abc"),
            || {
                let result = resolve_env_vars("${TEST_WEBHOOK_VAR}");
                assert_eq!(result.unwrap(), "https://example.com/hooks/abc");
            },
        );
    }

    #[test]
    #[serial]
    fn resolve_env_vars_substitutes_multiple_variables() {
        temp_env::with_vars(
            [
                ("TEST_HOST", Some("mattermost.example.com")),
                ("TEST_TOKEN", Some("secret123")),
            ],
            || {
                let result = resolve_env_vars("https://${TEST_HOST}/hooks/${TEST_TOKEN}");
                assert_eq!(
                    result.unwrap(),
                    "https://mattermost.example.com/hooks/secret123"
                );
            },
        );
    }

    #[test]
    fn resolve_env_vars_returns_unchanged_without_pattern() {
        let input = "https://example.com/static/path";
        let result = resolve_env_vars(input);
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    #[serial]
    fn resolve_env_vars_error_on_undefined_variable() {
        temp_env::with_var("UNDEFINED_VAR_XYZ_123", None::<&str>, || {
            let result = resolve_env_vars("https://${UNDEFINED_VAR_XYZ_123}/path");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("UNDEFINED_VAR_XYZ_123"));
        });
    }

    #[test]
    fn resolve_body_template_inline() {
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
            body_template: Some("<p>Inline: {{ body }}</p>".to_string()),
            body_template_file: None,
        };

        let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = resolve_body_template(&config, &config_dir);
        assert_eq!(
            result.unwrap(),
            Some("<p>Inline: {{ body }}</p>".to_string())
        );
    }

    #[test]
    fn resolve_body_template_returns_none_for_default() {
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
            body_template: None,
            body_template_file: None,
        };

        let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = resolve_body_template(&config, &config_dir);
        assert!(result.unwrap().is_none());
    }

    #[test]
    #[serial]
    fn resolve_env_vars_error_lists_all_undefined_variables() {
        temp_env::with_vars(
            [("UNDEFINED_A", None::<&str>), ("UNDEFINED_B", None::<&str>)],
            || {
                let result = resolve_env_vars("${UNDEFINED_A} and ${UNDEFINED_B}");
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.to_string().contains("UNDEFINED_A"));
                assert!(err.to_string().contains("UNDEFINED_B"));
            },
        );
    }

    #[test]
    #[serial]
    fn resolve_env_vars_preserves_text_around_variables() {
        temp_env::with_var("TEST_MIDDLE", Some("REPLACED"), || {
            let result = resolve_env_vars("prefix_${TEST_MIDDLE}_suffix");
            assert_eq!(result.unwrap(), "prefix_REPLACED_suffix");
        });
    }

    #[test]
    #[serial]
    fn resolve_env_vars_handles_empty_env_value() {
        temp_env::with_var("TEST_EMPTY_VAR", Some(""), || {
            let result = resolve_env_vars("before${TEST_EMPTY_VAR}after");
            assert_eq!(result.unwrap(), "beforeafter");
        });
    }

    #[test]
    #[serial]
    fn resolve_env_vars_supports_lowercase_variables() {
        temp_env::with_var("test_lowercase_var", Some("lowercase_value"), || {
            let result = resolve_env_vars("${test_lowercase_var}");
            assert_eq!(result.unwrap(), "lowercase_value");
        });
    }

    #[test]
    fn resolve_body_template_file_success() {
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
            body_template: None,
            body_template_file: Some("templates/default-email.html.j2".to_string()),
        };

        let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = resolve_body_template(&config, &config_dir);

        assert!(result.is_ok());
        let template = result.unwrap();
        assert!(template.is_some());
        assert!(template.as_ref().unwrap().contains("<!DOCTYPE html>"));
    }

    #[test]
    fn resolve_body_template_file_not_found_fails() {
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
            body_template: None,
            body_template_file: Some("nonexistent/template.html".to_string()),
        };

        let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = resolve_body_template(&config, &config_dir);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
