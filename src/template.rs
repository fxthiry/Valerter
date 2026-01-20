//! Message templating engine for Mattermost notifications.
//!
//! This module transforms extracted log fields into formatted messages
//! using Jinja2-style templates powered by minijinja.
//!
//! # Architecture
//!
//! The template engine sits between the throttle and notify stages:
//! ```text
//! parser.rs → throttle.rs → template.rs → notify.rs
//! ```
//!
//! # Example
//!
//! ```ignore
//! use valerter::template::{TemplateEngine, RenderedMessage};
//! use serde_json::json;
//!
//! let engine = TemplateEngine::new(templates);
//! let fields = json!({"host": "server-01", "severity": "critical"});
//!
//! match engine.render("alert_template", &fields) {
//!     Ok(msg) => println!("Title: {}", msg.title),
//!     Err(e) => eprintln!("Render failed: {}", e),
//! }
//! ```

use crate::config::CompiledTemplate;
use crate::error::TemplateError;
use minijinja::{Environment, UndefinedBehavior};
use serde_json::Value;
use std::collections::HashMap;

/// Rendered message ready for notification.
///
/// Contains all fields needed to construct a Mattermost attachment or email.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedMessage {
    /// Title of the message (attachment fallback and title).
    pub title: String,
    /// Body text of the message (attachment text for Mattermost).
    pub body: String,
    /// Optional HTML body for email notifications (rendered with HTML auto-escape).
    pub body_html: Option<String>,
    /// Optional accent color for visual indicators (hex format: #rrggbb).
    /// Used for email colored dot and Mattermost sidebar color.
    pub accent_color: Option<String>,
}

/// Template engine for rendering messages with Jinja2 syntax.
///
/// The engine pre-loads all templates at construction time and
/// reuses a single minijinja `Environment` for all render operations.
///
/// # Thread Safety
///
/// The engine is NOT thread-safe for rendering (Environment is not Sync).
/// Create one engine per task/thread or wrap in appropriate synchronization.
pub struct TemplateEngine {
    /// Pre-created Jinja environment (created once, reused for performance).
    env: Environment<'static>,
    /// Pre-created Jinja environment with HTML auto-escape (for body_html rendering).
    html_env: Environment<'static>,
    /// Compiled templates indexed by name.
    templates: HashMap<String, CompiledTemplate>,
}

impl TemplateEngine {
    /// Create a new TemplateEngine from compiled templates.
    ///
    /// The templates are validated at config load time, so this constructor
    /// assumes all templates are syntactically valid.
    ///
    /// # Arguments
    ///
    /// * `templates` - Map of template names to compiled templates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let templates = runtime_config.templates;
    /// let engine = TemplateEngine::new(templates);
    /// ```
    pub fn new(templates: HashMap<String, CompiledTemplate>) -> Self {
        let mut env = Environment::new();
        // AC #5: Configure lenient undefined behavior for missing fields
        // This returns empty string instead of erroring on undefined variables
        env.set_undefined_behavior(UndefinedBehavior::Lenient);

        // Pre-create HTML environment for body_html rendering (performance optimization)
        let mut html_env = Environment::new();
        html_env.set_undefined_behavior(UndefinedBehavior::Lenient);
        html_env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);

        Self {
            env,
            html_env,
            templates,
        }
    }

    /// Render a template with the given fields.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template to render.
    /// * `fields` - Extracted log fields as JSON value.
    ///
    /// # Returns
    ///
    /// * `Ok(RenderedMessage)` - Successfully rendered message.
    /// * `Err(TemplateError::NotFound)` - Template name not found.
    /// * `Err(TemplateError::RenderFailed)` - Template rendering failed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fields = json!({"host": "server-01", "message": "Alert!"});
    /// let msg = engine.render("alert", &fields)?;
    /// ```
    pub fn render(
        &self,
        template_name: &str,
        fields: &Value,
    ) -> Result<RenderedMessage, TemplateError> {
        tracing::trace!(template_name = %template_name, "Starting template render");

        // Look up template
        let template =
            self.templates
                .get(template_name)
                .ok_or_else(|| TemplateError::NotFound {
                    name: template_name.to_string(),
                })?;

        // Render each field
        let title = self.render_string(&template.title, fields)?;
        let body = self.render_string(&template.body, fields)?;

        // Render body_html with HTML auto-escape if present
        let body_html = if let Some(body_html_template) = &template.body_html {
            Some(self.render_string_html_escaped(body_html_template, fields)?)
        } else {
            None
        };

        // accent_color is passed through (no template rendering)
        // It is a static value from config
        tracing::trace!(
            title_len = title.len(),
            body_len = body.len(),
            has_body_html = body_html.is_some(),
            "Template rendered successfully"
        );
        Ok(RenderedMessage {
            title,
            body,
            body_html,
            accent_color: template.accent_color.clone(),
        })
    }

    /// Render a single template string with fields (no auto-escape).
    fn render_string(&self, template_str: &str, fields: &Value) -> Result<String, TemplateError> {
        self.env
            .render_str(template_str, fields)
            .map_err(|e| TemplateError::RenderFailed {
                message: e.to_string(),
            })
    }

    /// Render a single template string with HTML auto-escape for security.
    /// Used for body_html to prevent XSS from log data injected into emails.
    fn render_string_html_escaped(
        &self,
        template_str: &str,
        fields: &Value,
    ) -> Result<String, TemplateError> {
        self.html_env
            .render_str(template_str, fields)
            .map_err(|e| TemplateError::RenderFailed {
                message: e.to_string(),
            })
    }

    /// Render a template with fallback on error.
    ///
    /// If rendering fails, returns a fallback message with basic info.
    /// This is useful in production where we want to send *something*
    /// rather than dropping the alert entirely.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template to render.
    /// * `fields` - Extracted log fields as JSON value.
    /// * `rule_name` - Name of the rule (for fallback message and logging).
    ///
    /// # Returns
    ///
    /// Always returns a `RenderedMessage`, using fallback values on error.
    pub fn render_with_fallback(
        &self,
        template_name: &str,
        fields: &Value,
        rule_name: &str,
    ) -> RenderedMessage {
        match self.render(template_name, fields) {
            Ok(msg) => {
                tracing::trace!(rule_name = %rule_name, "Template render successful");
                msg
            }
            Err(e) => {
                tracing::warn!(
                    rule_name = %rule_name,
                    template = %template_name,
                    error = %e,
                    "Template render failed, using fallback"
                );

                // Fallback message with basic info
                // Note: We don't include raw fields to avoid exposing potentially
                // sensitive data (tokens, credentials) that might be in extracted logs
                RenderedMessage {
                    title: format!("[{}] Alert", rule_name),
                    body: format!("Template render failed: {}\n\nCheck logs for details.", e),
                    body_html: None,
                    accent_color: Some("#ff0000".to_string()), // Red for error
                }
            }
        }
    }
}

impl std::fmt::Debug for TemplateEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateEngine")
            .field("template_count", &self.templates.len())
            .field("templates", &self.templates.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_template(title: &str, body: &str) -> CompiledTemplate {
        CompiledTemplate {
            title: title.to_string(),
            body: body.to_string(),
            body_html: None,
            accent_color: None,
        }
    }

    fn make_template_with_accent_color(
        title: &str,
        body: &str,
        accent_color: Option<&str>,
    ) -> CompiledTemplate {
        CompiledTemplate {
            title: title.to_string(),
            body: body.to_string(),
            body_html: None,
            accent_color: accent_color.map(String::from),
        }
    }

    // ===================================================================
    // Task 5.1: Test rendu template simple avec variables
    // ===================================================================

    #[test]
    fn render_simple_template_with_variables() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template(
                "Alert: {{ host }}",
                "Host {{ host }} reported: {{ message }}",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "host": "server-01",
            "message": "CPU usage high"
        });

        let result = engine.render("alert", &fields).unwrap();

        assert_eq!(result.title, "Alert: server-01");
        assert_eq!(result.body, "Host server-01 reported: CPU usage high");
    }

    // ===================================================================
    // Task 5.2: Test rendu template avec syntaxe conditionnelle {% if %}
    // ===================================================================

    #[test]
    fn render_template_with_conditional_syntax() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template(
                "{% if severity == \"critical\" %}🚨 CRITICAL{% else %}⚠️ Warning{% endif %}",
                "Severity: {{ severity }}",
            ),
        );

        let engine = TemplateEngine::new(templates);

        // Test critical severity
        let fields_critical = json!({"severity": "critical"});
        let result = engine.render("alert", &fields_critical).unwrap();
        assert_eq!(result.title, "🚨 CRITICAL");

        // Test non-critical severity
        let fields_warning = json!({"severity": "warning"});
        let result = engine.render("alert", &fields_warning).unwrap();
        assert_eq!(result.title, "⚠️ Warning");
    }

    // ===================================================================
    // Task 5.3: Test rendu template avec champs nested {{ data.server.name }}
    // ===================================================================

    #[test]
    fn render_template_with_nested_fields() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template(
                "Server: {{ data.server.hostname }}",
                "Region: {{ data.server.region }}, Status: {{ data.status }}",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "data": {
                "server": {
                    "hostname": "prod-server-01",
                    "region": "us-east-1"
                },
                "status": "alert"
            }
        });

        let result = engine.render("alert", &fields).unwrap();

        assert_eq!(result.title, "Server: prod-server-01");
        assert_eq!(result.body, "Region: us-east-1, Status: alert");
    }

    // ===================================================================
    // Task 5.4: Test rendu template avec champ manquant (pas d'erreur)
    // ===================================================================

    #[test]
    fn render_template_with_missing_field_no_error() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("Host: {{ host }}", "Missing: {{ nonexistent }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        // Should NOT return an error, missing field renders as empty string
        let result = engine.render("alert", &fields).unwrap();

        assert_eq!(result.title, "Host: server-01");
        assert_eq!(result.body, "Missing: "); // Empty string for missing field
    }

    // ===================================================================
    // Task 5.5: Test rendu template avec tous les champs (title, body, accent_color)
    // ===================================================================

    #[test]
    fn render_template_with_all_fields() {
        let mut templates = HashMap::new();
        templates.insert(
            "full_alert".to_string(),
            make_template_with_accent_color("{{ title }}", "{{ body }}", Some("#ff0000")),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "title": "Critical Alert",
            "body": "Something went wrong"
        });

        let result = engine.render("full_alert", &fields).unwrap();

        assert_eq!(result.title, "Critical Alert");
        assert_eq!(result.body, "Something went wrong");
        assert_eq!(result.accent_color, Some("#ff0000".to_string()));
    }

    // ===================================================================
    // Task 5.6: Test gestion erreur template invalide au runtime
    // ===================================================================

    #[test]
    fn render_nonexistent_template_returns_error() {
        let templates = HashMap::new();
        let engine = TemplateEngine::new(templates);

        let fields = json!({"host": "server-01"});
        let result = engine.render("nonexistent", &fields);

        assert!(result.is_err());
        match result.unwrap_err() {
            TemplateError::NotFound { name } => {
                assert_eq!(name, "nonexistent");
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn render_with_invalid_filter_uses_fallback() {
        let mut templates = HashMap::new();
        // Template with invalid filter that will fail at render time
        templates.insert(
            "bad_template".to_string(),
            make_template("{{ host | nonexistent_filter }}", "body"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        // render() should return error
        let result = engine.render("bad_template", &fields);
        assert!(result.is_err());

        // render_with_fallback() should return fallback message
        let fallback = engine.render_with_fallback("bad_template", &fields, "test_rule");
        assert_eq!(fallback.title, "[test_rule] Alert");
        assert!(fallback.body.contains("Template render failed"));
        assert!(fallback.body.contains("Check logs for details"));
        // Should NOT contain raw fields (security: avoid exposing sensitive data)
        assert!(!fallback.body.contains("server-01"));
        assert_eq!(fallback.accent_color, Some("#ff0000".to_string()));
    }

    // ===================================================================
    // Task 5.7: Test réutilisation du même template par plusieurs règles
    // ===================================================================

    #[test]
    fn same_template_reused_by_multiple_renders() {
        let mut templates = HashMap::new();
        templates.insert(
            "shared_template".to_string(),
            make_template("Alert from {{ host }}", "Message: {{ message }}"),
        );

        let engine = TemplateEngine::new(templates);

        // Render for "rule 1"
        let fields1 = json!({"host": "server-01", "message": "Error A"});
        let result1 = engine.render("shared_template", &fields1).unwrap();

        // Render for "rule 2" with different data
        let fields2 = json!({"host": "server-02", "message": "Error B"});
        let result2 = engine.render("shared_template", &fields2).unwrap();

        // Both should render correctly with their own data
        assert_eq!(result1.title, "Alert from server-01");
        assert_eq!(result1.body, "Message: Error A");

        assert_eq!(result2.title, "Alert from server-02");
        assert_eq!(result2.body, "Message: Error B");
    }

    // ===================================================================
    // Additional tests for edge cases
    // ===================================================================

    #[test]
    fn render_template_with_empty_fields() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("Static Title", "Static Body"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({});

        let result = engine.render("alert", &fields).unwrap();
        assert_eq!(result.title, "Static Title");
        assert_eq!(result.body, "Static Body");
    }

    #[test]
    fn render_with_fallback_for_missing_template() {
        let templates = HashMap::new();
        let engine = TemplateEngine::new(templates);

        let fields = json!({"host": "server-01"});
        let result = engine.render_with_fallback("missing", &fields, "my_rule");

        assert_eq!(result.title, "[my_rule] Alert");
        assert!(result.body.contains("not found"));
    }

    #[test]
    fn render_with_fallback_success_path() {
        // Test the success path of render_with_fallback (Ok(msg) => msg)
        // This ensures 100% coverage of the render_with_fallback method
        let mut templates = HashMap::new();
        templates.insert(
            "valid".to_string(),
            make_template("Alert: {{ host }}", "Message from {{ host }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render_with_fallback("valid", &fields, "test_rule");

        // Should return rendered message, NOT fallback
        assert_eq!(result.title, "Alert: server-01");
        assert_eq!(result.body, "Message from server-01");
        // No fallback accent_color (None from template)
        assert_eq!(result.accent_color, None);
    }

    #[test]
    fn debug_format_shows_useful_info() {
        let mut templates = HashMap::new();
        templates.insert("alert".to_string(), make_template("title", "body"));
        templates.insert("warning".to_string(), make_template("warn", "text"));

        let engine = TemplateEngine::new(templates);
        let debug = format!("{:?}", engine);

        assert!(debug.contains("TemplateEngine"));
        assert!(debug.contains("template_count"));
        assert!(debug.contains("2"));
    }

    #[test]
    fn rendered_message_equality() {
        let msg1 = RenderedMessage {
            title: "Title".to_string(),
            body: "Body".to_string(),
            body_html: None,
            accent_color: Some("#000000".to_string()),
        };

        let msg2 = RenderedMessage {
            title: "Title".to_string(),
            body: "Body".to_string(),
            body_html: None,
            accent_color: Some("#000000".to_string()),
        };

        assert_eq!(msg1, msg2);
    }

    #[test]
    fn render_template_with_for_loop() {
        let mut templates = HashMap::new();
        templates.insert(
            "list".to_string(),
            make_template(
                "Items ({{ items | length }})",
                "{% for item in items %}- {{ item }}\n{% endfor %}",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "items": ["apple", "banana", "cherry"]
        });

        let result = engine.render("list", &fields).unwrap();
        assert_eq!(result.title, "Items (3)");
        assert!(result.body.contains("- apple"));
        assert!(result.body.contains("- banana"));
        assert!(result.body.contains("- cherry"));
    }

    #[test]
    fn render_template_with_empty_title_and_body() {
        // Edge case: empty template strings should render as empty strings
        let mut templates = HashMap::new();
        templates.insert("empty".to_string(), make_template("", ""));

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("empty", &fields).unwrap();
        assert_eq!(result.title, "");
        assert_eq!(result.body, "");
    }

    #[test]
    fn render_deeply_nested_json() {
        let mut templates = HashMap::new();
        templates.insert(
            "deep".to_string(),
            make_template("{{ a.b.c.d.e }}", "Value: {{ a.b.c.d.e }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "a": {
                "b": {
                    "c": {
                        "d": {
                            "e": "deep_value"
                        }
                    }
                }
            }
        });

        let result = engine.render("deep", &fields).unwrap();
        assert_eq!(result.title, "deep_value");
    }

    // ===================================================================
    // Task 9: Tests body_html rendering with HTML auto-escape
    // ===================================================================

    fn make_template_with_body_html(title: &str, body: &str, body_html: &str) -> CompiledTemplate {
        CompiledTemplate {
            title: title.to_string(),
            body: body.to_string(),
            body_html: Some(body_html.to_string()),
            accent_color: None,
        }
    }

    #[test]
    fn render_body_html_is_populated() {
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_body_html(
                "Alert: {{ host }}",
                "Host {{ host }} down",
                "<p><strong>Host:</strong> {{ host }}</p>",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("email_alert", &fields).unwrap();

        assert_eq!(result.title, "Alert: server-01");
        assert_eq!(result.body, "Host server-01 down");
        assert!(result.body_html.is_some());
        assert_eq!(
            result.body_html.unwrap(),
            "<p><strong>Host:</strong> server-01</p>"
        );
    }

    #[test]
    fn render_body_html_escapes_html_in_variables() {
        // AC3: Variables with HTML should be escaped
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_body_html("Alert", "body", "<p>Hostname: {{ hostname }}</p>"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"hostname": "<script>alert(1)</script>"});

        let result = engine.render("email_alert", &fields).unwrap();

        let body_html = result.body_html.unwrap();
        // HTML should be escaped
        assert!(
            body_html.contains("&lt;script&gt;"),
            "Script tags should be escaped: {}",
            body_html
        );
        assert!(
            !body_html.contains("<script>"),
            "Raw script tags should NOT be present: {}",
            body_html
        );
    }

    #[test]
    fn render_body_html_none_when_template_has_no_body_html() {
        let mut templates = HashMap::new();
        templates.insert(
            "mattermost_alert".to_string(),
            make_template("Alert", "Body text"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("mattermost_alert", &fields).unwrap();

        assert!(
            result.body_html.is_none(),
            "body_html should be None when template doesn't have it"
        );
    }
}
