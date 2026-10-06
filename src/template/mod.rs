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
//! match engine.render("alert_template", &fields, "my_rule") {
//!     Ok(msg) => println!("Title: {}", msg.title),
//!     Err(e) => eprintln!("Render failed: {}", e),
//! }
//! ```

pub mod filters;

use crate::config::{BodyFormat, CompiledTemplate, OutputFormat};
use crate::error::TemplateError;
use crate::markdown::MarkdownElement;
use minijinja::value::merge_maps;
use minijinja::{Environment, UndefinedBehavior, context};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// Rendered message ready for notification.
///
/// Contains all fields needed to construct a Mattermost attachment or email.
/// Notifiers read the body through [`RenderedMessage::body_for`].
#[derive(Debug, Clone, Default)]
pub struct RenderedMessage {
    /// Title of the message (attachment fallback and title).
    pub title: String,
    /// Body of the message as rendered from the template: the text sent to
    /// notifiers for a `text` body, the Markdown source for a `markdown` one.
    pub body: String,
    /// Optional HTML body for email notifications (rendered with HTML auto-escape).
    pub email_body_html: Option<String>,
    /// Optional accent color for visual indicators (hex format: #rrggbb).
    /// Used for email colored dot and Mattermost sidebar color.
    pub accent_color: Option<String>,
    /// Format of `body`.
    pub body_format: BodyFormat,
    /// Elements of `code`, `codeblock` and `md_link` standing for the tokens
    /// of a Markdown `body` (empty for a `text` body and the fallback
    /// message).
    pub slots: Arc<[MarkdownElement]>,
    /// Renderings of a Markdown `body`, computed on first use.
    pub renders: RenderCache,
}

/// Renderings of a Markdown body, one slot per [`OutputFormat`], each
/// computed at most once and shared by every clone of the message (so by
/// every destination of an alert).
#[derive(Debug, Clone, Default)]
pub struct RenderCache(Arc<[OnceLock<String>; 4]>);

impl RenderCache {
    fn slot(&self, format: OutputFormat) -> &OnceLock<String> {
        let index = OutputFormat::ALL
            .iter()
            .position(|f| *f == format)
            .expect("ALL lists every format");
        &self.0[index]
    }

    /// Whether the rendering in `format` has been computed.
    pub fn is_rendered(&self, format: OutputFormat) -> bool {
        self.slot(format).get().is_some()
    }
}

/// Body handed to a notifier: the text, and whether it is already escaped
/// for HTML (`html`, `telegram_html` renderings), in which case notifier
/// templates insert it as a safe value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyText<'a> {
    pub text: &'a str,
    pub safe: bool,
}

impl BodyText<'_> {
    /// The body as a template value: safe when already escaped, so `| e`
    /// and HTML auto-escaping leave it intact.
    pub fn to_value(self) -> minijinja::Value {
        if self.safe {
            minijinja::Value::from_safe_string(self.text.to_string())
        } else {
            minijinja::Value::from(self.text)
        }
    }
}

impl RenderedMessage {
    /// The body a notifier whose output format is `format` sends: `body` as
    /// is for a `text` body, its rendering in `format` for a `markdown` one
    /// (parsed and rendered on first use, then shared).
    pub fn body_for(&self, format: OutputFormat) -> BodyText<'_> {
        match self.body_format {
            BodyFormat::Text => BodyText {
                text: &self.body,
                safe: false,
            },
            BodyFormat::Markdown => BodyText {
                text: self
                    .renders
                    .slot(format)
                    .get_or_init(|| crate::markdown::render(&self.body, &self.slots, format)),
                safe: format.is_safe(),
            },
        }
    }
}

/// Messages compare by content: the render cache is derived from `body`.
impl PartialEq for RenderedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.title == other.title
            && self.body == other.body
            && self.email_body_html == other.email_body_html
            && self.accent_color == other.accent_color
            && self.body_format == other.body_format
            && self.slots == other.slots
    }
}

/// Template engine for rendering messages with Jinja2 syntax.
///
/// The engine pre-loads all templates at construction time and
/// reuses a single minijinja `Environment` for all render operations.
///
/// # Thread Safety
///
/// The engine is `Send + Sync` (`Environment<'static>` is): one engine is
/// shared by every rule task through an `Arc`.
pub struct TemplateEngine {
    /// Pre-created Jinja environment (created once, reused for performance).
    env: Environment<'static>,
    /// Pre-created Jinja environment with HTML auto-escape (for email_body_html rendering).
    html_env: Environment<'static>,
    /// Pre-created Jinja environment with Markdown auto-escape (for the body
    /// of a `body_format: markdown` template).
    md_env: Environment<'static>,
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
        filters::register(&mut env);

        // Pre-create HTML environment for email_body_html rendering (performance optimization)
        let mut html_env = Environment::new();
        html_env.set_undefined_behavior(UndefinedBehavior::Lenient);
        html_env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        filters::register(&mut html_env);

        let mut md_env = Environment::new();
        md_env.set_undefined_behavior(UndefinedBehavior::Lenient);
        filters::install_markdown_escape(&mut md_env);
        filters::register(&mut md_env);

        Self {
            env,
            html_env,
            md_env,
            templates,
        }
    }

    /// Render a template with the given fields.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template to render.
    /// * `fields` - Event fields with their dotted keys already unflattened
    ///   (`parser::unflatten_dotted_keys`, done once per alert by the engine):
    ///   a JSON value, or the `minijinja::Value` the alert payload carries
    ///   (`AlertPayload::log_from_fields`). Converted once for the three
    ///   rendered fields.
    /// * `rule_name` - Name of the rule that triggered this render. Injected
    ///   into the render context as `rule_name` so templates can reference
    ///   `{{ rule_name }}` (issue #31). Overrides any event field with the
    ///   same name.
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
    /// let msg = engine.render("alert", &fields, "my_rule")?;
    /// ```
    pub fn render<S: Serialize + ?Sized>(
        &self,
        template_name: &str,
        fields: &S,
        rule_name: &str,
        vl_source: &str,
    ) -> Result<RenderedMessage, TemplateError> {
        tracing::trace!(template_name = %template_name, "Starting template render");

        // Look up template
        let template =
            self.templates
                .get(template_name)
                .ok_or_else(|| TemplateError::NotFound {
                    name: template_name.to_string(),
                })?;

        // `rule_name` and `vl_source` are injected so they are available at
        // layer 1 (title, body, email_body_html), matching the notifier-level
        // (layer 2) contexts.
        let ctx = layer1_context(fields, rule_name, vl_source);
        let title = self.render_string(&template.title, &ctx)?;
        let (body, slots) = match template.body_format {
            BodyFormat::Text => (self.render_string(&template.body, &ctx)?, Vec::new()),
            BodyFormat::Markdown => filters::render_markdown(&self.md_env, &template.body, &ctx)
                .map_err(|e| TemplateError::RenderFailed {
                    message: e.to_string(),
                })?,
        };

        // Render email_body_html with HTML auto-escape if present
        let email_body_html = if let Some(email_body_html_template) = &template.email_body_html {
            Some(self.render_string_html_escaped(email_body_html_template, &ctx)?)
        } else {
            None
        };

        // accent_color is passed through (no template rendering)
        // It is a static value from config
        tracing::trace!(
            title_len = title.len(),
            body_len = body.len(),
            has_email_body_html = email_body_html.is_some(),
            "Template rendered successfully"
        );
        Ok(RenderedMessage {
            title,
            body,
            email_body_html,
            accent_color: template.accent_color.clone(),
            body_format: template.body_format,
            slots: slots.into(),
            renders: RenderCache::default(),
        })
    }

    /// Render a single template string with fields (no auto-escape).
    fn render_string(
        &self,
        template_str: &str,
        ctx: &minijinja::Value,
    ) -> Result<String, TemplateError> {
        render_with(&self.env, template_str, ctx)
    }

    /// Render a single template string with HTML auto-escape for security.
    /// Used for email_body_html to prevent XSS from log data injected into emails.
    fn render_string_html_escaped(
        &self,
        template_str: &str,
        ctx: &minijinja::Value,
    ) -> Result<String, TemplateError> {
        self.html_env
            .render_str(template_str, ctx)
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
    /// * `fields` - Event fields, dotted keys already unflattened (see
    ///   [`TemplateEngine::render`]).
    /// * `rule_name` - Name of the rule (for fallback message and logging).
    ///
    /// # Returns
    ///
    /// Always returns a `RenderedMessage`, using fallback values on error.
    pub fn render_with_fallback<S: Serialize + ?Sized>(
        &self,
        template_name: &str,
        fields: &S,
        rule_name: &str,
        vl_source: &str,
    ) -> RenderedMessage {
        match self.render(template_name, fields, rule_name, vl_source) {
            Ok(msg) => {
                tracing::trace!(
                    rule_name = %rule_name,
                    vl_source = %vl_source,
                    "Template render successful"
                );
                msg
            }
            Err(e) => {
                tracing::warn!(
                    rule_name = %rule_name,
                    vl_source = %vl_source,
                    template = %template_name,
                    error = %e,
                    "Template render failed, using fallback"
                );

                // Fallback message with basic info
                // Note: We don't include raw fields to avoid exposing potentially
                // sensitive data (tokens, credentials) that might be in extracted logs.
                // Always a `text` body, whatever the template's format: it is
                // sent as is, never parsed as Markdown.
                RenderedMessage {
                    title: format!("[{}] Alert", rule_name),
                    body: format!("Template render failed: {}\n\nCheck logs for details.", e),
                    email_body_html: None,
                    accent_color: Some("#ff0000".to_string()), // Red for error
                    body_format: BodyFormat::Text,
                    slots: Arc::default(),
                    renders: RenderCache::default(),
                }
            }
        }
    }
}

/// A message rendered from a one-off template (`title`, `body` of format
/// `body_format`) with `fields`, as the engine renders alerts (tests).
#[cfg(test)]
pub(crate) fn render_test_message(
    title: &str,
    body: &str,
    body_format: BodyFormat,
    fields: &serde_json::Value,
) -> RenderedMessage {
    let template = CompiledTemplate {
        title: title.to_string(),
        body: body.to_string(),
        email_body_html: None,
        accent_color: None,
        body_format,
    };
    TemplateEngine::new(HashMap::from([("t".to_string(), template)]))
        .render("t", fields, "r", "vl")
        .expect("test template renders")
}

/// Renders `template_str` in `env`.
fn render_with(
    env: &Environment<'static>,
    template_str: &str,
    ctx: &minijinja::Value,
) -> Result<String, TemplateError> {
    env.render_str(template_str, ctx)
        .map_err(|e| TemplateError::RenderFailed {
            message: e.to_string(),
        })
}

/// Layer 1 render context: the event fields plus the synthetic `rule_name`
/// (issue #31) and `vl_source` (v2.0.0) keys.
///
/// The synthetic values win over any event field literally named `rule_name`
/// or `vl_source` so operators can rely on them consistently across layer 1
/// and layer 2 templates. The merge is lazy: the fields are not copied.
fn layer1_context<S: Serialize + ?Sized>(
    fields: &S,
    rule_name: &str,
    vl_source: &str,
) -> minijinja::Value {
    // `merge_maps`: the last map holding a key wins.
    merge_maps([
        minijinja::Value::from_serialize(fields),
        context! { rule_name => rule_name, vl_source => vl_source },
    ])
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
            email_body_html: None,
            accent_color: None,
            body_format: crate::config::BodyFormat::Text,
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
            email_body_html: None,
            accent_color: accent_color.map(String::from),
            body_format: crate::config::BodyFormat::Text,
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

        let result = engine
            .render("alert", &fields, "test_rule", "vlprod")
            .unwrap();

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
        let result = engine
            .render("alert", &fields_critical, "test_rule", "vlprod")
            .unwrap();
        assert_eq!(result.title, "🚨 CRITICAL");

        // Test non-critical severity
        let fields_warning = json!({"severity": "warning"});
        let result = engine
            .render("alert", &fields_warning, "test_rule", "vlprod")
            .unwrap();
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

        let result = engine
            .render("alert", &fields, "test_rule", "vlprod")
            .unwrap();

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
        let result = engine
            .render("alert", &fields, "test_rule", "vlprod")
            .unwrap();

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

        let result = engine
            .render("full_alert", &fields, "test_rule", "vlprod")
            .unwrap();

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
        let result = engine.render("nonexistent", &fields, "test_rule", "vlprod");

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
        let result = engine.render("bad_template", &fields, "test_rule", "vlprod");
        assert!(result.is_err());

        // render_with_fallback() should return fallback message
        let fallback = engine.render_with_fallback("bad_template", &fields, "test_rule", "vlprod");
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
        let result1 = engine
            .render("shared_template", &fields1, "rule_1", "vlprod")
            .unwrap();

        // Render for "rule 2" with different data
        let fields2 = json!({"host": "server-02", "message": "Error B"});
        let result2 = engine
            .render("shared_template", &fields2, "rule_2", "vlprod")
            .unwrap();

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

        let result = engine
            .render("alert", &fields, "test_rule", "vlprod")
            .unwrap();
        assert_eq!(result.title, "Static Title");
        assert_eq!(result.body, "Static Body");
    }

    #[test]
    fn render_with_fallback_for_missing_template() {
        let templates = HashMap::new();
        let engine = TemplateEngine::new(templates);

        let fields = json!({"host": "server-01"});
        let result = engine.render_with_fallback("missing", &fields, "my_rule", "vlprod");

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

        let result = engine.render_with_fallback("valid", &fields, "test_rule", "vlprod");

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
            email_body_html: None,
            accent_color: Some("#000000".to_string()),
            ..Default::default()
        };

        let msg2 = RenderedMessage {
            title: "Title".to_string(),
            body: "Body".to_string(),
            email_body_html: None,
            accent_color: Some("#000000".to_string()),
            ..Default::default()
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

        let result = engine
            .render("list", &fields, "test_rule", "vlprod")
            .unwrap();
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

        let result = engine
            .render("empty", &fields, "test_rule", "vlprod")
            .unwrap();
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

        let result = engine
            .render("deep", &fields, "test_rule", "vlprod")
            .unwrap();
        assert_eq!(result.title, "deep_value");
    }

    // ===================================================================
    // Task 9: Tests email_body_html rendering with HTML auto-escape
    // ===================================================================

    fn make_template_with_email_body_html(
        title: &str,
        body: &str,
        email_body_html: &str,
    ) -> CompiledTemplate {
        CompiledTemplate {
            title: title.to_string(),
            body: body.to_string(),
            email_body_html: Some(email_body_html.to_string()),
            accent_color: None,
            body_format: crate::config::BodyFormat::Text,
        }
    }

    #[test]
    fn render_email_body_html_is_populated() {
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_email_body_html(
                "Alert: {{ host }}",
                "Host {{ host }} down",
                "<p><strong>Host:</strong> {{ host }}</p>",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine
            .render("email_alert", &fields, "test_rule", "vlprod")
            .unwrap();

        assert_eq!(result.title, "Alert: server-01");
        assert_eq!(result.body, "Host server-01 down");
        assert!(result.email_body_html.is_some());
        assert_eq!(
            result.email_body_html.unwrap(),
            "<p><strong>Host:</strong> server-01</p>"
        );
    }

    #[test]
    fn render_email_body_html_escapes_html_in_variables() {
        // AC3: Variables with HTML should be escaped
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_email_body_html("Alert", "body", "<p>Hostname: {{ hostname }}</p>"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"hostname": "<script>alert(1)</script>"});

        let result = engine
            .render("email_alert", &fields, "test_rule", "vlprod")
            .unwrap();

        let email_body_html = result.email_body_html.unwrap();
        // HTML should be escaped
        assert!(
            email_body_html.contains("&lt;script&gt;"),
            "Script tags should be escaped: {}",
            email_body_html
        );
        assert!(
            !email_body_html.contains("<script>"),
            "Raw script tags should NOT be present: {}",
            email_body_html
        );
    }

    #[test]
    fn render_applies_valerter_filters() {
        let mut templates = HashMap::new();
        let mut template = make_template("{{ host | mdv2_escape }}", "{{ host | md_escape }}");
        template.email_body_html = Some("<p>{{ host | md_escape }}</p>".to_string());
        templates.insert("alert".to_string(), template);
        let engine = TemplateEngine::new(templates);

        let result = engine
            .render("alert", &json!({"host": "web_01"}), "test_rule", "vlprod")
            .unwrap();

        assert_eq!(result.title, r"web\_01");
        assert_eq!(result.body, r"web\_01");
        assert_eq!(result.email_body_html.unwrap(), r"<p>web\_01</p>");
    }

    #[test]
    fn rule_template_does_not_inject_log() {
        // `log` is a notifier-level variable only: at layer 1 it is the event
        // field of that name, if any (Fluent Bit container output).
        let mut templates = HashMap::new();
        templates.insert("alert".to_string(), make_template("{{ log }}", "b"));
        let engine = TemplateEngine::new(templates);

        let fields = json!({"log": "container output"});
        let result = engine
            .render("alert", &fields, "test_rule", "vlprod")
            .unwrap();

        assert_eq!(result.title, "container output");
    }

    // ===================================================================
    // Issue #25: dotted flat-key resolution at render time
    // ===================================================================

    #[test]
    fn render_resolves_dotted_flat_key_via_unflatten() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template(
                "{{ nginx.http.request_id }}",
                "id={{ nginx.http.request_id }}",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"nginx.http.request_id": "abc"});
        let log = crate::notify::AlertPayload::log_from_fields(&fields);

        let result = engine.render("alert", &log, "test_rule", "vlprod").unwrap();
        assert_eq!(result.title, "abc");
        assert_eq!(result.body, "id=abc");
    }

    #[test]
    fn render_issue_25_full_template_end_to_end() {
        // Mirrors the user's config in issue #25.
        let mut templates = HashMap::new();
        templates.insert(
            "my_template".to_string(),
            make_template_with_email_body_html(
                "{{ title }}",
                "{{ body }}",
                "<p>{{ hostname }} - {{ nginx.http.request_id }} - {{ nginx.http.method }}</p>",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({
            "title": "T",
            "body": "B",
            "hostname": "srv-01",
            "nginx.http.request_id": "req-42",
            "nginx.http.method": "GET",
            "nginx.http.status_code": "400"
        });

        let log = crate::notify::AlertPayload::log_from_fields(&fields);

        let result = engine
            .render("my_template", &log, "test_rule", "vlprod")
            .unwrap();
        assert_eq!(result.title, "T");
        assert_eq!(result.body, "B");
        let email_body_html = result.email_body_html.unwrap();
        assert!(
            email_body_html.contains("srv-01")
                && email_body_html.contains("req-42")
                && email_body_html.contains("GET"),
            "expected all dotted fields rendered, got: {}",
            email_body_html
        );
    }

    // ===================================================================
    // Issue #31: rule_name available in layer 1 templates (title, body,
    // email_body_html) and in the throttle key, not only in layer 2
    // notifier-level subject_template / body_template contexts.
    // ===================================================================

    #[test]
    fn render_injects_rule_name_in_title() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("Alert {{ rule_name }}", "body"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vlprod").unwrap();
        assert_eq!(result.title, "Alert VM_OFF");
    }

    #[test]
    fn render_injects_rule_name_in_body() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template(
                "title",
                "rule={{ rule_name }}\nhost={{ host }}\nrule_again={{ rule_name }}",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vlprod").unwrap();
        assert_eq!(
            result.body,
            "rule=VM_OFF\nhost=server-01\nrule_again=VM_OFF"
        );
    }

    #[test]
    fn render_injects_rule_name_in_email_body_html() {
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_email_body_html(
                "t",
                "b",
                "<p>Rule: {{ rule_name }} on {{ host }}</p>",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine
            .render("email_alert", &fields, "VM_OFF", "vlprod")
            .unwrap();
        assert_eq!(
            result.email_body_html.unwrap(),
            "<p>Rule: VM_OFF on server-01</p>"
        );
    }

    // ===================================================================
    // v2.0.0: vl_source available in layer 1 templates (title, body,
    // email_body_html), matching the layer 2 notifier-level contexts and
    // the throttle key render context.
    // ===================================================================

    #[test]
    fn render_injects_vl_source_in_title() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("[{{ vl_source }}] {{ rule_name }}", "body"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vlprod").unwrap();
        assert_eq!(result.title, "[vlprod] VM_OFF");
    }

    #[test]
    fn render_injects_vl_source_in_body() {
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("title", "source={{ vl_source }}\nhost={{ host }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vldev").unwrap();
        assert_eq!(result.body, "source=vldev\nhost=server-01");
    }

    #[test]
    fn render_injects_vl_source_in_email_body_html() {
        let mut templates = HashMap::new();
        templates.insert(
            "email_alert".to_string(),
            make_template_with_email_body_html(
                "t",
                "b",
                "<p>Source: {{ vl_source }}, host: {{ host }}</p>",
            ),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine
            .render("email_alert", &fields, "VM_OFF", "vlprod")
            .unwrap();
        assert_eq!(
            result.email_body_html.unwrap(),
            "<p>Source: vlprod, host: server-01</p>"
        );
    }

    #[test]
    fn render_vl_source_synthetic_overrides_event_field() {
        // Collision policy: synthetic vl_source wins over any event field
        // literally named "vl_source" (matches rule_name collision policy).
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("{{ vl_source }}", "{{ vl_source }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"vl_source": "evil", "host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vlprod").unwrap();
        assert_eq!(result.title, "vlprod");
        assert_eq!(result.body, "vlprod");
    }

    #[test]
    fn render_rule_name_synthetic_overrides_event_field() {
        // Collision policy: synthetic rule_name wins over any event field
        // literally named "rule_name".
        let mut templates = HashMap::new();
        templates.insert(
            "alert".to_string(),
            make_template("{{ rule_name }}", "{{ rule_name }}"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"rule_name": "event-value", "host": "server-01"});

        let result = engine.render("alert", &fields, "VM_OFF", "vlprod").unwrap();
        assert_eq!(result.title, "VM_OFF");
        assert_eq!(result.body, "VM_OFF");
    }

    #[test]
    fn render_email_body_html_none_when_template_has_no_email_body_html() {
        let mut templates = HashMap::new();
        templates.insert(
            "mattermost_alert".to_string(),
            make_template("Alert", "Body text"),
        );

        let engine = TemplateEngine::new(templates);
        let fields = json!({"host": "server-01"});

        let result = engine
            .render("mattermost_alert", &fields, "test_rule", "vlprod")
            .unwrap();

        assert!(
            result.email_body_html.is_none(),
            "email_body_html should be None when template doesn't have it"
        );
    }

    // ===================================================================
    // Markdown bodies (markdown-body-format)
    // ===================================================================

    fn markdown_engine(title: &str, body: &str, email_body_html: Option<&str>) -> TemplateEngine {
        let mut templates = HashMap::new();
        templates.insert(
            "md".to_string(),
            CompiledTemplate {
                title: title.to_string(),
                body: body.to_string(),
                email_body_html: email_body_html.map(String::from),
                accent_color: None,
                body_format: BodyFormat::Markdown,
            },
        );
        TemplateEngine::new(templates)
    }

    fn markdown_body(body: &str, fields: serde_json::Value) -> String {
        markdown_engine("t", body, None)
            .render("md", &fields, "r", "vl")
            .unwrap()
            .body
    }

    #[test]
    fn markdown_body_escapes_inserted_values() {
        assert_eq!(
            markdown_body("**{{ host }}** down", json!({"host": "a_b*c"})),
            r"**a\_b\*c** down"
        );
        assert_eq!(markdown_body("[{{ missing }}]", json!({})), "[]");
        // Non-string values are written as in a text body, then escaped.
        let mut templates = HashMap::new();
        templates.insert("t".to_string(), make_template("t", "{{ n }} {{ nil }}"));
        let text = TemplateEngine::new(templates)
            .render("t", &json!({"n": 1.5, "nil": null}), "r", "vl")
            .unwrap()
            .body;
        assert_eq!(text, "1.5 None");
        assert_eq!(
            markdown_body("{{ n }} {{ nil }}", json!({"n": 1.5, "nil": null})),
            r"1\.5 None"
        );
    }

    #[test]
    fn markdown_body_opt_outs() {
        assert_eq!(
            markdown_body("{{ summary | safe }}", json!({"summary": "**OK**"})),
            "**OK**"
        );
        // `| tojson` is escaped as any value: `| safe` is the only opt-out.
        assert_eq!(
            markdown_body("{{ v | tojson }}", json!({"v": "a_b"})),
            r#"\"a\_b\""#
        );
        // `| e` escapes for the current context: Markdown, not HTML.
        assert_eq!(
            markdown_body("{{ v | e }}", json!({"v": "<a_b>"})),
            r"\<a\_b\>"
        );
        assert_eq!(
            markdown_body("{{ v | e | e }}", json!({"v": "a_b"})),
            r"a\_b"
        );
        assert_eq!(
            markdown_body("{{ host | md_escape }}", json!({"host": "a_b"})),
            r"a\_b"
        );
    }

    #[test]
    fn markdown_template_keeps_title_and_email_body_html_unchanged() {
        let engine = markdown_engine(
            "{{ host }} down",
            "{{ host }}",
            Some("<p>{{ host }} {{ host | code }}</p>"),
        );
        let msg = engine
            .render("md", &json!({"host": "web_01<b>"}), "r", "vl")
            .unwrap();
        assert_eq!(msg.title, "web_01<b> down");
        assert_eq!(
            msg.email_body_html.as_deref(),
            Some("<p>web_01&lt;b&gt; `web_01&lt;b&gt;`</p>")
        );
        assert_eq!(msg.body_format, BodyFormat::Markdown);
    }

    #[test]
    fn text_template_is_unchanged() {
        let mut templates = HashMap::new();
        templates.insert(
            "t".to_string(),
            make_template("{{ host }}", "**{{ host }}** <{{ v | e }}>"),
        );
        let msg = TemplateEngine::new(templates)
            .render("t", &json!({"host": "a_b*c", "v": "<x>"}), "r", "vl")
            .unwrap();
        assert_eq!(msg.body, "**a_b*c** <&lt;x&gt;>");
        assert_eq!(msg.body_format, BodyFormat::Text);
        for format in OutputFormat::ALL {
            assert_eq!(
                msg.body_for(format),
                BodyText {
                    text: "**a_b*c** <&lt;x&gt;>",
                    safe: false
                }
            );
        }
    }

    /// The message of a Markdown body, its renderings in the order of
    /// [`OutputFormat::ALL`].
    fn markdown_renders(body: &str, fields: serde_json::Value) -> (RenderedMessage, [String; 4]) {
        let msg = markdown_engine("t", body, None)
            .render("md", &fields, "r", "vl")
            .unwrap();
        let renders = OutputFormat::ALL.map(|format| msg.body_for(format).text.to_string());
        (msg, renders)
    }

    #[test]
    fn markdown_filters_and_md_link_function() {
        // Each element is a token of the source, kept in the slots.
        let (msg, [plain, md, html, _]) = markdown_renders("{{ v | code }}", json!({"v": "a`b"}));
        assert_eq!(msg.body, "\u{E000}0\u{E001}");
        assert_eq!(&*msg.slots, &[MarkdownElement::Code("a`b".to_string())]);
        assert_eq!((plain.as_str(), md.as_str()), ("a`b", "``a`b``"));
        assert_eq!(html, "<p><code>a`b</code></p>");

        let (msg, [_, md, ..]) = markdown_renders("{{ v | codeblock('js;x') }}", json!({"v": "a"}));
        assert_eq!(
            &*msg.slots,
            &[MarkdownElement::CodeBlock {
                lang: "jsx".to_string(),
                text: "a".to_string()
            }]
        );
        assert_eq!(md, "```jsx\na\n```");

        let (_, [_, md, ..]) = markdown_renders(
            r#"{{ md_link("logs " ~ host, "https://vl.example.com/q?h=" ~ host) }}"#,
            json!({"host": "web_01"}),
        );
        assert_eq!(md, r"[logs web\_01](https://vl.example.com/q?h=web_01)");

        let (_, [plain, md, ..]) =
            markdown_renders(r#"{{ md_link("x", "javascript:alert(1)") }}"#, json!({}));
        assert_eq!(plain, "x (javascript:alert(1))");
        assert_eq!(md, "x (javascript:alert(1))");
    }

    /// Asserts that no rendering holds markup coming from a value.
    fn assert_no_markup(renders: &[String; 4]) {
        let [_, md, html, tg] = renders;
        for out in [html, tg] {
            for forbidden in ["<h1", "href", "<strong>", "<b>"] {
                assert!(!out.contains(forbidden), "{forbidden} in {out}");
            }
        }
        // No active link, heading or emphasis in the `markdown` rendering,
        // read back as Markdown.
        let reparsed = crate::markdown::render(md, &[], OutputFormat::Html);
        for forbidden in ["<h1", "href", "<strong>"] {
            assert!(!reparsed.contains(forbidden), "{forbidden} in {md}");
        }
    }

    #[test]
    fn code_filter_scenarios() {
        let (_, [plain, md, html, tg]) = markdown_renders("{{ v | code }}", json!({"v": "a`b"}));
        assert_eq!(md, "``a`b``");
        assert_eq!(plain, "a`b");
        assert_eq!(html, "<p><code>a`b</code></p>");
        assert_eq!(tg, "<code>a`b</code>");

        let (_, [plain, md, html, tg]) = markdown_renders("{{ v | code }}", json!({"v": "**x**"}));
        assert_eq!(plain, "**x**");
        assert_eq!(md, "`**x**`");
        assert_eq!(html, "<p><code>**x**</code></p>");
        assert_eq!(tg, "<code>**x**</code>");

        let (_, renders) = markdown_renders(
            "# Host {{ v | code }}",
            json!({"v": "[a](https://evil.example)"}),
        );
        assert_eq!(
            renders[2],
            "<h1>Host <code>[a](https://evil.example)</code></h1>"
        );
        assert_eq!(renders[0], "Host [a](https://evil.example)");
        assert!(!renders.iter().any(|r| r.contains("href")), "{renders:?}");
    }

    #[test]
    fn codeblock_filter_scenarios() {
        let (_, [plain, md, html, tg]) = markdown_renders(
            "Log:\n{{ _msg | codeblock('json') }}",
            json!({"_msg": r#"{"a": "<b>"}"#}),
        );
        assert!(
            html.contains(r#"<pre><code class="language-json">{&quot;a&quot;: &quot;&lt;b&gt;&quot;}</code></pre>"#),
            "{html}"
        );
        assert_eq!(plain, "Log:\n\n{\"a\": \"<b>\"}");
        assert_eq!(md, "Log:\n\n```json\n{\"a\": \"<b>\"}\n```");
        assert!(tg.contains("<pre><code class=\"language-json\">"), "{tg}");

        // A value holding a fence.
        let (_, [plain, md, ..]) =
            markdown_renders("{{ v | codeblock }}", json!({"v": "a\n```\nb"}));
        assert_eq!(md, "````\na\n```\nb\n````");
        assert_eq!(plain, "a\n```\nb");

        // In a list item.
        let v = "a\n# b\n[c](https://evil.example)";
        let (_, renders) = markdown_renders("- x\n- {{ v | codeblock }}", json!({"v": v}));
        assert!(
            renders[2]
                .contains("<li><pre><code>a\n# b\n[c](https://evil.example)</code></pre></li>"),
            "{}",
            renders[2]
        );
        assert_no_markup(&renders);

        // In a quote.
        let (_, renders) = markdown_renders("> {{ v | codeblock }}", json!({"v": "a\n<b>x</b>"}));
        assert_eq!(
            renders[3],
            "<blockquote><pre>a\n&lt;b&gt;x&lt;/b&gt;</pre></blockquote>"
        );
        assert_no_markup(&renders);

        // On an indented line (a code block of the template).
        let (_, renders) = markdown_renders("    {{ v | codeblock }}", json!({"v": "a\n**b**"}));
        assert_eq!(renders[0], "a\n**b**");
        assert_no_markup(&renders);

        // In the middle of a line: the paragraph is cut around the block.
        let (_, renders) = markdown_renders("Log: {{ v | codeblock }} end", json!({"v": "a\nb"}));
        assert_eq!(renders[0], "Log:\n\na\nb\n\nend");
        assert_eq!(
            renders[2],
            "<p>Log:</p>\n<pre><code>a\nb</code></pre>\n<p>end</p>"
        );
    }

    #[test]
    fn markdown_filter_content_is_literal() {
        let (_, renders) = markdown_renders(
            "**{{ v | codeblock }}**",
            json!({"v": "a\n[b](https://evil.example)"}),
        );
        assert_eq!(
            renders[2],
            "<p><strong><code>a [b](https://evil.example)</code></strong></p>"
        );
        assert_eq!(renders[3], "<b>a [b](https://evil.example)</b>");
        assert!(!renders.iter().any(|r| r.contains("href")), "{renders:?}");

        let (_, [plain, ..]) = markdown_renders("```\n{{ v | code }}\n```", json!({"v": "*x*"}));
        assert_eq!(plain, "*x*");

        let (_, [plain, md, html, _]) =
            markdown_renders("{{ (v | code) ~ '!' }}", json!({"v": "x"}));
        assert_eq!(plain, "`x`!");
        assert_eq!(md, r"\`x\`!");
        assert_eq!(html, "<p>`x`!</p>");
    }

    #[test]
    fn value_imitating_a_markdown_filter() {
        let (_, [plain, md, html, tg]) = markdown_renders(
            "{{ v }} {{ w | code }}",
            json!({"v": "\u{E000}0\u{E001}", "w": "x"}),
        );
        assert_eq!(plain, "\u{FFFD}0\u{FFFD} x");
        assert_eq!(md, "\u{FFFD}0\u{FFFD} `x`");
        assert_eq!(html, "<p>\u{FFFD}0\u{FFFD} <code>x</code></p>");
        assert_eq!(tg, "\u{FFFD}0\u{FFFD} <code>x</code>");
    }

    #[test]
    fn md_link_scenarios() {
        let (_, renders) = markdown_renders(
            r#"{{ md_link("logs " ~ host, "https://vl.example.com/select?q=host:" ~ host) }}"#,
            json!({"host": "web_01"}),
        );
        assert!(
            renders[2].contains(
                r#"<a href="https://vl.example.com/select?q=host:web_01">logs web_01</a>"#
            ),
            "{}",
            renders[2]
        );
        for render in markdown_renders(r#"{{ md_link("x", "javascript:alert(1)") }}"#, json!({})).1
        {
            assert!(
                !render.contains("href") && !render.contains("]("),
                "{render}"
            );
            assert!(render.contains("x (javascript:alert(1))"), "{render}");
        }
        // A field named `link` does not hide the function.
        let msg = markdown_engine("t", "{{ md_link('x', 'https://a.example') }}", None)
            .render_with_fallback("md", &json!({"link": "https://y.example"}), "r", "vl");
        assert_eq!(msg.body_format, BodyFormat::Markdown, "{}", msg.body);
        assert!(
            msg.body_for(OutputFormat::Html)
                .text
                .contains(r#"<a href="https://a.example">x</a>"#)
        );
        // A link in a link: the inner one is text.
        let (_, renders) = markdown_renders(
            "[voir {{ md_link('x', 'https://a.example') }}](https://b.example)",
            json!({}),
        );
        assert_eq!(
            renders[2],
            r#"<p><a href="https://b.example">voir x (https://a.example)</a></p>"#
        );
    }

    #[test]
    fn urlencode_encodes_a_value_for_a_url() {
        let mut templates = HashMap::new();
        templates.insert("t".to_string(), make_template("t", "q={{ v | urlencode }}"));
        let msg = TemplateEngine::new(templates)
            .render("t", &json!({"v": "a&b c#d?e+f"}), "r", "vl")
            .unwrap();
        assert_eq!(msg.body, "q=a%26b%20c%23d%3Fe%2Bf");

        let (_, renders) = markdown_renders(
            r#"{{ md_link("logs", "https://vl.example.com/select?q=" ~ ("host:" ~ host) | urlencode) }}"#,
            json!({"host": "a&b #1"}),
        );
        assert!(
            renders[2].contains(r#"href="https://vl.example.com/select?q=host%3Aa%26b%20%231""#),
            "{}",
            renders[2]
        );
    }

    #[test]
    fn tojson_result_is_escaped_in_a_markdown_body() {
        let v = "**bold** [phish](https://evil.example)";
        let (_, renders) = markdown_renders("{{ v | tojson }}", json!({"v": v}));
        for render in &renders {
            for forbidden in ["<strong>", "<b>", "href"] {
                assert!(!render.contains(forbidden), "{forbidden} in {render}");
            }
        }
        assert_eq!(renders[0], format!("\"{v}\""));
    }

    #[test]
    fn tojson_is_unchanged_in_email_body_html() {
        let msg = markdown_engine("t", "x", Some("<pre>{{ v | tojson }}</pre>"))
            .render("md", &json!({"v": "<a&b>"}), "r", "vl")
            .unwrap();
        assert_eq!(
            msg.email_body_html.as_deref(),
            Some(r#"<pre>"\u003ca\u0026b\u003e"</pre>"#)
        );
    }

    #[test]
    fn markdown_filters_are_plain_strings_outside_markdown() {
        let mut templates = HashMap::new();
        templates.insert(
            "t".to_string(),
            make_template(
                "{{ v | code }}",
                r#"{{ v | code }} {{ md_link(v, "https://h") }}"#,
            ),
        );
        let msg = TemplateEngine::new(templates)
            .render("t", &json!({"v": "<a>"}), "r", "vl")
            .unwrap();
        assert_eq!(msg.title, "`<a>`");
        assert_eq!(msg.body, r"`<a>` [\<a\>](https://h)");
    }

    #[test]
    fn body_for_renders_markdown_once_per_format() {
        let msg = markdown_engine("t", "**{{ host }}**", None)
            .render("md", &json!({"host": "a_b"}), "r", "vl")
            .unwrap();
        assert!(!msg.renders.is_rendered(OutputFormat::TelegramHtml));
        let first = msg.body_for(OutputFormat::TelegramHtml);
        assert_eq!(
            first,
            BodyText {
                text: "<b>a_b</b>",
                safe: true
            }
        );
        assert!(msg.renders.is_rendered(OutputFormat::TelegramHtml));
        assert!(!msg.renders.is_rendered(OutputFormat::Plain));
        // Same allocation: the rendering is reused, and shared by clones.
        let clone = msg.clone();
        let second = clone.body_for(OutputFormat::TelegramHtml);
        assert!(std::ptr::eq(first.text, second.text));
        assert_eq!(
            msg.body_for(OutputFormat::Markdown),
            BodyText {
                text: r"**a\_b**",
                safe: false
            }
        );
        assert_eq!(msg.body_for(OutputFormat::Plain).text, "a_b");
        assert!(msg.body_for(OutputFormat::Html).safe);
    }

    #[test]
    fn body_for_is_shared_between_threads() {
        let msg = std::sync::Arc::new(
            markdown_engine("t", "**{{ host }}**", None)
                .render("md", &json!({"host": "a_b"}), "r", "vl")
                .unwrap(),
        );
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let msg = std::sync::Arc::clone(&msg);
                std::thread::spawn(move || {
                    msg.body_for(OutputFormat::TelegramHtml).text.as_ptr() as usize
                })
            })
            .collect();
        let pointers: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(pointers[0], pointers[1], "rendered once, shared");
        assert_eq!(msg.body_for(OutputFormat::TelegramHtml).text, "<b>a_b</b>");
    }

    #[test]
    fn markdown_fallback_message_is_text() {
        let engine = markdown_engine("t", "{{ x | nosuchfilter }}", None);
        let msg = engine.render_with_fallback("md", &json!({}), "r", "vl");
        assert_eq!(msg.body_format, BodyFormat::Text);
        assert!(msg.body.starts_with("Template render failed"));
        let body = msg.body_for(OutputFormat::TelegramHtml);
        assert_eq!(body.text, msg.body);
        assert!(!body.safe);
    }

    #[test]
    fn rendered_messages_compare_by_content() {
        let msg = markdown_engine("t", "**{{ host }}**", None)
            .render("md", &json!({"host": "a"}), "r", "vl")
            .unwrap();
        let fresh = msg.clone();
        msg.body_for(OutputFormat::Plain);
        let other = RenderedMessage {
            renders: RenderCache::default(),
            ..fresh
        };
        assert_eq!(msg, other);
    }

    /// The example of docs/templates.md, "Markdown bodies".
    #[test]
    fn markdown_documentation_example() {
        let msg = render_test_message(
            "Disk {{ host }}",
            "**{{ host }}** is at {{ usage }}% on {{ mount | code }}\n\
             {{ md_link(\"Logs in VictoriaLogs\", \"https://vl.example.com/select/vmui?query=\" ~ (\"host:\" ~ host) | urlencode) }}\n\
             {{ _msg | codeblock }}\n",
            BodyFormat::Markdown,
            &json!({"host": "web_01", "usage": 97, "mount": "/var", "_msg": "disk <full> & read-only"}),
        );
        assert_eq!(
            msg.body_for(OutputFormat::Markdown).text,
            "**web\\_01** is at 97% on `/var`\n\
             [Logs in VictoriaLogs](https://vl.example.com/select/vmui?query=host%3Aweb_01)\n\n\
             ```\ndisk <full> & read-only\n```"
        );
        assert_eq!(
            msg.body_for(OutputFormat::TelegramHtml).text,
            "<b>web_01</b> is at 97% on <code>/var</code>\n\
             <a href=\"https://vl.example.com/select/vmui?query=host%3Aweb_01\">Logs in VictoriaLogs</a>\n\n\
             <pre>disk &lt;full&gt; &amp; read-only</pre>"
        );
    }
}
