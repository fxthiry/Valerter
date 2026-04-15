//! Template and color validation utilities.

use minijinja::value::{Enumerator, Object, ObjectRepr, Value};
use minijinja::{Environment, UndefinedBehavior};
use regex::Regex;
use std::sync::{Arc, LazyLock};

/// Sentinel context object used during template validation.
///
/// Issue #25: validating templates that reference dotted VictoriaLogs fields
/// (`{{ nginx.http.request_id }}`) used to fail because chained attribute access
/// against an empty `json!({})` returned `undefined` instead of another value.
///
/// `TruthyChainable` returns itself on every attribute access (so chains never
/// hit `undefined`), is always truthy (so `{% if x.y %}` walks the body and
/// validates filters/syntax inside), stringifies as empty, and iterates as an
/// empty sequence (so `{% for x in tc %}` and `{{ tc | length }}` do not error
/// — matching the prior `Lenient + json!({})` behaviour).
#[derive(Debug)]
struct TruthyChainable;

impl Object for TruthyChainable {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }

    fn get_value(self: &Arc<Self>, _key: &Value) -> Option<Value> {
        Some(Value::from_dyn_object(self.clone()))
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Empty
    }

    fn is_true(self: &Arc<Self>) -> bool {
        true
    }

    fn render(self: &Arc<Self>, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

/// Validates Jinja template syntax.
pub(crate) fn validate_jinja_template(source: &str) -> Result<(), String> {
    let mut env = Environment::new();
    env.add_template("_validate", source)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates a Jinja template by performing a test render with empty data.
/// Detects runtime errors like unknown filters.
///
/// # Errors
/// Returns an error string if the template syntax is invalid or uses unknown filters.
pub fn validate_template_render(source: &str) -> Result<(), String> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Lenient);
    env.add_template("_render_test", source)
        .map_err(|e| e.to_string())?;

    let tmpl = env
        .get_template("_render_test")
        .map_err(|e| e.to_string())?;
    tmpl.render(Value::from_object(TruthyChainable))
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Validates a URL string.
pub(crate) fn validate_url(url: &str) -> Result<(), String> {
    reqwest::Url::parse(url)
        .map(|_| ())
        .map_err(|e| format!("invalid URL '{}': {}", url, e))
}

/// Validates a hex color string in format #rrggbb.
pub(crate) fn validate_hex_color(color: &str) -> Result<(), String> {
    static HEX_COLOR_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^#[0-9a-fA-F]{6}$").expect("valid regex"));

    if HEX_COLOR_REGEX.is_match(color) {
        Ok(())
    } else {
        Err(format!(
            "invalid hex color '{}': must be in format #rrggbb (e.g., #ff0000)",
            color
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_hex_color_valid_formats() {
        assert!(validate_hex_color("#ff0000").is_ok());
        assert!(validate_hex_color("#FF0000").is_ok());
        assert!(validate_hex_color("#123456").is_ok());
        assert!(validate_hex_color("#abcdef").is_ok());
        assert!(validate_hex_color("#ABCDEF").is_ok());
        assert!(validate_hex_color("#000000").is_ok());
        assert!(validate_hex_color("#ffffff").is_ok());
    }

    #[test]
    fn validate_hex_color_invalid_formats() {
        assert!(validate_hex_color("ff0000").is_err()); // Missing #
        assert!(validate_hex_color("#fff").is_err()); // Too short
        assert!(validate_hex_color("#ff000000").is_err()); // Too long
        assert!(validate_hex_color("#gggggg").is_err()); // Invalid chars
        assert!(validate_hex_color("red").is_err()); // Named color
        assert!(validate_hex_color("").is_err());
        assert!(validate_hex_color("#").is_err());
    }

    #[test]
    fn validate_template_render_detects_unknown_filter() {
        let result = validate_template_render("{{ name | truncate(50) }}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncate"));
    }

    #[test]
    fn validate_template_render_allows_builtin_filters() {
        let result = validate_template_render("{{ name | upper | default('unknown') }}");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_template_render_allows_missing_variables() {
        let result = validate_template_render("Hello {{ undefined_var }}!");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_jinja_template_detects_syntax_errors() {
        let result = validate_jinja_template("{% if unclosed");
        assert!(result.is_err());
    }

    #[test]
    fn validate_jinja_template_accepts_valid_syntax() {
        let result = validate_jinja_template("{{ name }} - {% if x %}yes{% endif %}");
        assert!(result.is_ok());
    }

    // ============================================================
    // Issue #25: dotted-field template validation
    // ============================================================

    #[test]
    fn validate_template_render_accepts_chained_undefined() {
        // The bug: `{{ a.b.c }}` against `json!({})` returned "undefined value".
        // With TruthyChainable, chained access on undefined should resolve.
        let result = validate_template_render("{{ a.b.c }}");
        assert!(
            result.is_ok(),
            "chained undefined access should validate cleanly: {:?}",
            result
        );
    }

    #[test]
    fn validate_template_render_still_catches_filter_in_if_block() {
        // Regression guard: a straight switch to UndefinedBehavior::Chainable
        // would silently skip this `{% if %}` body (falsy undefined) and miss
        // the unknown filter. TruthyChainable keeps is_true() = true so the
        // body is walked.
        let result = validate_template_render("{% if a.b %}{{ x | nosuchfilter }}{% endif %}");
        assert!(
            result.is_err(),
            "unknown filter inside if-block should still be caught"
        );
        assert!(result.unwrap_err().contains("nosuchfilter"));
    }

    #[test]
    fn validate_template_render_catches_syntax_errors() {
        let result = validate_template_render("{{ foo.");
        assert!(result.is_err());
    }

    #[test]
    fn validate_template_render_allows_for_loop_over_undefined() {
        // Regression guard: initial TruthyChainable had NonEnumerable + Plain repr,
        // which errored on `{% for %}` even though Lenient + json!({}) didn't.
        let result = validate_template_render("{% for x in items %}{{ x }}{% endfor %}");
        assert!(
            result.is_ok(),
            "for-loop over undefined should validate cleanly: {:?}",
            result
        );
    }

    #[test]
    fn validate_template_render_allows_length_on_undefined() {
        let result = validate_template_render("{{ (items | length) > 0 }}");
        assert!(
            result.is_ok(),
            "length on undefined should validate cleanly: {:?}",
            result
        );
    }
}
