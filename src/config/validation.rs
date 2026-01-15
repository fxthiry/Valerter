//! Template and color validation utilities.

use minijinja::{Environment, UndefinedBehavior};
use regex::Regex;
use std::sync::LazyLock;

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
    tmpl.render(serde_json::json!({}))
        .map_err(|e| e.to_string())?;

    Ok(())
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
}
