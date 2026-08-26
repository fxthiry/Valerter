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
        .map_err(|e| {
            let msg = e.to_string();
            match slash_field_hint(source) {
                Some(hint) if msg.contains("/ operator") => format!("{msg}\n  hint: {hint}"),
                _ => msg,
            }
        })?;

    Ok(())
}

/// Matches an identifier path containing a `/` inside a `{{ ... }}` expression,
/// e.g. `ocp.annotations.openshift.io/username`.
static SLASH_FIELD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{[^}]*?\b([A-Za-z_][\w.]*)/([A-Za-z_][\w./-]*)").expect("valid regex")
});

/// Issue #41: VictoriaLogs field names may contain `/` (e.g. Kubernetes
/// annotations like `authentication.openshift.io/username`). In a Jinja
/// expression `/` is the division operator, so `{{ a.b.io/username }}` fails
/// to render. Returns a hint with the bracket-notation rewrite when the
/// template contains such a path.
pub(crate) fn slash_field_hint(source: &str) -> Option<String> {
    let caps = SLASH_FIELD_REGEX.captures(source)?;
    let left = &caps[1];
    let right = &caps[2];
    let (prefix, leaf) = match left.rfind('.') {
        Some(i) => (&left[..i], &left[i + 1..]),
        None => ("", left),
    };
    let rewrite = if prefix.is_empty() {
        format!("{{{{ fields[\"{leaf}/{right}\"] }}}}")
    } else {
        format!("{{{{ {prefix}[\"{leaf}/{right}\"] }}}}")
    };
    Some(format!(
        "field names containing '/' must use bracket notation, e.g. `{rewrite}` \
         (in Jinja, '/' is the division operator; see docs/configuration.md#fields-with-special-characters)"
    ))
}

/// LogsQL pipes that require the full result set and are therefore rejected
/// by the VictoriaLogs `/select/logsql/tail` endpoint with HTTP 400.
const TAIL_UNSUPPORTED_PIPES: &[&str] = &[
    "stats",
    "sort",
    "top",
    "uniq",
    "limit",
    "offset",
    "first",
    "last",
    "facets",
    "join",
    "field_names",
    "field_values",
    "block_stats",
    "blocks_count",
    "union",
];

static PIPE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\|\s*([A-Za-z_]+)\b").expect("valid regex"));

/// Issue #42: validates that a rule query only uses pipes supported by the
/// VictoriaLogs `/tail` endpoint. Valerter streams logs in real time, so
/// aggregations such as `stats by (...)` can never work and would otherwise
/// fail at runtime with an opaque `HTTP 400` retry loop.
pub(crate) fn validate_tail_query(query: &str) -> Result<(), String> {
    for caps in PIPE_REGEX.captures_iter(query) {
        let pipe = caps[1].to_ascii_lowercase();
        if TAIL_UNSUPPORTED_PIPES.contains(&pipe.as_str()) {
            return Err(format!(
                "pipe '{pipe}' is not supported by the VictoriaLogs /tail endpoint \
                 (valerter streams logs in real time; aggregations need the full result set). \
                 Use filter pipes only, or pre-aggregate upstream (e.g. vmalert) and alert on the result. \
                 See docs/configuration.md#logsql-query-restrictions"
            ));
        }
    }
    Ok(())
}

/// Validates a URL string.
///
/// The URL is deliberately NOT echoed in the error: webhook URLs carry
/// secrets and this message ends up in logs.
///
/// Values containing an unresolved `${VAR}` placeholder are accepted here;
/// they are resolved (and re-checked) when the notifier is built.
pub(crate) fn validate_url(url: &str) -> Result<(), String> {
    if url.contains("${") {
        return Ok(());
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        other => Err(format!(
            "invalid URL: unsupported scheme '{other}' (expected http or https)"
        )),
    }
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

    #[test]
    fn slash_field_hint_suggests_bracket_notation() {
        let hint =
            slash_field_hint("<b>{{ ocp.annotations.authentication.openshift.io/username }}</b>")
                .expect("hint");
        assert!(
            hint.contains(r#"{{ ocp.annotations.authentication.openshift["io/username"] }}"#),
            "{hint}"
        );
    }

    #[test]
    fn slash_field_hint_top_level_key() {
        let hint = slash_field_hint("{{ io/username }}").expect("hint");
        assert!(hint.contains(r#"{{ fields["io/username"] }}"#), "{hint}");
    }

    #[test]
    fn slash_field_hint_none_for_plain_template() {
        assert!(slash_field_hint("{{ host }} {{ a.b }}").is_none());
    }

    #[test]
    fn validate_template_render_slash_field_error_carries_hint() {
        let err = validate_template_render("{{ ocp.openshift.io/decision }}").unwrap_err();
        assert!(err.contains("/ operator"), "{err}");
        assert!(err.contains("bracket notation"), "{err}");
    }

    #[test]
    fn validate_template_render_accepts_bracket_notation_for_slash_field() {
        assert!(validate_template_render(r#"{{ ocp.openshift["io/decision"] }}"#).is_ok());
    }

    #[test]
    fn validate_tail_query_rejects_stats_pipe() {
        let q =
            "* | package_event_type:package_inventory | stats by (host) count() c | filter c:>1";
        let err = validate_tail_query(q).unwrap_err();
        assert!(err.contains("'stats'"), "{err}");
    }

    #[test]
    fn validate_tail_query_rejects_sort_and_limit() {
        assert!(validate_tail_query("error | sort by (_time)").is_err());
        assert!(validate_tail_query("error | LIMIT 10").is_err());
    }

    #[test]
    fn validate_tail_query_accepts_filter_pipes() {
        assert!(validate_tail_query(r#"_stream:{host="s1"} | json | cpu > 90"#).is_ok());
        assert!(validate_tail_query("error | extract \"<a> <b>\" | filter a:x").is_ok());
        assert!(validate_tail_query("_msg:~\"stats by\"").is_ok());
    }

    #[test]
    fn validate_url_does_not_echo_secret_and_rejects_bad_schemes() {
        let err = validate_url("htps://mm.example.com/hooks/SECRET").unwrap_err();
        assert!(!err.contains("SECRET"), "{err}");
        let err = validate_url("ftp://example.com/x").unwrap_err();
        assert!(err.contains("unsupported scheme"), "{err}");
        assert!(validate_url("https://example.com/hooks/x").is_ok());
    }

    #[test]
    fn validate_url_accepts_unresolved_env_placeholder() {
        assert!(validate_url("${MATTERMOST_WEBHOOK}").is_ok());
        assert!(validate_url("https://h/hooks/${TOKEN}").is_ok());
    }
}
