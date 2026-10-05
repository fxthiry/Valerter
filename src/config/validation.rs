//! Template and color validation utilities.

use minijinja::value::{Enumerator, Object, ObjectRepr, Value};
use minijinja::{Environment, Error, ErrorKind, State, UndefinedBehavior};
use regex::Regex;
use std::sync::{Arc, LazyLock};

/// Sentinel value used during template validation.
///
/// Issue #25: validating templates that reference dotted VictoriaLogs fields
/// (`{{ nginx.http.request_id }}`) used to fail because chained attribute access
/// against an empty `json!({})` returned `undefined` instead of another value.
///
/// `TruthyChainable` returns another sentinel on every attribute access (so
/// chains never hit `undefined`), is always truthy (so `{% if x.y %}` walks the
/// body and validates filters/syntax inside), stringifies as empty, and
/// iterates as an empty sequence (so `{% for x in tc %}` and `{{ tc | length }}`
/// do not error — matching the prior `Lenient + json!({})` behaviour).
///
/// Calling a sentinel means the template called a name that is neither a
/// global function nor a method of a real value (`{{ nosuchfunc() }}`,
/// `{{ host.nosuch() }}`): it fails with `UnknownFunction`, which
/// [`validate_template_render`] rejects.
#[derive(Debug)]
struct TruthyChainable {
    name: String,
}

impl Object for TruthyChainable {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }

    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        Some(TruthyChainable::named(key))
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Empty
    }

    fn is_true(self: &Arc<Self>) -> bool {
        true
    }

    fn call(self: &Arc<Self>, _state: &State<'_, '_>, _args: &[Value]) -> Result<Value, Error> {
        Err(Error::new(
            ErrorKind::UnknownFunction,
            format!("{} is not a known function or method", self.name),
        ))
    }

    fn render(self: &Arc<Self>, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl TruthyChainable {
    fn named(key: &Value) -> Value {
        let name = key.as_str().map_or_else(|| key.to_string(), str::to_string);
        Value::from_object(TruthyChainable { name })
    }
}

/// Root context of a validation render: every top-level name is a
/// [`TruthyChainable`], except the environment's globals (`range`, `dict`,
/// `namespace`…), which must stay reachable as in a real render.
#[derive(Debug)]
struct ValidationRoot {
    globals: Vec<String>,
}

impl Object for ValidationRoot {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        let name = key.as_str()?;
        if self.globals.iter().any(|g| g == name) {
            return None;
        }
        Some(TruthyChainable::named(key))
    }
}

/// Validates Jinja template syntax.
pub(crate) fn validate_jinja_template(source: &str) -> Result<(), String> {
    let mut env = Environment::new();
    env.add_template("_validate", source)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates a Jinja template by performing a test render against a sentinel
/// context where every field is defined and truthy.
///
/// The sentinel cannot stand for every real value (a sequence is not a number
/// or a string), so only errors that do not depend on the event's values are
/// reported: syntax errors, unknown filters, tests, functions and methods, and
/// the `/` operator applied to a field path (issue #41). Any other runtime
/// error (`| int`, `| float`, `| round`, arithmetic…) is caused by the fake
/// context and accepted.
///
/// # Errors
/// Returns an error string if the template syntax is invalid, uses an unknown
/// filter, test, function or method, or divides field paths.
pub fn validate_template_render(source: &str) -> Result<(), String> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Lenient);
    env.add_template("_render_test", source)
        .map_err(|e| e.to_string())?;

    let tmpl = env
        .get_template("_render_test")
        .map_err(|e| e.to_string())?;
    let root = ValidationRoot {
        globals: env.globals().map(|(name, _)| name.to_string()).collect(),
    };
    let Err(err) = tmpl.render(Value::from_object(root)) else {
        return Ok(());
    };

    let msg = err.to_string();
    match err.kind() {
        ErrorKind::SyntaxError
        | ErrorKind::UnknownFilter
        | ErrorKind::UnknownTest
        | ErrorKind::UnknownFunction
        | ErrorKind::UnknownMethod => Err(msg),
        ErrorKind::InvalidOperation if msg.contains("/ operator") => {
            match slash_field_hint(source) {
                Some(hint) => Err(format!("{msg}\n  hint: {hint}")),
                None => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

/// Checks a notifier-level template (`body_template`, `subject_template`):
/// syntax first, then a render test (see [`validate_template_render`]).
/// Errors read `<field>: <error>` or `<field> render: <error>`.
///
/// Called when notifiers are built, so the check runs at daemon startup and
/// in `--validate` (preflight), never in `Config::validate()`.
pub fn validate_notifier_template(field: &str, source: &str) -> Result<(), String> {
    validate_jinja_template(source).map_err(|e| format!("{field}: {e}"))?;
    validate_template_render(source).map_err(|e| format!("{field} render: {e}"))
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
/// template contains such a path. A top-level field (`{{ io/username }}`) has
/// no parent object to index, so the hint suggests renaming it in the query.
pub(crate) fn slash_field_hint(source: &str) -> Option<String> {
    let caps = SLASH_FIELD_REGEX.captures(source)?;
    let left = &caps[1];
    let right = &caps[2];
    let Some((prefix, leaf)) = left.rsplit_once('.') else {
        let field = format!("{left}/{right}");
        let renamed = field.replace(['/', '.', '-'], "_");
        return Some(format!(
            "field names containing '/' must use bracket notation on their parent object; \
             a top-level field like '{field}' has no parent and cannot be referenced directly: \
             rename it in the rule query, e.g. `| rename \"{field}\" as {renamed}`, then use `{{{{ {renamed} }}}}` \
             (see docs/configuration.md#fields-with-special-characters)"
        ));
    };
    let rewrite = format!("{{{{ {prefix}[\"{leaf}/{right}\"] }}}}");
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
/// they are resolved (and re-checked with [`validate_resolved_url`]) when the
/// notifier is built.
pub(crate) fn validate_url(url: &str) -> Result<(), String> {
    if url.contains("${") {
        return Ok(());
    }
    validate_resolved_url(url)
}

/// Validates a URL whose `${VAR}` placeholders have already been resolved:
/// it must parse and use the `http` or `https` scheme. No exception is made
/// for a value still containing `${`.
///
/// Like [`validate_url`], the URL is never echoed in the error.
pub fn validate_resolved_url(url: &str) -> Result<(), String> {
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
    fn slash_field_hint_top_level_key_suggests_rename() {
        let hint = slash_field_hint("{{ io/username }}").expect("hint");
        assert!(hint.contains("rename"), "{hint}");
        assert!(
            hint.contains(r#"| rename "io/username" as io_username"#),
            "{hint}"
        );
        assert!(hint.contains("{{ io_username }}"), "{hint}");
        assert!(!hint.contains("fields["), "{hint}");
    }

    #[test]
    fn validate_template_render_top_level_slash_field_is_rejected_with_rename_hint() {
        let err = validate_template_render("{{ io/username }}").unwrap_err();
        assert!(err.contains("/ operator"), "{err}");
        assert!(err.contains("rename"), "{err}");
        assert!(!err.contains("fields["), "{err}");
    }

    // ============================================================
    // D1: only value-independent errors fail the render test
    // ============================================================

    #[test]
    fn validate_template_render_accepts_type_conversions_on_fields() {
        for source in [
            "{{ status | int }}",
            "{{ latency | float }}",
            "{{ (latency | float) > 1.5 }}",
            "{{ ratio | round }}",
            "{{ delta | abs }}",
            "{{ tags | split(',') | first }}",
            "{{ count + 1 }}",
            "{{ host }}-{{ status | int }}",
        ] {
            assert!(
                validate_template_render(source).is_ok(),
                "{source} should validate: {:?}",
                validate_template_render(source)
            );
        }
    }

    #[test]
    fn validate_template_render_rejects_unknown_test() {
        let err = validate_template_render("{% if host is nosuchtest %}x{% endif %}").unwrap_err();
        assert!(err.contains("nosuchtest"), "{err}");
    }

    #[test]
    fn validate_template_render_rejects_unknown_function() {
        let err = validate_template_render("{{ nosuchfunc() }}").unwrap_err();
        assert!(err.contains("nosuchfunc"), "{err}");
    }

    #[test]
    fn validate_template_render_rejects_unknown_method() {
        let err = validate_template_render("{{ host.nosuchmethod() }}").unwrap_err();
        assert!(err.contains("nosuchmethod"), "{err}");
        let err = validate_template_render("{{ 'a'.upper() }}").unwrap_err();
        assert!(err.contains("upper"), "{err}");
    }

    #[test]
    fn validate_template_render_keeps_global_functions_reachable() {
        assert!(validate_template_render("{% for i in range(3) %}{{ i }}{% endfor %}").is_ok());
        assert!(validate_template_render("{% set ns = namespace(n=0) %}{{ ns.n }}").is_ok());
    }

    #[test]
    fn validate_template_render_accepts_escaping_filters() {
        assert!(validate_template_render("{{ title | tojson }} {{ body | e }}").is_ok());
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
    fn validate_resolved_url_rejects_bad_scheme_without_echoing_url() {
        let err = validate_resolved_url("ftp://vl.example.com:9428/SECRET").unwrap_err();
        assert_eq!(
            err,
            "invalid URL: unsupported scheme 'ftp' (expected http or https)"
        );
        let err = validate_resolved_url("not a url SECRET").unwrap_err();
        assert!(err.starts_with("invalid URL:"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }

    #[test]
    fn validate_resolved_url_has_no_placeholder_exception() {
        let err = validate_resolved_url("${VL_URL}").unwrap_err();
        assert!(err.starts_with("invalid URL:"), "{err}");
        assert!(validate_resolved_url("https://vl.example.com:9428").is_ok());
    }

    #[test]
    fn validate_url_accepts_unresolved_env_placeholder() {
        assert!(validate_url("${MATTERMOST_WEBHOOK}").is_ok());
        assert!(validate_url("https://h/hooks/${TOKEN}").is_ok());
    }
}
