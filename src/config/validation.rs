//! Template and color validation utilities.

use minijinja::value::{Enumerator, Object, ObjectRepr, Rest, Value};
use minijinja::{Environment, Error, ErrorKind, State, UndefinedBehavior};
use regex::Regex;
use std::sync::{Arc, LazyLock};

/// Which branch a validation render explores (see [`validate_template_render`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// Every condition on a field is true and every loop over a field
    /// iterates one element.
    Truthy,
    /// Every condition on a field is false, every loop is empty and the
    /// `defined` test is false for a field.
    Falsy,
}

/// Sentinel value used during template validation.
///
/// Issue #25: validating templates that reference dotted VictoriaLogs fields
/// (`{{ nginx.http.request_id }}`) used to fail because chained attribute access
/// against an empty `json!({})` returned `undefined` instead of another value.
///
/// `TruthyChainable` returns another sentinel on every attribute access (so
/// chains never hit `undefined`) and stringifies as empty. Its truthiness and
/// iteration depend on the [`Pass`]: in the truthy pass it is true and a
/// non-leaf sentinel iterates one leaf sentinel (so `{% for x in tc %}` walks
/// the body), in the falsy pass it is false and iterates as an empty sequence
/// (so `else` branches and `{% if not x %}` bodies are walked). A leaf always
/// iterates as an empty sequence: without it `{{ tc | tojson }}` would recurse
/// forever.
///
/// Calling a sentinel means the template called a name that is neither a
/// global function nor a method of a real value (`{{ nosuchfunc() }}`,
/// `{{ host.nosuch() }}`): it fails with `UnknownFunction`, which
/// [`validate_template_render`] rejects.
#[derive(Debug)]
struct TruthyChainable {
    name: String,
    pass: Pass,
    leaf: bool,
}

impl Object for TruthyChainable {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }

    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        Some(TruthyChainable::named(key, self.pass))
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        if self.pass == Pass::Truthy && !self.leaf {
            Enumerator::Values(vec![TruthyChainable::leaf(&self.name, self.pass)])
        } else {
            Enumerator::Empty
        }
    }

    fn is_true(self: &Arc<Self>) -> bool {
        self.pass == Pass::Truthy
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
    fn named(key: &Value, pass: Pass) -> Value {
        let name = key.as_str().map_or_else(|| key.to_string(), str::to_string);
        Value::from_object(TruthyChainable {
            name,
            pass,
            leaf: false,
        })
    }

    fn leaf(name: &str, pass: Pass) -> Value {
        Value::from_object(TruthyChainable {
            name: name.to_string(),
            pass,
            leaf: true,
        })
    }
}

fn is_sentinel(value: &Value) -> bool {
    value.downcast_object_ref::<TruthyChainable>().is_some()
}

/// Root context of a validation render: every top-level name is a
/// [`TruthyChainable`], except the environment's globals (`range`, `dict`,
/// `namespace`…), which must stay reachable as in a real render.
#[derive(Debug)]
struct ValidationRoot {
    globals: Vec<String>,
    pass: Pass,
}

impl Object for ValidationRoot {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        let name = key.as_str()?;
        if self.globals.iter().any(|g| g == name) {
            return None;
        }
        Some(TruthyChainable::named(key, self.pass))
    }
}

/// Errors that do not depend on the event's values: the only ones a
/// validation render reports (besides the `/` operator on a field path).
fn is_value_independent(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::SyntaxError
            | ErrorKind::UnknownFilter
            | ErrorKind::UnknownTest
            | ErrorKind::UnknownFunction
            | ErrorKind::UnknownMethod
    )
}

/// The built-in filters of minijinja 2.24 with the `builtins`, `json` and
/// `urlencode` features (keep in sync with `build_builtin_filters` in minijinja's
/// `defaults.rs`; `builtin_filter_wrappers_still_report_unknown_filters`
/// guards the list). Wrapped in the validation environment together with
/// valerter's own filters ([`crate::template::filters::valerter_filters`]),
/// so the validation environment stays faithful to production.
fn builtin_filters() -> Vec<(&'static str, Value)> {
    use minijinja::filters as f;
    vec![
        ("safe", Value::from_function(f::safe)),
        ("escape", Value::from_function(f::escape)),
        ("e", Value::from_function(f::escape)),
        ("lower", Value::from_function(f::lower)),
        ("upper", Value::from_function(f::upper)),
        ("title", Value::from_function(f::title)),
        ("capitalize", Value::from_function(f::capitalize)),
        ("replace", Value::from_function(f::replace)),
        ("length", Value::from_function(f::length)),
        ("count", Value::from_function(f::length)),
        ("dictsort", Value::from_function(f::dictsort)),
        ("items", Value::from_function(f::items)),
        ("reverse", Value::from_function(f::reverse)),
        ("trim", Value::from_function(f::trim)),
        ("join", Value::from_function(f::join)),
        ("split", Value::from_function(f::split)),
        ("lines", Value::from_function(f::lines)),
        ("default", Value::from_function(f::default)),
        ("d", Value::from_function(f::default)),
        ("round", Value::from_function(f::round)),
        ("abs", Value::from_function(f::abs)),
        ("int", Value::from_function(f::int)),
        ("float", Value::from_function(f::float)),
        ("attr", Value::from_function(f::attr)),
        ("first", Value::from_function(f::first)),
        ("last", Value::from_function(f::last)),
        ("min", Value::from_function(f::min)),
        ("max", Value::from_function(f::max)),
        ("sort", Value::from_function(f::sort)),
        ("list", Value::from_function(f::list)),
        ("string", Value::from_function(f::string)),
        ("bool", Value::from_function(f::bool)),
        ("batch", Value::from_function(f::batch)),
        ("slice", Value::from_function(f::slice)),
        ("sum", Value::from_function(f::sum)),
        ("indent", Value::from_function(f::indent)),
        ("select", Value::from_function(f::select)),
        ("reject", Value::from_function(f::reject)),
        ("selectattr", Value::from_function(f::selectattr)),
        ("rejectattr", Value::from_function(f::rejectattr)),
        ("map", Value::from_function(f::map)),
        ("groupby", Value::from_function(f::groupby)),
        ("unique", Value::from_function(f::unique)),
        ("chain", Value::from_function(f::chain)),
        ("zip", Value::from_function(f::zip)),
        ("pprint", Value::from_function(f::pprint)),
        ("format", Value::from_function(f::format)),
        ("tojson", Value::from_function(f::tojson)),
        ("urlencode", Value::from_function(f::urlencode)),
    ]
}

/// Value returned by a wrapped built-in filter that failed on a sentinel:
/// a number after a conversion (so `{{ count | int + 1 }}` keeps rendering),
/// one sentinel pair for `items`/`dictsort` (so `{% for k, v in m | items %}`
/// walks its body), a leaf sentinel otherwise (so chaining continues).
fn filter_substitute(name: &str, pass: Pass) -> Value {
    match name {
        "int" | "abs" => Value::from(0),
        "float" | "round" => Value::from(0.0),
        "items" | "dictsort" if pass == Pass::Truthy => Value::from(vec![Value::from(vec![
            TruthyChainable::leaf(name, pass),
            TruthyChainable::leaf(name, pass),
        ])]),
        "items" | "dictsort" => Value::from(Vec::<Value>::new()),
        _ => TruthyChainable::leaf(name, pass),
    }
}

/// Wraps a filter or function so that a failure caused by a sentinel
/// argument returns [`filter_substitute`] instead of stopping the render.
fn wrap(
    name: &'static str,
    callable: Value,
    pass: Pass,
) -> impl Fn(&State, Rest<Value>) -> Result<Value, Error> + Send + Sync + 'static {
    move |state: &State, args: Rest<Value>| -> Result<Value, Error> {
        match callable.call(state, &args) {
            Err(err) if !is_value_independent(err.kind()) && args.iter().any(is_sentinel) => {
                Ok(filter_substitute(name, pass))
            }
            other => other,
        }
    }
}

/// Builds the environment of a validation render: lenient undefined values
/// as in production, every built-in and valerter filter and valerter's
/// functions wrapped (see [`wrap`]), the Markdown auto-escaping of a
/// `body_format: markdown` body when `markdown` is set, and, in the falsy
/// pass, `defined`/`undefined` tests that treat a sentinel as undefined (so
/// `{% if x is not defined %}` bodies are walked).
///
/// The Markdown formatter is required: without it, minijinja's default
/// formatter fails on the first value written, an error that depends on the
/// values and is therefore accepted, which would end the pass silently.
fn validation_env(pass: Pass, markdown: bool) -> Environment<'static> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Lenient);
    if markdown {
        crate::template::filters::install_markdown_escape(&mut env);
    }
    let filters = builtin_filters()
        .into_iter()
        .chain(crate::template::filters::valerter_filters());
    for (name, filter) in filters {
        env.add_filter(name, wrap(name, filter, pass));
    }
    // Globals: reachable through `ValidationRoot`, which skips them.
    for (name, function) in crate::template::filters::valerter_functions() {
        env.add_global(name, Value::from_function(wrap(name, function, pass)));
    }
    if pass == Pass::Falsy {
        env.add_test("defined", |v: &Value| !v.is_undefined() && !is_sentinel(v));
        env.add_test("undefined", |v: &Value| v.is_undefined() || is_sentinel(v));
    }
    env
}

/// Validates Jinja template syntax.
pub(crate) fn validate_jinja_template(source: &str) -> Result<(), String> {
    let mut env = Environment::new();
    env.add_template("_validate", source)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates a Jinja template by performing two test renders against a
/// sentinel context where every field is defined: a truthy pass (conditions
/// true, loops over a field iterate one element) then a falsy pass
/// (conditions false, loops empty, `is defined` false), so `else` branches,
/// `{% if not x %}`, `is not defined` and loop bodies are all checked. The
/// first rejected error is returned.
///
/// The sentinel cannot stand for every real value (a sequence is not a number
/// or a string), so only errors that do not depend on the event's values are
/// reported: syntax errors, unknown filters, tests, functions and methods, and
/// the `/` operator applied to a field path (issue #41). A built-in filter
/// applied to a field (`| int`, `| float`, `| round`, `| split`, `| upper`…)
/// does not stop the render: it returns a substitute value and the rest of the
/// template is still checked. Any other runtime error (arithmetic on a raw
/// field, `{{ count + 1 }}`…) is caused by the fake context and accepted, but
/// stops the current pass. The body of an `elif` is reached by neither pass.
///
/// # Errors
/// Returns an error string if the template syntax is invalid, uses an unknown
/// filter, test, function or method, or divides field paths.
pub fn validate_template_render(source: &str) -> Result<(), String> {
    render_pass(source, Pass::Truthy, false)?;
    render_pass(source, Pass::Falsy, false)
}

/// [`validate_template_render`] for the `body` of a `body_format: markdown`
/// template, rendered with the Markdown auto-escaping as in production.
pub fn validate_markdown_template_render(source: &str) -> Result<(), String> {
    render_pass(source, Pass::Truthy, true)?;
    render_pass(source, Pass::Falsy, true)
}

fn render_pass(source: &str, pass: Pass, markdown: bool) -> Result<(), String> {
    let mut env = validation_env(pass, markdown);
    env.add_template("_render_test", source)
        .map_err(|e| e.to_string())?;

    let tmpl = env
        .get_template("_render_test")
        .map_err(|e| e.to_string())?;
    let root = ValidationRoot {
        globals: env.globals().map(|(name, _)| name.to_string()).collect(),
        pass,
    };
    let Err(err) = tmpl.render(Value::from_object(root)) else {
        return Ok(());
    };

    let msg = err.to_string();
    match err.kind() {
        kind if is_value_independent(kind) => Err(msg),
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
/// template contains such a path. A top-level field (`{{ io/user-name }}`) has
/// no parent object to index, so the hint suggests renaming it in the query.
///
/// Only paths whose left side is dotted (`a.b/c`) or whose right side contains
/// `.`, `-` or `/` are field paths: `{{ total/count }}` is a division between
/// two plain identifiers and gets no hint.
pub(crate) fn slash_field_hint(source: &str) -> Option<String> {
    let caps = SLASH_FIELD_REGEX
        .captures_iter(source)
        .find(|caps| caps[1].contains('.') || caps[2].contains(['.', '-', '/']))?;
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
/// Like `validate_url`, the URL is never echoed in the error.
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
        let hint = slash_field_hint("{{ io/user-name }}").expect("hint");
        assert!(hint.contains("rename"), "{hint}");
        assert!(
            hint.contains(r#"| rename "io/user-name" as io_user_name"#),
            "{hint}"
        );
        assert!(hint.contains("{{ io_user_name }}"), "{hint}");
        assert!(!hint.contains("fields["), "{hint}");
    }

    #[test]
    fn validate_template_render_top_level_slash_field_is_rejected_with_rename_hint() {
        let err = validate_template_render("{{ io/user-name }}").unwrap_err();
        assert!(err.contains("/ operator"), "{err}");
        assert!(err.contains("rename"), "{err}");
        assert!(!err.contains("fields["), "{err}");
    }

    #[test]
    fn validate_template_render_accepts_division_between_plain_identifiers() {
        assert!(slash_field_hint("{{ total/count }}").is_none());
        assert!(
            validate_template_render("{{ total/count }}").is_ok(),
            "{:?}",
            validate_template_render("{{ total/count }}")
        );
        // A later dotted field path is still detected.
        let hint = slash_field_hint("{{ total/count }} {{ a.b/c }}").expect("hint");
        assert!(hint.contains(r#"{{ a["b/c"] }}"#), "{hint}");
    }

    // ============================================================
    // Two-pass render test with wrapped built-in filters
    // ============================================================

    #[test]
    fn sentinel_tojson_and_nested_loops_do_not_overflow() {
        for pass in [Pass::Truthy, Pass::Falsy] {
            let env = validation_env(pass, false);
            let root = || {
                Value::from_object(ValidationRoot {
                    globals: Vec::new(),
                    pass,
                })
            };
            env.render_str("{{ a | tojson }}", root())
                .expect("tojson on a sentinel");
            env.render_str(
                "{% for x in a %}{% for y in x %}{{ y }}{% endfor %}{% endfor %}",
                root(),
            )
            .expect("nested loops on a sentinel");
        }
    }

    #[test]
    fn validation_env_keeps_builtin_filter_results() {
        for pass in [Pass::Truthy, Pass::Falsy] {
            let env = validation_env(pass, false);
            assert_eq!(env.render_str("{{ '7' | int + 1 }}", ()).unwrap(), "8");
            assert_eq!(
                env.render_str("{{ 3.14159 | round(2) }}", ()).unwrap(),
                "3.14"
            );
            assert_eq!(
                env.render_str(
                    "{{ 'a,c,b' | split(',') | sort(reverse=true) | join('') }}",
                    ()
                )
                .unwrap(),
                "cba"
            );
        }
    }

    #[test]
    fn validate_template_render_rejects_unknown_filter_after_builtin_filter() {
        for source in [
            "{{ status | int }}-{{ host | truncat(10) }}",
            "{{ x | float | round(2) }} {{ y | nosuch }}",
            "{{ host | split('.') | first }} {{ host | nosuch }}",
        ] {
            let err = validate_template_render(source).unwrap_err();
            assert!(
                err.contains("truncat") || err.contains("nosuch"),
                "{source}: {err}"
            );
        }
    }

    #[test]
    fn validate_template_render_rejects_unknown_filter_in_alternative_branch() {
        for source in [
            "{% if a %}ok{% else %}{{ a | nosuch }}{% endif %}",
            "{% if not a %}{{ a | nosuch }}{% endif %}",
            "{% if a is not defined %}{{ a | nosuch }}{% endif %}",
            "{% if a is undefined %}{{ a | nosuch }}{% endif %}",
        ] {
            let err = validate_template_render(source).unwrap_err();
            assert!(err.contains("nosuch"), "{source}: {err}");
        }
    }

    #[test]
    fn validate_template_render_rejects_unknown_filter_in_loop_body() {
        for source in [
            "{% for i in items %}{{ i | nosuch }}{% endfor %}",
            "{% for k, v in m | items %}{{ v | nosuch }}{% endfor %}",
            "{% for k, v in m | dictsort %}{{ k | nosuch }}{% endfor %}",
        ] {
            let err = validate_template_render(source).unwrap_err();
            assert!(err.contains("nosuch"), "{source}: {err}");
        }
    }

    #[test]
    fn validate_template_render_accepts_common_builtin_filters_on_fields() {
        for source in [
            "{{ status | int }} {{ (latency | float) > 1.5 }} {{ count + 1 }}",
            "{{ a | length }} {{ a | join(',') }} {{ a | default('x') | upper }} \
             {{ a | replace('a', 'b') | lower | trim }} {{ a | tojson }} {{ a | dictsort }} \
             {{ count | int + 1 }}",
            "{{ a | sum }} {{ a | max }} {{ a | min }} {{ a | sort }} {{ a | unique }} \
             {{ a | reverse }} {{ a | batch(2) }}",
            "{% set ns = namespace(n=0) %}{% for i in items %}{% set ns.n = ns.n + 1 %}{% endfor %}{{ ns.n }}",
            "{% if status == '500' %}x{% elif status > 3 %}y{% endif %}",
            "{% if a is defined %}{{ a }}{% else %}none{% endif %}",
        ] {
            assert!(
                validate_template_render(source).is_ok(),
                "{source}: {:?}",
                validate_template_render(source)
            );
        }
    }

    /// Guard for minijinja upgrades: every wrapped built-in or valerter filter,
    /// applied to a field, must let the render reach the unknown filter that
    /// follows.
    #[test]
    fn builtin_filter_wrappers_still_report_unknown_filters() {
        let required_args = |name: &str| match name {
            "replace" => "('a', 'b')",
            "attr" | "selectattr" | "rejectattr" | "groupby" => "('a')",
            "batch" | "slice" | "indent" => "(2)",
            "map" => "('upper')",
            "chain" | "zip" => "(y)",
            _ => "",
        };
        let filters = builtin_filters()
            .into_iter()
            .chain(crate::template::filters::valerter_filters());
        for (name, _) in filters {
            let source = format!(
                "{{{{ x | {name}{} }}}}{{{{ y | nosuchfilter }}}}",
                required_args(name)
            );
            for validate in [validate_template_render, validate_markdown_template_render] {
                let err = validate(&source).expect_err(&format!("{source} should be rejected"));
                assert!(err.contains("nosuchfilter"), "{source}: {err}");
            }
        }
        for (name, _) in crate::template::filters::valerter_functions() {
            let source = format!("{{{{ {name}(x, y) }}}}{{{{ y | nosuchfilter }}}}");
            for validate in [validate_template_render, validate_markdown_template_render] {
                let err = validate(&source).expect_err(&format!("{source} should be rejected"));
                assert!(err.contains("nosuchfilter"), "{source}: {err}");
            }
        }
    }

    /// The guard above iterates the lists: these entries must stay in them,
    /// or the test render would refuse filters that production knows.
    #[test]
    fn wrapped_lists_hold_urlencode_tojson_and_md_link() {
        let filters: Vec<_> = builtin_filters()
            .into_iter()
            .chain(crate::template::filters::valerter_filters())
            .map(|(name, _)| name)
            .collect();
        assert!(filters.contains(&"urlencode"), "{filters:?}");
        assert!(filters.contains(&"tojson"), "{filters:?}");
        let functions: Vec<_> = crate::template::filters::valerter_functions()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(functions, ["md_link"]);
        for validate in [validate_template_render, validate_markdown_template_render] {
            assert_eq!(
                validate("{{ x | urlencode }} {{ x | tojson }} {{ md_link(x, y) }}"),
                Ok(())
            );
            let err = validate("{{ host | urlencode }} {{ host | nosuch }}").unwrap_err();
            assert!(err.contains("nosuch"), "{err}");
        }
    }

    // ============================================================
    // Markdown bodies (markdown-body-format)
    // ============================================================

    /// Without the Markdown formatter, the first value written would fail
    /// (accepted as value-dependent) and hide the unknown filter after it.
    #[test]
    fn markdown_render_reports_unknown_filter_after_an_escaped_value() {
        let err = validate_markdown_template_render("{{ host }} {{ host | nosuch }}")
            .expect_err("unknown filter must be reported");
        assert!(err.contains("nosuch"), "{err}");
    }

    #[test]
    fn markdown_render_accepts_markdown_filters() {
        let source = "{{ _msg | codeblock('json') }} {{ host | code }} \
            {{ md_link(host, url ~ (host | urlencode)) }} \
            {{ x | safe }} {{ x | tojson }} {{ x | e }} {{ x | md_escape }} \
            {% autoescape false %}{{ x }}{% endautoescape %}";
        assert_eq!(validate_markdown_template_render(source), Ok(()));
        assert_eq!(validate_template_render(source), Ok(()));
    }

    #[test]
    fn markdown_render_rejects_unknown_function() {
        let err = validate_markdown_template_render("{{ lnk(a, b) }}").unwrap_err();
        assert!(err.contains("lnk"), "{err}");
    }

    #[test]
    fn notifier_template_reports_unknown_filter_after_md_link() {
        let err = validate_notifier_template(
            "body_template",
            "{{ md_link(log.a, log.b) }} {{ log.c | nosuch }}",
        )
        .unwrap_err();
        assert!(err.contains("body_template render"), "{err}");
        assert!(err.contains("nosuch"), "{err}");
    }

    #[test]
    fn validate_template_render_reports_unknown_filter_after_valerter_filter() {
        let err = validate_template_render("{{ host | md_escape }} {{ host | nosuch }}")
            .expect_err("unknown filter must be reported");
        assert!(err.contains("nosuch"), "{err}");
    }

    #[test]
    fn validate_notifier_template_accepts_valerter_filters_on_log_fields() {
        let source = "{{ log.host | mdv2_escape }} {{ log.msg | md_escape | upper }}";
        assert_eq!(validate_notifier_template("body_template", source), Ok(()));
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
