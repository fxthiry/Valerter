//! Filters valerter registers in every minijinja environment, on top of
//! minijinja's built-in filters.
//!
//! [`valerter_filters`] is the single list: [`register`] adds it to the
//! rendering environments (rule templates, `throttle.key`, notifier
//! templates) and the validation environment wraps the same list, so a
//! template accepted by `--validate` renders the same way in production.

use crate::markdown::{self, MarkdownElement};
use minijinja::value::{Kwargs, Object, Rest};
use minijinja::{AutoEscape, Environment, Error, State, Value};
use std::sync::Mutex;

/// Name of the auto-escape mode of a Markdown body (`body_format: markdown`).
pub const MARKDOWN_AUTO_ESCAPE: &str = "markdown";

/// Characters escaped by [`md_escape`]: the escape set of Mattermost's
/// Markdown engine (`inline.escape` of the `mattermost/marked` fork), all of
/// them escapable in CommonMark too. Other ASCII punctuation (`:`, `/`, `<`,
/// `&`…) is left alone, as Mattermost would show the backslash.
const MD_ESCAPE_CHARS: &[char] = &[
    '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '>', '|', '~',
];

/// Characters escaped by [`mdv2_escape`]: the 18 reserved characters of
/// Telegram MarkdownV2, plus the backslash, which the Bot API also requires
/// to be escaped.
const MDV2_ESCAPE_CHARS: &[char] = &[
    '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!', '\\',
];

/// Text of a value given to a Markdown filter (see [`value_text`]), its
/// token characters neutralised ([`markdown::neutralise_tokens`]).
fn element_text(value: &Value) -> String {
    markdown::neutralise_tokens(&value_text(value))
}

/// Converts `value` to a string: `none` and an undefined value give an empty
/// string, a number its usual form.
fn value_text(value: &Value) -> String {
    if value.is_none() || value.is_undefined() {
        return String::new();
    }
    value.to_string()
}

/// Converts `value` to a string (see [`value_text`]) and prefixes each
/// character of `set` with a backslash.
fn escape_with(value: &Value, set: &[char]) -> String {
    let text = value_text(value);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if set.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Whether the template being rendered is a Markdown body.
fn in_markdown(state: &State) -> bool {
    state.auto_escape() == AutoEscape::Custom(MARKDOWN_AUTO_ESCAPE)
}

/// Name of the state temp holding the [`Slots`] of a Markdown body render.
const SLOTS: &str = "valerter.markdown.slots";

/// Elements written by the formatter of a Markdown body, in token order: a
/// token's index is the element's position.
#[derive(Debug, Default)]
struct Slots(Mutex<Vec<MarkdownElement>>);

impl Object for Slots {}

/// Element produced by a Markdown filter: a [`MarkdownElement`] in a Markdown
/// body (written as a token by the formatter), its Markdown source as an
/// ordinary string elsewhere, escaped by the context (HTML in
/// `email_body_html`).
fn markdown_value(state: &State, element: MarkdownElement) -> Value {
    if in_markdown(state) {
        Value::from_object(element)
    } else {
        Value::from(element.to_string())
    }
}

/// Sets up the auto-escaping of a Markdown body in `env`: every template is
/// rendered in the [`MARKDOWN_AUTO_ESCAPE`] mode, where an inserted value has
/// all its ASCII punctuation escaped ([`markdown::escape`]) unless it is safe
/// (`| safe`), and an element of `code`, `codeblock` or `md_link` is written
/// as a token ([`markdown::TOKEN_OPEN`]) and kept in the slots of the render
/// ([`render_markdown`]). Other modes (`{% autoescape %}` blocks) keep
/// minijinja's formatting.
///
/// The formatter is required: minijinja's default one fails on a custom
/// mode, at render time as in a validation render.
pub fn install_markdown_escape(env: &mut Environment<'_>) {
    env.set_auto_escape_callback(|_| AutoEscape::Custom(MARKDOWN_AUTO_ESCAPE));
    env.set_formatter(|out, state, value| {
        if !in_markdown(state) {
            return minijinja::escape_formatter(out, state, value);
        }
        if let Some(element) = value.downcast_object_ref::<MarkdownElement>() {
            let slots = state.get_or_set_temp_object(SLOTS, Slots::default);
            let mut slots = slots.0.lock().expect("slots lock");
            slots.push(element.clone());
            let index = slots.len() - 1;
            return write!(
                out,
                "{}{index}{}",
                markdown::TOKEN_OPEN,
                markdown::TOKEN_CLOSE
            )
            .map_err(Error::from);
        }
        let written = match value.as_str() {
            Some(text) if value.is_safe() => out.write_str(text),
            _ => out.write_str(&markdown::escape(&value.to_string())),
        };
        written.map_err(Error::from)
    });
}

/// Renders the Markdown body `source` in `env` (set up by
/// [`install_markdown_escape`]): the Markdown source, holding tokens, and the
/// elements they stand for, to be passed to [`markdown::render`].
pub fn render_markdown<S: serde::Serialize>(
    env: &Environment<'_>,
    source: &str,
    ctx: S,
) -> Result<(String, Vec<MarkdownElement>), Error> {
    let rendered = env.template_from_str(source)?.render_captured(ctx)?;
    let slots = rendered
        .state()
        .get_temp(SLOTS)
        .and_then(|slots| slots.downcast_object::<Slots>())
        .map(|slots| std::mem::take(&mut *slots.0.lock().expect("slots lock")))
        .unwrap_or_default();
    Ok((rendered.into_output(), slots))
}

/// `md_escape` filter: escapes a value for a CommonMark body rendered by
/// Mattermost, so it shows literally. `<` and `&` are not neutralised. In a
/// Markdown body it is the automatic escaping, returned as a safe value (no
/// double escaping).
pub fn md_escape(state: &State, value: &Value) -> Value {
    if in_markdown(state) {
        return Value::from_safe_string(markdown::escape(&value_text(value)));
    }
    Value::from(escape_with(value, MD_ESCAPE_CHARS))
}

/// `mdv2_escape` filter: escapes a value for Telegram MarkdownV2 text outside
/// `pre` and `code` entities.
pub fn mdv2_escape(value: &Value) -> String {
    escape_with(value, MDV2_ESCAPE_CHARS)
}

/// `code` filter: a Markdown code span showing the value literally
/// ([`markdown::code_span`]; a line break becomes a space). An empty value
/// gives an empty string.
pub fn code(state: &State, value: &Value) -> Value {
    let text = element_text(value).replace(['\r', '\n'], " ");
    if text.is_empty() {
        return Value::from("");
    }
    markdown_value(state, MarkdownElement::Code(text))
}

/// `codeblock(lang)` filter: a fenced code block showing the value literally,
/// with a fence of backticks longer than any run in the value (at least
/// three). The language keeps only `A-Z`, `a-z`, `0-9`, `_`, `+`, `-`, `.`
/// and `#`. In a Markdown body, the block may be written anywhere: where a
/// block cannot stand (in an emphasis, a heading, a link), it becomes a code
/// span.
pub fn codeblock(state: &State, value: &Value, lang: Option<Value>) -> Value {
    let text = element_text(value);
    let lang: String = lang
        .as_ref()
        .map(value_text)
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | '#'))
        .collect();
    markdown_value(state, MarkdownElement::CodeBlock { lang, text })
}

/// `md_link(text, url)` function: a Markdown link whose text is literal and
/// whose destination is [encoded](markdown::encode_destination); for a scheme
/// other than `http`, `https` or `mailto`, the text followed by the URL in
/// parentheses, without a link.
pub fn md_link(state: &State, text: &Value, url: &Value) -> Value {
    let text = element_text(text);
    let url = element_text(url);
    let element = if markdown::allowed_scheme(&url) {
        MarkdownElement::Link {
            text,
            dest: markdown::encode_destination(&url),
        }
    } else {
        MarkdownElement::Text(format!("{text} ({url})"))
    };
    markdown_value(state, element)
}

/// `tojson` filter: minijinja's, whose result is safe (HTML and JSON), except
/// in a Markdown body, where it is an ordinary string, escaped as any value:
/// only `| safe` inserts a value as is.
pub fn tojson(
    state: &State,
    value: &Value,
    indent: Option<Value>,
    kwargs: Kwargs,
) -> Result<Value, Error> {
    let json = minijinja::filters::tojson(value, indent, kwargs)?;
    if in_markdown(state) {
        return Ok(Value::from(json.to_string()));
    }
    Ok(json)
}

/// The filters valerter adds to minijinja's built-ins, by name.
pub fn valerter_filters() -> Vec<(&'static str, Value)> {
    vec![
        ("md_escape", Value::from_function(md_escape)),
        ("mdv2_escape", Value::from_function(mdv2_escape)),
        ("code", Value::from_function(code)),
        ("codeblock", Value::from_function(codeblock)),
        ("tojson", Value::from_function(tojson)),
    ]
}

/// The global functions valerter adds to minijinja's, by name.
pub fn valerter_functions() -> Vec<(&'static str, Value)> {
    vec![("md_link", Value::from_function(md_link))]
}

/// Registers [`valerter_filters`] and [`valerter_functions`] in `env`.
pub fn register(env: &mut Environment<'_>) {
    for (name, filter) in valerter_filters() {
        env.add_filter(
            name,
            move |state: &State, args: Rest<Value>| -> Result<Value, Error> {
                filter.call(state, &args)
            },
        );
    }
    for (name, function) in valerter_functions() {
        env.add_global(name, function);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::context;

    fn render(source: &str, v: Value) -> String {
        let mut env = Environment::new();
        register(&mut env);
        env.render_str(source, context! { v => v }).unwrap()
    }

    #[test]
    fn md_escape_escapes_every_character_of_its_set() {
        for c in MD_ESCAPE_CHARS {
            let input = format!("a{c}b");
            assert_eq!(
                render("{{ v | md_escape }}", Value::from(input)),
                format!("a\\{c}b"),
                "character {c:?}"
            );
        }
    }

    #[test]
    fn md_escape_escapes_markdown_punctuation() {
        assert_eq!(
            render("{{ v | md_escape }}", Value::from("*a_b* [x](y)")),
            r"\*a\_b\* \[x\]\(y\)"
        );
    }

    #[test]
    fn md_escape_keeps_other_characters() {
        // `>` is in the set (blockquote), `<` is not.
        assert_eq!(
            render(
                "{{ v | md_escape }}",
                Value::from("https://h:8080/p?a=1&b=<2>")
            ),
            r"https://h:8080/p?a=1&b=<2\>"
        );
        let kept = "<&:/=?@'\"%$,;";
        assert_eq!(render("{{ v | md_escape }}", Value::from(kept)), kept);
    }

    #[test]
    fn md_escape_keeps_multibyte_characters() {
        assert_eq!(
            render("{{ v | md_escape }}", Value::from("déjà_vu 🔥")),
            r"déjà\_vu 🔥"
        );
    }

    #[test]
    fn mdv2_escape_escapes_every_character_of_its_set() {
        assert_eq!(MDV2_ESCAPE_CHARS.len(), 19);
        for c in MDV2_ESCAPE_CHARS {
            let input = format!("a{c}b");
            assert_eq!(
                render("{{ v | mdv2_escape }}", Value::from(input)),
                format!("a\\{c}b"),
                "character {c:?}"
            );
        }
    }

    #[test]
    fn mdv2_escape_escapes_reserved_characters_and_backslash() {
        assert_eq!(
            render("{{ v | mdv2_escape }}", Value::from("a.b-c=d!")),
            r"a\.b\-c\=d\!"
        );
        assert_eq!(
            render("{{ v | mdv2_escape }}", Value::from(r"C:\temp")),
            r"C:\\temp"
        );
    }

    #[test]
    fn mdv2_escape_keeps_other_characters() {
        let text = "déjà vu 🔥 <a&b : / ? @ $ % ,";
        assert_eq!(render("{{ v | mdv2_escape }}", Value::from(text)), text);
    }

    #[test]
    fn filters_convert_non_string_values() {
        for filter in ["md_escape", "mdv2_escape"] {
            let source = format!("{{{{ v | {filter} }}}}");
            assert_eq!(render(&source, Value::from(-1.5)), r"\-1\.5", "{filter}");
            assert_eq!(render(&source, Value::from(42)), "42", "{filter}");
            assert_eq!(render(&source, Value::from(())), "", "{filter}");
            assert_eq!(render(&source, Value::UNDEFINED), "", "{filter}");
            assert_eq!(
                render(&format!("{{{{ missing | {filter} }}}}"), Value::UNDEFINED),
                "",
                "{filter}"
            );
        }
    }

    #[test]
    fn filter_output_is_html_escaped_in_an_auto_escaped_environment() {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        register(&mut env);
        let out = env
            .render_str("{{ v | md_escape }}", context! { v => "<i>_x_" })
            .unwrap();
        assert_eq!(out, r"&lt;i\&gt;\_x\_");
    }

    /// `source` rendered as a Markdown body, each token replaced by the
    /// Markdown source of its element.
    fn render_markdown(source: &str, v: Value) -> String {
        let mut env = Environment::new();
        install_markdown_escape(&mut env);
        register(&mut env);
        let (out, slots) = super::render_markdown(&env, source, context! { v => v }).unwrap();
        slots.iter().enumerate().fold(out, |out, (index, element)| {
            out.replace(
                &format!("{}{index}{}", markdown::TOKEN_OPEN, markdown::TOKEN_CLOSE),
                &element.to_string(),
            )
        })
    }

    /// `source` rendered as a Markdown body: the source, holding tokens, and
    /// the elements.
    fn render_markdown_raw(source: &str, v: Value) -> (String, Vec<MarkdownElement>) {
        let mut env = Environment::new();
        install_markdown_escape(&mut env);
        register(&mut env);
        super::render_markdown(&env, source, context! { v => v }).unwrap()
    }

    fn token(index: usize) -> String {
        format!("{}{index}{}", markdown::TOKEN_OPEN, markdown::TOKEN_CLOSE)
    }

    #[test]
    fn markdown_element_is_written_as_a_token() {
        let (out, slots) = render_markdown_raw("a {{ v | code }} {{ v | codeblock }}", "x".into());
        assert_eq!(out, format!("a {} {}", token(0), token(1)));
        assert_eq!(
            slots,
            vec![
                MarkdownElement::Code("x".to_string()),
                MarkdownElement::CodeBlock {
                    lang: String::new(),
                    text: "x".to_string()
                }
            ]
        );
    }

    #[test]
    fn markdown_element_converted_to_a_string_is_escaped() {
        let (out, slots) = render_markdown_raw("{{ (v | code) ~ '!' }}", "x".into());
        assert_eq!(out, r"\`x\`\!");
        assert!(slots.is_empty());
        let (out, _) = render_markdown_raw("{{ v | code | upper }}", "x".into());
        assert_eq!(out, r"\`X\`");
    }

    #[test]
    fn captures_and_macros_keep_their_tokens() {
        let (out, slots) =
            render_markdown_raw("{% set x %}{{ v | code }}{% endset %}{{ x }}", "a_b".into());
        assert_eq!(out, token(0));
        assert_eq!(slots, vec![MarkdownElement::Code("a_b".to_string())]);
        let (out, slots) = render_markdown_raw(
            "{% macro m(x) %}[{{ x | codeblock }}]{% endmacro %}{{ m(v) }}",
            "a_b".into(),
        );
        assert_eq!(out, format!("[{}]", token(0)));
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn empty_code_is_an_empty_string() {
        assert_eq!(
            render_markdown_raw("{{ v | code }}", "".into()),
            (String::new(), vec![])
        );
        assert_eq!(
            render_markdown_raw("{% if v | code %}x{% endif %}", "".into()).0,
            ""
        );
    }

    #[test]
    fn md_escape_in_markdown_body_is_the_automatic_escaping() {
        // Every ASCII punctuation character, as the auto-escaping, once.
        assert_eq!(
            render_markdown("{{ v | md_escape }}", Value::from("a_b:c<d>")),
            r"a\_b\:c\<d\>"
        );
        assert_eq!(
            render_markdown("{{ v | md_escape }}", Value::from("a_b:c<d>")),
            render_markdown("{{ v }}", Value::from("a_b:c<d>"))
        );
    }

    #[test]
    fn code_fences_and_pads() {
        let code = |v: &str| render_markdown("{{ v | code }}", Value::from(v));
        assert_eq!(code("x"), "`x`");
        assert_eq!(code("a`b"), "``a`b``");
        assert_eq!(code("`x"), "`` `x ``");
        assert_eq!(code("x``"), "``` x`` ```");
        assert_eq!(code(" x "), "`  x  `");
        assert_eq!(code("a\nb"), "`a b`");
        assert_eq!(code(""), "");
        assert_eq!(
            render_markdown("{{ missing | code }}", Value::UNDEFINED),
            ""
        );
    }

    #[test]
    fn codeblock_fences_and_language() {
        let block = |source: &str, v: &str| render_markdown(source, Value::from(v));
        assert_eq!(block("{{ v | codeblock }}", "x"), "```\nx\n```");
        assert_eq!(block("{{ v | codeblock }}", "x\n"), "```\nx\n```");
        assert_eq!(block("{{ v | codeblock('c++') }}", "x"), "```c++\nx\n```");
        assert_eq!(
            block("{{ v | codeblock('a b<\">`') }}", "x"),
            "```ab\nx\n```"
        );
        assert_eq!(block("{{ v | codeblock }}", "````"), "`````\n````\n`````");
    }

    #[test]
    fn md_link_destination_and_schemes() {
        let md_link = |text: &str, url: &str| {
            render_markdown(
                "{{ md_link(v[0], v[1]) }}",
                Value::from(vec![text.to_string(), url.to_string()]),
            )
        };
        assert_eq!(
            md_link("a_b", "https://h/p?q=1"),
            r"[a\_b](https://h/p?q=1)"
        );
        assert_eq!(md_link("t", "HTTPS://h"), "[t](HTTPS://h)");
        assert_eq!(md_link("t", "mailto:a@b.c"), "[t](mailto:a@b.c)");
        assert_eq!(md_link("t", "https://h/a b"), "[t](https://h/a%20b)");
        assert_eq!(md_link("t", "ftp://h"), r"t \(ftp\:\/\/h\)");
        assert_eq!(md_link("t", "/relative"), r"t \(\/relative\)");
    }

    #[test]
    fn markdown_filters_are_escaped_in_an_html_environment() {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        register(&mut env);
        let out = env
            .render_str(
                "{{ v | code }} {{ v | codeblock }} {{ md_link(v, 'https://h') }}",
                context! { v => "<b>" },
            )
            .unwrap();
        assert_eq!(
            out,
            "`&lt;b&gt;` ```\n&lt;b&gt;\n``` [\\&lt;b\\&gt;](https:&#x2f;&#x2f;h)"
        );
    }
}
