//! Filters valerter registers in every minijinja environment, on top of
//! minijinja's built-in filters.
//!
//! [`valerter_filters`] is the single list: [`register`] adds it to the
//! rendering environments (rule templates, `throttle.key`, notifier
//! templates) and the validation environment wraps the same list, so a
//! template accepted by `--validate` renders the same way in production.

use crate::markdown;
use minijinja::value::Rest;
use minijinja::{AutoEscape, Environment, Error, State, Value};

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

/// Markdown produced by a filter: safe (inserted as is) in a Markdown body,
/// an ordinary string elsewhere, escaped by the context (HTML in
/// `email_body_html`).
fn markdown_value(state: &State, markdown: String) -> Value {
    if in_markdown(state) {
        Value::from_safe_string(markdown)
    } else {
        Value::from(markdown)
    }
}

/// Sets up the auto-escaping of a Markdown body in `env`: every template is
/// rendered in the [`MARKDOWN_AUTO_ESCAPE`] mode, where an inserted value has
/// all its ASCII punctuation escaped ([`markdown::escape`]) unless it is safe
/// (`| safe`, `| tojson`, `code`, `codeblock`, `link`). Other modes
/// (`{% autoescape %}` blocks) keep minijinja's formatting.
///
/// The formatter is required: minijinja's default one fails on a custom
/// mode, at render time as in a validation render.
pub fn install_markdown_escape(env: &mut Environment<'_>) {
    env.set_auto_escape_callback(|_| AutoEscape::Custom(MARKDOWN_AUTO_ESCAPE));
    env.set_formatter(|out, state, value| {
        if !in_markdown(state) {
            return minijinja::escape_formatter(out, state, value);
        }
        let written = match value.as_str() {
            Some(text) if value.is_safe() => out.write_str(text),
            _ => out.write_str(&markdown::escape(&value.to_string())),
        };
        written.map_err(Error::from)
    });
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
/// ([`markdown::code_span`]; a line break becomes a space).
pub fn code(state: &State, value: &Value) -> Value {
    markdown_value(state, markdown::code_span(&value_text(value)))
}

/// `codeblock(lang)` filter: a fenced code block showing the value literally,
/// with a fence of backticks longer than any run in the value (at least
/// three). The language keeps only `A-Z`, `a-z`, `0-9`, `_`, `+`, `-`, `.`
/// and `#`. The block must stand alone on its line in the template.
pub fn codeblock(state: &State, value: &Value, lang: Option<Value>) -> Value {
    let text = value_text(value);
    let lang: String = lang
        .as_ref()
        .map(value_text)
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | '#'))
        .collect();
    let fence = "`".repeat((markdown::longest_backtick_run(&text) + 1).max(3));
    let newline = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    markdown_value(state, format!("{fence}{lang}\n{text}{newline}{fence}"))
}

/// `link(text, url)` function: a Markdown link whose text is escaped and
/// whose destination is [encoded](markdown::encode_destination); for a scheme
/// other than `http`, `https` or `mailto`, the escaped text followed by the
/// URL in parentheses, without a link.
pub fn link(state: &State, text: &Value, url: &Value) -> Value {
    let text = value_text(text);
    let url = value_text(url);
    let markdown = if markdown::allowed_scheme(&url) {
        format!(
            "[{}]({})",
            markdown::escape(&text),
            markdown::encode_destination(&url)
        )
    } else {
        markdown::escape(&format!("{text} ({url})"))
    };
    markdown_value(state, markdown)
}

/// The filters valerter adds to minijinja's built-ins, by name.
pub fn valerter_filters() -> Vec<(&'static str, Value)> {
    vec![
        ("md_escape", Value::from_function(md_escape)),
        ("mdv2_escape", Value::from_function(mdv2_escape)),
        ("code", Value::from_function(code)),
        ("codeblock", Value::from_function(codeblock)),
    ]
}

/// The global functions valerter adds to minijinja's, by name.
pub fn valerter_functions() -> Vec<(&'static str, Value)> {
    vec![("link", Value::from_function(link))]
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

    fn render_markdown(source: &str, v: Value) -> String {
        let mut env = Environment::new();
        install_markdown_escape(&mut env);
        register(&mut env);
        env.render_str(source, context! { v => v }).unwrap()
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
    fn link_destination_and_schemes() {
        let link = |text: &str, url: &str| {
            render_markdown(
                "{{ link(v[0], v[1]) }}",
                Value::from(vec![text.to_string(), url.to_string()]),
            )
        };
        assert_eq!(link("a_b", "https://h/p?q=1"), r"[a\_b](https://h/p?q=1)");
        assert_eq!(link("t", "HTTPS://h"), "[t](HTTPS://h)");
        assert_eq!(link("t", "mailto:a@b.c"), "[t](mailto:a@b.c)");
        assert_eq!(link("t", "https://h/a b"), "[t](https://h/a%20b)");
        assert_eq!(link("t", "ftp://h"), r"t \(ftp\:\/\/h\)");
        assert_eq!(link("t", "/relative"), r"t \(\/relative\)");
    }

    #[test]
    fn markdown_filters_are_escaped_in_an_html_environment() {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        register(&mut env);
        let out = env
            .render_str(
                "{{ v | code }} {{ v | codeblock }} {{ link(v, 'https://h') }}",
                context! { v => "<b>" },
            )
            .unwrap();
        assert_eq!(
            out,
            "`&lt;b&gt;` ```\n&lt;b&gt;\n``` [\\&lt;b\\&gt;](https:&#x2f;&#x2f;h)"
        );
    }
}
