//! Filters valerter registers in every minijinja environment, on top of
//! minijinja's built-in filters.
//!
//! [`valerter_filters`] is the single list: [`register`] adds it to the
//! rendering environments (rule templates, `throttle.key`, notifier
//! templates) and the validation environment wraps the same list, so a
//! template accepted by `--validate` renders the same way in production.

use minijinja::value::Rest;
use minijinja::{Environment, Error, State, Value};

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

/// Converts `value` to a string (`none` and an undefined value give an empty
/// string, a number its usual form) and prefixes each character of `set` with
/// a backslash.
fn escape_with(value: &Value, set: &[char]) -> String {
    if value.is_none() || value.is_undefined() {
        return String::new();
    }
    let text = value.to_string();
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if set.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `md_escape` filter: escapes a value for a CommonMark body rendered by
/// Mattermost, so it shows literally. `<` and `&` are not neutralised.
pub fn md_escape(value: &Value) -> String {
    escape_with(value, MD_ESCAPE_CHARS)
}

/// `mdv2_escape` filter: escapes a value for Telegram MarkdownV2 text outside
/// `pre` and `code` entities.
pub fn mdv2_escape(value: &Value) -> String {
    escape_with(value, MDV2_ESCAPE_CHARS)
}

/// The filters valerter adds to minijinja's built-ins, by name.
pub fn valerter_filters() -> Vec<(&'static str, Value)> {
    vec![
        ("md_escape", Value::from_function(md_escape)),
        ("mdv2_escape", Value::from_function(mdv2_escape)),
    ]
}

/// Registers [`valerter_filters`] in `env`.
pub fn register(env: &mut Environment<'_>) {
    for (name, filter) in valerter_filters() {
        env.add_filter(
            name,
            move |state: &State, args: Rest<Value>| -> Result<Value, Error> {
                filter.call(state, &args)
            },
        );
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
}
