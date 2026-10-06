//! Restricted tree → `plain`, `markdown`, `html` and `telegram_html`.

use super::{Block, Inline, parse};
use crate::config::OutputFormat;

/// Parses `source` and renders it in `format`.
pub fn render(source: &str, format: OutputFormat) -> String {
    render_blocks(&parse(source), format)
}

/// Renders a parsed body in `format`.
pub fn render_blocks(blocks: &[Block], format: OutputFormat) -> String {
    match format {
        OutputFormat::Plain => plain_blocks(blocks, "\n\n"),
        OutputFormat::Markdown => md_blocks(blocks, 0),
        OutputFormat::Html => Html {
            telegram: false,
            in_link: false,
            in_quote: false,
        }
        .blocks(blocks, "\n"),
        OutputFormat::TelegramHtml => Html {
            telegram: true,
            in_link: false,
            in_quote: false,
        }
        .blocks(blocks, "\n\n"),
    }
}

/// Whether a link destination uses a scheme valerter emits links for:
/// `http`, `https` or `mailto` (case-insensitive). Relative destinations
/// have no scheme and are refused.
pub fn allowed_scheme(dest: &str) -> bool {
    let Some((scheme, _)) = dest.split_once(':') else {
        return false;
    };
    ["http", "https", "mailto"]
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
}

/// Percent-encodes what breaks an unbracketed link destination: spaces,
/// control characters, `<`, `>`, `(`, `)` and `\`. The rest of the URL is
/// left intact.
pub fn encode_destination(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    for c in url.chars() {
        if c == ' ' || c.is_control() || matches!(c, '<' | '>' | '(' | ')' | '\\') {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A Markdown code span showing `text` literally: the fence is one backtick
/// longer than the longest run of backticks in `text`, padded with a space on
/// each side when `text` starts or ends with a backtick (or with a space on
/// both sides, which CommonMark would strip). Line breaks become spaces, as
/// CommonMark renders them, so the span cannot be split.
pub fn code_span(text: &str) -> String {
    let text = text.replace(['\r', '\n'], " ");
    if text.is_empty() {
        return String::new();
    }
    let fence = "`".repeat(longest_backtick_run(&text) + 1);
    let pad = text.starts_with('`')
        || text.ends_with('`')
        || (text.starts_with(' ') && text.ends_with(' ') && !text.trim().is_empty());
    let space = if pad { " " } else { "" };
    format!("{fence}{space}{text}{space}{fence}")
}

/// Length of the longest run of backticks in `text`.
pub(crate) fn longest_backtick_run(text: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for c in text.chars() {
        if c == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// Prefixes each line of `text` with `prefix` (`empty` for an empty line).
fn prefix_lines(text: &str, prefix: &str, empty: &str) -> String {
    text.split('\n')
        .map(|line| {
            if line.is_empty() {
                empty.to_string()
            } else {
                format!("{prefix}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A list item: `marker` before the first line, the following lines
/// indented by the marker's width.
fn list_item(marker: &str, content: &str) -> String {
    let indent = " ".repeat(marker.chars().count());
    let mut out = String::new();
    for (i, line) in content.split('\n').enumerate() {
        if i == 0 {
            out.push_str(marker);
        } else {
            out.push('\n');
            if !line.is_empty() {
                out.push_str(&indent);
            }
        }
        out.push_str(line);
    }
    out
}

/// Marker of the item at `index` of a list starting at `start` (unordered
/// when `None`).
fn list_marker(start: Option<u64>, index: usize, bullet: &str) -> String {
    match start {
        Some(start) => format!("{}. ", start.saturating_add(index as u64)),
        None => bullet.to_string(),
    }
}

/// Text of a code block without its final line break.
fn code_text(text: &str) -> &str {
    text.strip_suffix('\n').unwrap_or(text)
}

/// Whether a link whose text is `text` can be shown as its destination
/// alone (`<https://x>`, `<a@b.c>`, or a link without text).
fn text_is_destination(text: &str, dest: &str) -> bool {
    text.is_empty() || text == dest || dest.strip_prefix("mailto:") == Some(text)
}

// ---------------------------------------------------------------- plain

fn plain_blocks(blocks: &[Block], separator: &str) -> String {
    blocks
        .iter()
        .map(plain_block)
        .collect::<Vec<_>>()
        .join(separator)
}

fn plain_block(block: &Block) -> String {
    match block {
        Block::Paragraph(inlines) | Block::Plain(inlines) | Block::Heading(_, inlines) => {
            plain_inlines(inlines)
        }
        Block::BlockQuote(blocks) => prefix_lines(&plain_blocks(blocks, "\n\n"), "> ", ">"),
        Block::CodeBlock { text, .. } => code_text(text).to_string(),
        Block::List { start, items } => items
            .iter()
            .enumerate()
            .map(|(i, item)| list_item(&list_marker(*start, i, "- "), &plain_blocks(item, "\n")))
            .collect::<Vec<_>>()
            .join("\n"),
        Block::Rule => "---".to_string(),
    }
}

fn plain_inlines(inlines: &[Inline]) -> String {
    let mut out = String::new();
    for inline in inlines {
        match inline {
            Inline::Text(t) | Inline::Code(t) => out.push_str(t),
            Inline::LineBreak => out.push('\n'),
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strikethrough(c) => {
                out.push_str(&plain_inlines(c))
            }
            Inline::Link { dest, children } => {
                let text = plain_inlines(children);
                if text_is_destination(&text, dest) {
                    out.push_str(if text.is_empty() { dest } else { &text });
                } else {
                    out.push_str(&format!("{text} ({dest})"));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- html, telegram_html

/// Escapes text for HTML: `& < > " '` (email) or `& < >` (Telegram, whose
/// parser accepts only these entities and the numeric ones).
fn escape_html(text: &str, telegram: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if !telegram => out.push_str("&quot;"),
            '\'' if !telegram => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escapes an attribute value (`href`): `"` is always escaped.
fn escape_attr(text: &str, telegram: bool) -> String {
    let escaped = escape_html(text, telegram);
    if telegram {
        escaped.replace('"', "&quot;")
    } else {
        escaped
    }
}

/// Keeps the characters of a code block language that cannot break an
/// attribute: `A-Z`, `a-z`, `0-9`, `_`, `+`, `-`, `.`, `#`.
fn sanitize_lang(lang: &str) -> String {
    lang.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | '#'))
        .collect()
}

/// HTML writer: `html` (email) or `telegram_html` (Bot API subset).
#[derive(Clone, Copy)]
struct Html {
    telegram: bool,
    /// Inside a link: a nested link (image in a link) is written as text.
    in_link: bool,
    /// Inside a Telegram block quote, which cannot be nested.
    in_quote: bool,
}

impl Html {
    fn esc(&self, text: &str) -> String {
        escape_html(text, self.telegram)
    }

    fn blocks(&self, blocks: &[Block], separator: &str) -> String {
        blocks
            .iter()
            .map(|b| self.block(b))
            .collect::<Vec<_>>()
            .join(separator)
    }

    fn block(&self, block: &Block) -> String {
        if self.telegram {
            self.telegram_block(block)
        } else {
            self.html_block(block)
        }
    }

    fn html_block(&self, block: &Block) -> String {
        match block {
            Block::Paragraph(inlines) => format!("<p>{}</p>", self.inlines(inlines)),
            Block::Plain(inlines) => self.inlines(inlines),
            Block::Heading(level, inlines) => {
                format!("<h{level}>{}</h{level}>", self.inlines(inlines))
            }
            Block::BlockQuote(blocks) => {
                format!("<blockquote>\n{}\n</blockquote>", self.blocks(blocks, "\n"))
            }
            Block::CodeBlock { lang, text } => {
                let lang = sanitize_lang(lang);
                let class = if lang.is_empty() {
                    String::new()
                } else {
                    format!(" class=\"language-{lang}\"")
                };
                format!(
                    "<pre><code{class}>{}</code></pre>",
                    self.esc(code_text(text))
                )
            }
            Block::List { start, items } => {
                let open = match start {
                    None => "<ul>".to_string(),
                    Some(1) => "<ol>".to_string(),
                    Some(n) => format!("<ol start=\"{n}\">"),
                };
                let close = if start.is_some() { "</ol>" } else { "</ul>" };
                let items: Vec<String> = items
                    .iter()
                    .map(|item| format!("<li>{}</li>", self.blocks(item, "\n")))
                    .collect();
                format!("{open}\n{}\n{close}", items.join("\n"))
            }
            Block::Rule => "<hr>".to_string(),
        }
    }

    fn telegram_block(&self, block: &Block) -> String {
        match block {
            Block::Paragraph(inlines) | Block::Plain(inlines) => self.inlines(inlines),
            Block::Heading(_, inlines) => format!("<b>{}</b>", self.inlines(inlines)),
            Block::BlockQuote(blocks) if self.in_quote => self.blocks(blocks, "\n\n"),
            Block::BlockQuote(blocks) => {
                let inner = Html {
                    in_quote: true,
                    ..*self
                };
                format!("<blockquote>{}</blockquote>", inner.blocks(blocks, "\n\n"))
            }
            Block::CodeBlock { lang, text } => {
                let lang = sanitize_lang(lang);
                let text = self.esc(code_text(text));
                if lang.is_empty() {
                    format!("<pre>{text}</pre>")
                } else {
                    format!("<pre><code class=\"language-{lang}\">{text}</code></pre>")
                }
            }
            Block::List { start, items } => items
                .iter()
                .enumerate()
                .map(|(i, item)| list_item(&list_marker(*start, i, "• "), &self.blocks(item, "\n")))
                .collect::<Vec<_>>()
                .join("\n"),
            Block::Rule => "———".to_string(),
        }
    }

    fn inlines(&self, inlines: &[Inline]) -> String {
        let (strong, em, del, br) = if self.telegram {
            ("b", "i", "s", "\n")
        } else {
            ("strong", "em", "del", "<br>\n")
        };
        let mut out = String::new();
        for inline in inlines {
            match inline {
                Inline::Text(t) => out.push_str(&self.esc(t)),
                Inline::Code(t) => out.push_str(&format!("<code>{}</code>", self.esc(t))),
                Inline::LineBreak => out.push_str(br),
                Inline::Strong(c) => {
                    out.push_str(&format!("<{strong}>{}</{strong}>", self.inlines(c)))
                }
                Inline::Emphasis(c) => out.push_str(&format!("<{em}>{}</{em}>", self.inlines(c))),
                Inline::Strikethrough(c) => {
                    out.push_str(&format!("<{del}>{}</{del}>", self.inlines(c)))
                }
                Inline::Link { dest, children } => {
                    if allowed_scheme(dest) && !self.in_link {
                        let inner = Html {
                            in_link: true,
                            ..*self
                        };
                        out.push_str(&format!(
                            "<a href=\"{}\">{}</a>",
                            escape_attr(dest, self.telegram),
                            inner.inlines(children)
                        ));
                    } else {
                        let text = self.inlines(children);
                        if text_is_destination(&plain_inlines(children), dest) {
                            if text.is_empty() {
                                out.push_str(&self.esc(dest));
                            } else {
                                out.push_str(&text);
                            }
                        } else {
                            out.push_str(&format!("{text} ({})", self.esc(dest)));
                        }
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------- markdown

/// Escapes always written in the `markdown` rendering: all of them belong to
/// the escape set of Mattermost's engine.
const MD_ALWAYS: &[char] = &['\\', '`', '*', '_', '[', ']', '~', '|'];

/// Escaped only at the start of a line (headings, lists, quotes, setext
/// underlines).
const MD_LINE_START: &[char] = &['#', '+', '-', '=', '>'];

/// Blocks separated by a blank line, so that a block cannot continue the
/// previous one (lazy continuation), except a nested list right after the
/// text of an item, which interrupts it. `depth` is the list nesting level.
fn md_blocks(blocks: &[Block], depth: usize) -> String {
    let mut out = String::new();
    let mut previous_list: Option<(bool, bool)> = None;
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 {
            let interrupts = matches!(
                (&blocks[i - 1], block),
                (
                    Block::Plain(_),
                    Block::List {
                        start: None | Some(1),
                        ..
                    }
                )
            );
            out.push_str(if interrupts { "\n" } else { "\n\n" });
        }
        // Two adjacent lists of the same kind would merge into one: the
        // second one switches its marker.
        let alternate = match block {
            Block::List { start, .. } => {
                let ordered = start.is_some();
                let alternate = matches!(
                    previous_list,
                    Some((prev_ordered, false)) if prev_ordered == ordered
                );
                previous_list = Some((ordered, alternate));
                alternate
            }
            _ => {
                previous_list = None;
                false
            }
        };
        out.push_str(&md_block(block, alternate, depth));
    }
    out
}

fn md_block(block: &Block, alternate: bool, depth: usize) -> String {
    match block {
        Block::Paragraph(inlines) | Block::Plain(inlines) => {
            let mut out = String::new();
            md_inlines(&mut out, inlines, false);
            out
        }
        Block::Heading(level, inlines) => {
            let mut out = "#".repeat(usize::from(*level));
            out.push(' ');
            let prefix = out.len();
            md_inlines(&mut out, inlines, false);
            // A trailing run of `#` would be read as the closing sequence.
            let content = &out[prefix..];
            let kept = content.trim_end_matches('#').len();
            if kept < content.len() && !content[..kept].ends_with('\\') {
                out.insert(prefix + kept, '\\');
            }
            out
        }
        Block::BlockQuote(blocks) => prefix_lines(&md_blocks(blocks, depth), "> ", ">"),
        Block::CodeBlock { lang, text } => {
            let fence = "`".repeat((longest_backtick_run(text) + 1).max(3));
            let lang = sanitize_lang(lang);
            let mut text = text.clone();
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            format!("{fence}{lang}\n{text}{fence}")
        }
        Block::List { start, items } => {
            // Bullets alternate with the nesting level (`- * -` is not a
            // thematic break, `- - -` is) and between adjacent lists.
            let bullet = if alternate {
                "+ "
            } else if depth % 2 == 1 {
                "* "
            } else {
                "- "
            };
            let delimiter = if alternate { ')' } else { '.' };
            items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let marker = match start {
                        Some(start) => format!("{}{delimiter} ", start.saturating_add(i as u64)),
                        None => bullet.to_string(),
                    };
                    list_item(&marker, &md_blocks(item, depth + 1))
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        // Not `---` nor `***`: `- ---` or `* ***` (a rule in a list item)
        // would be a rule itself.
        Block::Rule => "___".to_string(),
    }
}

/// Whether the current line of `out` holds nothing yet.
fn at_line_start(out: &str) -> bool {
    out.is_empty() || out.ends_with('\n')
}

/// Whether `rest` (what follows a `&`) completes an entity reference
/// (`amp;`, `#38;`, `#x26;`).
fn starts_entity(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let end = match bytes.first() {
        Some(b'#') => match bytes.get(1) {
            Some(b'x' | b'X') => {
                let n = bytes[2..]
                    .iter()
                    .take_while(|b| b.is_ascii_hexdigit())
                    .count();
                (1..=6).contains(&n).then_some(2 + n)
            }
            _ => {
                let n = bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count();
                (1..=7).contains(&n).then_some(1 + n)
            }
        },
        Some(b) if b.is_ascii_alphabetic() => {
            let n = bytes
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            (n <= 32).then_some(n)
        }
        _ => None,
    };
    end.is_some_and(|end| bytes.get(end) == Some(&b';'))
}

/// Writes `text` escaped for Mattermost's Markdown engine.
fn md_text(out: &mut String, text: &str) {
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let line_start = at_line_start(out);
        if line_start && (c == ' ' || c == '\t') {
            // Leading blanks would make an indented code block or a list.
            continue;
        }
        match c {
            c if MD_ALWAYS.contains(&c) => {
                out.push('\\');
                out.push(c);
            }
            '<' => out.push_str("&lt;"),
            '&' if starts_entity(&text[i + 1..]) => out.push_str("&amp;"),
            c if line_start && MD_LINE_START.contains(&c) => {
                out.push('\\');
                out.push(c);
            }
            '0'..='9' if line_start => {
                // `1.` or `1)` at the start of a line starts an ordered list.
                out.push(c);
                while let Some(&(_, d)) = chars.peek() {
                    if !d.is_ascii_digit() {
                        break;
                    }
                    out.push(d);
                    chars.next();
                }
                if let Some(&(_, p @ ('.' | ')'))) = chars.peek() {
                    out.push('\\');
                    out.push(p);
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
}

fn md_inlines(out: &mut String, inlines: &[Inline], in_link: bool) {
    for inline in inlines {
        match inline {
            Inline::Text(t) => md_text(out, t),
            Inline::Code(t) => {
                // Two adjacent spans would merge their fences.
                if out.ends_with('`') && !out.ends_with("\\`") {
                    out.push(' ');
                }
                out.push_str(&code_span(t));
            }
            Inline::LineBreak => out.push('\n'),
            Inline::Strong(c) => md_wrap(out, "**", c, in_link),
            Inline::Emphasis(c) => md_wrap(out, "*", c, in_link),
            Inline::Strikethrough(c) => md_wrap(out, "~~", c, in_link),
            Inline::Link { dest, children } => {
                let text = plain_inlines(children);
                let autolink = text_is_destination(&text, dest)
                    && !dest.contains(|c: char| {
                        c.is_whitespace() || c.is_control() || c == '<' || c == '>'
                    });
                if allowed_scheme(dest) && !in_link && autolink {
                    // `<https://x>` or `<a@b.c>`, as written in the source.
                    out.push('<');
                    out.push_str(if dest == &format!("mailto:{text}") {
                        &text
                    } else {
                        dest
                    });
                    out.push('>');
                } else if allowed_scheme(dest) && !in_link {
                    // A literal `!` before the link would make it an image.
                    if out.ends_with('!') {
                        out.pop();
                        out.push_str("\\!");
                    }
                    out.push('[');
                    md_inlines(out, children, true);
                    out.push_str("](");
                    out.push_str(&encode_destination(dest));
                    out.push(')');
                } else if text.is_empty() {
                    md_text(out, dest);
                } else if text_is_destination(&text, dest) {
                    md_inlines(out, children, in_link);
                } else {
                    md_inlines(out, children, in_link);
                    md_text(out, &format!(" ({dest})"));
                }
            }
        }
    }
}

/// Writes an emphasis. Its content is written apart, as if at the start of a
/// line (conservative escaping), and stripped of surrounding blanks: a
/// delimiter next to a blank would not open or close the emphasis, and `* `
/// at the start of a line would start a list.
fn md_wrap(out: &mut String, delimiter: &str, children: &[Inline], in_link: bool) {
    let mut inner = String::new();
    md_inlines(&mut inner, children, in_link);
    let inner = inner.trim();
    if inner.is_empty() {
        return;
    }
    out.push_str(delimiter);
    out.push_str(inner);
    out.push_str(delimiter);
}
