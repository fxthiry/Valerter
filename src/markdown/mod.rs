//! Markdown bodies (`body_format: markdown`).
//!
//! A Markdown body is parsed once by pulldown-cmark into a restricted tree
//! ([`Block`], [`Inline`]) holding only the elements valerter renders, then
//! written in the output format of each notifier ([`render`]):
//!
//! ```text
//! body source ─ parse ─▶ Vec<Block> ─┬─ plain
//!                                    ├─ markdown (Mattermost escaping)
//!                                    ├─ html (email)
//!                                    └─ telegram_html (Bot API subset)
//! ```
//!
//! Every renderer writes from the tree, never by concatenating raw source:
//! raw HTML and tables of the source become text, links are only emitted for
//! the `http`, `https` and `mailto` schemes, and HTML outputs are balanced by
//! construction. The tree does not expose pulldown-cmark types, so a change of
//! the crate stays local to [`parse`].

mod parse;
mod render;
#[cfg(test)]
pub(crate) mod tests;

pub use parse::parse;
pub(crate) use render::longest_backtick_run;
pub use render::{allowed_scheme, code_span, encode_destination, render, render_blocks};

use std::fmt;
use std::sync::Arc;

/// Opens the token standing for a [`MarkdownElement`] in a Markdown body
/// source: `U+E000 <index> U+E001`, the index being the element's position in
/// the slots of the rendering. Private use characters are letters for
/// CommonMark (neither punctuation nor blank), so a token is read as a word,
/// and [`escape`] removes them from every inserted value.
pub const TOKEN_OPEN: char = '\u{E000}';
/// Closes a token (see [`TOKEN_OPEN`]).
pub const TOKEN_CLOSE: char = '\u{E001}';

/// Block element of a parsed Markdown body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A paragraph.
    Paragraph(Vec<Inline>),
    /// Inline content not wrapped in a paragraph (item of a tight list).
    Plain(Vec<Inline>),
    /// A heading of level 1 to 6.
    Heading(u8, Vec<Inline>),
    /// A block quote.
    BlockQuote(Vec<Block>),
    /// A code block: language (possibly empty) and literal text, which ends
    /// with a line break unless empty.
    CodeBlock { lang: String, text: String },
    /// A list, ordered from `start` when set; each item is a list of blocks.
    List {
        start: Option<u64>,
        items: Vec<Vec<Block>>,
    },
    /// A thematic break.
    Rule,
}

/// Inline element of a parsed Markdown body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    /// Literal text.
    Text(String),
    /// A code span.
    Code(String),
    /// A line break (hard, or soft: every line break of the source is kept).
    LineBreak,
    /// Strong emphasis.
    Strong(Vec<Inline>),
    /// Emphasis.
    Emphasis(Vec<Inline>),
    /// Strikethrough (`~~x~~`).
    Strikethrough(Vec<Inline>),
    /// A link (or an image, turned into a link to the image): destination
    /// and text.
    Link { dest: String, children: Vec<Inline> },
}

/// Element produced by the `code` and `codeblock` filters and the `md_link`
/// function in a Markdown body. The formatter writes it as a token
/// ([`TOKEN_OPEN`]) and keeps it apart; [`parse`] puts it back into the tree
/// once the source is parsed, so its content stays literal wherever the
/// filter is written.
///
/// Converted to a string (`~`, `| upper`…), it gives its Markdown source,
/// then an ordinary string escaped as any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkdownElement {
    /// A code span (line breaks already turned into spaces).
    Code(String),
    /// A code block: sanitized language and literal text.
    CodeBlock { lang: String, text: String },
    /// A link: literal text and encoded destination.
    Link { text: String, dest: String },
    /// Literal text (link with a refused scheme).
    Text(String),
}

impl fmt::Display for MarkdownElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(text) => f.write_str(&code_span(text)),
            Self::CodeBlock { lang, text } => {
                let fence = "`".repeat((longest_backtick_run(text) + 1).max(3));
                let newline = if text.is_empty() || text.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                write!(f, "{fence}{lang}\n{text}{newline}{fence}")
            }
            Self::Link { text, dest } => write!(f, "[{}]({dest})", escape(text)),
            Self::Text(text) => f.write_str(&escape(text)),
        }
    }
}

impl minijinja::value::Object for MarkdownElement {
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

/// `text` with the token characters ([`TOKEN_OPEN`], [`TOKEN_CLOSE`])
/// replaced by U+FFFD: the content of a [`MarkdownElement`] never shows them.
pub fn neutralise_tokens(text: &str) -> String {
    text.replace([TOKEN_OPEN, TOKEN_CLOSE], "\u{FFFD}")
}

/// Escapes `text` for a Markdown source:
///
/// - every ASCII punctuation character is preceded by a backslash (always
///   valid in CommonMark), so the text is read literally;
/// - the token characters ([`TOKEN_OPEN`], [`TOKEN_CLOSE`]) become U+FFFD, so
///   no value can stand for an element;
/// - line breaks (`\n`, `\r\n`, `\r`) are written `\n`, each leading blank
///   of a line becomes U+00A0 (four for a tab) and an empty line a U+00A0
///   alone: a value can neither end a paragraph (an emphasis, an item, a
///   quote) with a blank line nor open an indented code block, and its
///   indentation stays visible.
///
/// The source is never sent as is: it is parsed and re-rendered per
/// notifier, so the extra backslashes never show.
pub fn escape(text: &str) -> String {
    const NBSP: char = '\u{A0}';
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    // In the leading blanks of a line; nothing written on the line yet.
    let (mut leading, mut empty) = (true, true);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                if empty {
                    out.push(NBSP);
                }
                out.push('\n');
                (leading, empty) = (true, true);
                continue;
            }
            ' ' if leading => out.push(NBSP),
            '\t' if leading => out.extend([NBSP; 4]),
            TOKEN_OPEN | TOKEN_CLOSE => out.push(char::REPLACEMENT_CHARACTER),
            c if c.is_ascii_punctuation() => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
        leading = leading && matches!(c, ' ' | '\t');
        empty = false;
    }
    if empty && !text.is_empty() {
        out.push(NBSP);
    }
    out
}
