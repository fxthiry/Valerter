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
mod tests;

pub use parse::parse;
pub(crate) use render::longest_backtick_run;
pub use render::{allowed_scheme, code_span, encode_destination, render, render_blocks};

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

/// Escapes `text` for a Markdown source: every ASCII punctuation character
/// is preceded by a backslash (always valid in CommonMark), so the text is
/// read literally. The source is never sent as is: it is parsed and
/// re-rendered per notifier, so the extra backslashes never show.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    for c in text.chars() {
        if c.is_ascii_punctuation() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
