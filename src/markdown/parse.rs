//! pulldown-cmark event stream → restricted tree.

use super::{Block, Inline, MarkdownElement, TOKEN_CLOSE, TOKEN_OPEN};
use pulldown_cmark::{CodeBlockKind, Event, LinkType, Options, Parser, Tag};

/// Maximum depth of the tree (root excluded), every block and inline
/// container counting one level. An element opened when `MAX_DEPTH - 1`
/// elements are already open is transparent (its text is kept, the element is
/// dropped), so that the text a block container holds, wrapped in a
/// [`Block::Plain`], still fits. Every walk of the tree (renderers, `Clone`,
/// `Drop`…) is recursive: the bound keeps a body of any size (a log line
/// inserted with `| safe`) from overflowing the stack.
pub(super) const MAX_DEPTH: usize = 32;

/// What an open element becomes when it is closed.
enum Kind {
    Root,
    Paragraph,
    Heading(u8),
    BlockQuote,
    /// Fenced or indented code block with its language; the text is
    /// accumulated in `raw`.
    CodeBlock(String),
    /// Raw HTML block: rendered as a paragraph of text.
    HtmlBlock,
    List(Option<u64>),
    Item,
    Strong,
    Emphasis,
    Strikethrough,
    Link(String),
    /// Element outside the restricted set (not emitted with the options
    /// used): its content is kept, the element itself is dropped.
    Transparent,
}

/// An open element: the blocks and inlines read so far.
struct Frame {
    kind: Kind,
    blocks: Vec<Block>,
    inlines: Vec<Inline>,
    items: Vec<Vec<Block>>,
    raw: String,
}

impl Frame {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            blocks: Vec::new(),
            inlines: Vec::new(),
            items: Vec::new(),
            raw: String::new(),
        }
    }

    /// Whether the element holds inline content (as opposed to blocks).
    fn is_inline_container(&self) -> bool {
        matches!(
            self.kind,
            Kind::Paragraph
                | Kind::Heading(_)
                | Kind::Strong
                | Kind::Emphasis
                | Kind::Strikethrough
                | Kind::Link(_)
        )
    }

    /// Moves pending inlines of a block container into a [`Block::Plain`].
    fn flush_inlines(&mut self) {
        let inlines = trim_breaks(std::mem::take(&mut self.inlines));
        if !inlines.is_empty() {
            self.blocks.push(Block::Plain(inlines));
        }
    }

    fn push_inline(&mut self, inline: Inline) {
        if let (Some(Inline::Text(last)), Inline::Text(text)) = (self.inlines.last_mut(), &inline) {
            last.push_str(text);
            return;
        }
        self.inlines.push(inline);
    }

    fn push_block(&mut self, block: Block) {
        if self.is_inline_container() {
            // Cannot happen with a balanced stream; keep the text anyway.
            if !self.inlines.is_empty() {
                self.inlines.push(Inline::LineBreak);
            }
            self.inlines.extend(block_inlines(block));
            return;
        }
        self.flush_inlines();
        self.blocks.push(block);
    }

    /// Closes the element, returning its blocks (block containers) once
    /// pending inlines are flushed.
    fn into_blocks(mut self) -> Vec<Block> {
        self.flush_inlines();
        self.blocks
    }
}

/// Flattens a block into inlines (block found where inlines are expected).
fn block_inlines(block: Block) -> Vec<Inline> {
    match block {
        Block::Paragraph(inlines) | Block::Plain(inlines) | Block::Heading(_, inlines) => inlines,
        Block::CodeBlock { text, .. } => text_with_breaks(&text),
        Block::BlockQuote(blocks) => blocks.into_iter().flat_map(block_inlines).collect(),
        Block::List { items, .. } => items
            .into_iter()
            .flatten()
            .flat_map(block_inlines)
            .collect(),
        Block::Rule => vec![Inline::Text("---".to_string())],
    }
}

/// Drops the line breaks starting or ending a paragraph (`\` ending its
/// first line): they show nothing and a re-rendering could not keep them.
fn trim_breaks(mut inlines: Vec<Inline>) -> Vec<Inline> {
    while inlines.last() == Some(&Inline::LineBreak) {
        inlines.pop();
    }
    let leading = inlines
        .iter()
        .take_while(|i| **i == Inline::LineBreak)
        .count();
    inlines.drain(..leading);
    inlines
}

/// Joins the lines of a heading (setext headings span lines): a heading is
/// written on one line by every renderer.
fn one_line(inlines: Vec<Inline>) -> Vec<Inline> {
    let mut out: Vec<Inline> = Vec::with_capacity(inlines.len());
    for inline in trim_breaks(inlines) {
        let inline = match inline {
            Inline::LineBreak => Inline::Text(" ".to_string()),
            Inline::Strong(c) => Inline::Strong(one_line(c)),
            Inline::Emphasis(c) => Inline::Emphasis(one_line(c)),
            Inline::Strikethrough(c) => Inline::Strikethrough(one_line(c)),
            Inline::Link { dest, children } => Inline::Link {
                dest,
                children: one_line(children),
            },
            other => other,
        };
        match (out.last_mut(), &inline) {
            (Some(Inline::Text(last)), Inline::Text(text)) => last.push_str(text),
            _ => out.push(inline),
        }
    }
    out
}

/// Lines of `text`: CommonMark ends a line with `\n`, `\r\n` or `\r`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'))
}

/// Splits `text` on line breaks (a final one is dropped).
fn text_with_breaks(text: &str) -> Vec<Inline> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    let mut inlines = Vec::new();
    for (i, line) in lines(text).enumerate() {
        if i > 0 {
            inlines.push(Inline::LineBreak);
        }
        if !line.is_empty() {
            inlines.push(Inline::Text(line.to_string()));
        }
    }
    inlines
}

struct Builder {
    stack: Vec<Frame>,
}

impl Builder {
    fn top(&mut self) -> &mut Frame {
        self.stack
            .last_mut()
            .expect("the root frame is never popped")
    }

    fn open(&mut self, kind: Kind) {
        self.stack.push(Frame::new(kind));
    }

    fn inline(&mut self, inline: Inline) {
        self.top().push_inline(inline);
    }

    fn block(&mut self, block: Block) {
        self.top().push_block(block);
    }

    /// Text of the source: raw text inside a code or HTML block, an inline
    /// elsewhere.
    fn text(&mut self, text: &str) {
        let top = self.top();
        match top.kind {
            Kind::CodeBlock(_) | Kind::HtmlBlock => top.raw.push_str(text),
            _ => {
                for inline in text_with_breaks_keep_last(text) {
                    top.push_inline(inline);
                }
            }
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        let kind = match tag {
            Tag::Paragraph => Kind::Paragraph,
            Tag::Heading { level, .. } => Kind::Heading(level as u8),
            Tag::BlockQuote(_) => Kind::BlockQuote,
            Tag::CodeBlock(CodeBlockKind::Fenced(info)) => {
                Kind::CodeBlock(info.split_whitespace().next().unwrap_or("").to_string())
            }
            Tag::CodeBlock(CodeBlockKind::Indented) => Kind::CodeBlock(String::new()),
            Tag::HtmlBlock => Kind::HtmlBlock,
            Tag::List(start) => Kind::List(start),
            Tag::Item => Kind::Item,
            Tag::Emphasis => Kind::Emphasis,
            Tag::Strong => Kind::Strong,
            Tag::Strikethrough => Kind::Strikethrough,
            Tag::Link {
                link_type: LinkType::Email,
                dest_url,
                ..
            } => Kind::Link(format!("mailto:{dest_url}")),
            Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                Kind::Link(dest_url.to_string())
            }
            Tag::FootnoteDefinition(_)
            | Tag::DefinitionList
            | Tag::DefinitionListTitle
            | Tag::DefinitionListDefinition
            | Tag::Table(_)
            | Tag::TableHead
            | Tag::TableRow
            | Tag::TableCell
            | Tag::Superscript
            | Tag::Subscript
            | Tag::MetadataBlock(_) => Kind::Transparent,
        };
        // The frame is still pushed, to stay paired with its `Event::End`.
        let kind = if self.stack.len() >= MAX_DEPTH {
            Kind::Transparent
        } else {
            kind
        };
        self.open(kind);
    }

    fn end(&mut self) {
        if self.stack.len() == 1 {
            return;
        }
        let mut frame = self.stack.pop().expect("checked above");
        match frame.kind {
            Kind::Root => unreachable!("the root frame is never popped"),
            Kind::Paragraph => self.block(Block::Paragraph(trim_breaks(frame.inlines))),
            Kind::Heading(level) => self.block(Block::Heading(level, one_line(frame.inlines))),
            Kind::BlockQuote => {
                let blocks = frame.into_blocks();
                self.block(Block::BlockQuote(blocks));
            }
            Kind::CodeBlock(ref lang) => {
                let lang = lang.clone();
                self.block(Block::CodeBlock {
                    lang,
                    text: frame.raw,
                });
            }
            Kind::HtmlBlock => self.block(Block::Paragraph(text_with_breaks(&frame.raw))),
            Kind::List(start) => {
                // Blocks and inlines received directly come from items made
                // transparent by `MAX_DEPTH`: kept as a last item.
                let mut items = std::mem::take(&mut frame.items);
                let rest = frame.into_blocks();
                if !rest.is_empty() {
                    items.push(rest);
                }
                self.block(Block::List { start, items });
            }
            Kind::Item => {
                let blocks = frame.into_blocks();
                let parent = self.top();
                if matches!(parent.kind, Kind::List(_)) {
                    parent.items.push(blocks);
                } else {
                    for block in blocks {
                        parent.push_block(block);
                    }
                }
            }
            Kind::Strong => self.inline(Inline::Strong(frame.inlines)),
            Kind::Emphasis => self.inline(Inline::Emphasis(frame.inlines)),
            Kind::Strikethrough => self.inline(Inline::Strikethrough(frame.inlines)),
            Kind::Link(ref dest) => {
                let dest = dest.clone();
                self.inline(Inline::Link {
                    dest,
                    children: frame.inlines,
                });
            }
            Kind::Transparent => {
                let Frame {
                    blocks, inlines, ..
                } = frame;
                for block in blocks {
                    self.block(block);
                }
                for inline in inlines {
                    self.inline(inline);
                }
            }
        }
    }

    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(_) => self.end(),
            Event::Text(text) => self.text(&text),
            Event::Code(code) => self.inline(Inline::Code(code.to_string())),
            Event::InlineMath(math) => self.inline(Inline::Text(format!("${math}$"))),
            Event::DisplayMath(math) => self.inline(Inline::Text(format!("$${math}$$"))),
            // Raw HTML is never interpreted: it is shown as text.
            Event::Html(html) | Event::InlineHtml(html) => self.text(&html),
            Event::FootnoteReference(name) => self.inline(Inline::Text(format!("[^{name}]"))),
            // Alerts are line oriented: every line break of the source is kept.
            Event::SoftBreak | Event::HardBreak => self.inline(Inline::LineBreak),
            Event::Rule => self.block(Block::Rule),
            Event::TaskListMarker(checked) => self.inline(Inline::Text(
                if checked { "[x] " } else { "[ ] " }.to_string(),
            )),
        }
    }
}

/// Splits `text` on line breaks, keeping a final one (inline HTML spanning
/// lines).
fn text_with_breaks_keep_last(text: &str) -> Vec<Inline> {
    let mut inlines = Vec::new();
    for (i, line) in lines(text).enumerate() {
        if i > 0 {
            inlines.push(Inline::LineBreak);
        }
        if !line.is_empty() {
            inlines.push(Inline::Text(line.to_string()));
        }
    }
    inlines
}

/// Parses a Markdown body (CommonMark plus `~~strikethrough~~`) into the
/// restricted tree, then puts back the elements of `slots` in place of their
/// tokens (see [`MarkdownElement`]).
pub fn parse(source: &str, slots: &[MarkdownElement]) -> Vec<Block> {
    let mut builder = Builder {
        stack: vec![Frame::new(Kind::Root)],
    };
    for event in Parser::new_ext(source, Options::ENABLE_STRIKETHROUGH) {
        builder.event(event);
    }
    while builder.stack.len() > 1 {
        builder.end();
    }
    let blocks = builder.stack.pop().expect("root frame").into_blocks();
    if has_tokens(source) {
        substitute_blocks(blocks, slots, 1)
    } else {
        blocks
    }
}

// ------------------------------------------------------------ token substitution

/// Whether `text` holds a token character.
fn has_tokens(text: &str) -> bool {
    text.contains([TOKEN_OPEN, TOKEN_CLOSE])
}

/// Part of a text holding tokens.
enum Piece<'a> {
    Text(&'a str),
    /// A token and the element it stands for, `None` for an unknown index
    /// (a token written in the template source).
    Slot(Option<&'a MarkdownElement>),
    /// A token character outside a well-formed token.
    Stray,
}

/// Splits `text` into text and tokens.
fn pieces<'a>(text: &'a str, slots: &'a [MarkdownElement]) -> Vec<Piece<'a>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find([TOKEN_OPEN, TOKEN_CLOSE]) {
        if i > 0 {
            out.push(Piece::Text(&rest[..i]));
        }
        let opens = rest[i..].starts_with(TOKEN_OPEN);
        let after = &rest[i + TOKEN_OPEN.len_utf8()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if opens && digits > 0 && after[digits..].starts_with(TOKEN_CLOSE) {
            let slot = after[..digits]
                .parse::<usize>()
                .ok()
                .and_then(|index| slots.get(index));
            out.push(Piece::Slot(slot));
            rest = &after[digits + TOKEN_CLOSE.len_utf8()..];
        } else {
            out.push(Piece::Stray);
            rest = after;
        }
    }
    if !rest.is_empty() {
        out.push(Piece::Text(rest));
    }
    out
}

/// Where a token stands in literal text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Raw {
    /// Text of a code block of the template.
    CodeBlock,
    /// Content of a code span of the template.
    CodeSpan,
    /// Destination of a link of the template.
    Destination,
}

/// `text` with its tokens replaced by the literal content of their element.
fn raw(text: &str, slots: &[MarkdownElement], at: Raw) -> String {
    if !has_tokens(text) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for piece in pieces(text, slots) {
        let content = match piece {
            Piece::Text(text) => {
                out.push_str(text);
                continue;
            }
            Piece::Stray | Piece::Slot(None) => char::REPLACEMENT_CHARACTER.to_string(),
            Piece::Slot(Some(element)) => match element {
                MarkdownElement::Code(text)
                | MarkdownElement::Text(text)
                | MarkdownElement::CodeBlock { text, .. } => text.clone(),
                MarkdownElement::Link { dest, .. } if at == Raw::Destination => dest.clone(),
                MarkdownElement::Link { text, dest } => format!("{text} ({dest})"),
            },
        };
        match at {
            Raw::CodeBlock => out.push_str(&content),
            Raw::CodeSpan => out.push_str(&content.replace(['\r', '\n'], " ")),
            Raw::Destination => out.push_str(&super::encode_destination(&content)),
        }
    }
    out
}

/// `lang` without its tokens.
fn strip_tokens(lang: &str) -> String {
    if !has_tokens(lang) {
        return lang.to_string();
    }
    let mut out = String::new();
    for piece in pieces(lang, &[]) {
        if let Piece::Text(text) = piece {
            out.push_str(text);
        }
    }
    out
}

/// An inline, or a block cutting a paragraph.
enum Part {
    Inline(Inline),
    Block(Block),
}

/// Text of a link or of a refused link, on one line: a blank line would end
/// the link, or an emphasis around it, in the `markdown` rendering.
fn one_line_text(text: &str) -> Inline {
    Inline::Text(text.replace("\r\n", " ").replace(['\r', '\n'], " "))
}

/// Puts back the element a token stands for, at inline level `depth`: a code
/// block is a block when `blocks` is set (direct content of a paragraph), a
/// code span elsewhere; a link deeper than [`MAX_DEPTH`] is text.
fn element_parts(element: &MarkdownElement, depth: usize, blocks: bool, out: &mut Vec<Part>) {
    match element {
        MarkdownElement::Code(text) => out.push(Part::Inline(Inline::Code(text.clone()))),
        MarkdownElement::Text(text) => out.push(Part::Inline(one_line_text(text))),
        MarkdownElement::CodeBlock { lang, text } if blocks => {
            let mut text = text.clone();
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            out.push(Part::Block(Block::CodeBlock {
                lang: lang.clone(),
                text,
            }));
        }
        MarkdownElement::CodeBlock { text, .. } => {
            let text = text.replace(['\r', '\n'], " ");
            if !text.is_empty() {
                out.push(Part::Inline(Inline::Code(text)));
            }
        }
        MarkdownElement::Link { text, dest } if depth <= MAX_DEPTH => {
            let children = if text.is_empty() {
                Vec::new()
            } else {
                vec![one_line_text(text)]
            };
            out.push(Part::Inline(Inline::Link {
                dest: dest.clone(),
                children,
            }));
        }
        MarkdownElement::Link { text, dest } => {
            out.push(Part::Inline(one_line_text(&format!("{text} ({dest})"))));
        }
    }
}

/// Substitutes the tokens of `inlines`, at inline level `depth`.
fn substitute_inlines(
    inlines: Vec<Inline>,
    slots: &[MarkdownElement],
    depth: usize,
    blocks: bool,
) -> Vec<Part> {
    let mut out = Vec::with_capacity(inlines.len());
    for inline in inlines {
        let inline = match inline {
            Inline::Text(text) if has_tokens(&text) => {
                for piece in pieces(&text, slots) {
                    match piece {
                        Piece::Text(text) => out.push(Part::Inline(Inline::Text(text.to_string()))),
                        Piece::Stray | Piece::Slot(None) => out.push(Part::Inline(Inline::Text(
                            char::REPLACEMENT_CHARACTER.to_string(),
                        ))),
                        Piece::Slot(Some(element)) => {
                            element_parts(element, depth, blocks, &mut out)
                        }
                    }
                }
                continue;
            }
            Inline::Code(text) => Inline::Code(raw(&text, slots, Raw::CodeSpan)),
            Inline::Strong(c) => Inline::Strong(substitute_nested(c, slots, depth + 1)),
            Inline::Emphasis(c) => Inline::Emphasis(substitute_nested(c, slots, depth + 1)),
            Inline::Strikethrough(c) => {
                Inline::Strikethrough(substitute_nested(c, slots, depth + 1))
            }
            Inline::Link { dest, children } => Inline::Link {
                dest: raw(&dest, slots, Raw::Destination),
                children: substitute_nested(children, slots, depth + 1),
            },
            other => other,
        };
        out.push(Part::Inline(inline));
    }
    out
}

/// Substitutes the tokens of inlines where no block can stand.
fn substitute_nested(inlines: Vec<Inline>, slots: &[MarkdownElement], depth: usize) -> Vec<Inline> {
    let mut out = Frame::new(Kind::Root);
    for part in substitute_inlines(inlines, slots, depth, false) {
        if let Part::Inline(inline) = part {
            out.push_inline(inline);
        }
    }
    out.inlines
}

/// Drops the blanks and line breaks ending `inlines` (before a block).
fn trim_end_blank(mut inlines: Vec<Inline>) -> Vec<Inline> {
    loop {
        match inlines.last_mut() {
            Some(Inline::LineBreak) => {}
            Some(Inline::Text(text)) => {
                let kept = text.trim_end().len();
                if kept > 0 {
                    text.truncate(kept);
                    return inlines;
                }
            }
            _ => return inlines,
        }
        inlines.pop();
    }
}

/// Drops the blanks and line breaks starting `inlines` (after a block).
fn trim_start_blank(inlines: Vec<Inline>) -> Vec<Inline> {
    let mut out = Vec::with_capacity(inlines.len());
    for inline in inlines {
        if out.is_empty() {
            match inline {
                Inline::LineBreak => continue,
                Inline::Text(text) => {
                    let trimmed = text.trim_start();
                    if !trimmed.is_empty() {
                        out.push(Inline::Text(trimmed.to_string()));
                    }
                    continue;
                }
                _ => {}
            }
        }
        out.push(inline);
    }
    out
}

/// Substitutes the tokens of a paragraph (or [`Block::Plain`]) at block
/// level `depth`: a code block cuts it, the inlines before and after it
/// becoming paragraphs of their own (omitted when empty).
fn substitute_paragraph(
    inlines: Vec<Inline>,
    slots: &[MarkdownElement],
    depth: usize,
    make: fn(Vec<Inline>) -> Block,
    out: &mut Vec<Block>,
) {
    let mut run = Frame::new(Kind::Root);
    let mut cut = false;
    for part in substitute_inlines(inlines, slots, depth + 1, true) {
        match part {
            Part::Inline(inline) => run.push_inline(inline),
            Part::Block(block) => {
                let mut before = trim_end_blank(std::mem::take(&mut run.inlines));
                if cut {
                    before = trim_start_blank(before);
                }
                if !before.is_empty() {
                    out.push(make(before));
                }
                out.push(block);
                cut = true;
            }
        }
    }
    if !cut {
        out.push(make(run.inlines));
        return;
    }
    let after = trim_start_blank(run.inlines);
    if !after.is_empty() {
        out.push(make(after));
    }
}

/// Substitutes the tokens of `blocks`, at block level `depth` (1 for the
/// top-level blocks).
fn substitute_blocks(blocks: Vec<Block>, slots: &[MarkdownElement], depth: usize) -> Vec<Block> {
    let mut out = Vec::with_capacity(blocks.len());
    for block in blocks {
        let block = match block {
            Block::Paragraph(inlines) => {
                substitute_paragraph(inlines, slots, depth, Block::Paragraph, &mut out);
                continue;
            }
            Block::Plain(inlines) => {
                substitute_paragraph(inlines, slots, depth, Block::Plain, &mut out);
                continue;
            }
            Block::Heading(level, inlines) => Block::Heading(
                level,
                one_line(substitute_nested(inlines, slots, depth + 1)),
            ),
            Block::BlockQuote(blocks) => {
                Block::BlockQuote(substitute_blocks(blocks, slots, depth + 1))
            }
            Block::CodeBlock { lang, text } => Block::CodeBlock {
                lang: strip_tokens(&lang),
                text: raw(&text, slots, Raw::CodeBlock),
            },
            Block::List { start, items } => Block::List {
                start,
                items: items
                    .into_iter()
                    .map(|item| substitute_blocks(item, slots, depth + 1))
                    .collect(),
            },
            Block::Rule => Block::Rule,
        };
        out.push(block);
    }
    out
}
