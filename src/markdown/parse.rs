//! pulldown-cmark event stream → restricted tree.

use super::{Block, Inline};
use pulldown_cmark::{CodeBlockKind, Event, LinkType, Options, Parser, Tag};

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
        self.open(kind);
    }

    fn end(&mut self) {
        if self.stack.len() == 1 {
            return;
        }
        let frame = self.stack.pop().expect("checked above");
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
            Kind::List(start) => self.block(Block::List {
                start,
                items: frame.items,
            }),
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
/// restricted tree.
pub fn parse(source: &str) -> Vec<Block> {
    let mut builder = Builder {
        stack: vec![Frame::new(Kind::Root)],
    };
    for event in Parser::new_ext(source, Options::ENABLE_STRIKETHROUGH) {
        builder.event(event);
    }
    while builder.stack.len() > 1 {
        builder.end();
    }
    builder.stack.pop().expect("root frame").into_blocks()
}
