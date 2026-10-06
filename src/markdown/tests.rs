//! Tests of the Markdown parser and renderers.

use super::parse::MAX_DEPTH;
use super::*;
use crate::config::OutputFormat::{self, Html, Markdown, Plain, TelegramHtml};
use minijinja::{Environment, Value, context};

fn text(t: &str) -> Inline {
    Inline::Text(t.to_string())
}

fn para(inlines: Vec<Inline>) -> Block {
    Block::Paragraph(inlines)
}

/// Parses a source without tokens.
fn parse(source: &str) -> Vec<Block> {
    super::parse(source, &[])
}

/// Renders a source without tokens.
fn render(source: &str, format: OutputFormat) -> String {
    super::render(source, &[], format)
}

/// A `body_format: markdown` body: `template` rendered with the Markdown
/// auto-escaping and valerter's filters, as the source (holding tokens) and
/// the elements the tokens stand for.
fn rendered(template: &str, ctx: Value) -> (String, Vec<MarkdownElement>) {
    let mut env = Environment::new();
    crate::template::filters::install_markdown_escape(&mut env);
    crate::template::filters::register(&mut env);
    crate::template::filters::render_markdown(&env, template, ctx).unwrap()
}

/// Markdown source of a body, each token replaced by the Markdown source of
/// its element (what the filters wrote before tokens existed).
fn source(template: &str, ctx: Value) -> String {
    let (source, slots) = rendered(template, ctx);
    slots
        .iter()
        .enumerate()
        .fold(source, |source, (index, element)| {
            source.replace(
                &format!("{TOKEN_OPEN}{index}{TOKEN_CLOSE}"),
                &element.to_string(),
            )
        })
}

/// The four renderings of a template rendered as a Markdown body.
fn renders(template: &str, ctx: Value) -> [String; 4] {
    let (src, slots) = rendered(template, ctx);
    OutputFormat::ALL.map(|format| super::render(&src, &slots, format))
}

// ------------------------------------------------------------- parse (2.1)

#[test]
fn parse_paragraph_breaks_and_emphasis() {
    assert_eq!(
        parse("a **b** *c* ~~d~~ `e`\nf  \ng"),
        vec![para(vec![
            text("a "),
            Inline::Strong(vec![text("b")]),
            text(" "),
            Inline::Emphasis(vec![text("c")]),
            text(" "),
            Inline::Strikethrough(vec![text("d")]),
            text(" "),
            Inline::Code("e".to_string()),
            Inline::LineBreak,
            text("f"),
            Inline::LineBreak,
            text("g"),
        ])]
    );
}

#[test]
fn parse_headings_rule_and_quote() {
    assert_eq!(
        parse("# T\n\n---\n\n> q\n\n### U"),
        vec![
            Block::Heading(1, vec![text("T")]),
            Block::Rule,
            Block::BlockQuote(vec![para(vec![text("q")])]),
            Block::Heading(3, vec![text("U")]),
        ]
    );
}

#[test]
fn parse_code_blocks() {
    assert_eq!(
        parse("```json extra\n{\"a\": 1}\n```\n\n    indented\n"),
        vec![
            Block::CodeBlock {
                lang: "json".to_string(),
                text: "{\"a\": 1}\n".to_string()
            },
            Block::CodeBlock {
                lang: String::new(),
                text: "indented\n".to_string()
            },
        ]
    );
}

#[test]
fn parse_lists() {
    assert_eq!(
        parse("- a\n- b\n\n3. c\n4. d"),
        vec![
            Block::List {
                start: None,
                items: vec![
                    vec![Block::Plain(vec![text("a")])],
                    vec![Block::Plain(vec![text("b")])],
                ]
            },
            Block::List {
                start: Some(3),
                items: vec![
                    vec![Block::Plain(vec![text("c")])],
                    vec![Block::Plain(vec![text("d")])],
                ]
            },
        ]
    );
}

#[test]
fn parse_links_reference_links_autolinks_and_images() {
    let link_to = |dest: &str, t: &str| Inline::Link {
        dest: dest.to_string(),
        children: vec![text(t)],
    };
    assert_eq!(
        parse(
            "[a](https://a.example) [b][r] <https://c.example> <d@e.example> ![alt](https://i.example/p.png)\n\n[r]: https://r.example"
        ),
        vec![para(vec![
            link_to("https://a.example", "a"),
            text(" "),
            link_to("https://r.example", "b"),
            text(" "),
            link_to("https://c.example", "https://c.example"),
            text(" "),
            link_to("mailto:d@e.example", "d@e.example"),
            text(" "),
            link_to("https://i.example/p.png", "alt"),
        ])]
    );
}

#[test]
fn parse_raw_html_as_text() {
    assert_eq!(
        parse("a <b>x</b> c"),
        vec![para(vec![text("a <b>x</b> c")])]
    );
    assert_eq!(
        parse("<div>\n<script>alert(1)</script>\n</div>"),
        vec![para(vec![
            text("<div>"),
            Inline::LineBreak,
            text("<script>alert(1)</script>"),
            Inline::LineBreak,
            text("</div>"),
        ])]
    );
}

#[test]
fn parse_table_as_text() {
    assert_eq!(
        parse("| a | b |\n|---|---|\n| 1 | 2 |"),
        vec![para(vec![
            text("| a | b |"),
            Inline::LineBreak,
            text("|---|---|"),
            Inline::LineBreak,
            text("| 1 | 2 |"),
        ])]
    );
}

#[test]
fn parse_ignores_footnotes_and_task_lists() {
    // Not enabled: read as plain CommonMark.
    assert_eq!(
        parse("- [ ] t"),
        vec![Block::List {
            start: None,
            items: vec![vec![Block::Plain(vec![text("[ ] t")])]]
        }]
    );
    assert_eq!(parse("a[^1]"), vec![para(vec![text("a[^1]")])]);
}

// ------------------------------------------------- scenarios (2.2, specs)

#[test]
fn escaped_value_inside_strong() {
    let [plain, md, html, tg] = renders("**{{ host }}** down", context! { host => "a_b*c" });
    assert_eq!(
        source("**{{ host }}** down", context! { host => "a_b*c" }),
        r"**a\_b\*c** down"
    );
    assert_eq!(plain, "a_b*c down");
    assert_eq!(md, r"**a\_b\*c** down");
    assert_eq!(html, "<p><strong>a_b*c</strong> down</p>");
    assert_eq!(tg, "<b>a_b*c</b> down");
}

#[test]
fn raw_html_in_source_is_text() {
    let [plain, md, html, tg] = renders("<b>x</b> {{ v }}", context! { v => "y" });
    assert_eq!(tg, "&lt;b&gt;x&lt;/b&gt; y");
    assert_eq!(html, "<p>&lt;b&gt;x&lt;/b&gt; y</p>");
    assert_eq!(plain, "<b>x</b> y");
    assert_eq!(md, "&lt;b>x&lt;/b> y");
}

#[test]
fn single_line_break_is_kept() {
    assert_eq!(render("ligne 1\nligne 2", Plain), "ligne 1\nligne 2");
    assert_eq!(
        render("ligne 1\nligne 2", Html),
        "<p>ligne 1<br>\nligne 2</p>"
    );
    assert_eq!(render("ligne 1\nligne 2", TelegramHtml), "ligne 1\nligne 2");
    assert_eq!(render("ligne 1\nligne 2", Markdown), "ligne 1\nligne 2");
}

#[test]
fn table_is_not_recognised() {
    let source = "| a | b |\n|---|---|";
    for format in OutputFormat::ALL {
        let out = render(source, format);
        assert!(!out.contains("<table"), "{format}: {out}");
        assert!(out.contains('a') && out.contains('b'), "{format}: {out}");
    }
    assert_eq!(render(source, Plain), "| a | b |\n|---|---|");
    assert_eq!(render(source, Markdown), "\\| a \\| b \\|\n\\|---\\|---\\|");
}

#[test]
fn plain_hostile_values() {
    let [plain, ..] = renders(
        "**{{ a }}** {{ b }} {{ c }}",
        context! { a => "<nil>", b => "&amp;", c => "](x)" },
    );
    assert_eq!(plain, "<nil> &amp; ](x)");
}

#[test]
fn plain_rendering_of_links() {
    assert_eq!(
        render("[Voir](https://vl.example.com)", Plain),
        "Voir (https://vl.example.com)"
    );
    assert_eq!(
        render("<https://vl.example.com>", Plain),
        "https://vl.example.com"
    );
}

#[test]
fn plain_blocks_rendering() {
    assert_eq!(
        render(
            "# Titre\n\n- a\n- b\n\n3. c\n\n> q\n\n---\n\n```\ncode\n```",
            Plain
        ),
        "Titre\n\n- a\n- b\n\n3. c\n\n> q\n\n---\n\ncode"
    );
}

#[test]
fn html_hostile_values() {
    let [_, _, html, _] = renders(
        "**{{ a }}** {{ b }}",
        context! { a => "<script>", b => "&amp;" },
    );
    assert_eq!(html, "<p><strong>&lt;script&gt;</strong> &amp;amp;</p>");
}

#[test]
fn source_link_with_refused_scheme() {
    let source = "[clic](javascript:alert(1))";
    let html = render(source, Html);
    assert!(!html.contains("href"), "{html}");
    assert_eq!(html, "<p>clic (javascript:alert(1))</p>");
    assert_eq!(render(source, TelegramHtml), "clic (javascript:alert(1))");
    assert_eq!(render(source, Plain), "clic (javascript:alert(1))");
    assert_eq!(render(source, Markdown), "clic (javascript:alert(1))");
}

#[test]
fn html_blocks_rendering() {
    assert_eq!(
        render(
            "# T\n\n- a\n- b\n\n3. c\n\n> q\n\n---\n\n*e* ~~s~~ `c` [l](mailto:x@y.z)",
            Html
        ),
        "<h1>T</h1>\n<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n<ol start=\"3\">\n<li>c</li>\n</ol>\n\
         <blockquote>\n<p>q</p>\n</blockquote>\n<hr>\n\
         <p><em>e</em> <del>s</del> <code>c</code> <a href=\"mailto:x@y.z\">l</a></p>"
    );
}

#[test]
fn telegram_blocks_rendering() {
    assert_eq!(
        render(
            "# T\n\n- a\n- b\n\n3. c\n\n> q\n\n---\n\n*e* ~~s~~ `c` [l](https://x.y/?a=1&b=\"2\")\n\n```sh\nls <x>\n```\n\n```\nraw\n```",
            TelegramHtml
        ),
        "<b>T</b>\n\n• a\n• b\n\n3. c\n\n<blockquote>q</blockquote>\n\n———\n\n\
         <i>e</i> <s>s</s> <code>c</code> <a href=\"https://x.y/?a=1&amp;b=&quot;2&quot;\">l</a>\n\n\
         <pre><code class=\"language-sh\">ls &lt;x&gt;</code></pre>\n\n<pre>raw</pre>"
    );
}

#[test]
fn telegram_never_nests_links_or_quotes() {
    let tg = render(
        "[![alt](https://i.example/p.png)](https://x.example)\n\n> a\n> > b",
        TelegramHtml,
    );
    assert_eq!(
        tg,
        "<a href=\"https://x.example\">alt (https://i.example/p.png)</a>\n\n<blockquote>a\n\nb</blockquote>"
    );
}

#[test]
fn markdown_common_values_stay_readable() {
    let [_, md, ..] = renders(
        "{{ host }} at {{ ts }}",
        context! { host => "web-01.example.com", ts => "10:49:35" },
    );
    assert_eq!(md, "web-01.example.com at 10:49:35");
}

#[test]
fn markdown_neutralises_markdown_punctuation() {
    let [_, md, ..] = renders(
        "**{{ a }}** {{ b }}",
        context! { a => "a_b*c", b => "<nil> &amp;" },
    );
    assert_eq!(md, r"**a\_b\*c** &lt;nil> &amp;amp;");
}

#[test]
fn markdown_escapes_line_starts() {
    let [_, md, ..] = renders(
        "{{ a }}\n{{ b }}\n{{ c }}\n{{ d }}\n{{ e }}\n{{ f }}\n{{ g }}",
        context! { a => "# h", b => "- l", c => "1. o", d => "> q", e => "+ p", f => "===", g => "2) x" },
    );
    assert_eq!(md, "\\# h\n\\- l\n1\\. o\n\\> q\n\\+ p\n\\===\n2\\) x");
}

#[test]
fn markdown_blocks_rendering() {
    assert_eq!(
        render(
            "## T\n\n- a\n- b\n\n3. c\n\n> q\n\n---\n\n*e* ~~s~~ `c` [l](<https://x.y/a b>)\n\n````\n```\n````",
            Markdown
        ),
        "## T\n\n- a\n- b\n\n3. c\n\n> q\n\n___\n\n*e* ~~s~~ `c` [l](https://x.y/a%20b)\n\n````\n```\n````"
    );
}

#[test]
fn codeblock_scenario() {
    let ctx = context! { _msg => r#"{"a": "<b>"}"# };
    let src = source("Log:\n{{ _msg | codeblock('json') }}", ctx.clone());
    assert_eq!(src, "Log:\n```json\n{\"a\": \"<b>\"}\n```");
    let [plain, md, html, tg] = renders("Log:\n{{ _msg | codeblock('json') }}", ctx);
    assert!(
        html.contains(
            r#"<pre><code class="language-json">{&quot;a&quot;: &quot;&lt;b&gt;&quot;}</code></pre>"#
        ),
        "{html}"
    );
    assert_eq!(plain, "Log:\n\n{\"a\": \"<b>\"}");
    assert_eq!(md, "Log:\n\n```json\n{\"a\": \"<b>\"}\n```");
    assert_eq!(
        tg,
        "Log:\n\n<pre><code class=\"language-json\">{\"a\": \"&lt;b&gt;\"}</code></pre>"
    );
}

#[test]
fn codeblock_value_containing_a_fence() {
    let ctx = context! { v => "a\n```\nb" };
    let src = source("{{ v | codeblock }}", ctx.clone());
    assert_eq!(src, "````\na\n```\nb\n````");
    let [plain, ..] = renders("{{ v | codeblock }}", ctx);
    assert_eq!(plain, "a\n```\nb");
}

#[test]
fn code_scenarios() {
    assert_eq!(source("{{ v | code }}", context! { v => "a`b" }), "``a`b``");
    let [plain, _, html, _] = renders("{{ v | code }}", context! { v => "a`b" });
    assert_eq!(plain, "a`b");
    assert_eq!(html, "<p><code>a`b</code></p>");

    let [_, md, html, tg] = renders("{{ v | code }}", context! { v => "**x**" });
    assert_eq!(html, "<p><code>**x**</code></p>");
    assert_eq!(tg, "<code>**x**</code>");
    assert_eq!(md, "`**x**`");

    assert_eq!(
        source("{{ v | code }}", context! { v => "`x`" }),
        "`` `x` ``"
    );
    assert_eq!(
        render(&source("{{ v | code }}", context! { v => "`x`" }), Plain),
        "`x`"
    );
}

#[test]
fn code_turns_line_breaks_into_spaces() {
    let [plain, ..] = renders("{{ v | code }}", context! { v => "a\n\n# b" });
    assert_eq!(plain, "a  # b");
}

#[test]
fn md_link_rendering_scenarios() {
    let ctx = context! { host => "web_01" };
    let template =
        r#"{{ md_link("logs " ~ host, "https://vl.example.com/select?q=host:" ~ host) }}"#;
    let [plain, md, html, tg] = renders(template, ctx);
    assert!(
        html.contains(r#"<a href="https://vl.example.com/select?q=host:web_01">logs web_01</a>"#),
        "{html}"
    );
    assert_eq!(
        tg,
        r#"<a href="https://vl.example.com/select?q=host:web_01">logs web_01</a>"#
    );
    assert_eq!(
        plain,
        "logs web_01 (https://vl.example.com/select?q=host:web_01)"
    );
    assert_eq!(
        md,
        r"[logs web\_01](https://vl.example.com/select?q=host:web_01)"
    );

    for out in renders(r#"{{ md_link("x", "javascript:alert(1)") }}"#, context! {}) {
        assert!(!out.contains("href") && !out.contains("]("), "{out}");
        assert!(out.contains("x (javascript:alert(1))"), "{out}");
    }
}

#[test]
fn md_link_encodes_destination_syntax_only() {
    assert_eq!(
        source(
            r#"{{ md_link("t", "https://h/a b(c)<d>\\e?x=1&y=2") }}"#,
            context! {}
        ),
        "[t](https://h/a%20b%28c%29%3Cd%3E%5Ce?x=1&y=2)"
    );
}

#[test]
fn image_is_a_link_to_the_image() {
    let src = "![graph](https://g.example/p.png)";
    assert_eq!(render(src, Plain), "graph (https://g.example/p.png)");
    assert_eq!(
        render(src, Html),
        r#"<p><a href="https://g.example/p.png">graph</a></p>"#
    );
}

// ------------------------------------------------- hostile battery (2.2)

/// Values a log can carry that are Markdown or HTML syntax. Each is inserted
/// mid-line and at the start of a line, through the auto-escaping, and must
/// render literally in every format (leading blanks of a line of the value
/// and its empty lines are written U+00A0).
const HOSTILE: &[&str] = &[
    "<nil>",
    "a_b_c",
    "**",
    "`orphan",
    "](",
    "&amp;",
    "\\",
    "10:49:35",
    "web-01.example.com",
    "déjà 🔥 日本",
    "# h",
    "- l",
    "1. o",
    ">",
    "    four",
    "a\n\n    code",
    "a\r\n\r\nb",
];

/// Expected renderings of `"x {{ v }}\n{{ v }}"`, per value, in the order
/// plain, markdown, html, telegram_html.
const HOSTILE_EXPECTED: &[[&str; 4]] = &[
    [
        "x <nil>\n<nil>",
        "x &lt;nil>\n&lt;nil>",
        "<p>x &lt;nil&gt;<br>\n&lt;nil&gt;</p>",
        "x &lt;nil&gt;\n&lt;nil&gt;",
    ],
    [
        "x a_b_c\na_b_c",
        "x a\\_b\\_c\na\\_b\\_c",
        "<p>x a_b_c<br>\na_b_c</p>",
        "x a_b_c\na_b_c",
    ],
    [
        "x **\n**",
        "x \\*\\*\n\\*\\*",
        "<p>x **<br>\n**</p>",
        "x **\n**",
    ],
    [
        "x `orphan\n`orphan",
        "x \\`orphan\n\\`orphan",
        "<p>x `orphan<br>\n`orphan</p>",
        "x `orphan\n`orphan",
    ],
    [
        "x ](\n](",
        "x \\](\n\\](",
        "<p>x ](<br>\n](</p>",
        "x ](\n](",
    ],
    [
        "x &amp;\n&amp;",
        "x &amp;amp;\n&amp;amp;",
        "<p>x &amp;amp;<br>\n&amp;amp;</p>",
        "x &amp;amp;\n&amp;amp;",
    ],
    [
        "x \\\n\\",
        "x \\\\\n\\\\",
        "<p>x \\<br>\n\\</p>",
        "x \\\n\\",
    ],
    [
        "x 10:49:35\n10:49:35",
        "x 10:49:35\n10:49:35",
        "<p>x 10:49:35<br>\n10:49:35</p>",
        "x 10:49:35\n10:49:35",
    ],
    [
        "x web-01.example.com\nweb-01.example.com",
        "x web-01.example.com\nweb-01.example.com",
        "<p>x web-01.example.com<br>\nweb-01.example.com</p>",
        "x web-01.example.com\nweb-01.example.com",
    ],
    [
        "x déjà 🔥 日本\ndéjà 🔥 日本",
        "x déjà 🔥 日本\ndéjà 🔥 日本",
        "<p>x déjà 🔥 日本<br>\ndéjà 🔥 日本</p>",
        "x déjà 🔥 日本\ndéjà 🔥 日本",
    ],
    [
        "x # h\n# h",
        "x # h\n\\# h",
        "<p>x # h<br>\n# h</p>",
        "x # h\n# h",
    ],
    [
        "x - l\n- l",
        "x - l\n\\- l",
        "<p>x - l<br>\n- l</p>",
        "x - l\n- l",
    ],
    [
        "x 1. o\n1. o",
        "x 1. o\n1\\. o",
        "<p>x 1. o<br>\n1. o</p>",
        "x 1. o\n1. o",
    ],
    [
        "x >\n>",
        "x >\n\\>",
        "<p>x &gt;<br>\n&gt;</p>",
        "x &gt;\n&gt;",
    ],
    [
        "x \u{a0}\u{a0}\u{a0}\u{a0}four\n\u{a0}\u{a0}\u{a0}\u{a0}four",
        "x \u{a0}\u{a0}\u{a0}\u{a0}four\n\u{a0}\u{a0}\u{a0}\u{a0}four",
        "<p>x \u{a0}\u{a0}\u{a0}\u{a0}four<br>\n\u{a0}\u{a0}\u{a0}\u{a0}four</p>",
        "x \u{a0}\u{a0}\u{a0}\u{a0}four\n\u{a0}\u{a0}\u{a0}\u{a0}four",
    ],
    [
        "x a\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code\na\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code",
        "x a\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code\na\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code",
        "<p>x a<br>\n\u{a0}<br>\n\u{a0}\u{a0}\u{a0}\u{a0}code<br>\na<br>\n\u{a0}<br>\n\u{a0}\u{a0}\u{a0}\u{a0}code</p>",
        "x a\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code\na\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code",
    ],
    [
        "x a\n\u{a0}\nb\na\n\u{a0}\nb",
        "x a\n\u{a0}\nb\na\n\u{a0}\nb",
        "<p>x a<br>\n\u{a0}<br>\nb<br>\na<br>\n\u{a0}<br>\nb</p>",
        "x a\n\u{a0}\nb\na\n\u{a0}\nb",
    ],
];

#[test]
fn hostile_values_render_literally_in_every_format() {
    assert_eq!(HOSTILE.len(), HOSTILE_EXPECTED.len());
    for (value, expected) in HOSTILE.iter().zip(HOSTILE_EXPECTED) {
        let got = renders("x {{ v }}\n{{ v }}", context! { v => value });
        for (format, (got, expected)) in OutputFormat::ALL.iter().zip(got.iter().zip(expected)) {
            assert_eq!(got, expected, "value {value:?}, format {format}");
        }
    }
}

// ------------------------------------------------------ properties (2.3)

/// Small deterministic generator (xorshift64*), so failures reproduce.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Fragments random Markdown sources are made of: punctuation, markup,
/// tags, backticks, brackets, entities, block starts, multibyte text.
const FRAGMENTS: &[&str] = &[
    "a",
    "b",
    "web_01",
    " ",
    " ",
    "\n",
    "\n\n",
    "*",
    "**",
    "_",
    "__",
    "~~",
    "`",
    "```",
    "[",
    "]",
    "(",
    ")",
    "](",
    "![",
    "<",
    ">",
    "&",
    "&amp;",
    "&#60;",
    "&lt",
    "\\",
    "\"",
    "'",
    "<b>",
    "</b>",
    "<i>",
    "<a href=\"x\">",
    "</a>",
    "<!--",
    "-->",
    "<pre>",
    "# ",
    "## ",
    "- ",
    "* ",
    "1. ",
    "2) ",
    "> ",
    ">> ",
    "    ",
    "---",
    "===",
    "|",
    "| a | b |\n|---|---|\n",
    "é",
    "🔥",
    "日本",
    "https://x.example/a?b=1&c=2",
    "javascript:alert(1)",
    "[l](https://x.example)",
    "[l](javascript:x)",
    "![i](https://i.example/p.png)",
    "<https://a.example>",
    "<a@b.example>",
    "[r]",
    "\n[r]: https://r.example\n",
    "```js\n",
    "~~~\n",
    "\t",
    "\r\n",
    "**`x`**",
    "[`c`](https://x)",
    "# `h` ",
    "**a __b__ c**",
    "> ```\nx\n```",
];

pub(crate) fn random_source(rng: &mut Rng) -> String {
    let len = rng.below(40);
    (0..len)
        .map(|_| FRAGMENTS[rng.below(FRAGMENTS.len())])
        .collect()
}

/// Checks that `out` is well-formed HTML made only of the `allowed` tags
/// (`void` ones are never closed), with `attrs(tag, attributes)` deciding
/// which attribute strings are allowed, and no bare `<`, `>` or `&`.
fn check_html(
    out: &str,
    allowed: &[&str],
    void: &[&str],
    attrs: impl Fn(&str, &str) -> bool,
) -> Result<(), String> {
    let mut stack: Vec<String> = Vec::new();
    let mut rest = out;
    while let Some(i) = rest.find(['<', '>', '&']) {
        let (c, after) = (rest.as_bytes()[i], &rest[i + 1..]);
        match c {
            b'>' => return Err(format!("bare '>' at {:?}", &rest[i..])),
            b'&' => {
                let end = after.find(';').ok_or("bare '&'")?;
                let entity = &after[..end];
                let numeric = entity
                    .strip_prefix('#')
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
                if !(numeric || ["amp", "lt", "gt", "quot", "#39"].contains(&entity)) {
                    return Err(format!("bare '&' at {:?}", &rest[i..]));
                }
                rest = &after[end + 1..];
            }
            _ => {
                let end = after.find('>').ok_or("unterminated tag")?;
                let tag = &after[..end];
                if tag.contains('<') {
                    return Err(format!("bare '<' at {:?}", &rest[i..]));
                }
                if let Some(name) = tag.strip_prefix('/') {
                    match stack.pop() {
                        Some(open) if open == name => {}
                        other => return Err(format!("</{name}> closes {other:?}")),
                    }
                } else {
                    let (name, attributes) = tag.split_once(' ').unwrap_or((tag, ""));
                    if !allowed.contains(&name) {
                        return Err(format!("tag <{name}> not allowed"));
                    }
                    if !attributes.is_empty() && !attrs(name, attributes) {
                        return Err(format!("attributes {attributes:?} not allowed on <{name}>"));
                    }
                    if !void.contains(&name) {
                        stack.push(name.to_string());
                    }
                }
                rest = &after[end + 1..];
            }
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(format!("unclosed tags {stack:?}"))
    }
}

/// An attribute value without `"`, `<` or `>` (they must be entities).
fn plain_attribute(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|v| v.strip_suffix('"'))
        .is_some_and(|v| !v.contains(['"', '<', '>']))
}

pub(crate) fn check_telegram(out: &str) -> Result<(), String> {
    check_html(
        out,
        &["b", "i", "s", "code", "pre", "a", "blockquote"],
        &[],
        |tag, attributes| match tag {
            "a" => plain_attribute(attributes, "href=\""),
            "code" => plain_attribute(attributes, "class=\"language-"),
            _ => false,
        },
    )?;
    check_telegram_nesting(out)
}

/// Checks the nesting rules of the Bot API (tdlib's `are_entities_valid`) on
/// well-formed output: `code` and `pre` contain no tag and have no ancestor
/// but `blockquote` (`<pre><code class="language-…">` being one entity), `a`
/// contains no `a` nor `blockquote`, `blockquote` is never nested, and `b`,
/// `i`, `s` are never inside a tag of the same name.
fn check_telegram_nesting(out: &str) -> Result<(), String> {
    let mut stack: Vec<&str> = Vec::new();
    let mut rest = out;
    while let Some(i) = rest.find('<') {
        let end = rest[i..].find('>').ok_or("unterminated tag")? + i;
        let tag = &rest[i + 1..end];
        rest = &rest[end + 1..];
        if tag.starts_with('/') {
            stack.pop();
            continue;
        }
        let (name, attributes) = tag.split_once(' ').unwrap_or((tag, ""));
        let language_code = name == "code" && !attributes.is_empty();
        if language_code && stack.last() == Some(&"pre") {
            // `<pre><code class="language-…">`: the `pre` entity itself.
            stack.push("pre");
            continue;
        }
        if let Some(code) = stack.iter().find(|t| matches!(**t, "code" | "pre")) {
            return Err(format!("<{name}> inside <{code}>"));
        }
        let forbidden = match name {
            "code" | "pre" => stack.iter().find(|t| **t != "blockquote"),
            "a" => stack.iter().find(|t| **t == "a"),
            "blockquote" => stack.iter().find(|t| matches!(**t, "a" | "blockquote")),
            _ => stack.iter().find(|t| **t == name),
        };
        if let Some(ancestor) = forbidden {
            return Err(format!("<{name}> inside <{ancestor}>"));
        }
        stack.push(name);
    }
    Ok(())
}

fn check_email_html(out: &str) -> Result<(), String> {
    check_html(
        out,
        &[
            "p",
            "br",
            "strong",
            "em",
            "del",
            "code",
            "pre",
            "a",
            "blockquote",
            "ul",
            "ol",
            "li",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "hr",
        ],
        &["br", "hr"],
        |tag, attributes| match tag {
            "a" => plain_attribute(attributes, "href=\""),
            "code" => plain_attribute(attributes, "class=\"language-"),
            "ol" => plain_attribute(attributes, "start=\""),
            _ => false,
        },
    )
}

#[test]
fn checkers_reject_malformed_output() {
    assert!(check_telegram("<b>x</b> &amp; &lt;").is_ok());
    assert!(check_telegram("<b>x").is_err());
    assert!(check_telegram("<b><i>x</b></i>").is_err());
    assert!(check_telegram("a < b").is_err());
    assert!(check_telegram("a & b").is_err());
    assert!(check_telegram("<p>x</p>").is_err());
    assert!(check_telegram("<a href=\"x\" onclick=\"y\">x</a>").is_err());
    // Nesting rules of the Bot API.
    assert!(check_telegram("<b><code>x</code></b>").is_err());
    assert!(check_telegram("<a href=\"x\"><code>y</code></a>").is_err());
    assert!(check_telegram("<b><b>x</b></b>").is_err());
    assert!(check_telegram("<blockquote><blockquote>x</blockquote></blockquote>").is_err());
    assert!(check_telegram("<a href=\"x\"><a href=\"y\">z</a></a>").is_err());
    assert!(check_telegram("<pre><b>x</b></pre>").is_err());
    assert!(
        check_telegram("<blockquote><b><a href=\"x\">t</a></b>\n\n<pre>x</pre></blockquote>")
            .is_ok()
    );
    assert!(check_telegram("<pre><code class=\"language-rs\">x</code></pre>").is_ok());
    assert!(check_telegram("<b><i><s>x</s></i></b>").is_ok());
    assert!(check_email_html("<p>a<br>\nb</p><hr>").is_ok());
}

#[test]
fn telegram_html_and_html_are_always_well_formed() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..5000 {
        let source = random_source(&mut rng);
        let blocks = parse(&source);
        let tg = render_blocks(&blocks, TelegramHtml);
        if let Err(err) = check_telegram(&tg) {
            panic!("telegram_html of {source:?}: {err}\n{tg}");
        }
        let html = render_blocks(&blocks, Html);
        if let Err(err) = check_email_html(&html) {
            panic!("html of {source:?}: {err}\n{html}");
        }
        // The other renderings must not panic either.
        render_blocks(&blocks, Plain);
        render_blocks(&blocks, Markdown);
    }
}

/// Re-parsing the `markdown` rendering gives the same text: the rendering
/// escapes what the source escaped, links stay links and text stays text.
#[test]
fn markdown_rendering_round_trips_plain_text() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..5000 {
        let source = random_source(&mut rng);
        let md = render(&source, Markdown);
        // Blanks and quote markers are ignored: blanks starting or ending a
        // line or an emphasis are dropped, a heading spanning lines (setext)
        // is written on one line, and quote markers follow the lines. Emphasis delimiters are ignored: an emphasis
        // ending with punctuation next to a letter may not reparse (CommonMark
        // flanking rules) and then shows its delimiters, never other markup.
        // Destinations are compared decoded (see `encode_destination`).
        let trimmed = |s: String| {
            [
                ("%20", " "),
                ("%28", "("),
                ("%29", ")"),
                ("%3C", "<"),
                ("%3E", ">"),
                ("%5C", "\\"),
            ]
            .iter()
            .fold(s, |s, (encoded, c)| s.replace(encoded, c))
            .replace(['*', '_', '~', '>'], "")
            .split_whitespace()
            .collect::<String>()
        };
        assert_eq!(
            trimmed(render(&md, Plain)),
            trimmed(render(&source, Plain)),
            "source {source:?}\nmarkdown {md:?}"
        );
    }
}

/// A value inserted with the auto-escaping is always read as literal text.
#[test]
fn escaped_values_render_literally() {
    const CHARS: &[char] = &[
        'a', 'b', '_', '*', '`', '[', ']', '(', ')', '<', '>', '&', ';', '#', '-', '+', '=', '!',
        '|', '~', '\\', '"', '\'', ':', '/', '.', '1', ' ', 'é', '🔥',
    ];
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..5000 {
        let len = 1 + rng.below(20);
        let value: String = (0..len).map(|_| CHARS[rng.below(CHARS.len())]).collect();
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        let src = escape(&value);
        assert_eq!(render(&src, Plain), value, "value {value:?}");
        assert_eq!(
            render(&src, TelegramHtml),
            escape_html_for_test(&value),
            "value {value:?}"
        );
    }
}

fn escape_html_for_test(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// --------------------------------------------------- bounded depth (D1)

/// Runs `f` on a thread with the 2 MiB stack of a Tokio worker: a stack
/// overflow aborts the test binary, a panic fails the test.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .expect("spawn a thread")
        .join()
        .expect("rendering on a 2 MiB stack");
}

/// The four renderings of `{{ v | safe }}`, `v` inserted as is.
fn renders_safe(v: String) -> [String; 4] {
    renders("{{ v | safe }}", context! { v => v })
}

#[test]
fn deep_emphasis_renders_on_a_small_stack() {
    on_small_stack(|| {
        let v = format!("{}a{}", "*".repeat(50_000), "*".repeat(50_000));
        for (format, out) in OutputFormat::ALL.iter().zip(renders_safe(v)) {
            assert!(out.contains('a'), "{format}");
        }
    });
}

#[test]
fn deep_quotes_render_on_a_small_stack() {
    on_small_stack(|| {
        let v = format!("{}a", "> ".repeat(50_000));
        let outs = renders_safe(v);
        for (format, out) in OutputFormat::ALL.iter().zip(&outs) {
            assert!(out.contains('a'), "{format}");
        }
        assert_eq!(outs[3].matches("<blockquote>").count(), 1, "{}", outs[3]);
    });
}

#[test]
fn deep_lists_render_on_a_small_stack() {
    on_small_stack(|| {
        let v = format!("{}a", "- ".repeat(50_000));
        for (format, out) in OutputFormat::ALL.iter().zip(renders_safe(v)) {
            assert!(out.contains('a'), "{format}");
        }
    });
}

/// Nesting depth of a tree: one level per block, list or inline container.
fn depth(blocks: &[Block]) -> usize {
    blocks
        .iter()
        .map(|block| match block {
            Block::Paragraph(i) | Block::Plain(i) | Block::Heading(_, i) => 1 + depth_inlines(i),
            Block::BlockQuote(b) => 1 + depth(b),
            Block::List { items, .. } => 1 + items.iter().map(|i| depth(i)).max().unwrap_or(0),
            Block::CodeBlock { .. } | Block::Rule => 1,
        })
        .max()
        .unwrap_or(0)
}

fn depth_inlines(inlines: &[Inline]) -> usize {
    inlines
        .iter()
        .map(|inline| match inline {
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strikethrough(c) => {
                1 + depth_inlines(c)
            }
            Inline::Link { children, .. } => 1 + depth_inlines(children),
            Inline::Text(_) | Inline::Code(_) | Inline::LineBreak => 0,
        })
        .max()
        .unwrap_or(0)
}

#[test]
fn nested_emphases_are_bounded_and_keep_their_text() {
    let open: String = (0..40).map(|i| format!("*t{i} ")).collect();
    let close: String = (0..40).rev().map(|i| format!(" u{i}*")).collect();
    let blocks = parse(&format!("{open}core{close}"));
    assert!(depth(&blocks) <= MAX_DEPTH, "depth {}", depth(&blocks));
    let plain = render_blocks(&blocks, Plain);
    for i in 0..40 {
        assert!(plain.contains(&format!("t{i} ")), "t{i}: {plain}");
        assert!(plain.contains(&format!(" u{i}")), "u{i}: {plain}");
    }
    assert!(plain.contains("core"), "{plain}");
}

#[test]
fn nested_lists_are_bounded_and_keep_their_text() {
    let source: String = (0..40)
        .map(|i| format!("{}- l{i}\n", "  ".repeat(i)))
        .collect();
    let blocks = parse(&source);
    assert!(depth(&blocks) <= MAX_DEPTH, "depth {}", depth(&blocks));
    for format in OutputFormat::ALL {
        let out = render_blocks(&blocks, format);
        for i in 0..40 {
            assert!(out.contains(&format!("l{i}")), "{format} l{i}: {out}");
        }
    }
}

#[test]
fn code_block_beyond_the_bound_keeps_its_text() {
    // 32 quotes: the code block would be the 33rd level.
    let quote = "> ".repeat(MAX_DEPTH);
    let blocks = parse(&format!("{quote}```\n{quote}let x = 1;\n{quote}```"));
    assert!(depth(&blocks) <= MAX_DEPTH, "depth {}", depth(&blocks));
    let plain = render_blocks(&blocks, Plain);
    assert!(plain.contains("let x = 1;"), "{plain}");
    // Within the bound, the code block is kept.
    let quote = "> ".repeat(MAX_DEPTH - 2);
    let blocks = parse(&format!("{quote}```\n{quote}let x = 1;\n{quote}```"));
    assert!(
        render_blocks(&blocks, TelegramHtml).contains("<pre>let x = 1;</pre>"),
        "{blocks:?}"
    );
}

#[test]
fn tree_depth_is_always_bounded() {
    const PREFIXES: &[&str] = &["> ", "- ", "*", "  - ", "**", "[", "1. "];
    let mut rng = Rng(0x5851_F42D_4C95_7F2D);
    for _ in 0..2000 {
        let prefix = PREFIXES[rng.below(PREFIXES.len())].repeat(rng.below(80));
        let suffix = PREFIXES[rng.below(PREFIXES.len())].repeat(rng.below(80));
        let source = format!("{prefix}{}{suffix}", random_source(&mut rng));
        let blocks = parse(&source);
        assert!(depth(&blocks) <= MAX_DEPTH, "source {source:?}");
    }
}

// ------------------------------------------------ tokens of elements (D3)

/// The token standing for the element at `index`.
fn token(index: usize) -> String {
    format!("{TOKEN_OPEN}{index}{TOKEN_CLOSE}")
}

fn code_block(lang: &str, text: &str) -> MarkdownElement {
    MarkdownElement::CodeBlock {
        lang: lang.to_string(),
        text: text.to_string(),
    }
}

fn md_link(text: &str, dest: &str) -> MarkdownElement {
    MarkdownElement::Link {
        text: text.to_string(),
        dest: dest.to_string(),
    }
}

fn link_inline(dest: &str, t: &str) -> Inline {
    Inline::Link {
        dest: dest.to_string(),
        children: vec![text(t)],
    }
}

#[test]
fn escape_neutralises_token_characters() {
    assert_eq!(escape("a\u{E000}0\u{E001}b"), "a\u{FFFD}0\u{FFFD}b");
    assert_eq!(escape("\u{E002}_"), "\u{E002}\\_");
}

#[test]
fn element_display_is_its_markdown_source() {
    assert_eq!(
        MarkdownElement::Code("a`b".to_string()).to_string(),
        "``a`b``"
    );
    assert_eq!(code_block("json", "x").to_string(), "```json\nx\n```");
    assert_eq!(code_block("", "x\n").to_string(), "```\nx\n```");
    assert_eq!(code_block("", "````").to_string(), "`````\n````\n`````");
    assert_eq!(
        md_link("a_b", "https://h/a%20b").to_string(),
        r"[a\_b](https://h/a%20b)"
    );
    assert_eq!(
        MarkdownElement::Text("x (javascript:y)".to_string()).to_string(),
        r"x \(javascript\:y\)"
    );
}

#[test]
fn token_in_a_paragraph() {
    let slots = [
        code_block("sh", "x\ny"),
        MarkdownElement::Code("c".to_string()),
        md_link("l", "https://h.example"),
        MarkdownElement::Text("t (u)".to_string()),
    ];
    // A code block cuts the paragraph; blanks around it are dropped.
    assert_eq!(
        super::parse(&format!("a {} b", token(0)), &slots),
        vec![
            para(vec![text("a")]),
            Block::CodeBlock {
                lang: "sh".to_string(),
                text: "x\ny\n".to_string()
            },
            para(vec![text("b")]),
        ]
    );
    assert_eq!(
        super::parse(
            &format!("a {}{}\n{} {}", token(1), token(2), token(3), token(0)),
            &slots
        ),
        vec![
            para(vec![
                text("a "),
                Inline::Code("c".to_string()),
                link_inline("https://h.example", "l"),
                Inline::LineBreak,
                text("t (u)"),
            ]),
            Block::CodeBlock {
                lang: "sh".to_string(),
                text: "x\ny\n".to_string()
            },
        ]
    );
}

#[test]
fn token_alone_in_a_list_item_or_a_quote() {
    let slots = [code_block("", "a\n# b")];
    let block = Block::CodeBlock {
        lang: String::new(),
        text: "a\n# b\n".to_string(),
    };
    assert_eq!(
        super::parse(&format!("- x\n- {}", token(0)), &slots),
        vec![Block::List {
            start: None,
            items: vec![vec![Block::Plain(vec![text("x")])], vec![block.clone()]]
        }]
    );
    assert_eq!(
        super::parse(&format!("> {}", token(0)), &slots),
        vec![Block::BlockQuote(vec![block])]
    );
}

#[test]
fn token_where_no_block_can_stand() {
    let slots = [
        code_block("", "a\nb"),
        MarkdownElement::Code("c".to_string()),
        md_link("l", "https://h.example"),
        MarkdownElement::Text("t".to_string()),
    ];
    let all = format!("{} {} {} {}", token(0), token(1), token(2), token(3));
    let expected = vec![
        Inline::Code("a b".to_string()),
        text(" "),
        Inline::Code("c".to_string()),
        text(" "),
        link_inline("https://h.example", "l"),
        text(" t"),
    ];
    assert_eq!(
        super::parse(&format!("**{all}**"), &slots),
        vec![para(vec![Inline::Strong(expected.clone())])]
    );
    assert_eq!(
        super::parse(&format!("# {all}"), &slots),
        vec![Block::Heading(1, expected.clone())]
    );
    assert_eq!(
        super::parse(&format!("[{all}](https://o.example)"), &slots),
        vec![para(vec![Inline::Link {
            dest: "https://o.example".to_string(),
            children: expected
        }])]
    );
}

#[test]
fn token_in_a_code_block_of_the_template() {
    let slots = [
        code_block("", "a\n**b**"),
        MarkdownElement::Code("*c*".to_string()),
        md_link("l", "https://h.example"),
        MarkdownElement::Text("t".to_string()),
    ];
    let all = format!("{}|{}|{}|{}", token(0), token(1), token(2), token(3));
    let expected = "a\n**b**|*c*|l (https://h.example)|t\n";
    for source in [format!("```\n{all}\n```"), format!("    {all}\n")] {
        assert_eq!(
            super::parse(&source, &slots),
            vec![Block::CodeBlock {
                lang: String::new(),
                text: expected.to_string()
            }],
            "{source:?}"
        );
    }
    // In a code span of the template, line breaks become spaces.
    assert_eq!(
        super::parse(&format!("`{all}`"), &slots),
        vec![para(vec![Inline::Code(
            "a **b**|*c*|l (https://h.example)|t".to_string()
        )])]
    );
}

#[test]
fn token_in_a_destination_or_a_language() {
    let slots = [
        code_block("", "https://a.example/x y"),
        MarkdownElement::Code("https://b.example".to_string()),
        md_link("l", "https://c.example"),
        MarkdownElement::Text("https://d.example".to_string()),
    ];
    let dest = |index: usize| match &super::parse(&format!("[x]({})", token(index)), &slots)[..] {
        [Block::Paragraph(inlines)] => match &inlines[..] {
            [Inline::Link { dest, .. }] => dest.clone(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    assert_eq!(dest(0), "https://a.example/x%20y");
    assert_eq!(dest(1), "https://b.example");
    assert_eq!(dest(2), "https://c.example");
    assert_eq!(dest(3), "https://d.example");
    assert_eq!(
        super::parse(&format!("```j{}s\nx\n```", token(1)), &slots),
        vec![Block::CodeBlock {
            lang: "js".to_string(),
            text: "x\n".to_string()
        }]
    );
}

#[test]
fn unknown_or_stray_token_is_a_replacement_character() {
    let slots = [MarkdownElement::Code("c".to_string())];
    assert_eq!(
        super::parse(&format!("a {} {}", token(7), token(0)), &slots),
        vec![para(vec![
            text("a \u{FFFD} "),
            Inline::Code("c".to_string())
        ])]
    );
    assert_eq!(
        super::parse(
            "a \u{E000}x \u{E001} \u{E000}99999999999999999999999\u{E001}",
            &[]
        ),
        vec![para(vec![text("a \u{FFFD}x \u{FFFD} \u{FFFD}")])]
    );
    assert_eq!(
        super::parse(&format!("```\n{}\n```", token(3)), &slots),
        vec![Block::CodeBlock {
            lang: String::new(),
            text: "\u{FFFD}\n".to_string()
        }]
    );
}

/// `codeblock` wherever it can be written, with values that are Markdown or
/// HTML syntax: the value never becomes markup.
#[test]
fn codeblock_anywhere_never_renders_markup() {
    const PLACES: &[&str] = &[
        "{{ v | codeblock }}",
        "- {{ v | codeblock }}",
        "- x\n- {{ v | codeblock }}",
        "> {{ v | codeblock }}",
        "    {{ v | codeblock }}",
        "1. {{ v | codeblock }}",
        "text {{ v | codeblock }} text",
        "**{{ v | codeblock }}**",
        "[{{ v | codeblock }}](https://ok.example)",
        "# {{ v | codeblock }}",
        "{{ v | code }} {{ md_link(v, 'https://ok.example') }}",
    ];
    const VALUES: &[&str] = &[
        "# h",
        "[x](https://evil.example)",
        "<b>",
        "```",
        "a\n```\n# h\n```",
        "@channel",
        "\u{E000}0\u{E001}",
        "a\n\n- [x](https://evil.example)\n\n    code",
    ];
    // Markup of each rendering: what the template writes, never more.
    const MARKUP: &[&str] = &["<h1", "<b>", "<strong>", "<i>", "<em>", "href="];
    let markup = |[_, md, html, tg]: &[String; 4]| -> Vec<usize> {
        [render(md, Html), html.clone(), tg.clone()]
            .iter()
            .flat_map(|out| MARKUP.iter().map(|m| out.matches(m).count()))
            .collect()
    };
    for place in PLACES {
        let neutral = markup(&renders(place, context! { v => "n" }));
        for value in VALUES {
            let outs = renders(place, context! { v => value });
            let context = format!("{place:?} with {value:?}");
            assert_eq!(markup(&outs), neutral, "{context}: {outs:?}");
            let [plain, md, html, tg] = outs;
            for out in [&render(&md, Html), &html, &tg] {
                assert!(!out.contains("href=\"https://evil"), "{context}: {out}");
            }
            assert!(!plain.contains(TOKEN_OPEN), "{context}: {plain}");
            if let Err(err) = check_telegram(&tg) {
                panic!("{context}: {err}\n{tg}");
            }
        }
    }
}

// ------------------------------------------- Telegram nesting rules (D6)

#[test]
fn telegram_code_is_text_inside_an_entity() {
    assert_eq!(
        render("[`x`](https://h.example)", TelegramHtml),
        r#"<a href="https://h.example">x</a>"#
    );
    assert_eq!(render("**a `x` b**", TelegramHtml), "<b>a x b</b>");
    assert_eq!(render("# T `y`", TelegramHtml), "<b>T y</b>");
    assert_eq!(render("*a `<x>`*", TelegramHtml), "<i>a &lt;x&gt;</i>");
    // Email HTML allows these nestings.
    assert_eq!(
        render("**a `x` b**", Html),
        "<p><strong>a <code>x</code> b</strong></p>"
    );
}

#[test]
fn telegram_same_emphasis_is_not_nested() {
    assert_eq!(render("**a __b__ c**", TelegramHtml), "<b>a b c</b>");
    assert_eq!(render("# a **b**", TelegramHtml), "<b>a b</b>");
    assert_eq!(
        render("*a **b *c* d** e*", TelegramHtml),
        "<i>a <b>b c d</b> e</i>"
    );
    assert_eq!(
        render("**a __b__ c**", Html),
        "<p><strong>a <strong>b</strong> c</strong></p>"
    );
}

#[test]
fn telegram_allowed_nestings_are_kept() {
    let tg = render(
        "> **[t](https://h.example)**\n>\n> ```\n> x\n> ```",
        TelegramHtml,
    );
    assert!(
        tg.contains(r#"<blockquote><b><a href="https://h.example">t</a></b>"#),
        "{tg}"
    );
    assert!(tg.contains("<pre>x</pre></blockquote>"), "{tg}");
    assert_eq!(
        render("- **a** `c`\n\n  ```\n  x\n  ```", TelegramHtml),
        "• <b>a</b> <code>c</code>\n  <pre>x</pre>"
    );
}

// -------------------------------- line breaks and indentation of values (D7)

#[test]
fn blank_line_of_a_value_does_not_end_an_emphasis() {
    let [plain, md, html, tg] = renders("**{{ v }}**", context! { v => "a\n\nb" });
    assert_eq!(html, "<p><strong>a<br>\n\u{a0}<br>\nb</strong></p>");
    assert_eq!(tg, "<b>a\n\u{a0}\nb</b>");
    assert_eq!(plain, "a\n\u{a0}\nb");
    assert_eq!(md, "**a\n\u{a0}\nb**");
    assert!(!plain.contains("**") && !tg.contains("**"));
}

#[test]
fn indentation_of_a_value_never_opens_a_code_block() {
    let outs = renders("{{ v }}", context! { v => "a\n\n    code" });
    for out in &outs {
        assert!(!out.contains("<pre") && !out.contains("<code"), "{out}");
    }
    assert_eq!(outs[0], "a\n\u{a0}\n\u{a0}\u{a0}\u{a0}\u{a0}code");
    assert!(!render(&outs[1], Html).contains("<pre"), "{}", outs[1]);
}

#[test]
fn blank_line_of_a_value_stays_in_its_item_or_quote() {
    let [_, _, html, tg] = renders("- {{ v }}", context! { v => "a\n\nb" });
    assert_eq!(html.matches("<li>").count(), 1, "{html}");
    assert_eq!(tg, "• a\n  \u{a0}\n  b");
    let [_, _, html, tg] = renders("> {{ v }}", context! { v => "a\n\nb" });
    assert_eq!(
        html,
        "<blockquote>\n<p>a<br>\n\u{a0}<br>\nb</p>\n</blockquote>"
    );
    assert_eq!(tg.matches("<blockquote>").count(), 1, "{tg}");
}

#[test]
fn stack_trace_keeps_its_indentation() {
    let trace = "java.lang.IllegalStateException: boom\n\tat a.B.c(B.java:1)\n    at d.E.f(E.java:2)\r\nCaused by: x";
    let [plain, _, _, tg] = renders("Trace:\n{{ v }}", context! { v => trace });
    let nbsp4 = "\u{a0}".repeat(4);
    assert_eq!(
        tg,
        format!(
            "Trace:\njava.lang.IllegalStateException: boom\n{nbsp4}at a.B.c(B.java:1)\n\
             {nbsp4}at d.E.f(E.java:2)\nCaused by: x"
        )
    );
    assert_eq!(plain, tg);
}
