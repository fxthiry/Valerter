# Templates

Messages are written with [Jinja2 syntax](https://jinja.palletsprojects.com/)
(rendered by [minijinja](https://github.com/mitsuhiko/minijinja)): conditions,
loops, the built-in filters of minijinja and the
[filters valerter adds](#valerter-filters-and-functions).

```yaml
templates:
  default_alert:
    title: "{{ rule_name }} on {{ host }}"           # REQUIRED
    body: "{{ _msg }}"                               # REQUIRED
    email_body_html: "<p>{{ _msg }}</p>"             # REQUIRED for email destinations (text bodies)
    accent_color: "#ff0000"                          # Optional: hex color (Mattermost sidebar, email)
    body_format: text                                # Optional: text (default) or markdown
```

`body_format` describes the source of `body`: `text` (the default) sends it as
rendered, `markdown` makes it a Markdown source rendered for each notifier (see
[Markdown bodies](#markdown-bodies-body_format)).

## Rule templates and notifier templates

Templates are rendered at two levels:

- **Rule templates**: `title`, `body` and `email_body_html` of a template, and
  `throttle.key`. They are written once and shared by every destination of the
  rule. The fields of the event are at the top level: `{{ host }}`,
  `{{ _msg }}`.
- **Notifier templates**: `body_template` (webhook, Telegram, email) and
  `subject_template` (email). They are written for one channel: the place for
  markup (JSON for a webhook, HTML for Telegram and email). The fields of the
  event are under `log`: `{{ log.host }}`, `{{ log._msg }}`.

| Variable | Rule template | Notifier template | Description |
|----------|:-------------:|:-----------------:|-------------|
| Event fields (`_msg`, `_time`, `_stream`, `host`...) | `{{ host }}` | `{{ log.host }}` | Every field of the VictoriaLogs line, plus the fields added by the [parser](configuration.md#parser) |
| `rule_name` | yes | yes | Name of the rule that triggered |
| `vl_source` | yes | yes | Name of the VictoriaLogs source the event came from |
| `title` | | yes | The rendered `title` of the rule template |
| `body` | | yes | The rendered `body` of the rule template; for a [Markdown body](#markdown-bodies-body_format), its rendering in the notifier `format` |
| `log_timestamp` | | yes | Timestamp of the log line (`_time`), ISO 8601, for a VictoriaLogs search |
| `log_timestamp_formatted` | | yes | The same timestamp, human readable, in the [`timestamp_timezone`](configuration.md#timestamp-timezone) (`15/01/2026 11:00:00 CET`) |
| `accent_color` | | email only | The `accent_color` of the template, `none` when not set |
| `log` | | yes | Every field of the event (see below) |

- Every field of the line VictoriaLogs returns is available, whatever the
  parser: `_msg`, `_time`, `_stream` and the fields of the log. A parser only
  adds fields (regex captures, `json.fields`), replacing a field of the same
  name.
- `rule_name` and `vl_source` win over an event field of the same name, at both
  levels.
- `log_timestamp` and `log_timestamp_formatted` do not exist in a rule template
  (they render empty there): use the raw `{{ _time }}` field. The Mattermost
  footer shows `log_timestamp_formatted` automatically.
- Mattermost has no notifier template: it sends the rendered `title` and
  `body`.

`log` holds every field of the event, in the same view as the rule template:
dotted keys are available both flat and expanded (`{{ log["k8s.pod"] }}` and
`{{ log.k8s.pod }}`, see below), and a missing field renders empty
(`{{ log.missing }}`, `null` with `tojson`). It does not contain `rule_name` nor
`vl_source`: use the variables. `{{ log | tojson }}` renders the whole event as
a JSON object, with dotted keys present twice (flat and expanded). Each value
from `log` must be escaped for the channel of the notifier template (`| tojson`
in JSON, `| e` in Telegram HTML; email body templates escape as HTML
automatically).

`log` exists only in notifier templates: in a rule template, `{{ log }}` is the
event field named `log` if there is one (container output collected by
Fluent Bit, for instance). In a notifier template, a variable that is none of
the above renders empty: valerter logs the warning
`Notifier template references unknown variable` at startup and in
`--validate` (see [Template validation](#template-validation)).

## Fields with special characters

VictoriaLogs field names may contain characters that are operators in Jinja,
most commonly `/` in Kubernetes/OpenShift annotation keys such as
`ocp.annotations.authentication.openshift.io/username`. Dotted keys are
expanded into nested objects at render time, so reference the last segment
with bracket notation:

```jinja
{# WRONG: '/' is parsed as a division #}
{{ ocp.annotations.authentication.openshift.io/username }}

{# RIGHT #}
{{ ocp.annotations.authentication.openshift["io/username"] }}
```

`valerter --validate` detects this pattern and prints the rewritten expression.

Expansion has two limits, each logged as a warning and never stopping the
alert. A dotted key whose first segment is already a plain field (`a` and
`a.b`) is not expanded: `{{ a }}` keeps the plain value
(`skipping dotted-key expansion: top-level scalar already exists`). A dotted
key of more than 32 segments is not expanded either: only the flat key exists,
reachable with bracket notation (`{{ log["a.b.c…"] }}`), so that a malformed
log line cannot build objects thousands of levels deep
(`skipping dotted-key expansion: too many segments`, the key truncated to 128
bytes in the log).

A **top-level** field whose name contains `/` (e.g. `io/user-name`, with no dot
before it) has no parent object to index, so it cannot be referenced from a
template. Rename it in the rule query with the LogsQL `rename` pipe, then use
the new name:

```yaml
query: '_stream:{app="oauth"} | rename "io/user-name" as io_user_name'
# template: {{ io_user_name }}
```

`valerter --validate` suggests this rename for `{{ io/user-name }}`. A `/`
between two plain identifiers (`{{ total/count }}`) is read as a division and
accepted: it cannot be told apart from a field named `total/count`, so a
top-level field like `io/username` (no `.`, `-` or `/` in its last part) is not
detected and must be renamed the same way.

## valerter filters and functions

Besides the built-in filters of minijinja (`default`, `upper`, `lower`,
`length`, `replace`, `tojson`, `urlencode`, `e`...), valerter provides the
filters and the function below, available in every template (rule templates,
`throttle.key`, notifier templates). Filters that minijinja does not provide,
such as `truncate`, are unknown and refused by the
[test render](#template-validation).

| Name | Use | Result |
|------|-----|--------|
| `md_escape` | `{{ host \| md_escape }}` | The value with a backslash before each character Mattermost's Markdown engine recognises: `` \ ` * _ { } [ ] ( ) # + - . ! > \| ~ `` (`web_01` gives `web\_01`) |
| `mdv2_escape` | `{{ host \| mdv2_escape }}` | The value with a backslash before each character reserved by Telegram `parse_mode: MarkdownV2`: `` _ * [ ] ( ) ~ ` > # + - = \| { } . ! `` and `\` |
| `code` | `{{ host \| code }}` | A Markdown code span showing the value literally, whatever backticks it contains; a line break becomes a space |
| `codeblock(lang)` | `{{ _msg \| codeblock('json') }}` | A fenced Markdown code block showing the value literally; `lang` is optional and keeps only `A-Z a-z 0-9 _ + - . #` |
| `md_link(text, url)` | `{{ md_link("Logs", vl_url) }}` | A Markdown link whose text is literal (on one line); spaces, control characters, `<`, `>`, `(`, `)` and `\` of the URL are percent-encoded. A scheme other than `http`, `https` or `mailto` gives `text (url)`, without a link |
| `urlencode` (minijinja) | `{{ ("host:" ~ host) \| urlencode }}` | The value percent-encoded for a URL query (`host:web_01` gives `host%3Aweb_01`) |

**Escaping filters.** `md_escape` and `mdv2_escape` convert their value to a
string (`none` and a missing value give an empty string) and escape it so it is
displayed literally instead of being read as Markdown.

- `md_escape` escapes exactly the characters Mattermost's Markdown engine
  recognises: other punctuation (`:`, `/`, `=`, `?`, `@`...) is left alone, as
  Mattermost would show the backslash (`10\:49`). `<` and `&` are not
  neutralised either: harmless in Mattermost, which does not render HTML, but a
  CommonMark renderer that does would interpret them.
- `mdv2_escape` applies to MarkdownV2 text **outside** `pre` and `code`
  entities; inside them, Telegram only requires `` ` `` and `\` to be escaped.
- For HTML (Telegram `parse_mode: HTML`, a custom HTML body), use the built-in
  `| e`: it produces the entities Telegram expects (`&lt;`, `&gt;`, `&amp;`).
  In an email body template, values are escaped as HTML automatically.

Their result is an ordinary string: in an HTML-escaped template (email body,
`email_body_html`), it is still escaped as HTML afterwards. In the `body` of a
`body_format: markdown` template, values are already escaped: `md_escape` there
is the automatic escaping itself, applied once.

**Markdown filters.** `code`, `codeblock` and `md_link` build Markdown from
values; they are meant for [Markdown bodies](#markdown-bodies-body_format), where
their content stays literal wherever they are written (see below). Outside a
Markdown body, they return ordinary strings, escaped like any value (in
`email_body_html`, `{{ x | code }}` gives an HTML-escaped `` `x` ``). An event
field named `md_link` would hide the function, as any field hides a global
function of the same name.

## Markdown bodies (`body_format`)

With `body_format: markdown`, the `body` of a rule template is written once in
Markdown, and valerter renders it in the format of each notifier: Markdown for
Mattermost, the HTML subset of the Bot API for Telegram, HTML for email, plain
text for a webhook by default (see
[Output format per notifier](notifiers.md#output-format-per-notifier)). The
values of the log are shown as text on every channel, unless you insert them
with `| safe`. As in a text body, the client may still detect bare URLs,
`@channel`/`@here` (Mattermost) and mentions in a value: valerter does not
filter them.

```yaml
templates:
  disk_alert:
    title: "Disk {{ host }}"
    body_format: markdown
    body: |
      **{{ host }}** is at {{ usage }}% on {{ mount | code }}
      {{ md_link("Logs in VictoriaLogs", "https://vl.example.com/select/vmui?query=" ~ ("host:" ~ host) | urlencode) }}
      {{ _msg | codeblock }}
```

With `host=web_01`, `usage=97`, `mount=/var` and `_msg=disk <full> & read-only`,
Mattermost receives:

````
**web\_01** is at 97% on `/var`
[Logs in VictoriaLogs](https://vl.example.com/select/vmui?query=host%3Aweb_01)

```
disk <full> & read-only
```
````

and Telegram (`parse_mode: HTML`) receives, as `body`, after the bold title of
its default `body_template`:

```
<b>web_01</b> is at 97% on <code>/var</code>
<a href="https://vl.example.com/select/vmui?query=host%3Aweb_01">Logs in VictoriaLogs</a>

<pre>disk &lt;full&gt; &amp; read-only</pre>
```

`title` stays plain text (no escaping, no Markdown), and `email_body_html`, if
present, is still rendered as HTML. A template without `body_format`, or with
`body_format: text`, is rendered as written.

### Automatic escaping

In a Markdown body, every value inserted with `{{ ... }}` is escaped: each
ASCII punctuation character gets a backslash, so a value is always read as
literal text (`a_b*c` stays `a_b*c`, never italics). The markup written in the
template itself (`**...**`, `[...](...)`, lists...) is interpreted.

- `{{ summary | safe }}` is the only way to insert a value without escaping:
  the value is trusted Markdown (bold, links...).
- `{{ value | tojson }}` is escaped like any value: the JSON text is shown
  literally.
- `| e` escapes for the current context, which is Markdown here, not HTML (and
  never twice): `{{ v | e }}` is the same as `{{ v }}`.
- The line breaks of a value stay line breaks, but a value cannot change the
  structure around it: each leading space of a line of the value becomes a
  no-break space (U+00A0, four for a tab) and an empty line a lone U+00A0. So
  `**{{ _msg }}**` stays bold over a multi-line message, `- {{ _msg }}` stays one
  item, and the indentation of a stack trace stays visible instead of turning
  into a code block. The renderings, `plain` included, contain these U+00A0.
- The characters U+E000 and U+E001 of a value are shown as U+FFFD (valerter
  uses them internally for `code`, `codeblock` and `md_link`).

### Markdown filters in a Markdown body

The content of `code`, `codeblock` and `md_link` is always literal, wherever
they are written: after a list marker, in a quote, on an indented line or in
the middle of a line.

- `codeblock` cuts the paragraph it is written in: `Log: {{ _msg | codeblock }}`
  gives the paragraph `Log:`, then the block. Where a block cannot stand (in
  `**...**`, a heading or the text of a link), it becomes a code span; in a
  code block of the template, its text is written as is.
- A Markdown filter must end its expression: `{{ (v | code) ~ '!' }}` or
  `{{ v | code | upper }}` gives an ordinary string, escaped like any value
  (backticks shown).
- `md_link` does not encode the query of the URL: encode the values you put in
  it with the built-in `urlencode` filter, as in the example above
  (`("host:" ~ host) | urlencode` gives `host%3Aweb_01`).

### Recognised Markdown

CommonMark plus `~~strikethrough~~`, limited to: paragraphs, line breaks,
**bold**, *italics*, ~~strikethrough~~, code spans, code blocks, links, block
quotes, lists, headings and thematic breaks. An image becomes a link to the
image (its alternative text as link text).

- A single line break is kept as a line break: alerts are line oriented.
- Raw HTML in the source (`<b>`, `<br>`, `<div>`...) is shown as text, never
  interpreted.
- Tables are not recognised: their lines are shown as text.
- Links are only emitted for the `http`, `https` and `mailto` schemes, in the
  template as with `md_link`; `[x](javascript:...)` shows `x (javascript:...)`.
- Nesting is limited to 32 levels (quotes, lists, emphasis...): a deeper
  element is not recognised, its text is kept. A log line inserted with
  `| safe` cannot exhaust the stack of the process.

**Pitfall: `{{ x }}` inside a fence or backticks.** A value written inside a
code block or a code span of the template is escaped too, and code shows its
content literally, backslashes included. With `_msg=disk <full> & read-only`:

````jinja
```
{{ _msg }}
```
````

shows `disk \<full\> \& read\-only`, and `` `{{ mount }}` `` shows `\/var`.
Write `{{ _msg | codeblock }}` and `{{ mount | code }}` instead.

## Template validation

Templates (`title`, `body`, `email_body_html`, `throttle.key`, and the notifier
`subject_template`/`body_template`) are checked for syntax, then test-rendered
twice with placeholder values where every field is defined:

1. every condition on a field is true and every loop over a field iterates one
   element, so `{% if %}` bodies and `{% for %}` bodies are checked;
2. every condition on a field is false, every loop is empty and `is defined` is
   false for a field, so `{% else %}` branches, `{% if not x %}` and
   `{% if x is not defined %}` bodies are checked.

The test render refuses only errors that do not depend on the event's values,
in either pass:

- an unknown filter, test, function or method (`{{ _msg | truncate(50) }}`,
  `{% if host is nosuchtest %}`), reported as `<field> render: ...`, including
  after a built-in or [valerter filter](#valerter-filters-and-functions) applied
  to a field (`{{ status | int }}-{{ host | truncat(10) }}`,
  `{{ host | split('.') | first }} {{ host | nosuch }}`), in an `else` branch
  or in a loop body (`{% for k, v in m | items %}{{ v | nosuch }}{% endfor %}`);
- the `/` operator applied to a field path (see
  [Fields with special characters](#fields-with-special-characters)).

The `body` of a `body_format: markdown` template is test-rendered with the
Markdown escaping active, as in production; `code`, `codeblock`, `md_link`,
`urlencode` and `tojson` are checked like the other filters (an unknown filter
after them is reported).

In a notifier template (`body_template`, `subject_template`), a top-level
variable that is not part of its context (see
[Rule templates and notifier templates](#rule-templates-and-notifier-templates))
is not refused, since it renders empty, but logs a warning when the notifier is
built, at startup and in `--validate`:

```
WARN Notifier template references unknown variable notifier=hook field=body_template variable=host
```

The usual cause is a log field written `{{ host }}` instead of
`{{ log.host }}`. Loop and `set` variables and global functions (`range`,
`namespace`, `dict`) are not reported.

Conversions and arithmetic on fields (`{{ status | int }}`, `{{ (latency |
float) > 1.5 }}`, `{{ ratio | round }}`, `{{ count + 1 }}`) are accepted: their
outcome depends on the real values. A built-in filter applied to a field
(`| int`, `| float`, `| round`, `| split`, `| upper`, `| items`...) does not
stop the check: the rest of the template is still verified. An error of that
kind at runtime falls back to a generic message (rule templates), to the
`<rule>:error` key (throttle) or to a failed delivery (notifier templates).

Limits of the test render (these parts are not checked):

- **Arithmetic on a raw field** (`{{ count + 1 }}`) stops the current pass
  without error: what follows it is not checked in that pass. VictoriaLogs
  fields are strings, so this expression also fails at runtime: write
  `{{ count | int + 1 }}`, which is checked and works.
- **The body of an `elif`** is reached by neither pass (the first takes the
  `if`, the second the `else`).
- **A loop nested over a loop item** (`{% for y in x %}` inside
  `{% for x in items %}`) does not iterate, and unpacking an item without
  `| items` (`{% for a, b in x %}`) stops the pass.

## Email body HTML requirement

A template used by a rule with an email destination must define
`email_body_html`, the HTML body of the email, unless its body is Markdown
(`body_format: markdown`): the HTML rendering of the body is then the email
body, and `email_body_html`, when present, still takes priority. Valerter checks
this at startup and in `--validate` (enabled rules only), and refuses the
configuration otherwise.

`email_body_html` is rendered with HTML auto-escaping (values are escaped) and
is only used by email notifiers: Mattermost, Telegram and webhooks receive
`body`. How the email body template inserts it is described in
[Email body templates](../templates/README.md).
