# Notifiers

Valerter supports multiple notification channels. Configure them in the `notifiers:` section of your config file.

## Overview

| Type | Description | Best For |
|------|-------------|----------|
| `webhook` | Generic HTTP endpoint | PagerDuty, Slack, Discord, custom APIs |
| `email` | SMTP email | Ops teams, compliance, audit trails |
| `mattermost` | Mattermost incoming webhook | Team chat notifications |
| `telegram` | Telegram Bot API | Mobile alerts, small teams, channels |

## Output format per notifier

A rule template with
[`body_format: markdown`](configuration.md#markdown-bodies-body_format) has a
Markdown body that valerter renders in the format of each notifier. The
optional `format` key of a notifier chooses that format; without it, the
default of its type applies:

| Type | Default `format` | Accepted values | `body` received for a Markdown alert |
|------|------------------|-----------------|--------------------------------------|
| `mattermost` | `markdown` | `markdown` | Markdown escaped for Mattermost (`**web\_01**`) |
| `telegram` | `telegram_html` (`plain` when `parse_mode` is not `HTML`) | `telegram_html`, `plain` | HTML of the Bot API subset (`<b>web_01</b>`), already escaped |
| `email` | `html` | `html` | HTML (`<p><strong>web_01</strong></p>`), already escaped |
| `webhook` | `plain` | `plain`, `markdown`, `html` | Text without markup (`web_01`) by default |

- A value outside the accepted list is refused at startup and by `--validate`:
  `invalid notifier '<name>': format '<value>' is not supported for <type>
  notifiers (expected <list>)`.
- The `html` and `telegram_html` renderings are already escaped: `{{ body|e }}`
  (the default Telegram template) and the HTML auto-escaping of the email body
  leave them intact. `plain` and `markdown` are ordinary text, escaped like any
  value.
- Each rendering is computed once per alert and shared by the destinations
  that use it.
- An alert whose template has no `body_format` (or `body_format: text`) sends
  its `body` as before, whatever the `format`.

## Webhook (Generic HTTP)

The most flexible notifier - works with any HTTP API.

> **Note about `email_body_html`** — Webhook reads the outer template's `body`
> output key (and `title`, `rule_name`, `log_timestamp`, `log_timestamp_formatted`)
> inside its own `body_template`, along with the event fields under `log`. It
> does **not** receive `email_body_html`; `email_body_html` is email-only. If
> your HTTP target needs HTML, write the markup in the webhook `body_template`
> and insert each value escaped (`{{ log.host | e }}`).

### Configuration

```yaml
notifiers:
  pagerduty:
    type: webhook
    url: "https://events.pagerduty.com/v2/enqueue"
    method: POST                    # Optional, default: POST
    body_template: |
      {
        "routing_key": "${PAGERDUTY_ROUTING_KEY}",
        "event_action": "trigger",
        "payload": {
          "summary": {{ title | tojson }},
          "source": {{ log.host | default("valerter") | tojson }},
          "severity": "error",
          "custom_details": {
            "rule": {{ rule_name | tojson }},
            "vl_source": {{ vl_source | tojson }},
            "log_time": {{ log._time | tojson }},
            "message": {{ log._msg | tojson }},
            "pod": {{ log["k8s.pod"] | tojson }}
          }
          {#- Or send every field of the event:
          "custom_details": {{ log | tojson }}
          #}
        }
      }
```

The PagerDuty Events API v2 authenticates with the `routing_key` in the body, so no
`Authorization` header is needed. Set `PAGERDUTY_ROUTING_KEY` to the integration key of
your PagerDuty service in the daemon's environment: the key stays out of the
configuration file (see [`${VAR}` in `body_template`](#var-in-body_template)).

`custom_details` is built from the event fields (`log`): each one becomes a
separate PagerDuty field, `null` when the event does not carry it. The
commented variant sends the whole event instead; it then also contains every
dotted key twice, flat (`"k8s.pod"`) and expanded (`"k8s": {"pod": ...}`), and
every field of the log line, secrets included: prefer an explicit selection.

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `url` | Yes | Endpoint URL (`http` or `https`, supports `${VAR}` substitution) |
| `method` | No | HTTP method (default: `POST`) |
| `headers` | No | Custom headers (supports `${VAR}` substitution) |
| `body_template` | No | Custom JSON body (Jinja2 template, supports `${VAR}` substitution in its source) |
| `format` | No | Format of the body of a [Markdown alert](#output-format-per-notifier): `plain` (default), `markdown` or `html` |

### `${VAR}` in `body_template`

Like `url` and `headers`, `body_template` supports `${VAR}` placeholders, resolved
from the environment **once, in the template source**, when the notifier is built
(daemon startup and `valerter --validate`):

- An undefined variable refuses the configuration with
  `invalid notifier '<name>': body_template: invalid configuration: undefined environment variable: <VAR>`.
  To send a literal `${VAR}`, write `{{ '$' }}{VAR}`: the substitution does not
  recognize it and the render produces `${VAR}`.
- Values rendered from logs are never resolved: a `${HOME}` in a log line is sent as is.
- The resolved value is inserted **as is** in the template source, before Jinja
  parses it. A value containing `{{`, `{%` or `"` is interpreted by Jinja or breaks
  the JSON body: keep such values out of `body_template` (use a header instead).
- Substitution is a single pass: a value containing `${...}` is inserted as is,
  never resolved again.
- The resolved template is never logged, so a secret placed there is not exposed,
  with one exception: the message of a syntax error may quote a fragment of the
  resolved source, when a substituted value contains `{{`, `{%` or breaks the
  template syntax.

### Checks at startup and in `--validate`

The notifier is built at daemon startup and by `valerter --validate`, which
refuse the configuration (`invalid notifier '<name>': ...`, logged under
`Notifier configuration error`) when:

- `url`, `headers` or `body_template` reference an undefined `${VAR}`.
- `url`, once `${VAR}` placeholders are resolved, does not parse or does not use
  `http`/`https` (`url: invalid URL: ...`). The URL itself is never printed.
- `body_template` (after `${VAR}` resolution) has a syntax error (`body_template: ...`) or uses an unknown
  filter, test, function or method (`body_template render: ...`). The template is
  test-rendered with placeholder values, so value-dependent errors such as
  `{{ status | int }}` are not reported at this stage.

A `body_template` reading a variable that does not exist at this level is not
refused (it renders empty) but logs
`Notifier template references unknown variable` with the notifier, the field
(`body_template`) and the variable: most often a log field written
`{{ host }}` instead of `{{ log.host }}`.

### Content-Type

Requests carry `Content-Type: application/json` unless `headers` defines a
`Content-Type` (header names are case-insensitive). A configured `Content-Type`
always wins and is sent once, as is; set it explicitly if your endpoint expects
something other than JSON (`text/plain`, form data, ...).

### Default Payload

If `body_template` is omitted, sends:

```json
{
  "alert_name": "<notifier_name>",
  "rule_name": "...",
  "vl_source": "<source name from victorialogs map>",
  "title": "...",
  "body": "...",
  "timestamp": "<ISO8601>",
  "log_timestamp": "<ISO8601>",
  "log_timestamp_formatted": "DD/MM/YYYY HH:MM:SS TZ"
}
```

| Field | Description |
|-------|-------------|
| `body` | The alert body; for a [Markdown alert](#output-format-per-notifier), its rendering in the notifier `format` (`plain` by default) |
| `timestamp` | When the alert was sent |
| `log_timestamp` | Original log timestamp (ISO 8601, for VictoriaLogs search) |
| `log_timestamp_formatted` | Human-readable timestamp (respects `timestamp_timezone` setting) |

### Template Variables

When using `body_template`, these variables are available:

| Variable | Description |
|----------|-------------|
| `title` | Alert title |
| `body` | Alert body (for a Markdown alert, its rendering in the notifier `format`) |
| `rule_name` | Name of the rule |
| `vl_source` | Name of the VictoriaLogs source the event came from |
| `log_timestamp` | Original log timestamp (ISO 8601) |
| `log_timestamp_formatted` | Human-readable timestamp |
| `log` | Every field of the event: `{{ log.host }}`, `{{ log._msg }}`, `{{ log["k8s.pod"] }}` or `{{ log.k8s.pod }}` |

`{{ vl_source }}` is available wherever `{{ rule_name }}` is, and follows the
same collision policy: an event field literally named `vl_source` is masked
by the synthetic source name.

`log` exposes the event the way the rule template sees it: dotted keys both flat
(`log["k8s.pod"]`) and expanded (`log.k8s.pod`), a missing field rendering empty
(`null` with `tojson`). It does not contain `rule_name` nor `vl_source`, and
exists only in notifier templates, not in the rule template (see
[Rule templates and notifier templates](configuration.md#rule-templates-and-notifier-templates)).
`{{ log | tojson }}` renders the whole event as a JSON object, dotted keys
included twice. Values are inserted as is, never resolved as `${VAR}`.

### Markdown alerts: choosing `format`

A webhook targets services valerter knows nothing about (PagerDuty, ticketing,
SMS gateways, in-house APIs), most of which do not render Markdown: by default,
the body of a [Markdown alert](#output-format-per-notifier) is plain text
(`**{{ host }}** [logs](https://vl.example.com)` gives
`web-01 logs (https://vl.example.com)`). Declare `format: markdown` for a target
that renders Markdown (Discord, Rocket.Chat, GitHub, a Mattermost reached
through a generic webhook), and `format: html` for one that expects HTML
(Microsoft Teams, an HTML API):

```yaml
notifiers:
  discord-md:
    type: webhook
    url: "${DISCORD_WEBHOOK_URL}"
    format: markdown
    body_template: '{"content": {{ body | tojson }}}'
```

An `html` body is already escaped: insert it with `{{ body }}` in an HTML
document, or with `{{ body | tojson }}` in JSON.

### Writing JSON bodies: the `tojson` filter

Values are inserted **without any escaping**. Writing `"{{ body }}"` between quotes
produces invalid JSON as soon as a title or body contains a double quote, a
backslash or a line break, which is common in log lines. Insert every value with
the `tojson` filter and **without surrounding quotes**:

```yaml
body_template: |
  {"text": {{ body | tojson }}, "rule": {{ rule_name | tojson }}}
```

`tojson` renders a complete JSON string (quotes included) and escapes special
characters (`"`, `\`, control characters, and also `<`, `>`, `&`, `'` as
`\u00XX`, which is still valid JSON). To build a string from several values,
concatenate them with `~` before applying the filter:
`{{ ("*" ~ title ~ "*\n" ~ body) | tojson }}`.

When the effective `Content-Type` is JSON (`application/json` or any `+json`
type) and the rendered body is not valid JSON, valerter logs the warning
`Webhook body is not valid JSON` (with the notifier and rule names, never the
body itself) and **still sends the request**. Fix the template with `tojson`
to silence it.

### Examples

**Slack:**

```yaml
notifiers:
  slack-alerts:
    type: webhook
    url: "${SLACK_WEBHOOK_URL}"
    body_template: |
      {
        "text": {{ ("*" ~ title ~ "*\n" ~ body) | tojson }},
        "username": "Valerter"
      }
```

**Discord:**

```yaml
notifiers:
  discord-alerts:
    type: webhook
    url: "${DISCORD_WEBHOOK_URL}"
    body_template: |
      {
        "content": {{ ("**" ~ title ~ "**\n" ~ body) | tojson }}
      }
```

**Custom API:**

```yaml
notifiers:
  custom-api:
    type: webhook
    url: "https://api.example.com/alerts"
    method: PUT
    headers:
      Authorization: "Bearer ${API_TOKEN}"
      X-Source: "valerter"
    body_template: |
      {"alert": {{ title | tojson }}, "details": {{ body | tojson }}, "rule": {{ rule_name | tojson }}}
```

## Email (SMTP)

Send alerts via SMTP with HTML templates.

### Configuration

```yaml
notifiers:
  email-ops:
    type: email
    smtp:
      host: smtp.example.com           # REQUIRED
      port: 587                         # REQUIRED (587=STARTTLS, 465=TLS, 25=none)
      username: "${SMTP_USER}"          # Optional
      password: "${SMTP_PASSWORD}"      # Optional
      tls: starttls                     # Default: starttls (options: none, starttls, tls)
      tls_verify: true                  # Default: true
    from: "valerter@example.com"        # REQUIRED
    to:                                 # REQUIRED (at least one)
      - "ops@example.com"
      - "oncall@example.com"
    subject_template: "[{{ rule_name | upper }}] {{ title }}"    # REQUIRED
    body_template_file: "templates/custom-email.html.j2"         # Optional
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `smtp.host` | Yes | SMTP server hostname |
| `smtp.port` | Yes | SMTP port |
| `smtp.username` | No | SMTP auth username |
| `smtp.password` | No | SMTP auth password |
| `smtp.tls` | No | TLS mode: `none`, `starttls`, `tls` |
| `smtp.tls_verify` | No | Verify TLS certificate (default: true) |
| `from` | Yes | Sender email address |
| `to` | Yes | Recipient email addresses |
| `subject_template` | Yes | Email subject (Jinja2 template) |
| `body_template` | No | Inline HTML body template |
| `body_template_file` | No | Path to HTML template file |
| `format` | No | Format of the body of a [Markdown alert](#output-format-per-notifier): `html`, the only value (the message is a single HTML part) |

### Template Variables

`subject_template` and the body template see `title`, `body`, `rule_name`,
`vl_source`, `accent_color`, `log_timestamp`, `log_timestamp_formatted` and
`log`, the event fields (`{{ log.host }}`, `{{ log["k8s.pod"] }}`, see the
[webhook variables](#template-variables)). In the body template, `body` is, by
priority:

1. the rendered `email_body_html`, inserted without escaping;
2. for a [Markdown alert](#output-format-per-notifier) without
   `email_body_html`, the HTML rendering of its body, inserted without escaping
   (already escaped);
3. otherwise the plain `body` (the message sent when a rule template fails to
   render), escaped as HTML.

In `subject_template`, `body` is the plain-text rendering of a Markdown body (a
subject is text). Every other value, `log` fields included, is escaped as HTML
automatically in the body template:

```yaml
notifiers:
  email-oncall:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
      username: "${SMTP_USER}"
      password: "${SMTP_PASSWORD}"
    from: "valerter@example.com"
    to:
      - "oncall@example.com"
    subject_template: "[{{ log.severity | default('alert') | upper }}] {{ title }}"
    body_template: |
      <h2>{{ title }}</h2>
      <table>
        <tr><td>Host</td><td>{{ log.host }}</td></tr>
        <tr><td>Time</td><td>{{ log_timestamp_formatted }}</td></tr>
      </table>
      {{ body }}
```

With `host=<b>x</b>`, the cell contains `&lt;b&gt;x&lt;&#x2f;b&gt;`.

### TLS Modes

| Mode | Port | Description |
|------|------|-------------|
| `none` | 25 | No encryption (internal networks only) |
| `starttls` | 587 | STARTTLS upgrade (recommended) |
| `tls` | 465 | Direct TLS connection |

### email_body_html Requirement

**Important:** When using email destinations, your message template MUST include `email_body_html`:

```yaml
templates:
  my_template:
    title: "{{ title }}"
    body: "{{ body }}"
    email_body_html: "<p>{{ body }}</p>"    # REQUIRED for email
```

Valerter validates this at startup and in `valerter --validate`, and fails if missing.

A template with `body_format: markdown` does not need `email_body_html`: the HTML
rendering of its body is the email body (see
[Markdown bodies](configuration.md#markdown-bodies-body_format)).
`email_body_html`, when present, still takes priority.

### Retries and SMTP errors

Each recipient is sent separately and retried independently, based on the SMTP reply code (the error text is never used):

| Failure | Retried? |
|---------|----------|
| `5xx` reply (permanent: `535` authentication failed, `550` mailbox unavailable, `503` bad sequence...) | No: the recipient fails immediately with `permanent error for <recipient>: <error>` |
| `4xx` reply (transient: `421`, `451`, `454`...) | Yes |
| No SMTP reply: network, TLS or timeout error | Yes |

Retries use exponential backoff with a 1 s base and a 30 s cap, up to 3 attempts per recipient (see [Retry Behavior](#retry-behavior)).

### Custom Email Templates

See [templates/README.md](../templates/README.md) for detailed template documentation.

**Priority:** `body_template_file` > `body_template` > default template

The retained body template (file, inline or default) is checked when the
notifier is built, at daemon startup and by `valerter --validate`: a syntax
error is reported as `invalid notifier '<name>': body_template: ...`, an unknown
filter, test, function or method as `invalid notifier '<name>': body_template
render: ...`. `subject_template` gets the same checks (`subject_template: ...`,
`subject_template render: ...`). A variable that does not exist at this level
(`{{ host }}` instead of `{{ log.host }}`) logs the warning
`Notifier template references unknown variable` (field `subject_template` or
`body_template`) without refusing the configuration.

### Example: Minimal (internal network)

```yaml
notifiers:
  email-internal:
    type: email
    smtp:
      host: internal-smtp.local
      port: 25
      tls: none
    from: "alerts@internal.local"
    to:
      - "team@internal.local"
    subject_template: "Alert: {{ title }}"
```

## Mattermost

Send alerts to Mattermost channels via incoming webhooks.

> **Note about `email_body_html`** — Mattermost reads the outer template's `body`
> output key, **not** `email_body_html`. `email_body_html` is email-only. Mattermost
> renders Markdown in `body` (`**bold**`, `*italic*`, fenced code blocks,
> lists, links); write your formatting there. With
> [`body_format: markdown`](configuration.md#markdown-bodies-body_format), the
> values inserted in `body` are escaped, so `web_01` is not read as italics:
> the attachment text is `**web\_01**`.

### Configuration

```yaml
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/abc123"    # REQUIRED
    channel: "ops-alerts"              # Optional: override default channel
    username: "valerter"               # Optional: display name
    icon_url: "https://example.com/icon.png"    # Optional: avatar
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `webhook_url` | Yes | Mattermost incoming webhook URL (`http` or `https`, supports `${VAR}` substitution) |
| `channel` | No | Override default channel (a rule's `notify.mattermost_channel` takes precedence) |
| `username` | No | Bot username |
| `icon_url` | No | Bot avatar URL |
| `format` | No | Format of the body of a [Markdown alert](#output-format-per-notifier): `markdown`, the only value |

`webhook_url` is checked again once `${VAR}` placeholders are resolved, at
daemon startup and by `valerter --validate`: a value that does not parse or does
not use `http`/`https` is refused with `invalid notifier '<name>': webhook_url:
invalid URL: ...`, without printing the URL (it carries the hook token).

### Channel per rule

A rule can send its alerts to another channel with `notify.mattermost_channel`:

```yaml
rules:
  - name: "db_errors"
    query: '_stream:{app="db"} level:error'
    parser:
      json:
        fields: ["message"]
    notify:
      template: "default_alert"
      mattermost_channel: "db-alerts"   # Only used by Mattermost destinations
      destinations:
        - mattermost-ops
```

The channel is chosen in this order: the rule's `mattermost_channel`, then the
notifier's `channel`, then the default channel of the incoming webhook (no
`channel` key is sent). Other notifier types ignore `mattermost_channel`, and a
rule that sets it without any Mattermost destination logs
`mattermost_channel ignored - no mattermost notifier in destinations` at startup.

If Mattermost rejects the rule's channel with a 4xx response other than 429
(webhook locked to its own channel with "Lock to this channel", channel that
does not exist), the alert is **resent once to the notifier's `channel`** if it
has one and it differs from the rule's, **otherwise without `channel`** (the
webhook's default channel), so it is not lost, and this warning is logged for
every such alert until the configuration is fixed (`fallback_channel` is absent
when the resend has no `channel`):

```
WARN Mattermost rejected channel override, resending to notifier default notifier_name=mattermost-ops rule_name=db_errors channel=db-alerts fallback_channel=ops status=400 Bad Request
```

The resend follows the usual retry policy; a 4xx on the resend fails the alert
(`client error: <status>`). There is no such fallback for the notifier's own
`channel`: a 4xx fails the alert immediately.

### accent_color

The `accent_color` from your template is used for the Mattermost attachment sidebar color:

```yaml
templates:
  critical_alert:
    title: "{{ title }}"
    body: "{{ body }}"
    accent_color: "#ff0000"    # Red sidebar in Mattermost
```

### Timestamp in Footer

Mattermost notifications automatically include a footer with the rule name, the VictoriaLogs source and the original log timestamp, formatted according to the `timestamp_timezone` setting:

```
valerter | <rule_name> | <vl_source> | <log_timestamp_formatted>
```

For example:

```
valerter | high_cpu_alert | vlprod | 15/01/2026 11:00:00 CET
```

This helps operators quickly locate the original log entry in VictoriaLogs.

## Telegram

Send alerts to one or more Telegram chats via the Bot API.

> **Note about `email_body_html`** — Telegram reads the outer template's `body`
> output key, **not** `email_body_html`. `email_body_html` is email-only. With
> the default `body_template`, `body` is escaped (`{{ body|e }}`): HTML written
> in the rule template's `body` is shown literally, tags included. For rich
> formatting, write the markup in the Telegram `body_template` and escape each
> inserted value (see [Formatting messages](#formatting-messages)).

### Prerequisites

1. Create a bot via [@BotFather](https://t.me/BotFather) and note the token it gives you.
2. Add the bot to each target chat/group/channel — it must be a member (or admin, for channels) to post.
3. Get the `chat_id` for each destination. The simplest way: send a message in the chat, then call `https://api.telegram.org/bot<TOKEN>/getUpdates` and read `chat.id` from the response. For channels the id is negative (starts with `-100`).

### Configuration

```yaml
notifiers:
  telegram-alerts:
    type: telegram
    bot_token: "${TELEGRAM_BOT_TOKEN}"   # REQUIRED (supports ${ENV_VAR})
    chat_ids:                             # REQUIRED (non-empty)
      - "-100123456789"
      - "-100987654321"
    parse_mode: HTML                      # Optional (default: HTML)
    disable_notification: false           # Optional (silent delivery)
    disable_web_page_preview: true        # Optional (avoid link-preview noise)
    body_template: |                      # Optional (Jinja)
      <b>{{ title|e }}</b>
      {{ body|e }}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `bot_token` | Yes | Bot API token from @BotFather. Stored as a secret; never logged. |
| `chat_ids` | Yes | List of target chat IDs. Must be non-empty; each element must be non-empty. |
| `parse_mode` | No | `HTML` (default), `MarkdownV2` or `Markdown`, case-insensitive (`html` is sent as `HTML`). Any other value is refused at startup and by `--validate`: `parse_mode '<value>' is not supported (expected HTML, MarkdownV2 or Markdown)`. |
| `disable_notification` | No | When `true`, Telegram delivers silently (no push sound). |
| `disable_web_page_preview` | No | When `true`, Telegram does not expand link previews. |
| `format` | No | Format of the body of a [Markdown alert](#output-format-per-notifier): `telegram_html` (default with `parse_mode: HTML`) or `plain` (default with another `parse_mode`). `telegram_html` with another `parse_mode` is refused: `invalid notifier '<name>': format 'telegram_html' requires parse_mode HTML`. |
| `body_template` | No | Jinja template for the message text. Defaults to `<b>{{ title\|e }}</b>\n{{ body\|e }}`. Sees `title`, `body`, `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted` and `log` (the event fields, see the [webhook variables](#template-variables)). Checked at startup and by `--validate`: a syntax error (`body_template: ...`) or an unknown filter, test, function or method (`body_template render: ...`) is refused; an unknown variable (`{{ host }}` instead of `{{ log.host }}`) logs `Notifier template references unknown variable`. |

### Multi-chat delivery

Each `chat_id` receives one **sequential** `sendMessage` call — Telegram rate-limits at 1 message per second per chat, so parallel delivery wouldn't help. The order in `chat_ids` is preserved.

If at least one chat succeeds, the alert is delivered (`Ok`) and `valerter_alerts_sent_total` increases by 1, whatever the number of chats that succeeded. If every chat fails, the notifier returns `all chat_ids failed` and `valerter_notify_errors_total` / `valerter_alerts_failed_total` increase by 1, once for the alert. Each failed chat is logged at `error` level and counted in `valerter_telegram_chat_errors_total{rule_name, vl_source, notifier_name}`, the Telegram counterpart of `valerter_email_recipient_errors_total`. A chat delivered through the [plain-text fallback](#plain-text-fallback-on-html-rejection) is a success, not a failure.

### Message length

Telegram's hard limit is **4096 Unicode codepoints** per message. Longer messages are truncated to 4095 codepoints + `…` (one Unicode codepoint). Each truncation increments `valerter_alerts_truncated_total{notifier_type="telegram"}` **once per alert** (not per chat) and emits a `warn` log.

The cut is a plain codepoint cut: with `parse_mode: HTML` it can split a tag (`<pre>` left open, `</b` cut in half) or an entity (`&am`). Telegram then rejects the message with a 400 `can't parse entities`, and the plain-text fallback below delivers it.

### Plain-text fallback on HTML rejection

When `parse_mode` is `HTML` (any case) and Telegram answers **400** for a chat with a `description` containing `can't parse entities` (any case; e.g. `Bad Request: can't parse entities: Unclosed start tag at byte offset 4090`), the same text is resent **once** to that chat without `parse_mode`, so Telegram displays it as plain text: the alert is delivered, with its HTML tags and entities shown literally. A `warn` log `Telegram rejected HTML message, resending as plain text` is emitted (notifier, rule, chat and status; never the bot token, the API URL or the text).

The resend follows the usual retry policy (5xx, 429 and network errors, up to 3 attempts). A 4xx on the resend fails the chat for good (`client error: <status>`). There is no fallback for any other 400 (`chat not found`, `message text is empty`, a body without that description), for other 4xx statuses (401, 403, 404...) or with `parse_mode: MarkdownV2` or `Markdown`: those fail immediately.

Frequent fallback warnings mean the template produces invalid HTML: escape every inserted value with `|e` (see below).

### Rate limits and retries

Telegram returns HTTP 429 with a `Retry-After` header when you hit a rate limit. The notifier honors it (clamped to `[1s, 60s]`) and the retry counts against the same 3-attempt pool as 5xx and network errors.

### HTML escaping

With `parse_mode: HTML`, Telegram rejects messages containing unescaped `<`, `>`, or `&`. The default `body_template` uses the `|e` Jinja filter to escape these automatically. If you provide a custom `body_template`, make sure to escape user-controlled fields (`title`, `body`, `rule_name`, `log.*`...) the same way (`{{ body|e }}`, not `{{ body }}`): otherwise a log line containing `a < b` makes Telegram reject the message with a 400, and it is only delivered through the plain-text fallback, without formatting.

### Formatting messages

The simplest way to format a Telegram message is a rule template with
[`body_format: markdown`](configuration.md#markdown-bodies-body_format): its
body, written once in Markdown, reaches Telegram as HTML of the Bot API subset
(`<b>`, `<i>`, `<s>`, `<code>`, `<pre>`, `<a>`, `<blockquote>`), always well
formed, with the values of the log escaped. The default `body_template` works
unchanged (`{{ body|e }}` leaves this HTML intact):

```yaml
templates:
  disk_alert:
    title: "Disk {{ host }}"
    body_format: markdown
    body: "**{{ host }}** < 10% free"
```

With `host=a_b`, the message is `<b>Disk a_b</b>\n<b>a_b</b> &lt; 10% free`.
The same template gives Markdown to Mattermost and HTML to email.

- The `telegram_html` rendering needs `parse_mode: HTML` (the default).
- With `parse_mode: MarkdownV2`, the notifier receives the plain-text rendering
  by default: escape it with `mdv2_escape` in a `body_template` written for
  MarkdownV2, `*{{ title | mdv2_escape }}*\n{{ body | mdv2_escape }}`.

Without `body_format: markdown`, the markup belongs in the Telegram
`body_template`, which is written for
Telegram only; the values come from the alert and the event, each one escaped
with `|e`:

```yaml
notifiers:
  telegram-formatted:
    type: telegram
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_ids:
      - "-100123456789"
    body_template: |
      <b>{{ title|e }}</b>
      Host: <code>{{ log.host|e }}</code>
      Rule: <i>{{ rule_name|e }}</i> · {{ log_timestamp_formatted|e }}
      <pre>{{ log._msg|e }}</pre>
```

With `host=<web&01>`, the message shows `Host: <web&01>` in monospace, and a
`<` or `&` in the log line can no longer break the HTML.

- Do not put HTML in the rule template's `body`: the default `body_template`
  escapes it, and a custom one inserting `{{ body }}` without `|e` passes the
  log data it contains unescaped. Write `{{ body }}` without `|e` only for a
  `body` that holds no data from the log.
- With `parse_mode: MarkdownV2`, escape values with
  [`mdv2_escape`](configuration.md#valerter-filters) instead of `|e`:
  `*{{ title | mdv2_escape }}*`.
- `body_format: markdown` (above) follows the same approach without a
  `body_template` per notifier.

Background and next steps: [issue #24](https://github.com/fxthiry/valerter/issues/24).

### Example: two destinations, silent delivery

```yaml
notifiers:
  telegram-oncall:
    type: telegram
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_ids:
      - "-1001111111111"   # #oncall channel
      - "-1002222222222"   # #leadership channel
    disable_notification: false
    disable_web_page_preview: true
```

## Multi-Destination Routing

Send alerts to multiple notifiers per rule:

```yaml
rules:
  - name: "critical_error"
    query: '_stream:{app="myapp"} level:critical'
    parser:
      json:
        fields: ["message", "error"]
    notify:
      template: "critical_template"
      destinations:
        - mattermost-ops      # Team notification
        - email-ops           # Email trail
        - pagerduty           # On-call paging
```

Alerts are sent to all destinations **in parallel**. Each destination's success/failure is independent.

## Retry Behavior

All notifiers implement exponential backoff retry, up to **3 attempts** per send:

| Notifier | Base delay | Max delay |
|----------|------------|-----------|
| `webhook`, `mattermost`, `telegram` | 500ms | 5s |
| `email` | 1s | 30s |

What is retried depends on the notifier: HTTP notifiers retry 5xx, 429 and network errors and give up immediately on other 4xx statuses (see the Telegram [plain-text fallback](#plain-text-fallback-on-html-rejection) and the Mattermost [resend to the notifier default](#channel-per-rule) for the two exceptions); email retries 4xx SMTP replies and network, TLS or timeout errors, and gives up immediately on 5xx replies (see [Retries and SMTP errors](#retries-and-smtp-errors)).

After all retries are exhausted, the alert is marked as failed and logged.

Metrics count each alert **once per notifier** (see [Metrics](metrics.md)): `valerter_alerts_sent_total` when it is delivered (to at least one recipient or chat for `email` and `telegram`), `valerter_notify_errors_total` and `valerter_alerts_failed_total` when it permanently fails. A template that fails to render at send time (`body_template` of a `webhook`, subject or body of an `email`, message text of a `telegram` notifier) is such a permanent failure: nothing is sent, nothing is retried, and both counters increase by 1.

## Troubleshooting

### Webhook not receiving alerts

1. Check URL is accessible from Valerter host
2. Verify headers are correct (especially `Content-Type`)
3. Check logs: `journalctl -u valerter | grep webhook`

### Email not sending

1. Verify SMTP credentials
2. Check TLS mode matches your server
3. Test with `swaks` or similar tool
4. Check logs for SMTP errors

### Mattermost not posting

1. Verify webhook URL is correct
2. Check webhook is enabled in Mattermost
3. Verify channel exists (if specified); a rejected `mattermost_channel` logs `Mattermost rejected channel override, resending to notifier default`
4. Check logs for HTTP errors

## See Also

- [Configuration](configuration.md) - Full configuration reference
- [templates/README.md](../templates/README.md) - Email template documentation
