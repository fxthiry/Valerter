# Notifiers

Valerter supports multiple notification channels. Configure them in the `notifiers:` section of your config file.

## Overview

| Type | Description | Best For |
|------|-------------|----------|
| `webhook` | Generic HTTP endpoint | PagerDuty, Slack, Discord, custom APIs |
| `email` | SMTP email | Ops teams, compliance, audit trails |
| `mattermost` | Mattermost incoming webhook | Team chat notifications |
| `telegram` | Telegram Bot API | Mobile alerts, small teams, channels |

## Webhook (Generic HTTP)

The most flexible notifier - works with any HTTP API.

> **Note about `email_body_html`** — Webhook reads the outer template's `body`
> output key (and `title`, `rule_name`, `log_timestamp`, `log_timestamp_formatted`)
> inside its own `body_template`. It does **not** receive `email_body_html`;
> `email_body_html` is email-only. If your HTTP target needs HTML, put it in `body`
> at the outer template and reference `{{ body }}` from the webhook
> `body_template`.

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
          "source": "valerter",
          "severity": "error",
          "custom_details": {
            "body": {{ body | tojson }},
            "rule": {{ rule_name | tojson }}
          }
        }
      }
```

The PagerDuty Events API v2 authenticates with the `routing_key` in the body, so no
`Authorization` header is needed. Set `PAGERDUTY_ROUTING_KEY` to the integration key of
your PagerDuty service in the daemon's environment: the key stays out of the
configuration file (see [`${VAR}` in `body_template`](#var-in-body_template)).

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `url` | Yes | Endpoint URL (`http` or `https`, supports `${VAR}` substitution) |
| `method` | No | HTTP method (default: `POST`) |
| `headers` | No | Custom headers (supports `${VAR}` substitution) |
| `body_template` | No | Custom JSON body (Jinja2 template, supports `${VAR}` substitution in its source) |

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
| `timestamp` | When the alert was sent |
| `log_timestamp` | Original log timestamp (ISO 8601, for VictoriaLogs search) |
| `log_timestamp_formatted` | Human-readable timestamp (respects `timestamp_timezone` setting) |

### Template Variables

When using `body_template`, these variables are available:

| Variable | Description |
|----------|-------------|
| `title` | Alert title |
| `body` | Alert body |
| `rule_name` | Name of the rule |
| `vl_source` | Name of the VictoriaLogs source the event came from |
| `log_timestamp` | Original log timestamp (ISO 8601) |
| `log_timestamp_formatted` | Human-readable timestamp |

`{{ vl_source }}` is available wherever `{{ rule_name }}` is, and follows the
same collision policy: an event field literally named `vl_source` is masked
by the synthetic source name.

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
`subject_template render: ...`).

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
> lists, links); write your formatting there.

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
> output key, **not** `email_body_html`. `email_body_html` is email-only. For rich
> formatting inside Telegram, put the markup directly in `body` using
> Telegram's supported HTML subset: `<b>`, `<i>`, `<u>`, `<s>`, `<code>`,
> `<pre>`, `<blockquote>`, `<a href="…">`, `<span>`, `<tg-spoiler>`.
> Keep `parse_mode: HTML` (the default) so the Bot API interprets those tags.

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
| `body_template` | No | Jinja template for the message text. Defaults to `<b>{{ title\|e }}</b>\n{{ body\|e }}`. Checked at startup and by `--validate`: a syntax error (`body_template: ...`) or an unknown filter, test, function or method (`body_template render: ...`) is refused. |

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

With `parse_mode: HTML`, Telegram rejects messages containing unescaped `<`, `>`, or `&`. The default `body_template` uses the `|e` Jinja filter to escape these automatically. If you provide a custom `body_template`, make sure to escape user-controlled fields (`title`, `body`, `rule_name`...) the same way (`{{ body|e }}`, not `{{ body }}`): otherwise a log line containing `a < b` makes Telegram reject the message with a 400, and it is only delivered through the plain-text fallback, without formatting.

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
