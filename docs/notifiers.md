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
    headers:
      Authorization: "Token token=${PAGERDUTY_TOKEN}"
      Content-Type: "application/json"
    body_template: |
      {
        "routing_key": "${PAGERDUTY_ROUTING_KEY}",
        "event_action": "trigger",
        "payload": {
          "summary": "{{ title }}",
          "source": "valerter",
          "severity": "error",
          "custom_details": {
            "body": "{{ body }}",
            "rule": "{{ rule_name }}"
          }
        }
      }
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `url` | Yes | Endpoint URL |
| `method` | No | HTTP method (default: `POST`) |
| `headers` | No | Custom headers (supports `${VAR}` substitution) |
| `body_template` | No | Custom JSON body (Jinja2 template) |

### Default Payload

If `body_template` is omitted, sends:

```json
{
  "alert_name": "<notifier_name>",
  "rule_name": "...",
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
| `log_timestamp` | Original log timestamp (ISO 8601) |
| `log_timestamp_formatted` | Human-readable timestamp |

### Examples

**Slack:**

```yaml
notifiers:
  slack-alerts:
    type: webhook
    url: "${SLACK_WEBHOOK_URL}"
    body_template: |
      {
        "text": "*{{ title }}*\n{{ body }}",
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
        "content": "**{{ title }}**\n{{ body }}"
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
      {"alert": "{{ title }}", "details": "{{ body }}", "rule": "{{ rule_name }}"}
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

Valerter validates this at startup and will fail if missing.

### Custom Email Templates

See [templates/README.md](../templates/README.md) for detailed template documentation.

**Priority:** `body_template_file` > `body_template` > default template

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
| `webhook_url` | Yes | Mattermost incoming webhook URL |
| `channel` | No | Override default channel |
| `username` | No | Bot username |
| `icon_url` | No | Bot avatar URL |

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

Mattermost notifications automatically include the original log timestamp in the footer, formatted according to the `timestamp_timezone` setting:

```
Log time: 15/01/2026 11:00:00 CET
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
| `parse_mode` | No | `HTML` (default) or `MarkdownV2`. Passed through to the Bot API. |
| `disable_notification` | No | When `true`, Telegram delivers silently (no push sound). |
| `disable_web_page_preview` | No | When `true`, Telegram does not expand link previews. |
| `body_template` | No | Jinja template for the message text. Defaults to `<b>{{ title\|e }}</b>\n{{ body\|e }}`. |

### Multi-chat delivery

Each `chat_id` receives one **sequential** `sendMessage` call — Telegram rate-limits at 1 message per second per chat, so parallel delivery wouldn't help. The order in `chat_ids` is preserved.

If at least one chat succeeds, the alert is counted as delivered (`Ok`). Per-chat failures are logged at `error` level and recorded in `valerter_notify_errors_total` / `valerter_alerts_failed_total`.

### Message length

Telegram's hard limit is **4096 Unicode codepoints** per message. Longer messages are truncated to 4095 codepoints + `…` (one Unicode codepoint). Each truncation increments `valerter_alerts_truncated_total{notifier_type="telegram"}` **once per alert** (not per chat) and emits a `warn` log.

### Rate limits and retries

Telegram returns HTTP 429 with a `Retry-After` header when you hit a rate limit. The notifier honors it (clamped to `[1s, 60s]`) and the retry counts against the same 3-attempt pool as 5xx and network errors.

### HTML escaping

With `parse_mode: HTML`, Telegram rejects messages containing unescaped `<`, `>`, or `&`. The default `body_template` uses the `|e` Jinja filter to escape these automatically. If you provide a custom `body_template`, make sure to escape user-controlled fields (`title`, `body`) the same way, or your messages will be rejected with a 400.

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

All notifiers implement exponential backoff retry:

- **Base delay:** 500ms
- **Max delay:** 5s
- **Max retries:** 3

After all retries are exhausted, the alert is marked as failed and logged.

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
3. Verify channel exists (if specified)
4. Check logs for HTTP errors

## See Also

- [Configuration](configuration.md) - Full configuration reference
- [templates/README.md](../templates/README.md) - Email template documentation
