# Notifiers

Valerter supports multiple notification channels. Configure them in the `notifiers:` section of your config file.

## Overview

| Type | Description | Best For |
|------|-------------|----------|
| `webhook` | Generic HTTP endpoint | PagerDuty, Slack, Discord, custom APIs |
| `email` | SMTP email | Ops teams, compliance, audit trails |
| `mattermost` | Mattermost incoming webhook | Team chat notifications |

## Webhook (Generic HTTP)

The most flexible notifier - works with any HTTP API.

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
  "timestamp": "<ISO8601>"
}
```

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

### body_html Requirement

**Important:** When using email destinations, your message template MUST include `body_html`:

```yaml
templates:
  my_template:
    title: "{{ title }}"
    body: "{{ body }}"
    body_html: "<p>{{ body }}</p>"    # REQUIRED for email
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
