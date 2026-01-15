# Configuration Reference

Valerter is configured via a YAML file, typically at `/etc/valerter/config.yaml`.

See [config/config.example.yaml](../config/config.example.yaml) for a complete annotated example.

## Configuration File

| Location | Description |
|----------|-------------|
| `/etc/valerter/config.yaml` | Default location (systemd) |
| Custom path via `-c` flag | `valerter -c /path/to/config.yaml` |

**Security:** The file should be owned by `valerter:valerter` with mode `600` (owner read/write only).

## Structure Overview

```yaml
victorialogs:    # VictoriaLogs connection (REQUIRED)
metrics:         # Prometheus metrics (optional)
notifiers:       # Named notification channels (recommended)
defaults:        # Default throttle and notify settings (REQUIRED)
templates:       # Message templates (REQUIRED)
rules:           # Alert rules (REQUIRED, at least one)
```

## VictoriaLogs Connection

```yaml
victorialogs:
  url: "http://victorialogs:9428"    # REQUIRED

  # Optional: Basic Authentication
  basic_auth:
    username: "${VL_USER}"
    password: "${VL_PASS}"

  # Optional: Custom headers (for tokens, API keys)
  headers:
    Authorization: "Bearer ${VL_TOKEN}"

  # Optional: TLS configuration
  tls:
    verify: true    # Set to false for self-signed certs
```

### Reverse Proxy Configuration

If VictoriaLogs is behind a reverse proxy (nginx, Traefik, etc.), you **must** disable buffering and caching for the `/select/logsql/tail` endpoint. Valerter uses HTTP streaming to receive logs in real-time, and proxy buffering will cause delays or connection issues.

**Nginx example:**

```nginx
# Add this BEFORE your general /select location block
location = /select/logsql/tail {
    proxy_pass http://victorialogs_backend;

    # CRITICAL: Disable buffering and caching for streaming
    proxy_buffering off;
    proxy_cache off;

    # Long timeouts for persistent connections
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

**Key settings:**
- `proxy_buffering off` — Send data immediately to client
- `proxy_cache off` — Don't cache streaming responses
- `proxy_read_timeout 3600s` — Keep connection alive for 1 hour

## Defaults

Default values applied to all rules unless overridden.

```yaml
defaults:
  throttle:
    count: 5         # Max alerts per window
    window: 60s      # Time window (e.g., 60s, 5m, 1h)
  notify:
    template: "default_alert"    # Template name
  # timestamp_timezone: "Europe/Paris"  # Optional: timezone for formatted timestamps (default: UTC)
```

### Timestamp Timezone

The `timestamp_timezone` setting controls the timezone used for `{{ log_timestamp_formatted }}` in templates and Mattermost footers.

| Value | Example Output |
|-------|----------------|
| `UTC` (default) | `15/01/2026 10:00:00 UTC` |
| `Europe/Paris` | `15/01/2026 11:00:00 CET` (winter) / `CEST` (summer) |
| `America/New_York` | `15/01/2026 05:00:00 EST` |

Uses [IANA timezone names](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). Invalid timezone will fail at startup.

## Templates

Message templates use [Jinja2 syntax](https://jinja.palletsprojects.com/) (via minijinja).

```yaml
templates:
  default_alert:
    title: "{{ title | default('Alert') }}"           # REQUIRED
    body: "{{ body }}"                                 # REQUIRED
    body_html: "<p>{{ body }}</p>"                     # REQUIRED for email destinations
    accent_color: "#ff0000"                            # Optional: hex color
```

### Available Variables

Variables come from the parser output plus built-in fields:

| Variable | Description |
|----------|-------------|
| `rule_name` | Name of the rule that triggered |
| `_msg` | Original log message (from VictoriaLogs) |
| `_time` | Log timestamp (raw from VictoriaLogs) |
| `_stream` | Stream labels |
| `log_timestamp` | Original log timestamp in ISO 8601 format (for VictoriaLogs search) |
| `log_timestamp_formatted` | Human-readable timestamp (respects `timestamp_timezone` setting) |
| Custom fields | Extracted by regex/JSON parser |

**Note:** `log_timestamp` and `log_timestamp_formatted` are available in:
- Email subject and body templates
- Webhook `body_template`
- Mattermost footer (automatically includes `log_timestamp_formatted`)

### body_html Requirement

**Important:** Templates used with email destinations MUST include `body_html`. Valerter validates this at startup and will fail if missing.

## Rules

Alert rules define what logs to monitor and how to process them.

```yaml
rules:
  - name: "high_cpu_alert"           # REQUIRED: unique name
    enabled: true                     # Default: true
    query: '_stream:{host="server1"} | json | cpu > 90'    # REQUIRED: LogsQL

    parser:                           # At least one recommended
      json:
        fields: ["host", "cpu", "timestamp"]
      # OR
      regex: '(?P<level>\S+) (?P<message>.*)'

    throttle:                         # Optional: overrides defaults
      key: "{{ host }}"               # Group throttling by field
      count: 3
      window: 5m

    notify:                           # Optional: overrides defaults
      template: "custom_template"
      destinations:                   # Send to specific notifiers
        - mattermost-ops
        - email-ops
```

### Parser Types

**JSON Parser:** Extract specific fields from JSON logs.

```yaml
parser:
  json:
    fields: ["host", "level", "message", "timestamp"]
```

**Regex Parser:** Extract fields using named capture groups.

```yaml
parser:
  regex: '(?P<timestamp>\S+) (?P<level>\S+) (?P<message>.*)'
```

### Throttling

Prevents alert spam by limiting notifications per time window.

| Field | Description |
|-------|-------------|
| `key` | Template to group alerts (e.g., `{{ host }}`) |
| `count` | Max alerts per window |
| `window` | Time window (e.g., `30s`, `5m`, `1h`) |

Example: Max 3 alerts per host per 5 minutes:

```yaml
throttle:
  key: "{{ host }}"
  count: 3
  window: 5m
```

## Secrets Management

### Recommended: Direct Values

Put secrets directly in the config file and secure with permissions:

```yaml
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/abc123def456"
```

```bash
sudo chmod 600 /etc/valerter/config.yaml
sudo chown valerter:valerter /etc/valerter/config.yaml
```

### Alternative: Environment Variables

For Kubernetes or orchestrators, use `${VAR_NAME}` syntax:

```yaml
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "${MATTERMOST_WEBHOOK}"
```

Variables are resolved at startup from the process environment.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VL_USER` | VictoriaLogs Basic Auth username |
| `VL_PASS` | VictoriaLogs Basic Auth password |
| `SMTP_USER` | SMTP authentication username |
| `SMTP_PASSWORD` | SMTP authentication password |
| `RUST_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `LOG_FORMAT` | Output format: `text` (default), `json` |

## CLI Options

```
valerter [OPTIONS]

Options:
  -c, --config <PATH>  Path to configuration file [default: /etc/valerter/config.yaml]
      --validate       Validate configuration and exit
  -h, --help           Print help
  -V, --version        Print version
```

## Validation

Always validate before deploying:

```bash
valerter --validate
```

This checks:
- YAML syntax
- Required fields
- Template syntax
- Notifier configuration
- Rule destinations exist
- Email templates have `body_html`

## See Also

- [Notifiers](notifiers.md) - Mattermost, Email, Webhook configuration
- [Metrics](metrics.md) - Prometheus metrics reference
- [Architecture](architecture.md) - How Valerter works
