# Configuration Reference

Valerter is configured via a YAML file, typically at `/etc/valerter/config.yaml`.

See [config/config.example.yaml](../config/config.example.yaml) for a complete annotated example.

## Configuration File

| Location | Description |
|----------|-------------|
| `/etc/valerter/config.yaml` | Default location (systemd) |
| Custom path via `-c` flag | `valerter -c /path/to/config.yaml` |

**Security:** The file should be owned by `valerter:valerter` with mode `600` (owner read/write only).

## Multi-File Configuration

For large deployments, you can split rules, templates, and notifiers into separate files in `.d/` directories alongside `config.yaml`:

```
/etc/valerter/
├── config.yaml         # Main config
├── rules.d/
│   ├── security.yaml   # Security team rules
│   └── infra.yaml      # Infrastructure rules
├── templates.d/
│   └── custom.yaml     # Custom templates
└── notifiers.d/
    └── team-channels.yaml
```

### Format in `.d/` Files

Files in `.d/` directories use a **HashMap format** where the name is the YAML key:

```yaml
# rules.d/security.yaml
auth_failure:
  query: "_msg:authentication AND status:failed"
  parser:
    json:
      fields: [user, ip]
  notify:
    template: "security_alert"
    destinations:
      - security-team

brute_force:
  query: "_msg:blocked"
  parser:
    regex: "IP (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
  notify:
    template: "security_alert"
    destinations:
      - security-team
```

```yaml
# templates.d/custom.yaml
security_alert:
  title: "Security: {{ title }}"
  body: "{{ body }}"
  accent_color: "#ff0000"
```

```yaml
# notifiers.d/team-channels.yaml
security-team:
  type: mattermost
  webhook_url: "https://mattermost.example.com/hooks/security"

infra-team:
  type: mattermost
  webhook_url: "https://mattermost.example.com/hooks/infra"
```

### Rules

- **Files processed:** `*.yaml` and `*.yml` only
- **Order:** Alphabetical (deterministic)
- **Hidden files:** Files starting with `.` are ignored
- **Empty files:** Silently skipped
- **Name uniqueness:** Names must be unique across `config.yaml` and all `.d/` files
- **Cross-references:** Rules in `.d/` can reference templates in `config.yaml` and vice versa

### Collision Detection

If the same name is defined in multiple files, Valerter fails at startup with an explicit error:

```
Error: duplicate rule name 'my_rule': defined in 'config.yaml' and 'rules.d/extra.yaml'
```

## Structure Overview

```yaml
victorialogs:    # VictoriaLogs connection (REQUIRED)
metrics:         # Prometheus metrics (optional)
notifiers:       # Named notification channels (recommended)
defaults:        # Default throttle and notify settings (REQUIRED)
templates:       # Message templates (REQUIRED)
rules:           # Alert rules (REQUIRED, at least one)
```

## VictoriaLogs Sources (multi-source)

`victorialogs` is a map of named sources. A single valerter instance can tail
multiple VL backends concurrently and route alerts per source. At least one
source is required.

```yaml
victorialogs:
  default:                            # Source name (used as `vl_source`)
    url: "http://victorialogs:9428"   # REQUIRED

    # Optional: Basic Authentication (per-source)
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

### Multi-source example

```yaml
victorialogs:
  vlprod:
    url: "https://victorialogs.prod.example.com:9428"
    basic_auth:
      username: "${VL_PROD_USER}"
      password: "${VL_PROD_PASS}"
  vldev:
    url: "http://victorialogs.dev.internal:9428"
```

Rules can target a subset of sources via `vl_sources: [name, ...]`, or omit
the field to fan out across every configured source. The current source name
is exposed in templates as `{{ vl_source }}` (layer 1 templates,
`throttle.key`, and notifier-level layer 2 contexts).

### Migration from v1.x (breaking change)

The v1.x single-URL shape (`victorialogs.url: ...` at the top level) is
rejected at load with a clear error. Wrap your existing settings under a
named key (we recommend `default` for single-source deployments):

```yaml
# Before (v1.x):
victorialogs:
  url: "http://victorialogs:9428"
  basic_auth:
    username: "u"
    password: "p"

# After (v2.0+):
victorialogs:
  default:
    url: "http://victorialogs:9428"
    basic_auth:
      username: "u"
      password: "p"
```

The default throttle key also changed from `{rule}:global` to
`{rule}-{source}:global` so multi-source buckets are isolated by default. To
preserve v1.x cross-source dedup, set `throttle.key: "{{ rule_name }}"`
explicitly on the rules that need it.

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
  # timestamp_timezone: "Europe/Paris"  # Optional: timezone for formatted timestamps (default: UTC)
  # max_streams: 50                     # Optional: hard cap on total VictoriaLogs streams (default: 50)
```

### `max_streams` — fan-out guardrail

Multi-source deployments spawn one stream per `(enabled rule, target source)`
pair. With unscoped fan-out rules and many sources the total scales as
`rules × sources`, which can DoS a backend by accident. `defaults.max_streams`
caps that total at load time:

```
total = sum(if rule.vl_sources is empty then sources.len() else rule.vl_sources.len()
            for rule in enabled_rules)
```

Disabled rules do not contribute. Breaching the cap fails `valerter --validate`
with a message stating both the actual count and the cap so an operator knows
whether to raise the cap or trim rules. Default: `50`.

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
    email_body_html: "<p>{{ body }}</p>"                     # REQUIRED for email destinations
    accent_color: "#ff0000"                            # Optional: hex color
```

### Available Variables

Variables come from the parser output plus built-in fields:

| Variable | Description |
|----------|-------------|
| `rule_name` | Name of the rule that triggered |
| `vl_source` | Name of the VictoriaLogs source the event came from |
| `_msg` | Original log message (from VictoriaLogs) |
| `_time` | Log timestamp (raw from VictoriaLogs) |
| `_stream` | Stream labels |
| `log_timestamp` | Original log timestamp in ISO 8601 format (for VictoriaLogs search) |
| `log_timestamp_formatted` | Human-readable timestamp (respects `timestamp_timezone` setting) |
| Custom fields | Extracted by regex/JSON parser |

**Note:** `rule_name` and `vl_source` are available in all template contexts:
the top-level template fields (`title`, `body`, `email_body_html`), the
`throttle.key`, and the notifier-level templates (`subject_template`,
`body_template`). If an event field happens to be named `rule_name` or
`vl_source`, the synthetic value wins.

**Note:** `log_timestamp` and `log_timestamp_formatted` are available in:
- Email subject and body templates
- Webhook `body_template`
- Mattermost footer (automatically includes `log_timestamp_formatted`)

These timestamps are computed **after** the top-level template renders, so they are only accessible in notifier-level templates. If you need a timestamp at the top-level, reference `{{ _time }}` (raw VictoriaLogs field) directly.

### Fields with special characters

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

### email_body_html Requirement

**Important:** Templates used with email destinations MUST include `email_body_html`. Valerter validates this at startup and will fail if missing.

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

    vl_sources: [vlprod]              # Optional: target specific sources
                                      # Empty/omitted = fan out across all
                                      # sources defined in `victorialogs:`.
                                      # Unknown names rejected at load.

    notify:                           # REQUIRED
      template: "custom_template"     # REQUIRED: template name
      destinations:                   # REQUIRED: at least one notifier
        - mattermost-ops
        - email-ops
      mattermost_channel: "alerts"    # Optional: override Mattermost channel
```

### LogsQL query restrictions

Valerter uses the VictoriaLogs `/select/logsql/tail` endpoint, which streams
matching logs as they arrive. Pipes that need the **full result set** are not
supported by `/tail` and are rejected by `valerter --validate`:
`stats`, `sort`, `top`, `uniq`, `limit`, `offset`, `first`, `last`, `facets`,
`join`, `field_names`, `field_values`, `block_stats`, `blocks_count`, `union`.

Filter-style pipes (`filter`, `json`, `extract`, `extract_regexp`, `unpack_json`,
`format`, `fields`, `rename`, `math`, `replace`, ...) work as expected.

For aggregation-based alerts ("more than N distinct versions per host"),
run the `stats` query on a schedule with [vmalert](https://docs.victoriametrics.com/vmalert/)
and let Valerter alert on individual events instead.

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

`${VAR_NAME}` placeholders are resolved at startup in notifier secrets
(`webhook_url`, `url`, `headers`, `bot_token`, SMTP `username`/`password`) and
in VictoriaLogs sources (`url`, `basic_auth.username`/`password`, `headers`).
An undefined variable is a load error.

For Kubernetes or orchestrators, use `${VAR_NAME}` syntax:

```yaml
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "${MATTERMOST_WEBHOOK}"
```

Variables are resolved at startup from the process environment. You can use **any environment variable** - there is no predefined list. Common examples:

- `${VL_USER}`, `${VL_PASS}` - VictoriaLogs credentials
- `${SMTP_USER}`, `${SMTP_PASSWORD}` - Email credentials
- `${SLACK_WEBHOOK_URL}`, `${PAGERDUTY_TOKEN}` - Notification services

## Runtime Environment Variables

These variables are read directly by the process (not substituted in config):

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Log level: `error`, `warn`, `info` (default), `debug`, `trace` |
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
- Email templates have `email_body_html`

## See Also

- [Notifiers](notifiers.md) - Mattermost, Email, Webhook configuration
- [Metrics](metrics.md) - Prometheus metrics reference
- [Architecture](architecture.md) - How Valerter works
