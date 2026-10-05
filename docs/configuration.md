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
- **Order:** Files are read in alphabetical order of their path. Rules keep a
  stable order on every load: the rules of `config.yaml` in their declared order,
  then the rules of `rules.d/` sorted by file path, then by rule name within a
  file (not by declaration order in the file)
- **Hidden files:** Files starting with `.` are ignored
- **Empty files:** Silently skipped
- **Name uniqueness:** Names must be unique across `config.yaml` and all `.d/` files
- **Cross-references:** Rules in `.d/` can reference templates in `config.yaml` and vice versa

### Collision Detection

If the same name is defined in multiple files, Valerter fails at startup with an explicit error:

```
Error: duplicate rule name 'my_rule': defined in 'config.yaml' and 'rules.d/extra.yaml'
```

The message has the same form for templates and notifiers (`duplicate template
name '...'`, `duplicate notifier name '...'`), whether the collision is between
`config.yaml` and a `.d/` file or between two files of the same `.d/` directory
(the first file in alphabetical order is cited first).

## Structure Overview

```yaml
victorialogs:    # VictoriaLogs connection (REQUIRED)
metrics:         # Prometheus metrics (optional)
notifiers:       # Named notification channels (REQUIRED, at least one)
defaults:        # Default throttle, timestamp timezone and stream cap (REQUIRED)
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
    url: "http://victorialogs:9428"   # REQUIRED (a trailing "/" is ignored)

    # Optional: Basic Authentication (per-source)
    basic_auth:
      username: "${VL_USER}"
      password: "${VL_PASS}"

    # Optional: Custom headers (for tokens, API keys).
    # Sent last: they replace a default or basic_auth header of the same name.
    # Use either basic_auth or an Authorization header, not both: here the
    # Bearer token would replace the basic_auth credentials.
    headers:
      Authorization: "Bearer ${VL_TOKEN}"

    # Optional: TLS configuration
    tls:
      verify: true    # Set to false for self-signed certs
```

### URL and headers

- `url` is the base URL of VictoriaLogs, optionally with a path prefix
  (`https://proxy.example.com/vl`). Trailing slashes are dropped before
  `/select/logsql/tail` is appended, so `http://victorialogs:9428/` and
  `http://victorialogs:9428` are equivalent.
- Each request carries `Accept: application/x-ndjson`, `Connection: keep-alive`
  and, when `basic_auth` is set, a Basic `Authorization` header. Custom
  `headers` are applied last and **replace** any of these with the same name
  (case-insensitive) instead of being sent alongside: `accept:
  "application/json"` yields a single `Accept: application/json`.
- A custom `Authorization` header therefore takes precedence over
  `basic_auth`. Valerter logs a warning at the start of each affected
  (rule, source) task (`Custom Authorization header overrides basic_auth for
  this VictoriaLogs source`, with `rule_name` and `vl_source` only, never the
  header value nor the credentials). Headers with another name, such as
  `X-Tenant` or `Authorization-Token`, are sent together with Basic Auth.
- Header values and the Basic Auth password are never written to the logs.
  The source URL (which may carry credentials or a token resolved from
  `${VAR}`) only appears masked in the streaming logs
  (`http://***@vl:9428/select/logsql/tail?***`, the LogsQL query being logged
  in a separate `query` field), and transport errors are logged without it.

The configuration is refused at load time (and by `valerter --validate`) when,
after `${VAR}` substitution:

- `url` does not parse or does not use `http`/`https`:
  `victorialogs.<source>.url: invalid URL: ...`. A value that still contains
  `${` after substitution is checked like any other URL. The URL is never
  printed.
- a `headers` name is not a valid HTTP header name:
  `victorialogs.<source>.headers: invalid header name '<name>'`.
- a `headers` value is not a valid HTTP header value (line break, control
  character): `victorialogs.<source>.headers: invalid value for header
  '<name>'`. The value is never printed.

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
explicitly on the rules that need it (effective since v2.1.0, see
[Throttling](#throttling)).

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
    count: 5         # Max alerts per window (>= 1)
    window: 60s      # Time window (e.g., 60s, 5m, 1h; > 0)
    # key: "{{ host }}"  # Optional: grouping key template
  # timestamp_timezone: "Europe/Paris"  # Optional: timezone for formatted timestamps (default: UTC)
  # max_streams: 50                     # Optional: hard cap on total VictoriaLogs streams (default: 50)
```

`defaults.throttle` applies to every rule without its own `throttle` block and
gets the same checks as a rule throttle (see [Throttling](#throttling)):
`count: 0` (`defaults.throttle.count must be >= 1 (0 would suppress every alert)`),
`window: 0s` (`defaults.throttle.window must be > 0 (0s disables throttling)`),
a `key` with a syntax error (`defaults.throttle.key: ...`) or an unknown filter,
test or function (`defaults.throttle.key render: ...`) are refused at load time.

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
    title: "{{ rule_name }}"                           # REQUIRED
    body: "{{ _msg }}"                                 # REQUIRED
    email_body_html: "<p>{{ _msg }}</p>"               # REQUIRED for email destinations
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

### Template validation

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
  after a built-in filter applied to a field
  (`{{ status | int }}-{{ host | truncat(10) }}`,
  `{{ host | split('.') | first }} {{ host | nosuch }}`), in an `else` branch
  or in a loop body (`{% for k, v in m | items %}{{ v | nosuch }}{% endfor %}`);
- the `/` operator applied to a field path (see above).

Conversions and arithmetic on fields (`{{ status | int }}`, `{{ (latency |
float) > 1.5 }}`, `{{ ratio | round }}`, `{{ count + 1 }}`) are accepted: their
outcome depends on the real values. A built-in filter applied to a field
(`| int`, `| float`, `| round`, `| split`, `| upper`, `| items`...) does not
stop the check: the rest of the template is still verified. An error of that
kind at runtime falls back to a generic message (templates) or to the
`<rule>:error` key (throttle).

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

### email_body_html Requirement

**Important:** Templates used with email destinations MUST include `email_body_html`. Valerter validates this at startup and in `--validate`, and fails if missing.

## Rules

Alert rules define what logs to monitor and how to process them.

```yaml
rules:
  - name: "high_cpu_alert"           # REQUIRED: unique name
    enabled: true                     # Default: true (at least one rule must be enabled)
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
      destinations:                   # REQUIRED: at least one notifier, each at most once
        - mattermost-ops
        - email-ops
      mattermost_channel: "alerts"    # Optional: channel for Mattermost destinations
                                      # (rule > notifier `channel` > webhook default;
                                      # if rejected, resent to the notifier `channel`
                                      # or the webhook default, see
                                      # notifiers.md#channel-per-rule)
```

`notify.destinations` must list each notifier at most once: a duplicate, which
would deliver every alert twice to the same notifier, refuses the configuration
at load time and in `--validate`, for enabled and disabled rules alike
(`rule '<rule>': notify.destinations contains duplicate entry '<name>' (each
notifier may appear at most once)`).

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

`count` must be >= 1 and `window` > 0. `key` is checked at load time like the
templates (syntax, then [test render](#template-validation)): a syntax error is
reported as `invalid template in rule '<name>': throttle.key: ...`, an unknown
filter, test or function as `invalid template in rule '<name>': throttle.key
render: ...`, for enabled and disabled rules alike. A key whose rendering fails
at runtime because of the event's values (e.g. `{{ port + 1 }}` with a string
`port`) uses the fallback key `<rule>:error`.

The window is fixed: a key's counter starts with its first alert and expires
`window` later. Without `key`, all alerts of the rule share one counter per
source (default key `{rule}-{source}:global`).

#### Throttling across sources

A rule keeps one throttle cache shared by all its sources (all configured
sources, or those listed in `vl_sources`). Every source that renders the same
key increments the same counter:

- **Default key**: it contains the source name, so each source has its own
  counter. Nothing to configure.
- **Custom key without `{{ vl_source }}`** (e.g. `{{ rule_name }}`,
  `{{ host }}`): the counter is shared by the rule's sources. The same outage
  seen by `vlprod` and `vldev` produces a single alert.
- **Custom key with `{{ vl_source }}`**: each source has its own counter.

```yaml
rules:
  # One alert per host across all sources
  - name: "switch_down"
    query: '_stream:{app="network"} AND "link down"'
    parser:
      regex: '(?P<host>SW-\d+)'
    throttle:
      key: "{{ host }}"
      count: 1
      window: 10m
    notify:
      template: "default_alert"
      destinations: ["mattermost-ops"]

  # One alert per host and per source
  - name: "switch_down_per_source"
    query: '_stream:{app="network"} AND "link down"'
    parser:
      regex: '(?P<host>SW-\d+)'
    throttle:
      key: "{{ vl_source }}-{{ host }}"
      count: 1
      window: 10m
    notify:
      template: "default_alert"
      destinations: ["mattermost-ops"]
```

At startup, valerter logs at INFO level, once per rule, every rule targeting
at least two sources whose custom key does not reference `vl_source`, to make
the shared counter visible. Two rules never share a counter, even when their
keys render the same value.

When a source reconnects after an error, only the counters fed exclusively by
that source are reset; counters another source has contributed to are kept.

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
(`webhook_url`, `url`, `headers`, `bot_token`, SMTP `username`/`password`), in
the source of the webhook `body_template` (never in values rendered from logs,
see [Notifiers](notifiers.md#var-in-body_template)) and
in VictoriaLogs sources (`url`, `basic_auth.username`/`password`, `headers`),
both at daemon startup and by `valerter --validate`. An undefined variable is
an error: they must therefore also be defined when running `--validate`.

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
- `${SLACK_WEBHOOK_URL}`, `${PAGERDUTY_ROUTING_KEY}` - Notification services

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
  -c, --config <CONFIG>            Path to configuration file [default: /etc/valerter/config.yaml]
      --validate                   Validate configuration and exit
      --log-format <LOG_FORMAT>    Log format: text or json [env: LOG_FORMAT=] [default: text]
  -h, --help                       Print help
  -V, --version                    Print version
```

## Validation

Always validate before deploying:

```bash
valerter --validate -c /etc/valerter/config.yaml
```

`--validate` runs every blocking check of the daemon startup, with the same error messages and exit code 1 on failure:

1. **Loading** — YAML syntax, unknown fields, `rules.d/`, `templates.d/` and `notifiers.d/` merge, `${VAR}` substitution in VictoriaLogs source URLs, `basic_auth` and `headers`
2. **Validation** — required fields, regexes, template syntax and [test render](#template-validation) (including `throttle.key`), source names, URLs and headers, `defaults.throttle`, `max_streams` cap, at least one enabled rule
3. **Notifier construction** — every notifier is built: `${VAR}` placeholders in notifier secrets (webhook URLs, headers, bot tokens, SMTP credentials) are resolved, resolved webhook and Mattermost URLs are checked, `body_template_file` is read (size and UTF-8 checked), email addresses, HTTP methods, headers, `chat_ids`, Telegram `parse_mode` and notifier templates (syntax and test render) are checked
4. **Rule destinations** — every rule destination (enabled or not) names a declared notifier
5. **Email body** — templates of enabled rules sent to email destinations define `email_body_html`
6. **Warning** — `mattermost_channel ignored - no mattermost notifier in destinations` is logged when a rule sets `mattermost_channel` without any Mattermost destination (exit code stays 0)

Errors from steps 3 to 5 are all reported in one pass. No daemon, metrics server or network connection is started: VictoriaLogs sources, SMTP servers and webhooks do not need to be reachable.

Because notifiers are built, **every environment variable referenced by a notifier must be defined when running `--validate`**, including in CI (dummy values are fine, nothing is sent). Run it as a user that can read the `body_template_file` files.

On success, a summary is printed on stdout:

```
Configuration is valid: /etc/valerter/config.yaml
  VictoriaLogs sources: 2 [default=http://localhost:9428, prod=https://***@vl.example.com:9428/?***]
  Rules: 3 (2 enabled)
  Templates: 2
  Notifiers: 2 [email-ops=email, mattermost-ops=mattermost]
  Metrics: enabled (port 9090)
```

Source URLs are redacted: credentials are replaced by `***`, the query string by `***` and the fragment is dropped. URLs without such parts are printed unchanged.

## See Also

- [Notifiers](notifiers.md) - Mattermost, Email, Webhook configuration
- [Metrics](metrics.md) - Prometheus metrics reference
- [Architecture](architecture.md) - How Valerter works
