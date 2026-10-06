# Configuration Reference

Valerter is configured via a YAML file, typically at `/etc/valerter/config.yaml`.
See [config/config.example.yaml](../config/config.example.yaml) for a complete
annotated example.

This page covers the configuration file itself. Related pages:

- [Templates](templates.md): variables, filters, Markdown bodies, template validation
- [Notifiers](notifiers.md): Mattermost, Telegram, email and webhook notifiers, delivery
- [Operations](operations.md): service, permissions, logs, upgrades, shutdown

## Configuration file

| Location | Description |
|----------|-------------|
| `/etc/valerter/config.yaml` | Default location (systemd) |
| Custom path via `-c` flag | `valerter -c /path/to/config.yaml` |

The file holds secrets (webhook URLs, tokens, passwords). The Debian package
installs it owned by `root:valerter` with mode `640`, in a directory with mode
`750`: the service reads it, other users cannot (see
[Files and permissions](operations.md#files-and-permissions)).

## Multi-file configuration

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

### Format in `.d/` files

Files in `.d/` directories use a **map format** where the name is the YAML key:

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
  title: "Security: {{ rule_name }} on {{ vl_source }}"
  body: "{{ _msg }}"
  email_body_html: "<p>{{ _msg }}</p>"
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

### Loading rules

- **Files processed:** `*.yaml` and `*.yml` only
- **Order:** Files are read in alphabetical order of their path. Rules keep a
  stable order on every load: the rules of `config.yaml` in their declared order,
  then the rules of `rules.d/` sorted by file path, then by rule name within a
  file (not by declaration order in the file)
- **Hidden files:** Files starting with `.` are ignored
- **Empty files:** Silently skipped
- **Name uniqueness:** Names must be unique across `config.yaml` and all `.d/` files
- **Cross-references:** Rules in `.d/` can reference templates in `config.yaml` and vice versa

### Collision detection

If the same name is defined in two files, the configuration is refused at
startup and by `valerter --validate` (exit code 1), with an explicit error:

```
ERROR valerter: Failed to load configuration error=duplicate rule name 'auth_failure': defined in 'rules.d/extra.yaml' and 'rules.d/security.yaml'
```

The message has the same form for templates and notifiers (`duplicate template
name '...'`, `duplicate notifier name '...'`), whether the collision is between
`config.yaml` and a `.d/` file or between two files of the same `.d/` directory
(the first file in alphabetical order is cited first).

## Structure overview

```yaml
victorialogs:    # VictoriaLogs sources (REQUIRED, at least one)
metrics:         # Prometheus metrics (optional, enabled on port 9090 by default)
notifiers:       # Named notification channels (REQUIRED, at least one)
defaults:        # Default throttle, timestamp timezone and stream cap (REQUIRED)
templates:       # Message templates (REQUIRED)
rules:           # Alert rules (REQUIRED, at least one enabled)
```

[Templates](templates.md) and [notifiers](notifiers.md) have their own pages.

## VictoriaLogs sources

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
the field to fan out across every configured source. Source names must match
`^[a-zA-Z0-9_]+$`. The current source name is available as `{{ vl_source }}`
in every template and in `throttle.key` (see [Templates](templates.md)).

### Reverse proxy

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

Disabled rules do not contribute. Breaching the cap fails the configuration at
load time (and `valerter --validate`) with a message stating both the actual
count and the cap (`defaults.max_streams exceeded: N stream(s) required by
enabled rules > cap of M`), so an operator knows whether to raise the cap or
trim rules. Default: `50`. `max_streams: 0` is refused
(`defaults.max_streams must be >= 1`).

### Timestamp timezone

The `timestamp_timezone` setting controls the timezone of `{{ log_timestamp_formatted }}` in notifier templates and of the Mattermost footer.

| Value | Example Output |
|-------|----------------|
| `UTC` (default) | `15/01/2026 10:00:00 UTC` |
| `Europe/Paris` | `15/01/2026 11:00:00 CET` (winter) / `CEST` (summer) |
| `America/New_York` | `15/01/2026 05:00:00 EST` |

Uses [IANA timezone names](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones). Invalid timezone will fail at startup.


## Metrics

```yaml
metrics:
  enabled: true    # Default: true
  port: 9090       # Default: 9090
```

The Prometheus endpoint is served on `http://<host>:<port>/metrics` while the
daemon runs (never by `--validate`). The section is optional: without it,
metrics are enabled on port 9090. See [Metrics](metrics.md) for the exposed
series.

## Templates

```yaml
templates:
  default_alert:
    title: "{{ rule_name }}"                 # REQUIRED
    body: "{{ _msg }}"                       # REQUIRED
    email_body_html: "<p>{{ _msg }}</p>"     # REQUIRED for email destinations (text bodies)
    accent_color: "#ff0000"                  # Optional: hex color
    body_format: text                        # Optional: text (default) or markdown
```

Variables, filters, Markdown bodies and the checks applied to templates are
described in [Templates](templates.md).

## Rules

Alert rules define what logs to monitor and how to process them.

```yaml
rules:
  - name: "high_cpu_alert"           # REQUIRED: unique name
    enabled: true                     # Default: true (at least one rule must be enabled)
    query: '_stream:{app="node"} | unpack_json | filter cpu:>90'   # REQUIRED: LogsQL

    parser:                           # REQUIRED key, may be empty: parser: {}
      regex: '(?P<level>\S+) (?P<message>.*)'   # Optional, applied to _msg first
      json:                                     # Optional, applied after the regex
        fields: ["host", "cpu"]

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

Pipes that transform or filter each line work as expected: `filter`,
`unpack_json`, `extract`, `extract_regexp`, `format`, `fields`, `rename`,
`math`, `replace`... A filter placed after a pipe goes through the `filter`
pipe and uses the LogsQL comparison syntax: `| unpack_json | filter cpu:>90`
(not `cpu > 90`). See the
[LogsQL reference](https://docs.victoriametrics.com/victorialogs/logsql/).

For aggregation-based alerts ("more than N distinct versions per host"),
run the `stats` query on a schedule with [vmalert](https://docs.victoriametrics.com/vmalert/)
and let Valerter alert on individual events instead.

### Parser

The `parser` key is required, but may be empty (`parser: {}`): every field of
the line returned by VictoriaLogs (`_msg`, `_time`, `_stream` and the fields of
the log) is available to templates whatever the parser. A parser adds fields:

- **`regex`**: applied to `_msg` first. Each named capture group
  (`(?P<name>...)`) becomes a field. A line whose `_msg` does not match is
  dropped (counted in `valerter_parse_errors_total{error_type="regex_no_match"}`):
  the regex also acts as a filter.
- **`json.fields`**: applied next, to the fields of the line. Each listed path
  (`data.server.hostname`) is copied to a top-level field named after its last
  segment (`hostname`). A top-level path (`host`) is already available as is;
  a missing path is ignored.

```yaml
parser:
  regex: '(?P<timestamp>\S+) (?P<level>\S+) (?P<message>.*)'
```

```yaml
parser:
  json:
    fields: ["data.server.hostname", "data.status"]
```

A line that is not valid JSON is dropped
(`valerter_parse_errors_total{error_type="invalid_json"}`).

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
templates (syntax, then [test render](templates.md#template-validation)): a syntax error is
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


## Secrets management

### Recommended: direct values

Put secrets directly in the config file, protected by its permissions
(`640 root:valerter`, set by the Debian package):

```yaml
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/abc123def456"
```

For an installation without the package:

```bash
sudo chown root:valerter /etc/valerter/config.yaml
sudo chmod 640 /etc/valerter/config.yaml
```

### Alternative: environment variables

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


## CLI and environment variables

```
valerter [OPTIONS]

Options:
  -c, --config <CONFIG>            Path to configuration file [default: /etc/valerter/config.yaml]
      --validate                   Validate configuration and exit
      --log-format <LOG_FORMAT>    Log format: text or json [env: LOG_FORMAT=] [default: text]
  -h, --help                       Print help
  -V, --version                    Print version
```

These variables are read directly by the process (not substituted in the
configuration):

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Log level: `error`, `warn`, `info` (default), `debug`, `trace`, or per module (`info,valerter::notify=debug`) |
| `LOG_FORMAT` | Log format: `text` (default) or `json`; `--log-format` wins |
| `NO_COLOR` | When set to a non-empty value, text logs have no colors even on a terminal (they never have colors under journald or in a file) |

See [Logs](operations.md#logs) for the format of the logs.

## Validation

Always validate before deploying:

```bash
valerter --validate -c /etc/valerter/config.yaml
```

`--validate` runs every blocking check of the daemon startup, in this order, with the same error messages and exit code 1 on failure:

1. **Loading** — YAML syntax, unknown fields, `rules.d/`, `templates.d/` and `notifiers.d/` merge (name collisions), `${VAR}` substitution in VictoriaLogs source URLs, `basic_auth` and `headers`
2. **Validation** — required fields, regexes, template syntax and [test render](templates.md#template-validation) (including `throttle.key`), source names, URLs and headers, `defaults.throttle`, `max_streams` cap, at least one enabled rule
3. **Notifier construction** — every notifier is built: `${VAR}` placeholders in notifier secrets (webhook URLs, headers, bot tokens, SMTP credentials) are resolved, resolved webhook and Mattermost URLs are checked, `body_template_file` is read (size and UTF-8 checked), email addresses, HTTP methods, headers, `chat_ids`, Telegram `parse_mode`, `format` and notifier templates (syntax and test render) are checked
4. **Rule destinations** — every rule destination (enabled or not) names a declared notifier
5. **Email body** — templates of enabled rules sent to email destinations define `email_body_html`, unless their body is Markdown (`body_format: markdown`)
6. **Warnings** — `mattermost_channel ignored - no mattermost notifier in destinations` is logged when a rule sets `mattermost_channel` without any Mattermost destination, and `Notifier template references unknown variable` when a notifier template reads a variable that does not exist at its level, such as `{{ host }}` instead of `{{ log.host }}` (see [Template validation](templates.md#template-validation)); the exit code stays 0

The daemon runs the same checks at startup, in the same order, before
connecting to anything.

Errors from steps 3 to 5 are all reported in one pass. No daemon, metrics server or network connection is started: VictoriaLogs sources, SMTP servers and webhooks do not need to be reachable.

Because notifiers are built, **every environment variable referenced by a notifier must be defined when running `--validate`**, including in CI (dummy values are fine, nothing is sent). Run it as a user that can read the configuration and the `body_template_file` files: with the Debian package, `root` or a member of the `valerter` group (see [Validating the configuration](operations.md#validating-the-configuration)).

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

- [Templates](templates.md) - Variables, filters, Markdown bodies
- [Notifiers](notifiers.md) - Mattermost, Telegram, email and webhook notifiers
- [Operations](operations.md) - Service, logs, upgrades, shutdown
- [Metrics](metrics.md) - Prometheus metrics reference
- [Architecture](architecture.md) - How Valerter works
