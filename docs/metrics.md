# Prometheus Metrics

Valerter exposes a `/metrics` endpoint for Prometheus monitoring.

## Configuration

```yaml
metrics:
  enabled: true    # Default: true
  port: 9090       # Default: 9090
```

## Exposed Metrics

> **v2.0.0 — multi-source label.** Every per-rule metric also carries a
> `vl_source` label naming the VictoriaLogs source that produced the event.
> The legacy `valerter_victorialogs_up{rule_name}` gauge is **removed** and
> replaced by `valerter_vl_source_up{vl_source}` (per-source, no `rule_name`).
> Dashboards that grouped by `rule_name` alone now have an extra dimension
> available; alerts that matched on `valerter_victorialogs_up` must move to
> `valerter_vl_source_up`.

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_alerts_sent_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Alerts delivered, once per alert and notifier (an `email` or `telegram` alert delivered to at least one recipient or chat counts once) |
| `valerter_alerts_throttled_total` | `rule_name`, `vl_source` | Alerts blocked by throttling |
| `valerter_alerts_passed_total` | `rule_name`, `vl_source` | Alerts that passed throttling |
| `valerter_alerts_dropped_total` | - | Deliveries dropped because a destination queue was full, summed over every destination (an alert dropped for two destinations counts twice) |
| `valerter_alerts_failed_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Alerts that permanently failed, once per alert and notifier: retries exhausted, non-retryable response, every recipient or chat failed, template render error at send time, or a notifier panic during the send |
| `valerter_alerts_truncated_total` | `notifier_type`, `notifier_name` | Alerts whose message was truncated to fit the notifier length limit (Telegram: 4096 codepoints), once per alert. Initialized to 0 for every `telegram` notifier |
| `valerter_destination_alerts_dropped_total` | `notifier_name`, `notifier_type` | Alerts dropped because the queue of this destination was full (oldest alert dropped). Initialized to 0 for every notifier |
| `valerter_email_recipient_errors_total` | `rule_name`, `vl_source`, `notifier_name` | Email delivery failures, one unit per failed recipient |
| `valerter_lines_discarded_total` | `rule_name`, `vl_source`, `reason` | Log lines discarded, one unit per line. `reason="oversized"`: line longer than 1 MiB, dropped whole (its remaining bytes are skipped up to the next `\n`); `reason="invalid_utf8"`: line that is not valid UTF-8. In both cases the other lines of the stream are kept |
| `valerter_logs_matched_total` | `rule_name`, `vl_source` | Logs matched by rule (before throttling) |
| `valerter_notify_errors_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Permanent notification failures, counted like `valerter_alerts_failed_total` (once per alert and notifier, render errors included), plus `notifier_type="unknown"` for a destination missing from the registry. Transient errors that a retry recovers from are not counted |
| `valerter_parse_errors_total` | `rule_name`, `vl_source`, `error_type` | Parsing errors: `error_type="invalid_json"` (any rule) or `error_type="regex_no_match"` (rules with a regex parser) |
| `valerter_reconnections_total` | `rule_name`, `vl_source` | VictoriaLogs reconnections after a failure: connection error, HTTP error response or error while reading the stream. Clean stream ends are counted in `valerter_stream_ends_total` |
| `valerter_rule_panics_total` | `rule_name`, `vl_source` | Rule task panics. The task is auto-restarted with exponential backoff (5 s to 5 min), never abandoned: a steady increase means a task panicking in a loop |
| `valerter_rule_errors_total` | `rule_name`, `vl_source` | Fatal rule errors |
| `valerter_stream_ends_total` | `rule_name`, `vl_source` | Clean VictoriaLogs stream ends (EOF without error), each followed by a reconnection. Not a failure: a proxy closing idle streams makes it grow |
| `valerter_telegram_chat_errors_total` | `rule_name`, `vl_source`, `notifier_name` | Telegram delivery failures, one unit per failed chat. A chat delivered through the plain-text fallback is not a failure |

### Series initialized at startup

Every series is created at 0 when valerter starts, with exactly the labels it
is emitted with, so `rate()` and `increase()` work from the first event:

- per `(enabled rule, resolved source)` pair: the `rule_name`, `vl_source`
  counters above, `valerter_lines_discarded_total` for both reasons,
  `valerter_parse_errors_total` for each possible `error_type`,
  `valerter_last_query_timestamp` and `valerter_query_duration_seconds`;
- per `(enabled rule, resolved source, rule destination)` triplet:
  `valerter_alerts_sent_total`, `valerter_notify_errors_total`,
  `valerter_alerts_failed_total`, plus `valerter_email_recipient_errors_total`
  or `valerter_telegram_chat_errors_total` for an `email` or `telegram`
  destination. A notifier used by no enabled rule gets none of these series;
- per notifier: `valerter_destination_queue_size`,
  `valerter_destination_alerts_dropped_total`, and
  `valerter_alerts_truncated_total` for a `telegram` notifier;
- per declared source: `valerter_vl_source_up`.

Notifier configuration errors (such as an undefined `${VAR}`) have no metric:
they stop valerter at startup, before the metrics endpoint opens, with an
ERROR log and exit code 1.

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_queue_size` | - | Pending deliveries summed over every destination queue (an alert waiting for two destinations counts twice). Each destination queue holds at most 100 alerts, so this sum can reach 100 × number of notifiers |
| `valerter_destination_queue_size` | `notifier_name`, `notifier_type` | Alerts pending in the queue of this destination (0 to 100). Initialized to 0 for every notifier |
| `valerter_last_query_timestamp` | `rule_name`, `vl_source` | Unix timestamp of last successful query chunk |
| `valerter_vl_source_up` | `vl_source` | Per-source VictoriaLogs reachability (1=connected, 0=disconnected). Replaces v1.x `valerter_victorialogs_up{rule_name}`. |
| `valerter_uptime_seconds` | - | Time since valerter started |
| `valerter_build_info` | `version` | Build information (always 1) |

### Histograms

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_query_duration_seconds` | `rule_name`, `vl_source` | VictoriaLogs query latency (time to first chunk) |

### Reconnect Backoff Jitter

Reconnect attempts apply `±10%` uniform jitter per `(rule, source)` task on top
of the existing exponential backoff (1s base, 60s cap). When `N` sources behind
a flapping load balancer would otherwise reconnect in lock-step, the jitter
spreads attempts in a `[0.9·D, 1.1·D]` window so the herd dissolves over a few
cycles. The jitter is hardcoded (not configurable in v2.0.0) and never drops
the effective delay below 100ms.

## Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'valerter'
    static_configs:
      - targets: ['localhost:9090']
```

## Example Alerting Rules

Monitor Valerter itself with these Prometheus alerting rules:

```yaml
groups:
  - name: valerter
    rules:
      # Valerter not querying VictoriaLogs for 5 minutes
      - alert: ValerterNotQuerying
        expr: time() - valerter_last_query_timestamp > 300
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Valerter rule {{ $labels.rule_name }} not querying"
          description: "No queries received from rule {{ $labels.rule_name }} for over 5 minutes"

      # VictoriaLogs source unreachable (per-source gauge, v2.0.0)
      - alert: ValerterVlSourceDown
        expr: valerter_vl_source_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Valerter disconnected from VictoriaLogs source {{ $labels.vl_source }}"
          description: "Source {{ $labels.vl_source }} is unreachable. Check network and VictoriaLogs health."

      # Alerts failing to send
      - alert: ValerterAlertsFailing
        expr: rate(valerter_alerts_failed_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Valerter alerts failing for {{ $labels.notifier_name }}"
          description: "Alerts are failing to send via {{ $labels.notifier_type }} notifier"

      # Too many alerts throttled (potential tuning needed)
      - alert: ValerterHighThrottleRate
        expr: rate(valerter_alerts_throttled_total[1h]) > 100
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "High throttle rate on rule {{ $labels.rule_name }}"
          description: "Consider adjusting throttle settings if this is unexpected"

      # A destination queue filling up (each queue holds at most 100 alerts).
      # Do not put an absolute threshold on valerter_queue_size: it is a sum
      # over every destination and can reach 100 x number of notifiers.
      - alert: ValerterQueueBacklog
        expr: max by (notifier_name) (valerter_destination_queue_size) > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Valerter queue backlog for {{ $labels.notifier_name }}"
          description: "{{ $value }} alerts pending for {{ $labels.notifier_name }}, its notifications are delayed"

      # A destination dropping alerts (queue full)
      - alert: ValerterAlertsDropped
        expr: rate(valerter_destination_alerts_dropped_total[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Valerter dropping alerts for {{ $labels.notifier_name }}"
          description: "The queue of {{ $labels.notifier_name }} is full: its oldest alerts are dropped"

      # Rule panics (indicates bugs). Panicked tasks are restarted forever
      # with a 5 s to 5 min backoff, so a looping panic shows up here.
      - alert: ValerterRulePanic
        expr: increase(valerter_rule_panics_total[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Valerter rule {{ $labels.rule_name }} panicked on {{ $labels.vl_source }}"
          description: "{{ $value }} panics in the last hour; the task is auto-restarted with backoff. Check logs for 'Rule task panicked - CRITICAL'."
```

## Key Metrics to Monitor

### Health

- `valerter_vl_source_up` - Per-source VictoriaLogs reachability (1=connected, 0=disconnected)
- `valerter_uptime_seconds` - Process uptime (detect restarts)

### Performance

- `valerter_destination_queue_size` - Notification backlog per destination (`valerter_queue_size` for the total)
- `valerter_query_duration_seconds` - Query latency

### Alerting Effectiveness

- `valerter_alerts_sent_total` - Successful alerts
- `valerter_alerts_throttled_total` - Throttled alerts (tuning indicator)
- `valerter_alerts_failed_total` - Failed alerts (notifier issues)

### Errors

- `valerter_parse_errors_total` - Log parsing issues
- `valerter_notify_errors_total` - Permanent notification failures (after retries, or not retryable)
- `valerter_email_recipient_errors_total` / `valerter_telegram_chat_errors_total` - Recipients or chats that missed an alert other targets received
- `valerter_rule_panics_total` - Critical: indicates bugs

## See Also

- [Configuration](configuration.md) - Enable/configure metrics
- [Architecture](architecture.md) - How metrics fit into the pipeline
