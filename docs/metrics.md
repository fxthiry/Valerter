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
| `valerter_alerts_sent_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Alerts sent successfully |
| `valerter_alerts_throttled_total` | `rule_name`, `vl_source` | Alerts blocked by throttling |
| `valerter_alerts_passed_total` | `rule_name`, `vl_source` | Alerts that passed throttling |
| `valerter_alerts_dropped_total` | - | Alerts dropped (queue full, global counter) |
| `valerter_alerts_failed_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Alerts that permanently failed |
| `valerter_email_recipient_errors_total` | `rule_name`, `vl_source`, `notifier_name` | Email delivery failures per recipient |
| `valerter_lines_discarded_total` | `rule_name`, `vl_source`, `reason` | Log lines discarded (e.g., reason=oversized for lines > 1MB) |
| `valerter_logs_matched_total` | `rule_name`, `vl_source` | Logs matched by rule (before throttling) |
| `valerter_notifier_config_errors_total` | `notifier`, `error_type` | Notifier configuration errors (e.g., env var resolution) |
| `valerter_notify_errors_total` | `rule_name`, `vl_source`, `notifier_name`, `notifier_type` | Notification send errors |
| `valerter_parse_errors_total` | `rule_name`, `vl_source`, `error_type` | Parsing errors |
| `valerter_reconnections_total` | `rule_name`, `vl_source` | VictoriaLogs reconnections |
| `valerter_rule_panics_total` | `rule_name`, `vl_source` | Rule task panics (auto-restarted) |
| `valerter_rule_errors_total` | `rule_name`, `vl_source` | Fatal rule errors |

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_queue_size` | - | Current notification queue size (shared queue, not per-source) |
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

      # Queue filling up
      - alert: ValerterQueueBacklog
        expr: valerter_queue_size > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Valerter notification queue backlog"
          description: "Queue size is {{ $value }}, notifications may be delayed"

      # Rule panics (indicates bugs)
      - alert: ValerterRulePanic
        expr: increase(valerter_rule_panics_total[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Valerter rule {{ $labels.rule_name }} panicked"
          description: "Rule panicked and was auto-restarted. Check logs for details."
```

## Key Metrics to Monitor

### Health

- `valerter_vl_source_up` - Per-source VictoriaLogs reachability (1=connected, 0=disconnected)
- `valerter_uptime_seconds` - Process uptime (detect restarts)

### Performance

- `valerter_queue_size` - Notification backlog
- `valerter_query_duration_seconds` - Query latency

### Alerting Effectiveness

- `valerter_alerts_sent_total` - Successful alerts
- `valerter_alerts_throttled_total` - Throttled alerts (tuning indicator)
- `valerter_alerts_failed_total` - Failed alerts (notifier issues)

### Errors

- `valerter_parse_errors_total` - Log parsing issues
- `valerter_notify_errors_total` - Transient notification errors
- `valerter_rule_panics_total` - Critical: indicates bugs

## See Also

- [Configuration](configuration.md) - Enable/configure metrics
- [Architecture](architecture.md) - How metrics fit into the pipeline
