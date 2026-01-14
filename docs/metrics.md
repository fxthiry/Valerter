# Prometheus Metrics

Valerter exposes a `/metrics` endpoint for Prometheus monitoring.

## Configuration

```yaml
metrics:
  enabled: true    # Default: true
  port: 9090       # Default: 9090
```

## Exposed Metrics

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_alerts_sent_total` | `rule_name`, `notifier_name`, `notifier_type` | Alerts sent successfully |
| `valerter_alerts_throttled_total` | `rule_name` | Alerts blocked by throttling |
| `valerter_alerts_passed_total` | `rule_name` | Alerts that passed throttling |
| `valerter_alerts_dropped_total` | `rule_name` | Alerts dropped (queue full) |
| `valerter_alerts_failed_total` | `rule_name`, `notifier_name`, `notifier_type` | Alerts that permanently failed |
| `valerter_logs_matched_total` | `rule_name` | Logs matched by rule (before throttling) |
| `valerter_notify_errors_total` | `rule_name`, `notifier_name`, `notifier_type` | Notification send errors |
| `valerter_parse_errors_total` | `rule_name`, `error_type` | Parsing errors |
| `valerter_reconnections_total` | `rule_name` | VictoriaLogs reconnections |
| `valerter_rule_panics_total` | `rule_name` | Rule task panics (auto-restarted) |
| `valerter_rule_errors_total` | `rule_name` | Fatal rule errors |

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_queue_size` | - | Current notification queue size |
| `valerter_last_query_timestamp` | `rule_name` | Unix timestamp of last successful query |
| `valerter_victorialogs_up` | `rule_name` | VictoriaLogs connection status (1=up, 0=down) |
| `valerter_uptime_seconds` | - | Time since valerter started |
| `valerter_build_info` | `version` | Build information (always 1) |

### Histograms

| Metric | Labels | Description |
|--------|--------|-------------|
| `valerter_query_duration_seconds` | `rule_name` | VictoriaLogs query latency (time to first chunk) |

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

      # VictoriaLogs connection down
      - alert: ValerterVictoriaLogsDown
        expr: valerter_victorialogs_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Valerter lost connection to VictoriaLogs"
          description: "Rule {{ $labels.rule_name }} cannot connect to VictoriaLogs"

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

- `valerter_victorialogs_up` - Connection to VictoriaLogs
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
