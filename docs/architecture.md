# Architecture

How Valerter works under the hood.

## Overview

Valerter is a real-time log alerting daemon that streams logs from VictoriaLogs and sends notifications with full log context.

![Pipeline: VictoriaLogs → Parse → Throttle → Template → Notify](../assets/svg/pipeline.svg)

## Pipeline Stages

### 1. Tail (Streaming)

Valerter connects to VictoriaLogs' `/select/logsql/tail` endpoint via HTTP streaming. Unlike polling-based approaches:

- **Real-time:** Logs arrive within seconds of being ingested
- **Efficient:** Single long-lived connection per rule
- **Resilient:** Automatic reconnection with exponential backoff

Each rule maintains its own streaming connection, providing isolation.

### 2. Parse

Extracts structured fields from log lines:

- **JSON Parser:** Extracts specified fields from JSON logs
- **Regex Parser:** Uses named capture groups (`(?P<field>...)`)

If parsing fails, the error is logged and the line is skipped (no crash).

### 3. Throttle

Prevents alert spam using a sliding window algorithm:

- **Per-key grouping:** Throttle by extracted field (e.g., `{{ host }}`)
- **Configurable limits:** `count` alerts per `window` duration
- **Cache reset:** On VictoriaLogs reconnection, throttle cache is cleared

### 4. Template

Renders the final message using Jinja2 templates (via minijinja):

- **Variables:** Extracted fields + built-in (`rule_name`, `_msg`, etc.)
- **Filters:** `default`, `upper`, `lower`, `length`, etc.
- **Fallback:** On render error, sends a fallback message (never drops alerts)

### 5. Notify

Sends alerts to configured destinations:

- **Fan-out:** One alert can go to multiple notifiers in parallel
- **Retry:** Exponential backoff (500ms → 5s, max 3 retries)
- **Drop Oldest:** If queue is full, oldest alerts are dropped (not newest)

## Concurrency Model

```
main.rs
    │
    ├── MetricsServer (tokio task)
    │
    ├── NotificationWorker (tokio task)
    │       └── consumes from broadcast queue
    │
    └── RuleEngine
            ├── Rule 1 (tokio task) ──► tail → parse → throttle → template → queue
            ├── Rule 2 (tokio task) ──► tail → parse → throttle → template → queue
            └── Rule N (tokio task) ──► ...
```

**Key properties:**

- **1 task per rule:** Rules are fully isolated
- **Error isolation:** One rule's failure doesn't affect others
- **Panic recovery:** Panicked rules are auto-restarted after 5 seconds
- **Graceful shutdown:** All tasks respect the cancellation token

## Reconnection Strategy

When VictoriaLogs connection fails:

1. **Exponential backoff:** 1s → 2s → 4s → 8s → ... → 60s (max)
2. **Metric update:** `valerter_victorialogs_up` set to 0
3. **Reconnection metric:** `valerter_reconnections_total` incremented
4. **On success:** Throttle cache is reset (prevents stale state)

## Notification Queue

Uses Tokio's `broadcast` channel with ring buffer semantics:

- **Capacity:** 100 alerts (configurable via code)
- **Drop Oldest:** When full, oldest alerts are overwritten
- **Metric:** `valerter_alerts_dropped_total` tracks dropped alerts
- **Non-blocking:** Producers never block when queue is full

## Fail-Fast Validation

At startup, Valerter validates:

1. **YAML syntax** - Config file is valid YAML
2. **Required fields** - All mandatory fields present
3. **Template syntax** - All templates compile
4. **Notifier config** - URLs, credentials resolve correctly
5. **Destinations exist** - Rule destinations match notifier names
6. **Email body_html** - Templates used with email have `body_html`

If any validation fails, Valerter exits immediately with a clear error message.

## Metrics Pipeline

```
Rule tasks ─────┐
                ├──► metrics::counter!() ──► Prometheus Recorder ──► /metrics
NotificationWorker ─┘
```

Metrics are emitted throughout the pipeline:
- `valerter_logs_matched_total` - After parsing succeeds
- `valerter_alerts_throttled_total` - When throttle blocks
- `valerter_alerts_sent_total` - After successful notification
- etc.

## Error Handling

**Log+Continue pattern:** Errors in spawned tasks are logged, never propagated up.

```rust
// ✅ CORRECT
match process().await {
    Ok(_) => continue,
    Err(e) => {
        tracing::error!(error = %e, "Processing failed");
        tokio::time::sleep(backoff).await;
    }
}

// ❌ NEVER DO THIS
tokio::spawn(async { process().unwrap(); }); // Silent crash
```

## Security

- **Config file:** `chmod 600` recommended (secrets in plaintext)
- **HTML escaping:** `body_html` templates auto-escape variables (XSS prevention)
- **TLS verification:** Enabled by default (`tls.verify: true`)
- **No shell execution:** No user input ever reaches a shell

## See Also

- [Configuration](configuration.md) - Configure the pipeline
- [Metrics](metrics.md) - Monitor the pipeline
- [project-context.md](../_bmad-output/project-context.md) - Implementation rules for developers
