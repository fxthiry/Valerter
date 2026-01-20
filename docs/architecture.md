# Architecture

How Valerter works under the hood.

## Overview

Valerter is a real-time log alerting daemon that streams logs from VictoriaLogs and sends notifications with full log context.

![Pipeline: VictoriaLogs → Parse → Throttle → Template → Notify](../assets/svg/pipeline.svg)

## Project Structure

```
src/
├── main.rs              # Entry point, startup, shutdown
├── lib.rs               # Library root, module re-exports
├── cli.rs               # CLI argument parsing (clap)
├── engine.rs            # RuleEngine - orchestrates rule tasks
├── error.rs             # Error types (thiserror)
├── tail.rs              # VictoriaLogs streaming client
├── parser.rs            # Regex/JSON field extraction
├── throttle.rs          # LRU cache-based rate limiting
├── template.rs          # Jinja2 templating (minijinja)
├── stream_buffer.rs     # UTF-8 safe NDJSON buffering
├── metrics.rs           # Prometheus metrics server
├── config/              # Configuration module
│   ├── mod.rs           # Module root
│   ├── types.rs         # Config, RuleConfig, etc.
│   ├── notifiers.rs     # Notifier-specific configs
│   ├── runtime.rs       # Compiled runtime config
│   ├── validation.rs    # Validation functions
│   ├── env.rs           # Environment variable resolution
│   ├── secret.rs        # SecretString for sensitive values
│   └── tests.rs         # Config tests
└── notify/              # Notification module
    ├── mod.rs           # Module root
    ├── traits.rs        # Notifier async trait
    ├── registry.rs      # NotifierRegistry
    ├── payload.rs       # AlertPayload structure
    ├── queue.rs         # NotificationQueue + Worker
    ├── mattermost.rs    # Mattermost notifier
    ├── email.rs         # Email notifier (SMTP)
    ├── webhook.rs       # Webhook notifier
    └── tests.rs         # Notify tests
```

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

Sends alerts to configured destinations via `NotifierRegistry`:

- **Fan-out:** One alert can go to multiple notifiers in parallel (`join_all`)
- **Retry:** Exponential backoff (500ms → 5s, max 3 retries)
- **Drop Oldest:** If queue is full, oldest alerts are dropped (not newest)
- **Notifier types:** Mattermost, Email (SMTP), Webhook (generic HTTP)
- **Timestamps:** `log_timestamp` (ISO 8601) and `log_timestamp_formatted` (human-readable with timezone)

## Concurrency Model

```
main.rs
    │
    ├── MetricsServer::run() ────────────────► :9090/metrics
    │
    ├── NotificationWorker::run() ───────────► consumes from bounded queue
    │
    └── RuleEngine::run()
            │
            └── JoinSet<()>
                    ├── rule_task("rule-1") ──► tail → parse → throttle → template → queue
                    ├── rule_task("rule-2") ──► tail → parse → throttle → template → queue
                    └── rule_task("rule-N") ──► ...
```

**Key properties:**

- **1 task per rule:** Rules are fully isolated via `JoinSet`
- **Error isolation:** One rule's failure doesn't affect others
- **Panic recovery:** Panicked rules are respawned after 5s delay (`PANIC_RESTART_DELAY`)
- **Graceful shutdown:** All tasks respect the `CancellationToken`
- **Metric:** `valerter_rule_panics_total{rule_name}` tracks panics per rule

## Reconnection Strategy

When VictoriaLogs connection fails:

1. **Exponential backoff:** 1s → 2s → 4s → 8s → ... → 60s (max)
2. **Metric update:** `valerter_victorialogs_up` set to 0 (restored to 1 on successful reconnection)
3. **Reconnection metric:** `valerter_reconnections_total` incremented
4. **On success:** Throttle cache is reset (prevents stale state)

## Notification Queue

Uses Tokio's `broadcast` channel with ring buffer semantics:

- **Capacity:** 100 alerts (constant `DEFAULT_QUEUE_CAPACITY`)
- **Drop Oldest:** When full, oldest alerts are overwritten (native broadcast behavior)
- **Metric:** `valerter_alerts_dropped_total` tracks dropped alerts globally via `RecvError::Lagged(n)`
- **Non-blocking:** Producers never block when queue is full
- **Fan-out:** `NotificationWorker` sends to ALL destinations in parallel via `join_all`

```
RuleEngine (producers)              NotificationWorker (consumer)
    │                                       │
    ├── rule_task ─┐                        │
    ├── rule_task ──┼── broadcast::Sender ──┼── broadcast::Receiver
    └── rule_task ─┘                        │
                                            ▼
                                    NotifierRegistry
                                       ├── mattermost-ops
                                       ├── email-alerts
                                       └── webhook-pagerduty
```

## Fail-Fast Validation

At startup, Valerter validates (in order):

1. **YAML syntax** — Config file is valid YAML
2. **Required fields** — All mandatory fields present
3. **Template syntax** — All templates compile (minijinja)
4. **Notifier config** — URLs, credentials, env vars resolve correctly
5. **Destinations exist** — Rule destinations match notifier names in registry
6. **Email body_html** — Templates used with email destinations have `body_html`
7. **Mattermost channel warning** — Warns if `mattermost_channel` set but no Mattermost notifier in destinations

If any validation fails, Valerter exits immediately with a clear error message.

### Multi-File Configuration

Config can be split across multiple files:

```
/etc/valerter/
├── config.yaml         # Main config (victorialogs, defaults, metrics)
├── rules.d/            # Rules as HashMap (name: config)
├── templates.d/        # Templates as HashMap
└── notifiers.d/        # Notifiers as HashMap
```

Files are loaded alphabetically. Duplicate names across files cause startup failure.

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
