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
    ├── queue.rs         # Per-destination queues + delivery workers
    ├── mattermost.rs    # Mattermost notifier
    ├── email.rs         # Email notifier (SMTP)
    ├── webhook.rs       # Webhook notifier
    └── tests.rs         # Notify tests
```

## Pipeline Stages

### 1. Tail (Streaming)

Valerter connects to VictoriaLogs' `/select/logsql/tail` endpoint via HTTP streaming. Unlike polling-based approaches:

- **Real-time:** Logs arrive within seconds of being ingested
- **Efficient:** Single long-lived connection per `(rule, source)` pair
- **Resilient:** Automatic reconnection with exponential backoff
- **Multi-source:** Each rule fans out to every configured `victorialogs.<name>` source (or to a named subset via `vl_sources:`), with one task per pair so an unhealthy source never blocks others.

### 2. Parse

Extracts structured fields from log lines:

- **JSON Parser:** Extracts specified fields from JSON logs
- **Regex Parser:** Uses named capture groups (`(?P<field>...)`)

If parsing fails, the error is logged and the line is skipped (no crash).

### 3. Throttle

Prevents alert spam using a fixed window per key:

- **Per-key grouping:** Throttle by extracted field (e.g., `{{ host }}`)
- **Configurable limits:** `count` alerts per `window` duration
- **Fixed window:** a key's counter starts with its first event and expires `window` later, whatever happened in between (it does not slide with later events)
- **Per-rule cache:** one cache per rule, shared by all its sources. Sources rendering the same key share its counter (`{{ rule_name }}` dedups across sources); the default key `<rule>-<source>:global` contains the source, so default buckets stay per source
- **Cache reset:** On VictoriaLogs reconnection after an error, only the keys fed exclusively by the reconnecting source are cleared; keys another source has contributed to are kept

### 4. Template

Renders the final message using Jinja2 templates (via minijinja):

- **Variables:** Extracted fields + built-in (`rule_name`, `_msg`, etc.)
- **Filters:** `default`, `upper`, `lower`, `length`, etc.
- **Fallback:** On render error, sends a fallback message (never drops alerts)

### 5. Notify

Sends alerts to configured destinations via `NotifierRegistry`:

- **Fan-out:** One alert can go to multiple notifiers; it is queued once per destination
- **Per-destination delivery:** each notifier has its own queue (exactly 100 alerts) and its own delivery task, so a slow, unavailable or saturated destination only delays or loses its own alerts
- **Order:** alerts are delivered in arrival order per destination (FIFO per destination, not globally)
- **Retry:** Exponential backoff (500ms → 5s, max 3 retries)
- **Drop Oldest:** If a destination queue is full, its oldest alert is dropped (not the newest), for that destination only
- **Panic isolation:** a notifier panic is logged (`Notifier panicked while sending alert`), counted as a failed delivery, and the destination moves on to its next alert
- **Notifier types:** Mattermost, Email (SMTP), Webhook (generic HTTP)
- **Timestamps:** `log_timestamp` (ISO 8601) and `log_timestamp_formatted` (human-readable with timezone)

## Concurrency Model

```
main.rs
    │
    ├── MetricsServer::run() ────────────────► :9090/metrics
    │
    ├── NotificationWorker::run()
    │       │
    │       └── JoinSet<()>
    │               ├── destination task("mattermost-ops") ──► its own bounded queue → send
    │               ├── destination task("email-alerts")   ──► its own bounded queue → send
    │               └── destination task("<notifier>")     ──► ...
    │
    │
    └── RuleEngine::run()
            │
            └── JoinSet<()>
                    ├── rule_task("rule-1", "vlprod") ──► tail → parse → throttle → template → queue
                    ├── rule_task("rule-1", "vldev")  ──► tail → parse → throttle → template → queue
                    ├── rule_task("rule-2", "vlprod") ──► tail → parse → throttle → template → queue
                    └── rule_task("rule-N", "<source>") ──► ...

        rule_task("rule-1", "vlprod") ─┐
                                       ├──► ThrottleStore("rule-1")  (one per rule, shared by its sources)
        rule_task("rule-1", "vldev")  ─┘
```

**Key properties:**

- **1 task per `(rule, source)` pair:** rules and sources are both fully isolated via `JoinSet`. A rule with `vl_sources: [a, b]` against a config defining sources `{a, b, c}` spawns 2 tasks; a rule with no `vl_sources` spawns N (one per configured source).
- **Error isolation:** one task's failure doesn't affect others — neither sibling sources of the same rule, nor sibling rules of the same source.
- **Shared throttle state:** each task has its own parser and stream connection, but the throttle cache belongs to the rule and is shared by its tasks. It survives a task respawn after panic, so a panic does not let a burst of duplicates through.
- **Panic recovery:** a panicked task is respawned with the same `(rule, source)` spawn context (source config, shared throttle store) after a delay that grows per consecutive panic: 5 s, doubled each time, capped at 5 min (`PANIC_RESTART_BASE_DELAY`, `PANIC_RESTART_MAX_DELAY`). A task that ran 10 min without panicking starts over at 5 s (`PANIC_STABLE_RUN_RESET`). The delay is spent inside the respawned task, not in the supervision loop: the other tasks stay supervised, a shutdown ends the wait at once without restarting the task, and a task waiting for its restart counts as active. Restarts are unlimited, a `(rule, source)` pair is never abandoned (`Respawning rule-source task after panic delay` logs `delay_secs` and `consecutive_panics`, then `Rule-source task respawned after panic` once the delay is over).
- **Graceful shutdown:** on SIGTERM/SIGINT, all rule tasks are cancelled through the shared `CancellationToken`; only once they have all stopped (`All rule tasks stopped`) does `main` cancel the separate drain token of the notification worker, which then drains its queues within 20 s (see [Notification Queue](#notification-queue)). A second SIGTERM/SIGINT, in any phase of the shutdown, logs `Second shutdown signal received, forcing immediate exit` and exits at once with code 1
- **No silent exit:** the engine returns `Ok` only after a shutdown request (SIGINT/SIGTERM). If no task can be spawned (`No enabled rules found, engine will exit`) or every task ends without a shutdown request (`All rule tasks completed unexpectedly`), it logs at ERROR and returns an error. `main` then cancels the shared token and drains the (usually empty) notification queues right away, instead of waiting for a timeout, and the process exits with code 1, so the shipped systemd unit (`Restart=on-failure`) restarts it and `systemctl status` shows it as failed. Exit code 0 means a requested shutdown and is never restarted.
- **Metric:** `valerter_rule_panics_total{rule_name, vl_source}` counts panics per `(rule, source)` task and keeps growing while a task panics in a loop: alert on its increase. Panics do not count in `valerter_rule_errors_total` (fatal errors only).
- **Delivery isolation:** one delivery task per notifier, each consuming its own queue sequentially (the next alert is taken once the current send, retries included, is over). Destinations progress independently: an endpoint that times out never delays the others.

## Reconnection Strategy

When VictoriaLogs connection fails:

1. **Cause logged first:** `Connection failed`, `Stream read error` or `HTTP error from VictoriaLogs` is logged with the error, then `Connection failed, retrying` with the attempt number and the delay in milliseconds (`delay_ms`), all before the wait starts
2. **Exponential backoff:** 1s → 2s → 4s → 8s → ... → 60s (max), with ±10% jitter
3. **Metric update:** `valerter_victorialogs_up` set to 0 (restored to 1 on successful reconnection)
4. **Reconnection metric:** `valerter_reconnections_total` incremented
5. **On success:** the throttle keys fed only by this source are reset (prevents stale state); keys shared with the rule's other sources are kept

When the server ends the response cleanly (EOF without error), this is not a failure: the throttle cache is kept and the tail is reopened after ~1s if the connection received data. If the server keeps closing the stream without sending anything, the delay grows with the number of consecutive empty EOFs: ~1s, then 2s, 4s, ... up to 60s, and drops back to ~1s as soon as a connection receives data.

## Notification Queue

`NotificationQueue` is a router over one bounded queue per notifier of the registry:

- **Capacity:** exactly 100 alerts **per destination** (constant `DEFAULT_QUEUE_CAPACITY`, no rounding), so at most 100 × number of notifiers alerts are pending overall
- **Routing:** `send` puts the alert (shared via `Arc`, not copied) in the queue of each of its destinations; a destination unknown to the registry is logged and counted (`notifier_type="unknown"`)
- **Drop Oldest:** when a destination queue is full, its oldest alert is dropped; `valerter_alerts_dropped_total` and `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}` are incremented at once, and the destination task logs `Queue full, dropping N oldest alerts` (fields `dropped_count`, `notifier`) when it takes its next alert
- **Non-blocking:** producers never block, even when a destination queue is full
- **Delivery:** `NotificationWorker` runs one task per destination, each delivering its alerts one by one in arrival order (FIFO per destination)
- **Panic isolation:** a panic during a send is caught, logged and counted in `valerter_notify_errors_total` / `valerter_alerts_failed_total`; the destination continues with its next alert
- **Shutdown drain:** the worker has its own drain token, cancelled by `main` once every rule task has stopped, so no alert can be queued anymore. Each destination task then finishes its in-flight send (retries included), delivers the alerts still in its queue in order until it is empty, and closes its queue (further sends fail with `notification queue closed`). Destinations drain in parallel: a slow one does not hold back the others. An empty queue does not delay the exit
- **Drain deadline:** `main` waits at most 20 s for the drain (constant `SHUTDOWN_DRAIN_TIMEOUT`, not configurable), counted once the rule tasks have stopped. It logs `Waiting for notification worker to drain queue...` (field `queued`), then either `Notification queue drained`, or, when the deadline expires, aborts the worker and logs the WARN `Shutdown drain timeout reached, alerts not delivered` with `undelivered` = alerts left in all queues (an interrupted in-flight send is not counted). The process still exits with code 0
- **Shutdown budget:** stopping the rule tasks + 20 s of drain + 2 s for the metrics server fits in the `TimeoutStopSec=30` of the shipped systemd unit (about 27 s at worst). Container runtimes must allow as much: `docker stop --stop-timeout 30`, or `stop_grace_period: 30s` in Compose (Docker's default of 10 s kills the process before the drain ends). A second SIGTERM/SIGINT skips the drain and exits immediately with code 1

```
RuleEngine (producers)        NotificationQueue (router)       Destination tasks
    │                                │
    ├── rule_task ─┐                 ├── queue[mattermost-ops]  ──► task ──► mattermost-ops
    ├── rule_task ──┼── send() ──────┼── queue[email-alerts]    ──► task ──► email-alerts
    └── rule_task ─┘                 └── queue[webhook-pager]   ──► task ──► webhook-pager
```

## Fail-Fast Validation

At startup, Valerter validates (in order):

1. **YAML syntax** — Config file is valid YAML
2. **Required fields** — All mandatory fields present, at least one notifier, one template and one **enabled** rule (a config whose rules are all `enabled: false` is refused)
3. **Template syntax** — All templates compile (minijinja)
4. **Notifier config** — URLs, credentials, env vars resolve correctly
5. **Destinations exist** — Rule destinations match declared notifier names
6. **Email template body** — Templates used with email destinations have `email_body_html`
7. **Mattermost channel warning** — Warns if `mattermost_channel` set but no Mattermost notifier in destinations

If any validation fails, Valerter exits with a clear error message and exit code 1. Steps 4 to 7 form the preflight (`src/preflight.rs`): all of its stages are evaluated before exiting, so every notifier, destination and email template error is reported in one pass, and a notifier that failed to build is not reported as an unknown destination.

`valerter --validate` runs this exact sequence (same code, same messages, same exit code) and then prints a summary instead of starting the engine, the notification worker and the metrics server. It makes no network call.

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
Rule tasks ──────────┐
                     ├──► metrics::counter!() ──► Prometheus Recorder ──► /metrics
Destination tasks ───┘
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
- **HTML escaping:** `email_body_html` templates auto-escape variables (XSS prevention)
- **TLS verification:** Enabled by default (`tls.verify: true`)
- **No shell execution:** No user input ever reaches a shell

## See Also

- [Configuration](configuration.md) - Configure the pipeline
- [Metrics](metrics.md) - Monitor the pipeline
