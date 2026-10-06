# Architecture

How Valerter works under the hood.

## Overview

Valerter is a real-time log alerting daemon that streams logs from VictoriaLogs and sends notifications with full log context.

![Pipeline: VictoriaLogs → Parse → Throttle → Template → Notify](../assets/svg/pipeline.svg)

## Project Structure

```
src/
├── main.rs              # Entry point: logging, startup, signals, shutdown
├── lib.rs               # Library root, module re-exports
├── cli.rs               # CLI argument parsing (clap)
├── preflight.rs         # Startup checks shared with --validate (notifiers, destinations, email bodies)
├── engine.rs            # RuleEngine: one task per (rule, source), supervision
├── error.rs             # Error types (thiserror)
├── tail.rs              # VictoriaLogs streaming client, reconnection
├── stream_buffer.rs     # UTF-8 safe NDJSON buffering
├── http_body.rs         # Size-limited reading of HTTP error bodies
├── parser.rs            # Regex/JSON field extraction, dotted-key expansion
├── throttle.rs          # Fixed-window rate limiting (moka cache)
├── metrics.rs           # Prometheus metrics server and series inventory
├── template/            # Rule templates
│   ├── mod.rs           # TemplateEngine, RenderedMessage (renderings per format)
│   └── filters.rs       # valerter filters and functions, Markdown auto-escaping
├── markdown/            # Markdown bodies (body_format: markdown)
│   ├── mod.rs           # Restricted tree, escaping
│   ├── parse.rs         # pulldown-cmark events → tree
│   └── render.rs        # plain, markdown, html, telegram_html renderings
├── config/              # Configuration
│   ├── mod.rs           # Module root, loading of config.yaml and .d/ files
│   ├── types.rs         # Config, RuleConfig, TemplateConfig, ...
│   ├── notifiers.rs     # Notifier configurations
│   ├── runtime.rs       # Compiled runtime config
│   ├── validation.rs    # Template test render, color and query checks
│   ├── env.rs           # ${VAR} resolution
│   └── secret.rs        # SecretString for sensitive values
└── notify/              # Notification
    ├── mod.rs           # Module root
    ├── traits.rs        # Notifier async trait
    ├── registry.rs      # NotifierRegistry
    ├── payload.rs       # AlertPayload (rendered message, log fields)
    ├── queue.rs         # Per-destination queues + delivery workers
    ├── notifier_template.rs  # Notifier templates (body_template, subject_template)
    ├── mattermost.rs    # Mattermost notifier
    ├── email.rs         # Email notifier (SMTP)
    ├── webhook.rs       # Webhook notifier
    └── telegram.rs      # Telegram notifier
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

Renders the message with Jinja2 templates (via minijinja), at two levels (see
[Templates](templates.md)):

- **Rule template**, once per alert: `title`, `body` and `email_body_html`, from
  the event fields, `rule_name` and `vl_source`. A rule template that fails to
  render is replaced by a fallback message (`Template render failed: ...`), so
  the alert is still sent.
- **Markdown body:** with `body_format: markdown`, `body` is a Markdown source,
  parsed and rendered once per output format used by the destinations
  (`plain`, `markdown`, `html`, `telegram_html`), the rendering being shared by
  the destinations of the alert.
- **Notifier templates**, at send time, per destination: `body_template` and
  `subject_template`, which see the rendered message and the event fields under
  `log`. A notifier template that fails to render is a permanent failure for
  that destination (nothing is sent, the failure is counted).
- **Filters:** the built-in filters of minijinja, plus `md_escape`,
  `mdv2_escape`, `code`, `codeblock` and the `md_link` function.

### 5. Notify

Sends alerts to configured destinations via `NotifierRegistry`:

- **Fan-out:** One alert can go to multiple notifiers; it is queued once per destination
- **Per-destination delivery:** each notifier has its own queue (exactly 100 alerts) and its own delivery task, so a slow, unavailable or saturated destination only delays or loses its own alerts
- **Order:** alerts are delivered in arrival order per destination (FIFO per destination, not globally)
- **Retry:** Exponential backoff, max 3 attempts: 500ms → 5s for Mattermost, webhook and Telegram, 1 s → 30 s for email
- **Drop Oldest:** If a destination queue is full, its oldest alert is dropped (not the newest), for that destination only
- **Panic isolation:** a notifier panic is logged (`Notifier panicked while sending alert`), counted as a failed delivery, and the destination moves on to its next alert
- **Notifier types:** Mattermost, Email (SMTP), Webhook (generic HTTP), Telegram
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
- **Graceful shutdown:** on SIGTERM/SIGINT, all rule tasks are cancelled through the shared `CancellationToken`; only once they have all stopped (`All rule tasks stopped`) does `main` cancel the separate drain token of the notification worker, which then drains its queues (see [Notification Queue](#notification-queue) and, for the operator's view, [Shutdown and alert drain](operations.md#shutdown-and-alert-drain))
- **No silent exit:** the engine returns `Ok` only after a shutdown request (SIGINT/SIGTERM). If no task can be spawned (`No enabled rules found, engine will exit`) or every task ends without a shutdown request (`All rule tasks completed unexpectedly`), it logs at ERROR and returns an error; `main` drains the (usually empty) queues right away and exits with code 1 (see [Exit codes](operations.md#exit-codes)).
- **Metric:** `valerter_rule_panics_total{rule_name, vl_source}` counts panics per `(rule, source)` task and keeps growing while a task panics in a loop: alert on its increase. Panics do not count in `valerter_rule_errors_total` (fatal errors only).
- **Delivery isolation:** one delivery task per notifier, each consuming its own queue sequentially (the next alert is taken once the current send, retries included, is over). Destinations progress independently: an endpoint that times out never delays the others.

## Reconnection Strategy

When VictoriaLogs connection fails:

1. **Cause logged first:** `Connection failed`, `Stream read error` or `HTTP error from VictoriaLogs` is logged with the error, then `Connection failed, retrying` with the attempt number and the delay in milliseconds (`delay_ms`), all before the wait starts
2. **Exponential backoff:** 1s → 2s → 4s → 8s → ... → 60s (max), with ±10% jitter
3. **Metric update:** the per-source gauge `valerter_vl_source_up{vl_source}` is set to 0 after 3 consecutive failures of a task (transient errors are debounced), and restored to 1 on successful reconnection
4. **Reconnection metric:** `valerter_reconnections_total{rule_name, vl_source}` incremented: it only counts reconnections after a failure (connection error, HTTP error response or error while reading the stream)
5. **On success:** the throttle keys fed only by this source are reset (prevents stale state); keys shared with the rule's other sources are kept. A stream cut by an error (connection reset, truncated chunked body) is a failure too: the next successful connection resets the source's throttle keys the same way

When the server ends the response cleanly (EOF without error), this is not a failure: the throttle cache is kept and the tail is reopened after ~1s if the connection received data. If the server keeps closing the stream without sending anything, the delay grows with the number of consecutive empty EOFs: ~1s, then 2s, 4s, ... up to 60s, and drops back to ~1s as soon as a connection receives data. Clean ends are counted in `valerter_stream_ends_total{rule_name, vl_source}`, not in `valerter_reconnections_total`, so a proxy closing idle streams does not look like a failing source.

## Notification Queue

`NotificationQueue` is a router over one bounded queue per notifier of the registry:

- **Capacity:** exactly 100 alerts **per destination** (constant `DEFAULT_QUEUE_CAPACITY`, no rounding), so at most 100 × number of notifiers alerts are pending overall
- **Routing:** `send` puts the alert (shared via `Arc`, not copied) in the queue of each of its destinations; a destination unknown to the registry is logged and counted (`notifier_type="unknown"`)
- **Drop Oldest:** when a destination queue is full, its oldest alert is dropped; `valerter_alerts_dropped_total` and `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}` are incremented at once, and the destination task logs `Queue full, dropping N oldest alerts` (fields `dropped_count`, `notifier`) when it takes its next alert
- **Non-blocking:** producers never block, even when a destination queue is full
- **Delivery:** `NotificationWorker` runs one task per destination, each delivering its alerts one by one in arrival order (FIFO per destination)
- **Panic isolation:** a panic during a send is caught, logged and counted in `valerter_notify_errors_total` / `valerter_alerts_failed_total`; the destination continues with its next alert
- **Shutdown drain:** the worker has its own drain token, cancelled by `main` once every rule task has stopped, so no alert can be queued anymore. Each destination task then finishes its in-flight send (retries included), delivers the alerts still in its queue in order until it is empty, and closes its queue (further sends fail with `notification queue closed`). Destinations drain in parallel: a slow one does not hold back the others. An empty queue does not delay the exit
- **Drain deadline:** `main` waits at most 20 s for the drain (constant `SHUTDOWN_DRAIN_TIMEOUT`, not configurable), counted once the rule tasks have stopped, then aborts the worker; `undelivered` counts the alerts left in all queues (an interrupted in-flight send is not counted). The metrics server stops as soon as the engine returns, and the teardown of the runtime waits at most 2 s for blocking tasks. Logs, exit codes and the stop timeouts to configure are described in [Operations](operations.md#shutdown-and-alert-drain)

```
RuleEngine (producers)        NotificationQueue (router)       Destination tasks
    │                                │
    ├── rule_task ─┐                 ├── queue[mattermost-ops]  ──► task ──► mattermost-ops
    ├── rule_task ──┼── send() ──────┼── queue[email-alerts]    ──► task ──► email-alerts
    └── rule_task ─┘                 └── queue[webhook-pager]   ──► task ──► webhook-pager
```

## Startup checks

At startup, valerter loads and validates the configuration, then runs the
preflight (`src/preflight.rs`): it builds every notifier, checks that every rule
destination exists and that email destinations get an HTML body. All the
preflight stages are evaluated before exiting, so every error is reported in
one pass. `valerter --validate` runs the same code and prints a summary
instead of starting the engine. The checks and their order are described in
[Validation](configuration.md#validation).

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

## Security

- **Config file:** secrets in plaintext, so the package installs it `640 root:valerter` (see [Files and permissions](operations.md#files-and-permissions))
- **HTML escaping:** `email_body_html` and email body templates auto-escape variables (XSS prevention); Markdown bodies escape every inserted value
- **Secrets in logs:** secret values are never logged, VictoriaLogs source URLs are masked
- **TLS verification:** Enabled by default (`tls.verify: true`)
- **No shell execution:** No user input ever reaches a shell

## See Also

- [Configuration](configuration.md) - Configure the pipeline
- [Templates](templates.md) - Rule and notifier templates
- [Operations](operations.md) - Run the daemon
- [Metrics](metrics.md) - Monitor the pipeline
