# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - Unreleased

### Fixed

- **The daemon now exits with code 1 when it no longer watches anything.** When every `(rule, source)` task stopped without a shutdown request, or when the engine started without any task, valerter logged a warning and exited with code 0: the shipped systemd unit (`Restart=on-failure`) did not restart it and `systemctl status` showed a clean `inactive (dead)` while no alert was produced anymore. The engine now returns an error in both cases (`No enabled rules found, engine will exit` / `All rule tasks completed unexpectedly`, same text, now logged at ERROR), the process exits with code 1, the unit shows `failed` and systemd restarts it. Exit code 0 now only follows a requested shutdown (SIGINT/SIGTERM).
- **No more ~7 s wait before exiting after the engine stops.** The shutdown token is now cancelled as soon as the engine returns, whatever the cause, so the notification worker and the metrics server stop at once instead of running until their 5 s and 2 s timeouts.
- **Upgrading the `.deb` no longer leaves the service stopped.** `prerm` no longer stops the service on `upgrade`, and `postinst` restarts it when it is active or enabled, including upgrades from 2.0.3 or earlier whose `prerm` already stopped it. Two seconds after the restart, `postinst` checks that the service is active and otherwise prints a visible warning pointing to `journalctl -u valerter`, without failing `dpkg`. An enabled service that was stopped on purpose is started again by the upgrade; a service that is stopped and disabled stays stopped.
- **Invalid UTF-8 now drops only the faulty line.** Each line of the tail stream is decoded on its own: a line that is not valid UTF-8 is dropped alone, while the other lines of the same network chunk and the pending partial line are kept (2.0.3 dropped the whole batch). `valerter_lines_discarded_total{reason="invalid_utf8"}` now counts one unit per dropped line, and the `Discarding log data with invalid UTF-8` warning is logged at most once per chunk with a `discarded_lines` field.
- **Lines over 1 MiB are dropped whole, without losing their neighbours or emitting a truncated fragment.** The limit now applies to the length of a line, not to the buffer plus the incoming chunk: valid lines received in the same chunk are kept, and the rest of the oversized line is skipped up to its `\n` instead of being forwarded to the parser as a truncated line (which could raise an alert on partial JSON or a misleading `invalid_json`). `valerter_lines_discarded_total{reason="oversized"}` is incremented once per line.
- **A VictoriaLogs `url` ending with `/` no longer produces `//select/logsql/tail`.** Trailing slashes are dropped before the tail path is appended.
- **Custom `headers` replace the default and Basic Auth headers instead of duplicating them.** `accept: "application/json"` now yields a single `Accept` header, and a custom `Authorization` replaces the one built from `basic_auth` (see Changed).
- **An invalid header name or value now fails the (rule, source) task at startup** with an error naming the header (never its value), instead of an endless reconnection loop that never sent a request. Such headers are now refused when the configuration is loaded (see Changed); this is a defensive guard for the runtime path.
- **The cause of a connection failure is logged before the backoff wait.** `Connection failed` / `Stream read error` used to be logged after the sleep (up to 60 s late); they now precede `Connection failed, retrying`.
- **The first empty stream end is followed by a ~1 s delay instead of 2 s.** Consecutive empty EOFs now back off 1 s, 2 s, 4 s... up to 60 s.
- **`throttle.key: "{{ rule_name }}"` now really dedups across sources.** Each `(rule, source)` task had its own throttle cache, so sources never shared a counter and the same outage seen by `vlprod` and `vldev` sent two alerts, contrary to MIGRATION.md and docs/configuration.md. A rule now has one throttle cache shared by all its sources. **Behavior change for multi-source rules with a custom key that does not contain `{{ vl_source }}`** (e.g. `{{ host }}`): their counter is now shared by the rule's sources; add `{{ vl_source }}` to the key to keep one counter per source. The default key `<rule_name>-<vl_source>:global` still isolates sources. The reset on reconnection after an error now only drops the counters fed exclusively by the reconnecting source, and the throttle cache survives a task restart after a panic. See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **docs/architecture.md described the throttle as a sliding window.** It is a fixed window, anchored on the first event of a key.
- **A slow or unavailable notifier no longer blocks the other destinations.** A single worker delivered the alerts one at a time, each alert waiting for every destination of the previous one (retries included): one endpoint that never answered (≈ 31.5 s per alert for an HTTP notifier, up to 60 s per `retry_after` for Telegram) delayed every notifier, then made the queue overwrite alerts meant for healthy channels. Each notifier now has its own queue and its own delivery task: a slow, unavailable or saturated destination only delays or loses its own alerts.
- **A panicking notifier no longer stops all deliveries.** A panic during a send killed the single worker, and every following alert failed with `notification queue closed`. The panic is now caught, logged at ERROR (`Notifier panicked while sending alert`, fields `notifier` and `rule_name`), counted in `valerter_notify_errors_total` and `valerter_alerts_failed_total`, and the destination moves on to its next alert.
- **Stopping or restarting the service no longer loses the queued alerts.** On SIGTERM/SIGINT the notification worker stopped with the rule tasks and dropped every pending alert without a log, and `main` gave the in-flight send only 5 s before cutting it off, so a restart during an incident (package upgrade, configuration change) discarded the most useful alerts. The rule tasks are now stopped first, then every destination finishes its in-flight send (retries included) and delivers the alerts left in its queue, in order, until it is empty. The drain is bounded to 20 s (fixed, not configurable) counted from the end of the rule tasks, and an empty queue exits at once. Logs: `Waiting for notification worker to drain queue...` (field `queued`), then `Notification queue drained`, or, when the deadline expires, the WARN `Shutdown drain timeout reached, alerts not delivered` with `undelivered` (alerts left in the queues); the exit code stays 0.
- **A panicking rule task no longer freezes supervision and shutdown.** After a panic, the engine slept 5 s inside its supervision loop: meanwhile it handled no other task (fatal errors and panics of other `(rule, source)` tasks waited) and ignored a shutdown request, and simultaneous panics added up their delays. The restart delay now runs inside the restarted task: the other tasks stay supervised, a shutdown during the delay cancels the restart at once, and simultaneous panics each wait their own delay. A task waiting for its restart still counts as active, so it never triggers `All rule tasks completed unexpectedly`.
- **A Telegram message rejected in HTML mode is now resent as plain text instead of being lost.** With `parse_mode: HTML`, a 400 from the Bot API (a tag or entity cut by the 4096-codepoint truncation, an unescaped `<` or `&` from a custom `body_template`) abandoned the chat. The same text is now resent once without `parse_mode`, so the alert is delivered with its tags shown literally, and the WARN `Telegram rejected HTML message, resending as plain text` is logged (notifier, rule, chat and status; never the token, the API URL or the text). The resend follows the usual retry policy; a 4xx on the resend fails the chat for good. Other 4xx statuses and `parse_mode: MarkdownV2` keep failing immediately. Truncation itself is unchanged.
- **SMTP errors are classified by reply code instead of by message text.** Any `5xx` reply is now permanent and not retried (`503`, `530`, `541`... used to be retried three times), while `4xx` replies and network, TLS or timeout errors are retried, even when their text mentions `authentication` or contains a number like `550` (a `454 4.7.0 temporary authentication failure` used to be given up at once).
- **The webhook notifier now sends `Content-Type: application/json` by default.** Requests had no `Content-Type` at all, which JSON endpoints (Slack, Discord, PagerDuty, REST APIs) reject or misread. The header is added when `headers` defines no `Content-Type` (whatever its case); a configured `Content-Type` still wins and is not duplicated. Set one explicitly if your endpoint expects another content type.
- **The webhook examples of docs/notifiers.md and config/config.example.yaml now produce valid JSON.** Slack, Discord, PagerDuty and Custom API examples wrote `"{{ body }}"` between quotes, which breaks as soon as a title or body contains a quote, a backslash or a line break; they now use `{{ body | tojson }}` without quotes, the documented way to insert a value in a JSON `body_template`. The PagerDuty example no longer sends a useless `Authorization` header nor a literal `${PAGERDUTY_ROUTING_KEY}` (`${VAR}` is not resolved in `body_template`): the routing key is a placeholder to replace. Rewrite your own JSON templates the same way.
- **The test render of templates no longer refuses valid templates.** Conversions and arithmetic on fields (`{{ status | int }}`, `| float`, `| round`, `| abs`, `| split`, `{{ count + 1 }}`) failed validation because the placeholder values used for the test render are not numbers. The test render now only refuses errors that do not depend on the event's values: syntax errors, unknown filters, tests, functions and methods, and the `/` operator on a field path. Global functions (`range`, `namespace`...) are also accepted again. This applies to templates, `throttle.key`, `subject_template` and `body_template`.
- **The hint for a top-level field containing `/` no longer suggests a syntax that does not exist.** `{{ io/username }}` was answered with `{{ fields["io/username"] }}`, but no `fields` variable exists; the hint now explains that such a field cannot be referenced and suggests renaming it in the rule query (`| rename "io/username" as io_username`, then `{{ io_username }}`).
- **Rules loaded from `rules.d/` now have a stable order.** Their order changed from one run to the next (logs, `--validate` summary, startup order); rules now follow the main file's rules in declared order, then the `rules.d/` rules sorted by file path, then by rule name within a file. Validation errors on templates and notifiers are also listed in alphabetical order of their name.
- **Collisions between two files of the same `.d/` directory use the singular**, like the other collisions: `duplicate rule name '...'` (resp. `template`, `notifier`) instead of `duplicate rules name '...'`.
- **docs/notifiers.md described a Mattermost footer that does not exist.** The footer is `valerter | <rule_name> | <vl_source> | <log_timestamp_formatted>`, not `Log time: <timestamp>`. The "Retry Behavior" section also claimed a 500 ms / 5 s backoff for every notifier: email uses 1 s / 30 s.

### Changed

- **A configuration whose rules are all disabled is now refused.** `Config::validate()` reports `all rules are disabled: enable at least one rule in config.yaml or rules.d/`, so `valerter --validate` flags it and the daemon refuses to start (exit code 1) instead of starting and exiting immediately with code 0. See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **`Connection failed, retrying` now logs the delay in milliseconds (`delay_ms`) instead of whole seconds (`delay_secs`)**, which logged `0` for sub-second delays. Log filters on `delay_secs` must be updated. See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **A custom `Authorization` header now masks `basic_auth`.** Both used to be sent and the server picked one; the custom header now wins and a warning (without any value) is logged at the start of each affected (rule, source) task.
- **`--validate` now runs every startup check.** Besides loading and validating the configuration, it compiles it, builds every notifier (resolving `${VAR}` placeholders in notifier secrets, reading `body_template_file`), checks that every rule destination exists and that templates sent to email destinations define `email_body_html`, and emits the `mattermost_channel ignored` warning, with the same messages and exit code 1 as the daemon. It still starts nothing and makes no network call. **Breaking for CI pipelines that validated without secrets:** environment variables referenced by notifiers must now be defined when running `--validate`. See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **The `--validate` summary gains a `Notifiers: <n> [<name>=<type>, ...]` line** after `Templates`.
- **Stricter configuration validation.** **Breaking: configurations accepted by 2.0.3 can be refused at startup**; run `valerter --validate -c /etc/valerter/config.yaml` with the new binary before upgrading. Refused at load time (`Config::validate()`): `defaults.throttle` with `count: 0` or `window: 0s` (previously a runtime warning; `defaults.throttle.count must be >= 1 ...`, `defaults.throttle.window must be > 0 ...`) and its `key` checked like a rule key (`defaults.throttle.key: ...`, `defaults.throttle.key render: ...`); an unknown filter, test or function in `throttle.key`, for enabled and disabled rules (`invalid template in rule '<rule>': throttle.key render: ...`, previously every event fell back to the key `<rule>:error`); an invalid header name or value in a VictoriaLogs source (`victorialogs.<source>.headers: invalid header name '<name>'` / `invalid value for header '<name>'`, the value is never printed); a source URL that still contains `${` after substitution. Refused when notifiers are built, at startup and by `--validate`: an unknown filter, test or function in a webhook, Telegram or email `body_template` (inline, `body_template_file` or default; `invalid notifier '<name>': body_template render: ...`, previously every send failed); a Telegram `parse_mode` other than `HTML`, `MarkdownV2` or `Markdown` (`parse_mode '<value>' is not supported (expected HTML, MarkdownV2 or Markdown)`, previously an HTTP 400 for every alert); a webhook `url` or Mattermost `webhook_url` whose `${VAR}` resolves to a non-URL or a scheme other than `http`/`https` (`url: invalid URL: ...` / `webhook_url: invalid URL: ...`, the URL is never printed). See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **Telegram `parse_mode` is case-insensitive and sent in canonical form:** `html` is sent as `HTML`, `markdownv2` as `MarkdownV2`.
- **Startup now reports every notifier, destination and email template error in one pass** instead of stopping at the first failed stage (same messages and exit code). A notifier that fails to build is no longer also reported as an unknown destination.
- **The throttle cache bound is now 10,000 keys per source of a rule**, for the rule's shared cache (previously 10,000 per `(rule, source)` task): same total memory budget, still not configurable.
- **The notification queue capacity is exactly 100 alerts per destination.** The single queue announced 100 but held 128 (the channel rounded up to a power of two); there is now one queue per notifier holding exactly 100 alerts, with drop-oldest applied per destination. Up to 100 × number of notifiers alerts can be pending. Delivery order is guaranteed per destination, no longer across destinations.
- **`valerter_queue_size` and `valerter_alerts_dropped_total` now count deliveries summed over every destination queue** (an alert routed to two destinations counts twice). Their names and selectors are unchanged, but **absolute thresholds on `valerter_queue_size` change meaning**: the sum can reach 100 × number of notifiers (128 at most before), so a rule like `valerter_queue_size > 50` no longer means "queue half full". Rewrite it on the new per-destination gauge, e.g. `max(valerter_destination_queue_size) > 50`; `rate(valerter_alerts_dropped_total[...])` alerts keep their meaning. The `Queue full, dropping N oldest alerts` warning gains a `notifier` field. See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **A shutdown can now take up to ~27 s when alerts are queued or an endpoint is slow** (rule tasks + 20 s of drain + 2 s for the metrics server), still within the `TimeoutStopSec=30` of the shipped systemd unit. **The `systemctl restart` run by the Debian `postinst` on upgrade can therefore block `dpkg`/`apt` for up to ~27 s.** Container runtimes need a 30 s stop timeout to benefit from the drain (`docker stop --stop-timeout 30`, `stop_grace_period: 30s`; Docker's default is 10 s). See [MIGRATION.md](MIGRATION.md#upgrading-to-210).
- **A second SIGTERM/SIGINT now forces an immediate exit.** It used to be ignored; whatever the shutdown phase, it now logs the WARN `Second shutdown signal received, forcing immediate exit` and exits at once with code 1, without waiting for the in-flight sends or the drain.
- **Restarts after a panic now back off exponentially.** A `(rule, source)` task that panics is restarted after 5 s, doubled at each consecutive panic up to 5 min, instead of every 5 s forever; a task that ran 10 min without panicking starts over at 5 s. Restarts stay unlimited: a task is never abandoned, and `valerter_rule_panics_total{rule_name, vl_source}` keeps increasing, which is the signal to alert on (see docs/metrics.md). `Respawning rule-source task after panic delay` gains a `consecutive_panics` field and `Rule-source task respawned after panic` is now logged when the delay is over.

### Added

- **Per-destination queue metrics.** `valerter_destination_queue_size{notifier_name, notifier_type}` (alerts pending for a destination, 0 to 100) and `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}` (alerts dropped because its queue was full), both initialized to 0 for every notifier.
- **Startup INFO log for throttle keys shared across sources.** Once per rule targeting at least two sources whose custom throttle key does not reference `vl_source`: `Throttle key does not reference vl_source: its counter is shared across the rule's sources; add {{ vl_source }} to the key to isolate them`, with `rule_name`, `source_count` and `throttle_key` fields. The key is analysed statically (no test render).
- **`Webhook body is not valid JSON` warning.** When the effective `Content-Type` of a webhook is JSON (`application/json` or any `+json` type) and the rendered `body_template` is not valid JSON, a WARN is logged with the notifier and rule names (never the body) and the request is still sent.

### Security

- **`--validate` no longer prints VictoriaLogs source credentials.** The summary showed each source URL after `${VAR}` resolution, so `http://user:secret@vl:9428?token=abc` reached stdout (often captured by CI). Credentials and query strings are now replaced by `***` and fragments dropped (`http://***@vl:9428/?***`); URLs without such parts are printed unchanged.

## [2.0.3] - 2026-08-26

Hardening release driven by a full code review. No new features, no breaking changes.

### Security

- **Webhook and Mattermost URLs no longer leak into logs on network errors.** Both notifiers logged the raw `reqwest::Error`, whose `Display` includes the request URL (i.e. the webhook secret). They now log `error.without_url()` like the Telegram notifier already did.
- **`validate_url` no longer echoes the URL in its error message.** A malformed `webhook_url` used to print the full value (token included) at startup. It also now restricts schemes to `http`/`https`; other schemes were accepted at validation and failed on the first alert.

### Fixed

- **`${ENV_VAR}` placeholders are now resolved in VictoriaLogs sources** (`url`, `basic_auth.username`/`password`, `headers`). This was documented and shown in `examples/multi-source` but never implemented: the literal `${VL_PASS}` was sent to VictoriaLogs, producing a 401 retry loop. An undefined variable is now a load error naming the source.
- **`webhook_url: "${MATTERMOST_WEBHOOK}"` (the documented form) no longer fails validation.** `validate_url` ran before env resolution and rejected the placeholder as an invalid URL. Values containing `${` are skipped at validation and checked after resolution.
- **Invalid UTF-8 in the tail stream no longer kills the rule permanently.** A single bad byte sequence raised `StreamError::Utf8Error`, which the supervisor treated as fatal without respawn: the (rule, source) pair silently stopped alerting until restart. The offending batch is now dropped, logged, and counted in `valerter_lines_discarded_total{reason="invalid_utf8"}`; streaming continues.
- **Clean stream end (HTTP 200 then EOF) no longer resets the throttle cache nor spins.** It was flagged as a failure, so the next connect fired `on_reconnect` → `Throttler::reset()` and let duplicate bursts through; it also reconnected with no delay. A benign EOF now reconnects after the base backoff (growing only while the server keeps closing immediately with no data), keeps throttle state, and increments `valerter_reconnections_total`.
- **Stream buffer is cleared on every (re)connection**, so a partial line from a dead connection is never glued to the first bytes of the new one.
- **HTTP error response body is now read and logged before the backoff sleep**, not after (the v2.0.2 change could log `<empty body>` once the server had closed the connection).
- **HTTP 429 from Mattermost/webhook endpoints is now retried** with backoff instead of being treated as a permanent client error and dropping the alert.
- **`connect_timeout` (10s) added to the tail HTTP client.** A blackholed host previously blocked each attempt for the OS SYN timeout (~2 min).
- **Validation now rejects** duplicate rule names within `config.yaml` (they silently shared throttle keys and metrics), `throttle.count: 0` and `throttle.window: 0s`.

## [2.0.2] - 2026-08-26

Patch release: actionable validation errors for two user-reported configuration pitfalls, plus dependency bumps clearing all open Dependabot alerts. No new features, no breaking changes.

### Fixed

- **Templates referencing fields with `/` in their name now get an actionable validation error** (#41). `{{ ocp.annotations.authentication.openshift.io/username }}` fails in Jinja because `/` is the division operator. `valerter --validate` now appends a hint with the working bracket-notation rewrite (`{{ ocp.annotations.authentication.openshift["io/username"] }}`). Documented in `docs/configuration.md#fields-with-special-characters`.

- **Queries using pipes unsupported by `/tail` are rejected at validation time** (#42). `stats`, `sort`, `top`, `uniq`, `limit`, `offset`, `first`, `last`, `facets`, `join`, `field_names`, `field_values`, `block_stats`, `blocks_count` and `union` need the full result set and are refused by the VictoriaLogs `/tail` endpoint with HTTP 400, which previously showed up as an endless opaque reconnect loop. The rule now fails `--validate` with an explicit message. Documented in `docs/configuration.md#logsql-query-restrictions`.

- **Non-2xx VictoriaLogs responses now log the response body** (truncated to 512 chars) alongside the status code, so the actual server-side error message is visible in `journalctl` instead of a bare `status=400 Bad Request`.

## [2.0.1] - 2026-04-17

Hardening patch after the v2.0.0 release. No new features, no breaking changes. Three fixes bundled into one coherent "post-v2.0.0 durability" release.

### Security

- **Notifier config secrets wrapped in `SecretString`**. `TelegramNotifierConfig.bot_token`, `MattermostNotifierConfig.webhook_url`, `WebhookNotifierConfig.url`, `WebhookNotifierConfig.headers` values, and `SmtpConfig.password` are now `SecretString` rather than raw `String`. A `format!("{:?}", config)` or a tracing context that captures the parsed config renders `[REDACTED]` instead of the actual value. Prior to this, the token lived as a plain `String` until notifier construction time, so any debug-log or error context that carried the config body would leak the secret. A regression-guard unit test (`notifier_config_debug_never_leaks_secrets`) runs canary values through each notifier config's `Debug` output and asserts none appear.

### Fixed

- **Migration error on v1.x configs now points to MIGRATION.md and covers rollback** (D-doc-1). Loading a v1.x `victorialogs.url`-shape config against v2.x used to emit a serde-flavoured error that referenced the CHANGELOG only. The new message leads with a human-readable "Configuration incompatible with valerter v2.0.0", includes the before/after YAML diff, a direct link to `MIGRATION.md`, and a rollback hint pointing at the GitHub releases page.

- **`valerter_vl_source_up` gauge debounced to 3 consecutive failures** (D-vl-obs-1). The gauge used to flip to `0` on any single HTTP 5xx, connection error, or mid-stream EOF, which made sources behind a flaky load balancer flap their reachability state and page operators on transient events. The flip is now gated by `VL_SOURCE_UP_FAILURE_THRESHOLD = 3` (fixed, not configurable): three consecutive failures before `0`, any single success resets the counter back to `1` and re-arms the debounce. Contract unchanged for persistently-down sources.

## [2.0.0] - 2026-04-16

### Security advisory

**Raw `_msg` piped into `email_body_html` renders unescaped in email clients.**

The example config switched `body: "{{ _msg }}"` in v1.2.0 (#26 fix), and operators may reasonably mirror that in `email_body_html`. The email notifier marks `body` as `safe` (pre-escaped HTML) before injection into the email envelope, so a log line containing raw HTML or `<script>` tags would render unescaped in the recipient's mail client.

This is pre-existing behaviour from v1.x, not a regression introduced in v2.0.0, but the surface is wider now that the example actively uses `_msg`.

**Mitigation:** if your VictoriaLogs ingests untrusted content (web request bodies, user-controlled fields), wrap the offending field with `| escape`, or render via plain `body` (not `email_body_html`) for email destinations until the email path is hardened in a follow-up.

### Breaking changes

- **`victorialogs` is now a map of named sources.** A single valerter instance can tail multiple VL backends and route alerts per source. The v1.x single-URL shape (`victorialogs.url: ...` at the top level) is rejected at load with an actionable migration error.

  Migrate from:

  ```yaml
  victorialogs:
    url: "http://victorialogs:9428"
    basic_auth:
      username: "u"
      password: "p"
  ```

  To:

  ```yaml
  victorialogs:
    default:
      url: "http://victorialogs:9428"
      basic_auth:
        username: "u"
        password: "p"
  ```

  Then optionally target sources per rule via `vl_sources: [name, ...]`, or omit the field to fan out across every configured source. Credentials, TLS, and headers are per-source, self-contained in each `VlSourceConfig`.

- **Default throttle key is now `{rule}-{source}:global`** (was `{rule}:global` in v1.x). Multi-source deployments get isolated throttle buckets per source with no extra config. Users who want cross-source dedup must override `throttle.key` explicitly (e.g. `key: "{{ rule_name }}"`).

- **Source names are restricted to `^[a-zA-Z0-9_]+$`.** No dashes, colons, dots, or spaces allowed. Validated at load. The constraint avoids ambiguity in the default throttle key format above.

- **Notifier output formats extended with `vl_source`.** The Mattermost footer now reads `valerter | <rule> | <source> | <timestamp>` instead of `valerter | <rule> | <timestamp>`. The default webhook payload exposes `vl_source` as a top-level JSON field. Downstream parsers / dashboards that match exact strings in either output need to update.

- **All per-rule Prometheus metrics now also carry a `vl_source` label.** Affected counters: `valerter_alerts_sent_total`, `valerter_alerts_throttled_total`, `valerter_alerts_passed_total`, `valerter_alerts_failed_total`, `valerter_email_recipient_errors_total`, `valerter_lines_discarded_total`, `valerter_logs_matched_total`, `valerter_notify_errors_total`, `valerter_parse_errors_total`, `valerter_reconnections_total`, `valerter_rule_panics_total`, `valerter_rule_errors_total`. Affected gauge/histogram: `valerter_last_query_timestamp`, `valerter_query_duration_seconds`. Dashboards and alerts that grouped by `rule_name` alone keep working but get an extra `vl_source` dimension; PromQL using `sum by (rule_name) (...)` still rolls up correctly. `valerter_queue_size` stays unlabeled (the queue is shared, not per-source).

- **`valerter_victorialogs_up{rule_name}` removed and replaced by `valerter_vl_source_up{vl_source}`.** The new gauge is per-source (one value per configured source, regardless of how many rules tail it) since reachability is a property of the source, not the rule. Alerts and panels need to migrate from per-rule to per-source semantics. Examples:

  ```promql
  # v1.x (per-rule):     valerter_victorialogs_up{rule_name="nginx-5xx"} == 0
  # v2.0.0 (per-source): valerter_vl_source_up{vl_source="prod"} == 0

  # v1.x (any rule down): min(valerter_victorialogs_up) == 0
  # v2.0.0 (any source):  min(valerter_vl_source_up) == 0
  ```

  The label key is now `vl_source` (not `rule_name`), and the cardinality drops from `|rules|` to `|sources|`.

- **`defaults.max_streams` cap introduced (default 50).** Total VictoriaLogs streams = sum of `(rule, source)` pairs spawned for enabled rules. Breaching the cap fails the config at load with both the actual count and the cap value. Configurable via `defaults.max_streams: <usize>`. Disabled rules do not contribute. Prevents accidental fan-out from DoSing a backend.

### Added

- **Multi-source VictoriaLogs support** (issue #34). The engine spawns one task per `(rule, source)` pair with per-source cancellation and reconnect isolation, so a single unhealthy source does not stop alerts on the others.
- **`{{ vl_source }}` template variable** available everywhere `{{ rule_name }}` is: layer 1 templates (`title`, `body`, `email_body_html`), `throttle.key`, and notifier-level layer 2 contexts (`subject_template`, `body_template`). Always non-empty, owned `String`, equal to the source name currently processing the event. Synthetic value wins over any event field literally named `vl_source` (matches the `rule_name` collision policy).
- **`AlertPayload.vl_source`** propagated end-to-end so notifiers can render the source name. See Breaking changes above for the related output format updates on Mattermost and webhook destinations.
- **`valerter_vl_source_up{vl_source}` per-source reachability gauge.** Initialized to 0 for every configured source at startup; engine flips to 1 on tail connect success and back to 0 on permanent failure or stream error. Replaces the v1.x per-rule `valerter_victorialogs_up`.
- **`±10%` uniform jitter on reconnect backoff** (per `(rule, source)` task). Sources behind a flapping load balancer no longer reconnect in lock-step, breaking the thundering-herd alignment over a few cycles. Hardcoded jitter range; not configurable in this release.
- **`tests/metrics_snapshot.rs` integration test.** Spins up a 2-source 1-rule engine, scrapes `/metrics`, and asserts the set of metric names + label keys (not values) against an inline expected string. Catches accidental relabel/rename in future PRs.
- **`examples/multi-source/config.yaml`** reference and top-level **[`MIGRATION.md`](MIGRATION.md)** for v1.x upgraders.

## [1.2.1] - 2026-04-16

### Fixed
- **`{{ rule_name }}` available in top-level templates and throttle key** (issue #31). `rule_name` is now injected into the render context of `templates.<name>.title`, `body`, and `email_body_html`, and also into the `throttle.key` template, not just the notifier-level `subject_template` / `body_template`. Configs that referenced `{{ rule_name }}` in a top-level template previously rendered an empty string; they now render the rule name. If an event field happens to be literally named `rule_name`, the synthetic rule name wins, matching the collision policy of the existing notifier-level contexts.
- **Dotted event fields resolve in `throttle.key`**. The unflatten step introduced in v1.2.0 for template rendering (issue #25) now also applies to the throttle key template, so `throttle.key: "{{ nginx.http.status_code }}-{{ hostname }}"` works consistently with `title` / `body`.

## [1.2.0] - 2026-04-15

### Breaking changes
- **Template field `body_html` renamed to `email_body_html`** to reflect that
  only the email notifier consumes it (Telegram, Mattermost, and webhook always
  ignored it). Migration: in every template, replace `body_html:` with
  `email_body_html:`. This applies to templates defined inline in `config.yaml`
  *and* to any split files under `templates.d/`. Configs using the old name are
  rejected at load time with a clear error that lists `email_body_html` among
  the expected fields, so `valerter --validate` will point out every template
  that needs updating on the first run.

### Fixed
- **Dotted field access in templates** (issue #25) — fields like
  `server.hostname` or `http.request.method` can now be referenced directly in
  Jinja templates using dotted notation, matching the shape users see in log
  payloads.
- **Empty Telegram message guard** (issue #26) — Telegram no longer 400s when a
  rendered body is empty. The notifier now substitutes a fallback string and
  records the drop reason, and the template documentation explicitly calls out
  that `body_html` (now `email_body_html`) is email-only so users do not
  accidentally leave `body` empty.

## [1.1.0] - 2026-04-15

### Added
- **Telegram notifier** (issue #22) — native `type: telegram` notifier using the
  Bot API `sendMessage` endpoint. Supports multi-chat delivery (one sequential
  HTTP call per `chat_id`), HTML `parse_mode` by default, 429 `Retry-After`
  handling, automatic codepoint-safe truncation at Telegram's 4096 character
  limit, and a new `valerter_alerts_truncated_total` Prometheus counter.

### Known Limitations
- Templates define a single `body` field that is shared across all notifiers. If
  you write a Markdown-flavored body (e.g. `**bold**`, triple-backtick fences)
  for Mattermost, Telegram will render those markers literally because it is
  configured with `parse_mode: HTML`. Workaround: override `body_template` on
  the Telegram notifier with HTML-friendly Jinja, for example
  `body_template: "<b>{{ title|e }}</b>\n<pre>{{ body|e }}</pre>"`. A proper
  render-pipeline-per-notifier abstraction is planned for 1.2.

## [1.0.0] - 2026-04-14

Promote `1.0.0-rc.5` to stable. No functional changes.

### Security
- Dependency updates via `cargo update` to pick up patched versions:
  - `aws-lc-sys` 0.35.0 → 0.39.1 (GHSA advisories on AWS-LC crypto/x509)
  - `quinn-proto` 0.11.13 → 0.11.14 (QUIC transport parameter DoS)
  - `rustls-webpki` 0.103.8 → 0.103.11 (CRL scope check)
  - `bytes` 1.11.0 → 1.11.1 (`BytesMut::reserve` integer overflow)

## [1.0.0-rc.5] - 2026-01-20

**Final RC** - Hardening and observability improvements before 1.0.0 stable.

### Added
- **TCP keepalive** - Prevents silent connection drops on long-lived VictoriaLogs streams (60s keepalive on reqwest client)
- **StreamBuffer size limit** - 1MB max line size with `valerter_lines_discarded_total{reason=oversized}` metric to prevent OOM from malformed input
- **Strict config validation** - `deny_unknown_fields` rejects typos, URL format validation for VictoriaLogs and webhook endpoints
- **Rust load-generator** - High-performance testing tool achieving 100k logs/sec for stress testing
- **Comprehensive debug logging** - Strategic debug/trace logs across all modules for troubleshooting
- **Performance test suite** - Load testing scripts and documented results (10k+ logs/sec sustained)

### Fixed
- **Tracing span propagation** - Use `instrument()` for async-safe span propagation in all notifier functions (engine, queue, mattermost, webhook, email)
- **Notification success logging** - Promoted from debug to info level for production visibility
- **Metrics label cleanup** - Removed unused `rule_name` label from `alerts_dropped_total` (global metric, not per-rule)
- **RUST_LOG support** - Now properly respects environment variable for log filtering

### Changed
- **Documentation overhaul** - Rewrote README "Why Valerter" section, updated metrics docs with `valerter_email_recipient_errors_total` and `valerter_notifier_config_errors_total`, added performance report

## [1.0.0-rc.4] - 2026-01-16

**Feature freeze** - From this release, only bug fixes until 1.0.0 stable. No new features or refactoring.

### Added
- **Multi-file configuration** - Split rules, templates, and notifiers into separate files in `.d/` directories (`rules.d/`, `templates.d/`, `notifiers.d/`)
- **Collision detection** - Explicit errors when duplicate names are found across config files
- **Warning for unused mattermost_channel** - Warns when `mattermost_channel` is set but no Mattermost notifier in destinations

### Changed
- **BREAKING: `notify.template` required** - Each rule must now specify its template explicitly (no more `defaults.notify.template` fallback)
- **BREAKING: `notify.destinations` required** - Each rule must specify at least one destination
- **BREAKING: `defaults.notify` removed** - The entire `defaults.notify` section has been removed
- **BREAKING: `notifiers` section required** - At least one notifier must be configured
- **BREAKING: `templates` section required** - At least one template must be defined
- **BREAKING: `MATTERMOST_WEBHOOK` env var removed** - Use `notifiers` section instead
- **BREAKING: `notify.channel` renamed** - Now `notify.mattermost_channel` for clarity
- **Strict field validation** - Unknown fields in `notify` section now cause parsing errors

### Fixed
- **Debian package** - Creates `.d/` directories on install

## [1.0.0-rc.3] - 2026-01-15

### Changed
- **Simplified tarball** - Contains only binary + config.example.yaml (removed install.sh, uninstall.sh, valerter.service)
- **Updated Quick Start** - Clear separation between .deb and static binary installation paths

## [1.0.0-rc.2] - 2026-01-15

### Added
- **Log timestamp in notifications** - Original log timestamp now included in all channels (Mattermost footer, Email template, Webhook payload)
- **Configurable timezone** - New `timestamp_timezone` setting for formatted timestamps (default: UTC)
- **Cisco switches example** - Complete alerting example for BPDU Guard violations in `examples/cisco-switches/`
- **Nginx proxy documentation** - Required configuration for streaming endpoints (`proxy_buffering off`)

### Fixed
- **VictoriaLogs streaming connection** - Use HTTP GET instead of POST for `/select/logsql/tail` endpoint
- **Email Outlook compatibility** - Simplified template with better rendering across email clients
- **Metric description** - `valerter_victorialogs_up` now correctly documented as connection status

### Changed
- **Refactored config module** - Split monolithic `config.rs` into focused submodules
- **Refactored notify module** - Split monolithic `notify.rs` into focused submodules

## [1.0.0-rc.1] - 2026-01-14

### Added
- **Email body template system** - HTML email templates with `body_html` field
- **Default email template** - Built-in `templates/default-email.html.j2`
- **Fail-fast validation** - Startup error if email destination uses template without `body_html`
- **Modular documentation** - New `docs/` folder with detailed guides (getting-started, configuration, notifiers, metrics, architecture)

### Fixed
- **Metrics recorder race condition** - Resolved startup race in Prometheus recorder initialization

### Changed
- **BREAKING: `color` → `accent_color`** - Template field renamed for clarity
- **BREAKING: `icon` removed** - Template field no longer supported
- **README refactored** - Reduced from 445 to ~110 lines, now a showcase with links to docs/
- **Pipeline diagram** - Mermaid replaced with static SVG (no overlay controls)

## [1.0.0-beta.1] - 2025-01-14

### Added
- **`valerter_build_info` metric** - Exposes version label for Prometheus dashboards
- **CHANGELOG.md** - Document all changes following Keep a Changelog format

### Fixed
- **Debian package auto-restart** - Service now automatically restarts on upgrade if running

### Changed
- **CI optimization** - Skip CI for documentation and asset-only changes (`.md`, images)

## [1.0.0-alpha.2] - 2025-01-14

### Added
- **6 new Prometheus metrics** for self-monitoring:
  - `valerter_alerts_passed_total` - alerts that passed throttling
  - `valerter_rule_panics_total` - rule task panics (auto-restarted)
  - `valerter_rule_errors_total` - fatal rule errors
  - `valerter_last_query_timestamp` - timestamp of last successful query
  - `valerter_victorialogs_up` - VictoriaLogs connection status
  - `valerter_query_duration_seconds` - query latency histogram
- **Official logo** with SVG/PNG variants (light, dark, inverted, lockup)
- **Example Prometheus alerts** in README for monitoring valerter itself
- **"Why Valerter?"** section in README comparing with vmalert

### Changed
- Simplified installation: `valerter_latest_amd64.deb` now available via `/releases/latest/download/`
- README header with centered logo and badges (License, Rust version)

## [1.0.0-alpha.1] - 2025-01-12

### Added
- Initial alpha release
- Real-time log streaming from VictoriaLogs `/tail` API
- Multi-channel notifications: Mattermost, Email SMTP, Generic Webhook
- Declarative YAML configuration with regex/JSON parsing
- Intelligent throttling with configurable rate limiting per key
- Prometheus metrics endpoint (`/metrics`)
- Debian package (.deb) and tarball releases
- systemd service integration

[Unreleased]: https://github.com/fxthiry/valerter/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/fxthiry/valerter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.5...v1.0.0
[1.0.0-rc.5]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.4...v1.0.0-rc.5
[1.0.0-rc.4]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.3...v1.0.0-rc.4
[1.0.0-rc.3]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.2...v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-beta.1...v1.0.0-rc.1
[1.0.0-beta.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.2...v1.0.0-beta.1
[1.0.0-alpha.2]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.1...v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/fxthiry/valerter/releases/tag/v1.0.0-alpha.1
