# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
