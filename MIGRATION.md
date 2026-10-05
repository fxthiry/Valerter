# Migration Guide

This guide covers the breaking and operationally visible changes between releases, newest first.

## Upgrading to 2.1.0

### A configuration with all rules disabled is now refused

Until 2.0.3, a configuration whose rules were all `enabled: false` passed validation; the daemon then started, found nothing to watch and exited with code 0. It is now a validation error, reported by `valerter --validate` and at startup (exit code 1):

```
all rules are disabled: enable at least one rule in config.yaml or rules.d/
```

To pause alerting, stop and disable the service rather than disabling every rule:

```bash
sudo systemctl disable --now valerter
```

Run `valerter --validate -c /etc/valerter/config.yaml` before upgrading to catch this case.

### Exit codes and systemd restarts

- Exit code **0** now only follows a requested shutdown (SIGINT/SIGTERM). systemd does not restart the unit.
- Exit code **1** covers every failure: invalid configuration (as before), all rules disabled (new), and the engine losing all its tasks at runtime (new, previously exit code 0).
- Under the shipped unit (`Restart=on-failure`, `RestartSec=5`), any exit code 1 makes systemd restart valerter every 5 seconds for as long as the cause persists. This restart loop already existed for invalid configurations; it now also applies to a configuration with all rules disabled. A dedicated exit code for configuration errors (to stop the loop with `RestartPreventExitStatus`) is out of scope for this release.
- You can now alert on the unit state (`failed`, or repeated restarts) or on the process exit code: a valerter that stops watching no longer looks like a clean stop.

### Automatic restart on `.deb` upgrade

`dpkg -i` of a new version now restarts the service when it is active or enabled; the manual `systemctl restart valerter` is no longer needed. If the service is not active two seconds after the restart (typically an invalid configuration), a warning pointing to `journalctl -u valerter` is printed and the upgrade still succeeds.

- An enabled service that you stopped on purpose is started again by the upgrade. Disable it (`systemctl disable valerter`) if it must stay stopped.
- When upgrading from 2.0.3 or earlier, the old package stops the service before the new one is installed. An enabled service is restarted; a service started by hand without being enabled stays stopped: run `sudo systemctl start valerter` after the upgrade.

### VictoriaLogs streaming: logs, headers and discarded-lines metric

- **Log field `delay_secs` renamed `delay_ms`.** The `Connection failed, retrying` warning now carries the backoff delay in milliseconds (`delay_ms=930`) instead of whole seconds (`delay_secs=0`). Update any log query, alert or dashboard that filters on `delay_secs`. The cause of the failure (`Connection failed` / `Stream read error`) is now logged before this warning instead of after the wait.
- **A custom `Authorization` header now masks `basic_auth`.** When a source defines both `basic_auth` and `headers: { Authorization: ... }`, only the custom header is sent (previously both were sent and the server chose). A warning is logged at startup for each affected (rule, source) task. Keep only the credentials you actually want to use. Custom headers with the name of a default header (`Accept`, `Connection`) also replace it instead of being sent twice.
- **`valerter_lines_discarded_total{reason="invalid_utf8"}` counts lines, not batches.** Only the invalid line is dropped now, and each one adds one unit, so the counter may grow faster than in 2.0.3 for the same stream. Revisit any alert threshold set on it.

### `--validate` is stricter

Until 2.0.3, `valerter --validate` stopped after loading and validating the configuration: a configuration with an unknown rule destination, an undefined notifier variable, a missing `body_template_file` or an email template without `email_body_html` passed it with exit code 0 and then failed at startup. `--validate` now runs every blocking startup check (same code, same messages, exit code 1), still without starting the daemon or making any network call.

- **Define every environment variable referenced by notifiers when running `--validate`**, including in CI pipelines that validated without secrets. Dummy values are fine, nothing is sent:

  ```bash
  MATTERMOST_WEBHOOK="https://mattermost.example.com/hooks/dummy" \
  SMTP_PASSWORD="dummy" \
    valerter --validate -c config.yaml
  ```

  Variables used by VictoriaLogs sources were already required by `--validate`.
- **`body_template_file` files must be readable** by the user running `--validate`, not only by the `valerter` service user.
- **New errors you may now get from `--validate`:** `Notifier configuration error` (`Failed to create notifiers: N errors`), `Destination validation error` (`Destination validation failed: N errors`) and `Email template validation error` (`Email template validation failed: N errors`). All of them are reported in one run, and the daemon now does the same at startup instead of stopping at the first failed stage.
- **Summary format.** A `  Notifiers: <n> [<name>=<type>, ...]` line is printed after `Templates`, and source URLs are redacted (`http://***@vl.example.com:9428/?***` for a URL carrying credentials or a query string; URLs without such parts are unchanged). Update scripts that parse this output.

### Stricter configuration validation

valerter 2.1.0 refuses, when the configuration is loaded or when notifiers are built, several mistakes that 2.0.3 accepted and that only showed up at runtime (silently suppressed alerts, a single throttle counter, every send failing, an endless reconnection loop). **The upgraded service refuses to start if your configuration has one of them.** Before installing the new package, validate the production configuration with the new binary, with the environment variables of the notifiers defined (dummy values are fine), and fix every reported error:

```bash
valerter --validate -c /etc/valerter/config.yaml
```

| 2.0.3 behavior | 2.1.0 error | Fix |
|---|---|---|
| `defaults.throttle.count: 0` accepted with a runtime warning: every rule without its own `throttle` sent at most its first alert | `defaults.throttle.count must be >= 1 (0 would suppress every alert)` | Set `count` to 1 or more |
| `defaults.throttle.window: 0s` accepted with a runtime warning: throttling silently disabled | `defaults.throttle.window must be > 0 (0s disables throttling)` | Set a positive `window` (e.g. `60s`) |
| Unknown filter, test or function in `throttle.key` (rule or `defaults`): every event of the rule fell back to the single key `<rule>:error` | `invalid template in rule '<rule>': throttle.key render: ...` / `defaults.throttle.key render: ...` | Fix or remove the filter; syntax errors in `defaults.throttle.key` are now reported too (`defaults.throttle.key: ...`) |
| Unknown filter, test or function in a webhook, Telegram or email `body_template` (inline, `body_template_file` or default): every send failed | `Notifier configuration error` with `invalid notifier '<name>': body_template render: ...` | Fix the template; the error names the filter |
| Invalid header name (space, `:`...) or value (line break) in `victorialogs.<source>.headers`: endless reconnection loop | `victorialogs.<source>.headers: invalid header name '<name>'` / `invalid value for header '<name>'` (the value is never printed) | Fix the header name, or the value or variable it resolves to |
| Telegram `parse_mode` other than `HTML`, `MarkdownV2` or `Markdown` (e.g. `Markdown2`, `markdown_v2`): HTTP 400 for every alert | `invalid notifier '<name>': parse_mode '<value>' is not supported (expected HTML, MarkdownV2 or Markdown)` | Use one of the three values; the case no longer matters (`html` is sent as `HTML`) |
| VictoriaLogs source `url` resolving to a value still containing `${`: accepted without any check | `victorialogs.<source>.url: invalid URL: ...` | Give the variable an `http(s)://` URL |
| Webhook `url` or Mattermost `webhook_url` built from a `${VAR}` that resolves to a wrong scheme or a non-URL: every send failed | `invalid notifier '<name>': url: invalid URL: ...` / `webhook_url: invalid URL: ...` (the URL is never printed) | Fix the variable's value |

The test render of templates is also more accurate: conversions and arithmetic on fields (`{{ status | int }}`, `{{ (latency | float) > 1.5 }}`, `{{ count + 1 }}`), wrongly refused until 2.0.3, are now accepted in templates, `throttle.key`, `subject_template` and `body_template`.

### Custom throttle keys are now shared across a rule's sources

Until 2.0.3, each `(rule, source)` task had its own throttle cache, so `throttle.key: "{{ rule_name }}"` did not dedup across sources as documented: the same outage seen by two sources sent two alerts. In 2.1.0 a rule has a single throttle cache shared by all its sources, and every source that renders the same key increments the same counter.

- **Rules without `throttle.key`** (default key `<rule_name>-<vl_source>:global`) or whose key already contains `{{ vl_source }}`: no change, each source keeps its own counter.
- **Rules targeting several sources with a custom key that does not contain `{{ vl_source }}`** (e.g. `{{ rule_name }}`, `{{ host }}`, also when inherited from `defaults.throttle.key`): the counter is now shared by the rule's sources, so these rules may send fewer alerts. To keep one counter per source, add `{{ vl_source }}` to the key:

  ```yaml
  throttle:
    key: "{{ vl_source }}-{{ host }}"   # was "{{ host }}"
  ```

- **Startup log.** valerter logs at INFO level, once per affected rule, `Throttle key does not reference vl_source: its counter is shared across the rule's sources; add {{ vl_source }} to the key to isolate them`, with the `rule_name`, `source_count` and `throttle_key` fields. Search your logs for it after the upgrade to list the rules concerned.
- **Reconnection reset.** When a source reconnects after an error, only the counters fed exclusively by that source are reset; counters shared with another source are kept. The throttle cache also survives a task restart after a panic.
- **Cache bound.** A rule's throttle cache holds up to 10,000 keys per source it targets (previously 10,000 per `(rule, source)` task): same total memory budget.

### One notification queue per destination

Until 2.0.3, every alert went through a single queue consumed by a single worker, so one unresponsive notifier delayed all the others. In 2.1.0 each notifier has its own queue and its own delivery task. No configuration change is needed; the visible changes are:

- **Order is guaranteed per destination.** Alerts reach each notifier in the order they were produced, but there is no ordering between destinations anymore: a healthy channel can receive an alert before a slow one receives an older alert.
- **Capacity is exactly 100 alerts per destination** (the old single queue held 128). When a destination queue is full, its oldest alert is dropped, for that destination only. The `Queue full, dropping N oldest alerts` warning now carries a `notifier` field.
- **`valerter_queue_size` and `valerter_alerts_dropped_total` count deliveries summed over every destination.** They keep their names and have no label, so existing selectors still work, but an alert pending (or dropped) for two destinations counts twice.
- **New series:** `valerter_destination_queue_size{notifier_name, notifier_type}` and `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}`, exposed at 0 for every notifier from startup.
- **Review PromQL alerts with an absolute threshold on `valerter_queue_size`.** As a sum over destinations it can now reach 100 × number of notifiers, so `valerter_queue_size > 50` no longer means "queue half full": it can fire while no queue is half full, or stay silent while one destination overflows if the threshold was tuned for 128. Rewrite it on the per-destination gauge:

  ```yaml
  # before
  expr: valerter_queue_size > 50
  # after
  expr: max(valerter_destination_queue_size) > 50
  ```

  Alerts based on `rate(valerter_alerts_dropped_total[...])` keep their meaning and need no change; use `valerter_destination_alerts_dropped_total` to see which destination drops.

### Queued alerts are delivered on shutdown

Until 2.0.3, a `systemctl stop` or `restart` dropped every alert still in the queue. In 2.1.0, on SIGTERM/SIGINT the rule tasks stop first, then every destination delivers its in-flight and queued alerts before the process exits, within 20 seconds. No configuration change is needed; the visible changes are:

- **A shutdown can take up to ~27 s** (about 20 s more than before) when alerts are queued or an endpoint is slow. With empty queues the process still exits at once. If the 20 s expire, the WARN `Shutdown drain timeout reached, alerts not delivered` gives the number of alerts lost (`undelivered`) and the exit code stays 0.
- **Package upgrades can block `dpkg`/`apt` for up to ~27 s.** The `systemctl restart` run by the Debian `postinst` waits for the old process to drain its queues. This is expected: do not interrupt the upgrade. The shipped unit (`TimeoutStopSec=30`) needs no change.
- **Raise the stop timeout of container runtimes to 30 s** to benefit from the drain: `docker stop --stop-timeout 30 valerter`, or `stop_grace_period: 30s` in Docker Compose. Docker's default of 10 s kills the process before the drain ends (alerts are then lost, as before 2.1.0). Use the same value for any other supervisor that sends SIGKILL after a delay.
- **A second SIGTERM/SIGINT forces an immediate exit** (e.g. a second Ctrl+C), whatever the shutdown phase. It logs `Second shutdown signal received, forcing immediate exit` and exits with code **1**, since queued alerts may be lost.

### Prometheus metrics: label sets and counting

2.1.0 makes the series exposed at startup match the ones that are incremented, and gives each counter a single meaning. No configuration change is needed; review your PromQL queries, dashboards and alerts:

- **Breaking: startup series with reduced labels are removed.** Until 2.0.3, valerter seeded at startup `valerter_alerts_sent_total{rule_name, vl_source}`, `valerter_parse_errors_total{rule_name, vl_source}` (without `error_type`), `valerter_alerts_failed_total{notifier}` and `valerter_notify_errors_total{notifier}`. Nothing ever incremented them: they stayed at 0 next to the real series, which only appeared at the first event. They are gone, and every series is now created at 0 with its emission labels (`rule_name`, `vl_source`, `notifier_name`, `notifier_type` for the notification counters; `error_type` for parse errors; see [docs/metrics.md](docs/metrics.md#series-initialized-at-startup)). Replace the `notifier` label with `notifier_name`:

  ```yaml
  # before
  expr: increase(valerter_alerts_failed_total{notifier="mattermost-ops"}[1h]) > 0
  # after
  expr: sum by (notifier_name) (increase(valerter_alerts_failed_total{notifier_name="mattermost-ops"}[1h])) > 0
  ```

  Unfiltered sums (`sum(valerter_alerts_sent_total)`) keep their values, since the removed series were always 0. A notifier used by no enabled rule no longer has `valerter_alerts_failed_total` or `valerter_notify_errors_total` series: list notifiers with `valerter_destination_queue_size`, which exists for every notifier.
- **Breaking: `valerter_notifier_config_errors_total` is removed.** It was incremented before the metrics exporter started and the error stops valerter with exit code 1, so no scrape could ever see it. To detect a notifier configuration error (e.g. an undefined `${VAR}`), alert on the systemd unit state (`failed`, repeated restarts) or on the ERROR log `Notifier configuration error`, and run `valerter --validate` before deploying.
- **Breaking: `valerter_reconnections_total` no longer counts clean stream ends.** 2.0.3 started counting a clean end of the stream (HTTP 200 then EOF without error) in `valerter_reconnections_total`, in a release announced without breaking changes. 2.1.0 reverts that choice: `valerter_reconnections_total` only counts reconnections after a failure (connection error, HTTP error response, error while reading the stream), and clean ends are counted in the new `valerter_stream_ends_total{rule_name, vl_source}`. Dashboards and alerts built since 2.0.3 see lower values, especially behind a proxy or load balancer that closes idle streams. To get the 2.0.3 total back:

  ```promql
  valerter_reconnections_total + valerter_stream_ends_total
  ```

  An alert such as `rate(valerter_reconnections_total[5m]) > 0` now only fires on failures, which makes it usable without filtering out normal stream ends.
- **Breaking: Telegram alerts are counted once per alert.** Until 2.0.3, a Telegram notifier incremented `valerter_alerts_sent_total` once per successful chat and `valerter_notify_errors_total` / `valerter_alerts_failed_total` once per failed chat, even when the alert reached other chats. It now counts like the email notifier: `valerter_alerts_sent_total` +1 when at least one chat received the alert, `valerter_notify_errors_total` and `valerter_alerts_failed_total` +1 only when every chat failed. For a notifier with several `chat_ids`, `valerter_alerts_sent_total` is therefore divided by the number of chats, and `rate(valerter_alerts_failed_total[5m]) > 0` no longer fires on a partial failure. To watch individual chats, use the new `valerter_telegram_chat_errors_total{rule_name, vl_source, notifier_name}` (one unit per failed chat; a chat delivered through the plain-text fallback is not a failure):

  ```yaml
  expr: increase(valerter_telegram_chat_errors_total[15m]) > 0
  ```
- **Template render errors at send time are counted.** A webhook `body_template`, an email subject or body, or a Telegram message text that fails to render now increments `valerter_notify_errors_total` and `valerter_alerts_failed_total`; it used to be only logged. Most of these errors are now refused at startup (see [Stricter configuration validation](#stricter-configuration-validation)).

## Upgrading from v1.x to v2.0.0

This section covers upgrading from Valerter **v1.x** to **v2.0.0**. Follow it section by section. Every breaking change has a before / after snippet you can copy.

If you only need a one-line summary: **the `victorialogs` section is now a map of named sources, every per-rule Prometheus metric gained a `vl_source` label, and `valerter_victorialogs_up` was renamed.**

## 1. Pre-Upgrade Checklist

Walk through this before you flip the binary. Each bullet is a concrete file or query you should touch.

### Configuration

- [ ] Open every `config.yaml`, `rules.d/*.yaml`, and `notifiers.d/*.yaml` you ship.
- [ ] Find the top-level `victorialogs:` block. If it has a direct `url:` key, you must rewrite it (see Section 2).
- [ ] Decide on your source name(s). Names must match `^[a-zA-Z0-9_]+$`. If you have only one backend today, pick `default`.
- [ ] Decide if any rule should pin to a subset of sources via `vl_sources: [name, ...]`. By default, rules fan out across every configured source.

### Prometheus Dashboards

- [ ] Search every Grafana dashboard JSON for `valerter_victorialogs_up`. Every match must move to `valerter_vl_source_up` (see Section 3).
- [ ] Search for PromQL queries that group by `rule_name` only (e.g. `sum by (rule_name) (valerter_alerts_sent_total)`). They keep working but now silently aggregate across sources. If that is not what you want, add `vl_source` to the `by` clause.
- [ ] Verify panels on per-source overlays will not collapse if a rule fans out to multiple sources.

### Prometheus Alerts

- [ ] Find every `alert:` rule that referenced `valerter_victorialogs_up{rule_name=...}`. Migrate the label key from `rule_name` to `vl_source` (see Section 3 for examples).
- [ ] Re-evaluate cardinality. Per-rule alerts now multiply by the number of sources you tail.

### Notifier Output

- [ ] If you parse the Mattermost footer string downstream, expect a 4-segment `valerter | <rule> | <source> | <timestamp>` instead of the 3-segment v1.x format (see Section 4).
- [ ] If you consume the default webhook payload, expect a new top-level `vl_source` field.

## 2. Config Migration

The `victorialogs` section is now a **map of named sources**. The v1.x single-URL shape is rejected at load with an actionable error.

### Before (v1.x)

```yaml
victorialogs:
  url: "http://victorialogs:9428"
  basic_auth:
    username: "u"
    password: "p"
```

### After (v2.0.0)

```yaml
victorialogs:
  default:
    url: "http://victorialogs:9428"
    basic_auth:
      username: "u"
      password: "p"
```

The minimum-effort migration is one new key (`default:`) and one extra indent level. Credentials, TLS, and headers move under each source, self-contained.

### Targeting sources per rule

Add `vl_sources: [name, ...]` to a rule to restrict it to a subset of sources. Omit the field to fan out across every configured source:

```yaml
rules:
  - name: "prod_only_alert"
    query: '...'
    vl_sources: [prod]      # only the `prod` source
    notify: { template: "...", destinations: ["..."] }

  - name: "all_envs_alert"
    query: '...'
    # no vl_sources → fans out across every source
    notify: { template: "...", destinations: ["..."] }
```

See [`examples/multi-source/`](examples/multi-source/) for a complete reference with prod + staging.

### Source name format

Source names must match `^[a-zA-Z0-9_]+$`. No dashes, dots, colons, or spaces. The constraint avoids ambiguity in the default throttle key format below. Validation runs at load time.

### Default throttle key change

The default throttle key changed from the literal string `<rule_name>:global` (v1.x) to `<rule_name>-<vl_source>:global` (v2.0.0). These angle-bracket placeholders are descriptive notation, not template syntax. Multi-source deployments get isolated throttle buckets per source automatically. If you want **cross-source dedup** (one bucket shared across sources for the same rule), set `throttle.key` explicitly:

```yaml
rules:
  - name: "shared_bucket_alert"
    throttle:
      key: "{{ rule_name }}"   # back to v1.x semantics
    # ...
```

Cross-source dedup with a custom key is effective since 2.1.0; in 2.0.x each source still counted separately. See [Custom throttle keys are now shared across a rule's sources](#custom-throttle-keys-are-now-shared-across-a-rules-sources).

### `defaults.max_streams` cap

A new cap on total `(rule, source)` pairs spawned, default `50`. Disabled rules do not contribute. Breaching the cap fails the config at load with both the actual count and the cap value. Tune via `defaults.max_streams: <usize>` if you fan out many rules across many sources.

## 3. Prometheus Migration

### Removed: `valerter_victorialogs_up{rule_name}`

This per-rule gauge was replaced by a per-source gauge. Reachability is a property of the **source**, not the rule (every rule that tails the same backend reports the same up/down state).

### Added: `valerter_vl_source_up{vl_source}`

One value per configured source, regardless of how many rules tail it. Initialized to 0 at startup; flipped to 1 on tail connect success and back to 0 on permanent failure or stream error. The label key is `vl_source` (not `rule_name`), and the cardinality drops from `|rules|` to `|sources|`.

#### PromQL migration examples

```promql
# v1.x (per-rule):     valerter_victorialogs_up{rule_name="nginx-5xx"} == 0
# v2.0.0 (per-source): valerter_vl_source_up{vl_source="prod"} == 0

# v1.x (any rule down): min(valerter_victorialogs_up) == 0
# v2.0.0 (any source):  min(valerter_vl_source_up) == 0
```

### `vl_source` label added to every per-rule metric

Affected counters: `valerter_alerts_sent_total`, `valerter_alerts_throttled_total`, `valerter_alerts_passed_total`, `valerter_alerts_failed_total`, `valerter_email_recipient_errors_total`, `valerter_lines_discarded_total`, `valerter_logs_matched_total`, `valerter_notify_errors_total`, `valerter_parse_errors_total`, `valerter_reconnections_total`, `valerter_rule_panics_total`, `valerter_rule_errors_total`.

Affected gauge / histogram: `valerter_last_query_timestamp`, `valerter_query_duration_seconds`.

Dashboards and alerts that grouped by `rule_name` alone keep working but now get an extra `vl_source` dimension. PromQL using `sum by (rule_name) (...)` still rolls up correctly across sources. `valerter_queue_size` stays unlabeled (the queue is shared, not per-source).

### Per-rule alert example

```yaml
# v1.x
- alert: ValerterVictoriaLogsDown
  expr: valerter_victorialogs_up == 0
  for: 5m

# v2.0.0
- alert: ValerterVictoriaLogsSourceDown
  expr: valerter_vl_source_up == 0
  for: 5m
  annotations:
    summary: "Source {{ $labels.vl_source }} unreachable"
```

## 4. Notifier Output Changes

### Mattermost footer

The footer now carries 4 segments instead of 3:

```
v1.x: valerter | <rule> | <timestamp>
v2.0.0: valerter | <rule> | <source> | <timestamp>
```

If you parse the footer string downstream, update the split logic.

### Default webhook payload

The default webhook payload (used when `body_template` is omitted) gained a top-level `vl_source` field:

```json
{
  "alert_name": "<notifier_name>",
  "rule_name": "...",
  "vl_source": "prod",
  "title": "...",
  "body": "...",
  "timestamp": "<ISO8601>",
  "log_timestamp": "<ISO8601>",
  "log_timestamp_formatted": "DD/MM/YYYY HH:MM:SS TZ"
}
```

### Templates

The `{{ vl_source }}` template variable is available everywhere `{{ rule_name }}` is: layer 1 templates (`title`, `body`, `email_body_html`), `throttle.key`, and notifier-level layer 2 contexts (`subject_template`, `body_template`). Always non-empty, equal to the source name currently processing the event.

If an event field is literally named `vl_source`, the synthetic value wins (matches the `rule_name` collision policy).

## 5. Rollback

If something goes wrong after the upgrade, you can roll back to **v1.2.1** with no state migration required. The Prometheus metric labels are additive at the storage layer, except for the removed `valerter_victorialogs_up` gauge (which simply stops being produced when v2.0.0 runs).

### Debian / Ubuntu

```bash
# Pin v1.2.1
curl -LO https://github.com/fxthiry/valerter/releases/download/v1.2.1/valerter_1.2.1_amd64.deb
sudo dpkg -i valerter_1.2.1_amd64.deb
sudo systemctl restart valerter
```

### Static binary

```bash
curl -LO https://github.com/fxthiry/valerter/releases/download/v1.2.1/valerter-linux-x86_64.tar.gz
tar -xzf valerter-linux-x86_64.tar.gz
./valerter --validate -c /etc/valerter/config.yaml
```

You will need to revert the v2.0.0 config rewrite (the v1.x binary will reject the map shape). Keep a `config.yaml.v1` backup before you upgrade.

### Notes

- No on-disk state to migrate: throttle buckets are in-memory only.
- Prometheus historical data with the new `vl_source` label remains valid (the label simply becomes empty for older samples in TSDB).
- The v1.x `valerter_victorialogs_up` time series stops growing under v2.0.0 and resumes under v1.2.1.

## See Also

- [`CHANGELOG.md`](CHANGELOG.md) : full v2.0.0 release notes
- [`examples/multi-source/`](examples/multi-source/) : complete working multi-source reference
- [`docs/configuration.md`](docs/configuration.md) : full configuration reference
- [`docs/metrics.md`](docs/metrics.md) : Prometheus metric catalog
