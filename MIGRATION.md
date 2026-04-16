# Migration Guide

This guide covers upgrading from Valerter **v1.x** to **v2.0.0**. Follow it section by section. Every breaking change has a before / after snippet you can copy.

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
