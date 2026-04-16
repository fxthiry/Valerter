# Multi-Source VictoriaLogs Example

Demonstrates the v2.0.0 multi-source feature: a single Valerter instance tails two VictoriaLogs backends (`prod` and `staging`) and routes alerts per source.

## Routing Matrix

The [`config.yaml`](config.yaml) file defines 2 sources and 3 rules covering the three routing patterns:

| Rule                       | `vl_sources`         | Spawns tasks for         | Use case                        |
| -------------------------- | -------------------- | ------------------------ | ------------------------------- |
| `prod_critical_errors`     | `[prod]`             | `(rule, prod)`           | Pin a rule to one backend       |
| `staging_deploy_failures`  | `[staging]`          | `(rule, staging)`        | Pin a rule to another backend   |
| `auth_failures_all_envs`   | (omitted)            | `(rule, prod)` + `(rule, staging)` | Fan out across every source |

Each `(rule, source)` pair runs as an isolated task with its own throttle bucket (default key: `{rule}-{source}:global`) and per-source reconnect with `±10%` jitter. A flapping `staging` backend does not stop alerts on `prod`.

## Source Name Constraints

Source names must match `^[a-zA-Z0-9_]+$` (alphanumeric or underscore only). No dashes, dots, or colons. The constraint avoids ambiguity in the default throttle key format.

## Stream Cap

`defaults.max_streams` (default 50) caps the total number of `(rule, source)` pairs spawned. Disabled rules do not contribute. Breaching the cap fails the config at load with the actual count and the cap value. Tune the limit if you fan many rules across many sources.

## Run It

```bash
# Set the basic_auth secrets referenced via ${...} in this example
export VL_PROD_USER="prod_user"
export VL_PROD_PASS="prod_password"

# Edit webhook_url in config.yaml to point at your real Mattermost hook
# (--validate parses webhook_url as a URL, so it must be valid at validate time;
#  ${WEBHOOK_URL} expansion is fine for runtime but not for `--validate`).

# Validate the config
valerter --validate -c examples/multi-source/config.yaml

# Run it
valerter -c examples/multi-source/config.yaml
```

## Observability

The new `valerter_vl_source_up{vl_source}` gauge reports per-source reachability (initialized to 0, flipped to 1 on tail connect success). All per-rule metrics now also carry a `vl_source` label so dashboards can group or filter by source. See [`MIGRATION.md`](../../MIGRATION.md) for the full Prometheus migration guide.
