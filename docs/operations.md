# Operations

Running valerter in production: files and permissions, the systemd service,
logs, exit codes, shutdown, delivery queues, upgrades and containers.

## Files and permissions

The Debian package installs:

| Path | Owner and mode | Content |
|------|----------------|---------|
| `/usr/bin/valerter` | `root`, `755` | The binary |
| `/lib/systemd/system/valerter.service` | `root`, `644` | The systemd unit |
| `/etc/valerter/` | `root:valerter`, `750` | Configuration directory |
| `/etc/valerter/config.yaml` | `root:valerter`, `640` | Configuration (a conffile, see [Upgrading the .deb package](#upgrading-the-deb-package)) |
| `/etc/valerter/rules.d/`, `templates.d/`, `notifiers.d/` | `root:valerter`, `750` | [Multi-file configuration](configuration.md#multi-file-configuration), created empty |
| `/etc/valerter/templates/default-email.html.j2` | `valerter:valerter`, `644` | Example email body template (the built-in default is compiled in the binary) |

The service runs as the `valerter` system user (no login shell, no home), which
can read the configuration but not write it. The configuration holds secrets:
only `root` and the `valerter` group can read it. The package sets these owners
and modes again on every install and upgrade.

For a static binary installation, reproduce this layout:

```bash
sudo groupadd --system valerter
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid valerter valerter
sudo chown root:valerter /etc/valerter /etc/valerter/config.yaml
sudo chmod 750 /etc/valerter
sudo chmod 640 /etc/valerter/config.yaml
```

## Running under systemd

```bash
sudo systemctl enable --now valerter   # start now and at boot
sudo systemctl status valerter
sudo systemctl restart valerter        # after a configuration change
```

The shipped unit runs `valerter -c /etc/valerter/config.yaml` as `valerter`,
with `Restart=on-failure` (`RestartSec=5`), `TimeoutStopSec=30` and a hardened
sandbox (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`NoNewPrivileges=yes`).

Secrets referenced as `${VAR}` in the configuration are read from the service
environment. Set them in a drop-in rather than in the unit file:

```bash
sudo systemctl edit valerter
```

```ini
[Service]
Environment=MATTERMOST_WEBHOOK=https://mattermost.example.com/hooks/...
Environment=SMTP_PASSWORD=...
```

To pause alerting, stop and disable the service
(`sudo systemctl disable --now valerter`): a configuration whose rules are all
disabled is refused.

## Logs

valerter writes its logs to stderr, collected by journald under systemd;
stdout is only used by the `--validate` summary.

```bash
journalctl -u valerter -f
journalctl -u valerter --since "1 hour ago" -p warning
```

- **Format:** human-readable text by default, or one JSON object per line with
  `--log-format json` or `LOG_FORMAT=json` (the event fields at the top level,
  with the current span, such as `rule_name` and `vl_source` of a rule task).
- **Colors:** text logs are colored only when stderr is a terminal and
  `NO_COLOR` is not set; journald and log files never receive color codes.
- **Level:** `RUST_LOG` (`info` by default), e.g. `RUST_LOG=debug` or
  `RUST_LOG=info,valerter::notify=debug`. Set it in the drop-in above.
- **Secrets** (webhook URLs, tokens, passwords, header values) are never
  logged; VictoriaLogs source URLs appear masked.

## Exit codes

| Code | Meaning | systemd (`Restart=on-failure`) |
|------|---------|--------------------------------|
| `0` | Requested shutdown (SIGTERM, SIGINT), or `--validate` succeeded | Not restarted |
| `1` | Any failure: invalid configuration, all rules disabled, the engine losing all its tasks, a fatal runtime error, a second shutdown signal, or `--validate` failed | Restarted every 5 s while the cause persists |

The unit then shows `failed` or repeated restarts: alert on the unit state or
on the ERROR logs. A fatal error is logged once at ERROR, in the configured log
format.

## Shutdown and alert drain

On SIGTERM or SIGINT (`systemctl stop`, `restart`, Ctrl+C):

1. the rule tasks stop (`All rule tasks stopped`): no new alert is produced;
2. every destination delivers its in-flight alert (retries included) and the
   alerts still in its queue, in parallel, within **20 seconds**
   (`Waiting for notification worker to drain queue...`, then
   `Notification queue drained`). With empty queues, the process exits at once;
3. if the 20 seconds expire, the WARN
   `Shutdown drain timeout reached, alerts not delivered` gives the number of
   alerts lost (`undelivered`); the exit code stays 0.

A second SIGTERM or SIGINT, at any point of the shutdown, logs
`Second shutdown signal received, forcing immediate exit` and exits at once
with code 1 (queued alerts may be lost).

The whole shutdown fits in the `TimeoutStopSec=30` of the shipped unit. Any
supervisor that kills the process after a delay must allow 30 seconds too (see
[Containers](#containers)).

## Delivery queues

Each notifier has its own queue of **100 alerts** and its own delivery task:

- a slow, unreachable or failing destination only delays its own alerts;
- alerts reach each destination in the order they were produced; there is no
  ordering between destinations;
- when a queue is full, its oldest alert is dropped, for that destination
  only, with the WARN `Queue full, dropping N oldest alerts` (field `notifier`).

Watch `valerter_destination_queue_size{notifier_name}` (backlog) and
`valerter_destination_alerts_dropped_total{notifier_name}` (losses), see
[Metrics](metrics.md). Retries and timeouts are described in
[Delivery](notifiers.md#delivery).

## Validating the configuration

```bash
valerter --validate -c /etc/valerter/config.yaml
```

`--validate` runs every startup check (see
[Validation](configuration.md#validation)) without starting the daemon nor
making any network call. Two things to know on a server installed with the
package:

- **Permissions.** The configuration is readable by `root` and the `valerter`
  group only: run `--validate` with `sudo` (or as a member of the group).
- **Environment.** `--validate` builds every notifier, so every `${VAR}` of the
  configuration must be defined. `sudo` drops the variables of your shell: pass
  them explicitly or keep them with `-E` (when your sudoers policy allows it):

  ```bash
  sudo MATTERMOST_WEBHOOK="https://mattermost.example.com/hooks/..." valerter --validate
  # or
  export MATTERMOST_WEBHOOK="https://mattermost.example.com/hooks/..."
  sudo -E valerter --validate
  ```

### Validating in CI

Run `--validate` on every configuration change. Dummy values are enough for the
variables referenced by notifiers: nothing is sent and no endpoint needs to be
reachable.

```bash
MATTERMOST_WEBHOOK="https://mattermost.example.com/hooks/dummy" \
SMTP_PASSWORD="dummy" \
  valerter --validate -c config.yaml
```

The exit code is 1 on any error; warnings (unknown variable in a notifier
template, ignored `mattermost_channel`) keep it at 0.

## Upgrading the .deb package

Before upgrading, validate the production configuration **with the new
binary** (extract it from the package or the static tarball), and read the
upgrade notes of the new version in [MIGRATION.md](../MIGRATION.md#upgrading-to-210).

```bash
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb
```

- **Restart.** The package restarts the service when it is active or enabled;
  no manual `systemctl restart` is needed. A service both stopped and disabled
  stays stopped; an enabled service you stopped on purpose is started again.
- **The upgrade can block for up to ~20 s.** The restart waits for the old
  process to [drain its queues](#shutdown-and-alert-drain). Do not interrupt
  it.
- **Startup check.** About two seconds after the restart, the package checks
  that the service is active. If it is not (typically an invalid
  configuration), it prints `WARNING: valerter failed to start after upgrade`
  and the upgrade still completes: read `journalctl -u valerter`, fix the
  configuration, then `sudo systemctl restart valerter`.
- **Configuration file prompt.** `/etc/valerter/config.yaml` is a conffile: if
  you modified it (you did), dpkg asks what to do with it. **Keep your version**
  (answer `N`, the default): answering `Y` replaces it with the example
  configuration (yours is saved as `config.yaml.dpkg-old`). For a
  non-interactive upgrade, keep it explicitly:

  ```bash
  sudo dpkg -i --force-confold valerter_latest_amd64.deb
  # or
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::=--force-confold ./valerter_latest_amd64.deb
  ```

  The new example is then written next to it as `config.yaml.dpkg-dist`.
- **From 2.0.3 or earlier**, the old package stops the service before the new
  one is installed: an enabled service is restarted, but a service started by
  hand without being enabled stays stopped (`sudo systemctl start valerter`).

Removal (`sudo dpkg -r valerter`) stops and disables the service and keeps the
configuration and the `valerter` user; `sudo dpkg --purge valerter` removes
them too.

## Containers

Use the static binary (`valerter-linux-x86_64.tar.gz` or `-aarch64`): it has no
runtime dependency. Run it in the foreground with the configuration mounted,
and give it **30 seconds** to stop, so that the
[drain](#shutdown-and-alert-drain) can finish before the runtime kills it:

```bash
docker stop --stop-timeout 30 valerter
```

```yaml
# docker-compose.yml
services:
  valerter:
    stop_grace_period: 30s
```

Docker's default of 10 seconds kills the process before the drain ends: queued
alerts are then lost. Installing the `.deb` in an image runs no `systemctl`
command (systemd is not the running init): start valerter the way your image
does.
