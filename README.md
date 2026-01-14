<p align="center">
  <img src="assets/svg/valerter-lockup-vertical.svg" alt="Valerter" height="180">
</p>

<p align="center">
  Real-time log alerting for VictoriaLogs with full log context in notifications.
</p>

<p align="center">
  <a href="https://github.com/fxthiry/valerter/actions/workflows/ci.yml"><img src="https://github.com/fxthiry/valerter/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/fxthiry/valerter"><img src="https://codecov.io/gh/fxthiry/valerter/branch/main/graph/badge.svg" alt="codecov"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust 1.85+">
</p>

## Features

- **Zero intrusion** - No modification to existing infrastructure required
- **Declarative rules** - YAML configuration with regex/JSON parsing, no hardcoded logic
- **Full log context** - Alerts include the actual log line and extracted fields, not just aggregated metrics
- **Multi-channel notifications** - Mattermost, Email SMTP, Generic Webhook (PagerDuty, Slack, etc.)
- **Intelligent throttling** - Avoid alert spam with configurable rate limiting per key
- **Real-time alerting** - Less than 5 seconds from log event to notification
- **Prometheus metrics** - Built-in `/metrics` endpoint for monitoring

## Table of Contents

- [Installation](#installation)
  - [Debian/Ubuntu (.deb)](#debianubuntu-deb)
  - [From GitHub Releases (Tarball)](#from-github-releases-tarball)
  - [From Sources](#from-sources)
- [Configuration](#configuration)
- [Usage](#usage)
- [Prometheus Metrics](#prometheus-metrics)
- [systemd Deployment](#systemd-deployment)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Debian/Ubuntu (.deb)

The easiest way to install on Debian-based systems:

```bash
# Download and install the latest release
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb
```

For ARM64 systems, use `valerter_latest_arm64.deb` instead.

The .deb package will:
1. Install binary to `/usr/bin/valerter`
2. Create `valerter` system user and group
3. Install systemd service to `/lib/systemd/system/`
4. Create config directory `/etc/valerter/` with example configuration

**Configuration is preserved during upgrades** - dpkg will prompt you if you've modified `/etc/valerter/config.yaml`.

To uninstall:
```bash
sudo dpkg -r valerter        # Remove (keeps config)
sudo dpkg --purge valerter   # Purge (removes everything)
```

### From GitHub Releases (Tarball)

Download and install the latest release:

```bash
# Download the latest release
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter-linux-x86_64.tar.gz

# Optional: Verify checksum
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/checksums-sha256.txt
sha256sum -c checksums-sha256.txt --ignore-missing

# Extract and install
tar -xzf valerter-linux-x86_64.tar.gz
cd valerter-linux-x86_64
sudo ./install.sh
```

The install script will:
1. Create `valerter` system user and group
2. Install binary to `/usr/local/bin/valerter`
3. Create config directory `/etc/valerter/`
4. Copy example configuration
5. Install and enable systemd service

### From Sources

```bash
# Clone repository
git clone https://github.com/fxthiry/valerter.git
cd valerter

# Build static binary (requires musl target)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Install
sudo ./scripts/install.sh
```

## Configuration

Valerter is configured via YAML file at `/etc/valerter/config.yaml`.

See [config/config.example.yaml](config/config.example.yaml) for a complete reference.

### Quick Start

Minimal configuration to get started:

```yaml
victorialogs:
  url: "http://victorialogs:9428"

# Define where to send alerts (recommended: direct value)
notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/your-webhook-id"

defaults:
  throttle:
    count: 5
    window: 60s
  notify:
    template: "default_alert"
    destinations:
      - mattermost-ops

templates:
  default_alert:
    title: "{{ title | default('Alert') }}"
    body: "{{ body }}"

rules:
  - name: "error_alert"
    query: '_stream:{app="myapp"} level:error'
    parser:
      regex: '(?P<message>.*)'
```

This example uses a direct webhook URL (recommended). See [Secrets Management](#secrets-management) for alternatives.

### Full Example

```yaml
# VictoriaLogs connection
victorialogs:
  url: "http://victorialogs:9428"
  # Optional: Basic Auth
  # basic_auth:
  #   username: "${VL_USER}"
  #   password: "${VL_PASS}"

# Prometheus metrics
metrics:
  enabled: true
  port: 9090

# Notifiers - define named notification channels
# Put secrets directly here (file is chmod 600) or use ${VAR} for orchestrators
notifiers:
  # Mattermost notifier (direct value - recommended)
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/abc123def456"
    channel: ops-alerts

  # Generic webhook (e.g., PagerDuty, Slack)
  pagerduty:
    type: webhook
    url: "https://events.pagerduty.com/v2/enqueue"
    headers:
      Authorization: "Token token=${PAGERDUTY_TOKEN}"
    body_template: |
      {
        "routing_key": "${PAGERDUTY_ROUTING_KEY}",
        "event_action": "trigger",
        "payload": {
          "summary": "{{ title }}",
          "source": "valerter",
          "severity": "error"
        }
      }

  # Email via SMTP
  email-ops:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
      username: "${SMTP_USER}"
      password: "${SMTP_PASSWORD}"
      tls: starttls
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "[{{ rule_name | upper }}] {{ title }}"

# Default settings
defaults:
  throttle:
    count: 5
    window: 60s
  notify:
    template: "default_alert"

# Message templates
templates:
  default_alert:
    title: "{{ title | default('Alert') }}"
    body: "{{ body }}"
    color: "#ff0000"

# Alert rules
rules:
  - name: "high_cpu_alert"
    enabled: true
    query: '_stream:{host="server1"} | json | cpu > 90'
    parser:
      json:
        fields: ["host", "cpu", "timestamp"]
    throttle:
      key: "{{ host }}"
      count: 3
      window: 5m
    notify:
      template: "default_alert"
      destinations:
        - mattermost-ops
        - email-ops
```

### Notifiers

Valerter supports three notifier types:

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `mattermost` | Mattermost incoming webhook | `webhook_url` |
| `webhook` | Generic HTTP endpoint | `url` |
| `email` | SMTP email | `smtp`, `from`, `to` |

**Mattermost:** Send alerts to Mattermost channels via incoming webhooks.

**Webhook:** Send alerts to any HTTP endpoint (PagerDuty, Slack, custom APIs). Supports custom headers and body templates.

**Email:** Send alerts via SMTP with TLS support (none, starttls, tls).

### Secrets Management

**Recommended:** Put all values (including secrets) directly in `/etc/valerter/config.yaml`. The file is secured with `chmod 600` (owner read/write only).

**Alternative (Kubernetes/Orchestrators):** Use `${VAR_NAME}` syntax in config for secrets that are injected as environment variables.

| Variable | Description |
|----------|-------------|
| `MATTERMOST_WEBHOOK` | Legacy webhook (backward compatible) |
| `VL_USER` | VictoriaLogs Basic Auth username |
| `VL_PASS` | VictoriaLogs Basic Auth password |
| `SMTP_USER` | SMTP authentication username |
| `SMTP_PASSWORD` | SMTP authentication password |
| `RUST_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `LOG_FORMAT` | Output format: `text` (default), `json` |

## Usage

### CLI Arguments

```
valerter [OPTIONS]

Options:
  -c, --config <PATH>  Path to configuration file [default: /etc/valerter/config.yaml]
      --validate       Validate configuration and exit
  -h, --help           Print help
  -V, --version        Print version
```

### Common Commands

```bash
# Validate configuration without starting
valerter --validate

# Run with custom config path
valerter -c /path/to/config.yaml

# Run with debug logging
RUST_LOG=debug valerter

# Run with JSON logs (for log aggregation)
LOG_FORMAT=json valerter
```

## Prometheus Metrics

When `metrics.enabled: true`, valerter exposes a `/metrics` endpoint on the configured port.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `valerter_alerts_sent_total` | Counter | `rule_name`, `notifier_name`, `notifier_type` | Alerts sent successfully |
| `valerter_alerts_throttled_total` | Counter | `rule_name` | Alerts blocked by throttling |
| `valerter_alerts_passed_total` | Counter | `rule_name` | Alerts that passed throttling (not blocked) |
| `valerter_alerts_dropped_total` | Counter | `rule_name` | Alerts dropped (queue full) |
| `valerter_alerts_failed_total` | Counter | `rule_name`, `notifier_name`, `notifier_type` | Alerts that permanently failed (all retries exhausted) |
| `valerter_logs_matched_total` | Counter | `rule_name` | Logs matched by rule (before throttling) |
| `valerter_notify_errors_total` | Counter | `rule_name`, `notifier_name`, `notifier_type` | Notification send errors |
| `valerter_parse_errors_total` | Counter | `rule_name`, `error_type` | Parsing errors (regex no-match, invalid JSON) |
| `valerter_reconnections_total` | Counter | `rule_name` | VictoriaLogs reconnections |
| `valerter_rule_panics_total` | Counter | `rule_name` | Rule task panics (auto-restarted) |
| `valerter_rule_errors_total` | Counter | `rule_name` | Fatal rule errors (non-recoverable) |
| `valerter_queue_size` | Gauge | - | Current notification queue size |
| `valerter_last_query_timestamp` | Gauge | `rule_name` | Unix timestamp of last successful query chunk |
| `valerter_victorialogs_up` | Gauge | `rule_name` | VictoriaLogs connection status (1=up, 0=down) |
| `valerter_uptime_seconds` | Gauge | - | Time since valerter started |
| `valerter_query_duration_seconds` | Histogram | `rule_name` | VictoriaLogs query latency (time to first chunk) |

### Example Prometheus Alerts

Use these alerting rules to monitor valerter itself:

```yaml
groups:
  - name: valerter
    rules:
      # Valerter not querying VictoriaLogs for 5 minutes
      - alert: ValerterNotQuerying
        expr: time() - valerter_last_query_timestamp > 300
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Valerter rule {{ $labels.rule_name }} not querying"

      # VictoriaLogs connection down
      - alert: ValerterVictoriaLogsDown
        expr: valerter_victorialogs_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Valerter lost connection to VictoriaLogs"

      # Alerts failing to send
      - alert: ValerterAlertsFailing
        expr: rate(valerter_alerts_failed_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Valerter alerts failing for {{ $labels.notifier_name }}"

      # Too many alerts throttled
      - alert: ValerterHighThrottleRate
        expr: rate(valerter_alerts_throttled_total[1h]) > 100
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "High throttle rate on rule {{ $labels.rule_name }}"
```

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'valerter'
    static_configs:
      - targets: ['localhost:9090']
```

## systemd Deployment

### Installation

The `install.sh` script handles systemd setup automatically:

```bash
sudo ./install.sh
```

To uninstall:

```bash
sudo ./uninstall.sh
```

### Service Management

```bash
# Start service
sudo systemctl start valerter

# Stop service
sudo systemctl stop valerter

# Check status
sudo systemctl status valerter

# Enable at boot
sudo systemctl enable valerter

# View logs
journalctl -u valerter -f

# View recent logs
journalctl -u valerter -n 100
```

### Post-Installation

1. Edit configuration: `sudo vim /etc/valerter/config.yaml`
2. Restart service: `sudo systemctl restart valerter`

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
