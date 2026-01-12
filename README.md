# Valerter

Real-time log alerting for VictoriaLogs with full log context in notifications.

![CI](https://github.com/fxthiry/valerter/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/fxthiry/valerter/branch/main/graph/badge.svg)](https://codecov.io/gh/fxthiry/valerter)

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
- [Configuration](#configuration)
- [Usage](#usage)
- [Prometheus Metrics](#prometheus-metrics)
- [systemd Deployment](#systemd-deployment)
- [Contributing](#contributing)
- [License](#license)

## Installation

### From GitHub Releases

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

defaults:
  throttle:
    count: 5
    window: 60s
  notify:
    template: "default_alert"

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

This sends alerts to `MATTERMOST_WEBHOOK` environment variable (legacy mode).

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
notifiers:
  # Mattermost notifier
  mattermost-ops:
    type: mattermost
    webhook_url: "${MATTERMOST_WEBHOOK}"
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

### Environment Variables

Use `${VAR_NAME}` syntax in config for secrets:

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
| `valerter_alerts_dropped_total` | Counter | `rule_name` | Alerts dropped (queue full) |
| `valerter_notify_errors_total` | Counter | `rule_name`, `notifier_name`, `notifier_type` | Notification send errors |
| `valerter_parse_errors_total` | Counter | `rule_name` | Parsing errors (regex no-match, invalid JSON) |
| `valerter_reconnections_total` | Counter | `rule_name` | VictoriaLogs reconnections |
| `valerter_queue_size` | Gauge | - | Current notification queue size |

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

### Configuration

1. Edit configuration: `sudo vim /etc/valerter/config.yaml`
2. Set environment variables: `sudo vim /etc/valerter/environment`
3. Restart service: `sudo systemctl restart valerter`

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
