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

## What is Valerter?

Valerter streams logs from VictoriaLogs in real-time and sends notifications with the actual log line plus extracted context (host, site, service, port, user, etc.). The goal is to put the key debugging context in the alert itself (full log line + fields), so you can start investigating right away.

<p align="center">
  <img src="assets/svg/pipeline.svg" alt="Pipeline: VictoriaLogs → Parse → Throttle → Template → Notify" width="700">
</p>

## Why Valerter?

Some alerts are about trends ("how many errors over 5 minutes"). Others are about a **critical event that just happened** and requires immediate action.

Valerter is built for the second category: must-not-miss events where you want the full raw log line and enough context to act immediately—without jumping into a log explorer first.

### When Valerter is the right tool

Use Valerter when the question is:
- "Do I need to act on this immediately?"
- "What exactly happened (full log line) and where?"

**Examples:**
- "BPDU Guard triggered: port disabled on CORE-SW-01 Gi1/0/24"
- "Disk I/O error on db-prod-01: sda sector 22563104"
- "OOM killer on worker-03: killed process nginx (pid 2603)"

|                      | Valerter                          |
| -------------------- | --------------------------------- |
| **Mode**             | Real-time streaming               |
| **VictoriaLogs API** | `/tail`                           |
| **Alert content**    | Full log line + extracted context |
| **Typical latency**  | < 5 seconds                       |

See [Cisco Switches example](examples/cisco-switches/) for a complete implementation.

## Features

- **Multi-channel notifications** — Webhook (PagerDuty, Slack, Discord), Email SMTP, Mattermost
- **Full log context** — Alerts include the actual log line and extracted fields
- **Intelligent throttling** — Avoid alert spam with per-key rate limiting
- **Real-time alerting** — Less than 5 seconds from log event to notification
- **Declarative rules** — YAML configuration with regex/JSON parsing
- **Multi-file config** — Split rules/templates/notifiers across `rules.d/`, `templates.d/`, `notifiers.d/`
- **Prometheus metrics** — Built-in `/metrics` endpoint for monitoring

## Quick Start

### Debian/Ubuntu (.deb)

```bash
# Install
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb

# Configure
sudo vim /etc/valerter/config.yaml

# Start
sudo systemctl start valerter
sudo systemctl enable valerter
```

### Static Binary

```bash
# Download (x86_64, or aarch64 for ARM)
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter-linux-x86_64.tar.gz
tar -xzf valerter-linux-x86_64.tar.gz
cd valerter-linux-x86_64

# Validate and run
./valerter --validate -c config.example.yaml
./valerter -c config.example.yaml
```

> For production installation with systemd, see [Getting Started](docs/getting-started.md).

Example configuration:

```yaml
victorialogs:
  url: "http://victorialogs:9428"

notifiers:
  mattermost-ops:
    type: mattermost
    webhook_url: "https://mattermost.example.com/hooks/your-webhook-id"

defaults:
  throttle:
    count: 5
    window: 60s
  timestamp_timezone: "UTC"

templates:
  error_alert:
    title: "Error detected"
    body: "{{ _msg }}"

rules:
  - name: "error_logs"
    query: '_msg:~"(error|failed|critical)"'
    parser:
      regex: '(?P<message>.*)'
    notify:
      template: "error_alert"
      destinations:
        - "mattermost-ops"
```

## Documentation

- **[Getting Started](docs/getting-started.md)** — Installation and first setup
- **[Configuration](docs/configuration.md)** — Full configuration reference
- **[Notifiers](docs/notifiers.md)** — Webhook, Email, Mattermost setup
- **[Metrics](docs/metrics.md)** — Prometheus metrics and alerting rules
- **[Performance](docs/performance.md)** — Benchmarks and capacity planning
- **[Architecture](docs/architecture.md)** — How Valerter works
- **[Examples](examples/)** — Real-world configurations

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
