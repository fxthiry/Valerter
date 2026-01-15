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

Valerter streams logs from VictoriaLogs in real-time and sends alerts with the **actual log content** — not just aggregated statistics.

<p align="center">
  <img src="assets/svg/pipeline.svg" alt="Pipeline: VictoriaLogs → Parse → Throttle → Template → Notify" width="700">
</p>

## Why Valerter?

Unlike [vmalert](https://docs.victoriametrics.com/victorialogs/vmalert/) which evaluates queries periodically and returns aggregated statistics, Valerter provides **real-time, per-event alerting**:

| | vmalert | Valerter |
|---|---------|----------|
| **Mode** | Periodic queries | Real-time streaming |
| **API** | `/stats_query` | `/tail` |
| **Alert content** | Aggregated stats ("500 errors in 5min") | **Full log line with context** |
| **Latency** | Evaluation interval (e.g., 1min) | < 5 seconds |

**Use vmalert**: "More than 100 errors in the last 5 minutes"

**Use Valerter**: "Payment failed for user X: connection timeout to stripe.com"

## Features

- **Multi-channel notifications** — Webhook (PagerDuty, Slack, Discord), Email SMTP, Mattermost
- **Full log context** — Alerts include the actual log line and extracted fields
- **Intelligent throttling** — Avoid alert spam with per-key rate limiting
- **Real-time alerting** — Less than 5 seconds from log event to notification
- **Declarative rules** — YAML configuration with regex/JSON parsing
- **Prometheus metrics** — Built-in `/metrics` endpoint for monitoring

## Quick Start

```bash
# Install (Debian/Ubuntu)
curl -LO https://github.com/fxthiry/valerter/releases/latest/download/valerter_latest_amd64.deb
sudo dpkg -i valerter_latest_amd64.deb

# Configure
sudo vim /etc/valerter/config.yaml

# Start
sudo systemctl start valerter
sudo systemctl enable valerter
```

Minimal configuration:

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

## Documentation

- **[Getting Started](docs/getting-started.md)** — Installation and first setup
- **[Configuration](docs/configuration.md)** — Full configuration reference
- **[Notifiers](docs/notifiers.md)** — Webhook, Email, Mattermost setup
- **[Metrics](docs/metrics.md)** — Prometheus metrics and alerting rules
- **[Architecture](docs/architecture.md)** — How Valerter works
- **[Examples](examples/)** — Real-world configurations with screenshots

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
