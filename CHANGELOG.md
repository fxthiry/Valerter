# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.5...HEAD
[1.0.0-rc.5]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.4...v1.0.0-rc.5
[1.0.0-rc.4]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.3...v1.0.0-rc.4
[1.0.0-rc.3]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.2...v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-beta.1...v1.0.0-rc.1
[1.0.0-beta.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.2...v1.0.0-beta.1
[1.0.0-alpha.2]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.1...v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/fxthiry/valerter/releases/tag/v1.0.0-alpha.1
