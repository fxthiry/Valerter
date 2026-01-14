# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/fxthiry/valerter/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-beta.1...v1.0.0-rc.1
[1.0.0-beta.1]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.2...v1.0.0-beta.1
[1.0.0-alpha.2]: https://github.com/fxthiry/valerter/compare/v1.0.0-alpha.1...v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/fxthiry/valerter/releases/tag/v1.0.0-alpha.1
