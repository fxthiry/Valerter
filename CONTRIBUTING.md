# Contributing to Valerter

Thank you for your interest in contributing to Valerter!

## Technical Overview

Valerter is built with these key technical choices:

- **Streaming VictoriaLogs** - Real-time connection to `/select/logsql/tail` API with HTTP chunked encoding
- **Async fan-out architecture** - One Tokio task per (rule, source) pair, so errors stay isolated to that pair
- **LRU throttling cache** - Moka cache with TTL for memory-bounded rate limiting
- **Jinja2 templating** - Minijinja for flexible message formatting
- **Resilience** - Auto-reconnect with exponential backoff, retry on failures
- **Static binary** - Musl compilation for zero runtime dependencies

## Development Prerequisites

- **Rust toolchain** (edition 2024) with musl target: `rustup target add x86_64-unknown-linux-musl`
- **Docker** (for SMTP integration tests with Mailhog)
- **cargo-tarpaulin** (optional, for coverage): `cargo install cargo-tarpaulin`

The minimum supported Rust version is 1.88 (`rust-version` in `Cargo.toml`).

With Nix, `nix develop` (or [direnv](https://direnv.net/) with the provided `.envrc`) gives a shell with the Rust toolchain, cargo-deb and cargo-tarpaulin. Without direnv, prefix the commands of this guide with `nix develop -c`, for example `nix develop -c cargo test`. Release builds (musl static binary, `.deb`) are produced by CI.

## Contribution Workflow

1. **Fork** the repository (external contributors) or **create a branch** directly (collaborators)
2. **Create a feature branch** from `main`: `git checkout -b feat/my-feature`
3. **Make your changes** and commit with [conventional commits](#commit-message-format)
4. **Push** and open a **Pull Request** against `main`
5. **Wait for review** - at least one approval is required
6. **CI must pass** - all checks (fmt, clippy, tests) must be green
7. Once approved, a maintainer will merge your PR

> **Note:** Direct pushes to `main` are disabled. All changes must go through a reviewed PR.

## Getting Started

```bash
# Clone the repository (or your fork)
git clone https://github.com/fxthiry/valerter.git
cd valerter

# Build
cargo build

# Run tests
cargo test
```

## Testing Strategy

The project uses three testing tiers:

1. **Unit tests** - Inline `#[cfg(test)] mod tests` in each module, run with `cargo test`
2. **Integration tests** - `tests/*.rs` with `wiremock` for HTTP mocking
3. **SMTP integration tests** - `tests/smtp_integration.rs`, marked `#[ignore]`, require Mailhog

Test fixtures are stored in `tests/fixtures/` (YAML, JSON samples).

### Running SMTP Integration Tests

```bash
# Start Mailhog
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Run SMTP tests (sequentially: they share the Mailhog inbox)
TEST_SMTP_HOST=localhost TEST_SMTP_PORT=1025 cargo test --test smtp_integration -- --ignored --test-threads=1
```

`TEST_SMTP_HOST` and `TEST_SMTP_PORT` default to `localhost` and `1025`. The tests read the received mail through the Mailhog API on port 8025 of `TEST_SMTP_HOST`.

## Code Quality Standards

CI (`.github/workflows/ci.yml`) runs these checks on every pull request, and all of them must pass:

```bash
# Formatting
cargo fmt --all -- --check

# Linting (warnings are errors)
cargo clippy -- -D warnings

# Tests, then the SMTP integration tests against a Mailhog service
cargo test
cargo test --test smtp_integration -- --ignored --test-threads=1
```

Running `cargo clippy --all-targets -- -D warnings` locally also lints the tests.

CI also measures coverage and uploads it to Codecov, without a minimum threshold:

```bash
cargo tarpaulin --timeout 120 --out xml --output-dir coverage --exclude-files 'tests/smtp_integration.rs'
```

The coverage target is 80%: new code should come with tests that keep the project at or above it.

## Documentation Site

The Markdown files of the repository are published at
<https://fxthiry.github.io/Valerter/> by `.github/workflows/pages.yml`
(Jekyll 4, `_config.yml`), on every push to `main`. Page content is never
rendered with Liquid, so Jinja examples (`{{ rule_name }}`, `{% if %}`) are
shown as written. To preview the site locally (no Ruby needed), run Docker
from the repository root and open <http://localhost:4000/Valerter/>:

```bash
docker run --rm -p 4000:4000 --user "$(id -u):$(id -g)" -e HOME=/tmp -e BUNDLE_PATH=/tmp/bundle \
  -v "$PWD":/site -w /site ruby:3.3 \
  sh -c 'bundle install && bundle exec jekyll serve --host 0.0.0.0'
```

## Naming Conventions

Following [RFC 430](https://rust-lang.github.io/rfcs/0430-finalizing-naming-conventions.html):

| Element | Convention | Example |
|---------|------------|---------|
| Types/Structs | `UpperCamelCase` | `RuleConfig` |
| Functions | `snake_case` | `process_log_line()` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_RETRIES` |
| Modules | `snake_case` | `stream_buffer` |

## Adding Features

### New Notifier Type

1. Create `src/notify/{notifier_name}.rs`
2. Implement the `Notifier` trait
3. Register in `src/notify/registry.rs`
4. Add the configuration struct and its `NotifierConfig` variant in `src/config/notifiers.rs`, and its checks in `Config::validate()` (`src/config/types.rs`)
5. Add unit tests inline and integration tests in `tests/`
6. Update `config/config.example.yaml` with example configuration

### New Metric

1. Add the metric description in `register_metric_descriptions()` (`src/metrics.rs`), and seed its series in `initialize_metrics()` so it is visible from startup
2. Use `valerter_` prefix and `{action}_{unit}` format
3. Include `rule_name` and `vl_source` labels for per-rule metrics
4. Update the metrics reference in [docs/metrics.md](docs/metrics.md)

## Pull Request Requirements

- [ ] All CI checks pass (fmt, clippy, tests)
- [ ] Conventional commit format: `feat(scope): description`, `fix(scope): description`
- [ ] Test coverage maintained or improved
- [ ] One feature/fix per PR
- [ ] Documentation updated if needed

### Commit Message Format

```
feat(notify): add Discord webhook notifier
fix(throttle): correct window calculation for edge cases
docs(readme): add Docker deployment section
chore(deps): update tokio to 1.48
```

## Architecture Guidelines

- **Error handling**: Use `thiserror` in modules, `anyhow` in main
- **Async**: Keep every queue bounded and never block the runtime
- **Logging**: Include `rule_name` and `vl_source` in spans for debugging
- **Testing**: Use `wiremock` for HTTP mocking, `MockEmailTransport` for SMTP

### Error Handling: Log and Continue

A rule task must keep watching its stream whatever a single log line or alert does:

- **Recoverable errors** are logged or counted, and the task moves on to the next line: a line that fails to parse is counted in `valerter_parse_errors_total` and skipped, a rule template that fails to render is replaced by a fallback message, and a full destination queue drops its oldest alert.
- **Stream errors** (connection failure, HTTP error, stream ended) are logged and the task reconnects to VictoriaLogs with exponential backoff.
- **Panics** in a rule task are caught by the engine (`src/engine.rs`), logged and counted in `valerter_rule_panics_total`, and the task is restarted after a backoff delay (5 s, doubled per consecutive panic, capped at 5 min).
- **A fatal error** returned by a rule task stops that (rule, source) pair only; the other tasks keep running. When no task is left, the engine returns an error to `main`.
- **Fatal errors in `main`** (invalid configuration, notifier setup failure, engine error) are logged once and the process exits with code 1.

Delivery failures follow the same idea: each destination has its own queue and delivery task (`src/notify/queue.rs`), so a failing notifier only delays or loses its own alerts.

### Critical Anti-Patterns (DO NOT USE)

| Anti-Pattern | Risk | Use Instead |
|--------------|------|-------------|
| `.unwrap()` in spawned tasks | Task panic and restart, alerts missed meanwhile | Log error + continue pattern |
| Unbounded queue or channel | OOM risk | Bounded queue with an explicit overflow policy, like the per-destination `VecDeque` of `src/notify/queue.rs` (100 alerts, oldest dropped when full) |
| `std::thread::sleep` | Blocks async runtime | `tokio::time::sleep` |
| Span without `rule_name` | Impossible to debug | Always include rule and source context |

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
