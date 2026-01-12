# Contributing to Valerter

Thank you for your interest in contributing to Valerter!

## Technical Overview

Valerter is built with these key technical choices:

- **Streaming VictoriaLogs** - Real-time connection to `/select/logsql/tail` API with HTTP chunked encoding
- **Async fan-out architecture** - Each alert rule runs as independent Tokio task, errors are isolated
- **LRU throttling cache** - Moka cache with TTL for memory-bounded rate limiting
- **Jinja2 templating** - Minijinja for flexible message formatting
- **Resilience** - Auto-reconnect with exponential backoff, retry on failures
- **Static binary** - Musl compilation for zero runtime dependencies

## Development Prerequisites

- **Rust toolchain** (edition 2024) with musl target: `rustup target add x86_64-unknown-linux-musl`
- **Docker** (for SMTP integration tests with Mailhog)
- **cargo-tarpaulin** (optional, for coverage): `cargo install cargo-tarpaulin`

## Getting Started

```bash
# Clone the repository
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
3. **SMTP integration tests** - Require Mailhog, run with `cargo test --ignored`

Test fixtures are stored in `tests/fixtures/` (YAML, JSON samples).

### Running SMTP Integration Tests

```bash
# Start Mailhog
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Run SMTP tests
TEST_SMTP_HOST=localhost TEST_SMTP_PORT=1025 cargo test --ignored
```

## Code Quality Standards

All submissions must pass:

```bash
# Formatting
cargo fmt --check

# Linting (warnings are errors)
cargo clippy -- -D warnings

# Tests
cargo test

# Coverage (target: 80%)
cargo tarpaulin --fail-under 80
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
4. Add configuration parsing in `src/config.rs`
5. Add unit tests inline and integration tests in `tests/`
6. Update `config/config.example.yaml` with example configuration

### New Metric

1. Add metric definition in `src/metrics.rs`
2. Use `valerter_` prefix and `{action}_{unit}` format
3. Include `rule_name` label for per-rule metrics
4. Update README.md metrics table

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
- **Async**: Always use bounded channels (`channel(100)`), never block the runtime
- **Logging**: Include `rule_name` in spans for debugging
- **Testing**: Use `wiremock` for HTTP mocking, `MockEmailTransport` for SMTP

### Critical Anti-Patterns (DO NOT USE)

| Anti-Pattern | Risk | Use Instead |
|--------------|------|-------------|
| `.unwrap()` in spawned tasks | Silent crash | Log error + continue pattern |
| `unbounded_channel()` | OOM risk | `channel(100)` bounded |
| `std::thread::sleep` | Blocks async runtime | `tokio::time::sleep` |
| Span without `rule_name` | Impossible to debug | Always include rule context |

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
