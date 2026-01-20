## Summary
What does this PR change?

## Checklist
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `cargo tarpaulin --fail-under 95` passes (if touching core modules)
- [ ] Tested with real VictoriaLogs instance (if streaming/tail changes)
- [ ] Ran `valerter --validate` with test config
- [ ] Documentation updated (if adding config options or notifiers)
- [ ] No secrets in configs/logs

## Component affected
- [ ] `tail.rs` - Streaming
- [ ] `parser.rs` - Regex/JSON extraction
- [ ] `throttle.rs` - Rate limiting
- [ ] `template.rs` - Minijinja rendering
- [ ] `notify/` - Notifiers (specify: mattermost / email / webhook)
- [ ] `config/` - Configuration
- [ ] `metrics.rs` - Prometheus
- [ ] `stream_buffer.rs` - UTF-8 buffering
- [ ] `engine.rs` - Rule orchestration
- [ ] `cli.rs` - CLI flags
- [ ] Other

## Notes
Anything reviewers should pay attention to?
