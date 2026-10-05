//! Integration tests for the --validate CLI mode.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn valerter_binary() -> PathBuf {
    // Built by cargo for integration tests (also under tarpaulin), no manual build needed.
    PathBuf::from(env!("CARGO_BIN_EXE_valerter"))
}

/// Run `valerter --validate -c <fixture>` with extra environment variables.
fn run_validate(fixture: &str, envs: &[(&str, &str)]) -> Output {
    Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path(fixture))
        .envs(envs.iter().copied())
        .output()
        .expect("Failed to run valerter")
}

/// Assert that the preflight refused the configuration: exit code 1, no summary
/// on stdout, and the configuration itself passed `Config::validate()`.
fn assert_preflight_failure(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "valerter --validate should exit with code 1\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.is_empty(),
        "stdout should be empty on failure, got: {}",
        stdout
    );
    assert!(
        !stderr.contains("Configuration validation error"),
        "fixture should pass Config::validate() and fail only the preflight: {}",
        stderr
    );
    stderr
}

// Test 6.5: --validate with valid config exits with code 0
#[test]
fn validate_valid_config_exits_success() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_valid.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        output.status.success(),
        "valerter --validate should exit with code 0 for valid config\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Fix M3: Verify detailed success message content
    assert!(
        stdout.contains("Configuration is valid"),
        "Output should indicate valid config: {}",
        stdout
    );
    assert!(
        stdout.contains("VictoriaLogs sources"),
        "Output should show VictoriaLogs sources summary: {}",
        stdout
    );
    assert!(
        stdout.contains("Rules:"),
        "Output should show rules count: {}",
        stdout
    );
    assert!(
        stdout.contains("Templates:"),
        "Output should show templates count: {}",
        stdout
    );

    // Summary lines, in the order required by the cli spec.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            format!(
                "Configuration is valid: {}",
                fixture_path("config_valid.yaml").display()
            )
            .as_str(),
            "  VictoriaLogs sources: 1 [default=http://victorialogs:9428]",
            "  Rules: 3 (2 enabled)",
            "  Templates: 2",
            "  Notifiers: 1 [default-mattermost=mattermost]",
            "  Metrics: enabled (port 9090)",
        ]
    );
}

// Test 6.6: --validate with invalid config exits with code 1
#[test]
fn validate_invalid_regex_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_invalid_regex.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter --validate should exit with non-zero code for invalid config"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 1, "Exit code should be 1 for validation failure");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid_regex_rule") || stderr.contains("regex"),
        "Error message should mention the problematic rule: {}",
        stderr
    );
}

// Test: --validate with invalid template exits with code 1
#[test]
fn validate_invalid_template_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_invalid_template.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter --validate should exit with non-zero code for invalid template"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 1);
}

// Test AC #3: --validate with disabled rule containing invalid regex exits with code 1 (Fix H2)
#[test]
fn validate_disabled_rule_with_invalid_regex_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_disabled_invalid.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter --validate should exit with non-zero code even for disabled rules with invalid regex (AD-11)"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 1,
        "Exit code should be 1 for validation failure on disabled rule"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("disabled_invalid_rule"),
        "Error message should mention the disabled rule with invalid regex: {}",
        stderr
    );
}

// Test: email destination with template missing email_body_html fails startup
// This validates AC2: fail-fast validation prevents runtime errors
// Note: This test runs valerter normally (not --validate) to cover the real daemon
// startup; `validate_mode_email_missing_email_body_html_exits_failure` covers --validate.
#[test]
fn validate_email_missing_email_body_html_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["-c"])
        .arg(fixture_path("config_email_missing_email_body_html.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter should exit with non-zero code for email destination without email_body_html"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 1,
        "Exit code should be 1 for missing email_body_html validation failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("email_body_html"),
        "Error message should mention email_body_html requirement: {}",
        stderr
    );
    assert!(
        stderr.contains("email"),
        "Error message should mention email destination: {}",
        stderr
    );
}

// Test: --validate with config missing notifiers exits with code 1
#[test]
fn validate_no_notifiers_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_no_notifier.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter --validate should exit with non-zero code for config without notifiers"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 1,
        "Exit code should be 1 for missing notifiers validation failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no notifiers configured"),
        "Error message should mention no notifiers configured: {}",
        stderr
    );
}

// Test: --validate with config missing templates exits with code 1
#[test]
fn validate_no_templates_exits_failure() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_no_template.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter --validate should exit with non-zero code for config without templates"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 1,
        "Exit code should be 1 for missing templates validation failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no templates defined"),
        "Error message should mention no templates defined: {}",
        stderr
    );
}

// Test: MATTERMOST_WEBHOOK env var is no longer used (breaking change)
// Config without notifiers should fail even if MATTERMOST_WEBHOOK is set
#[test]
fn validate_mattermost_env_var_ignored() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_no_notifier.yaml"))
        .env(
            "MATTERMOST_WEBHOOK",
            "https://mattermost.example.com/hooks/test",
        )
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "Config without notifiers should fail even with MATTERMOST_WEBHOOK env var set"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no notifiers configured"),
        "Error should mention 'no notifiers configured', got: {}",
        stderr
    );
}

// Test: shipped config/config.example.yaml passes --validate
// Locks the canonical example against future schema drift.
#[test]
fn shipped_config_example_validates() {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("config.example.yaml");

    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(&config_path)
        .output()
        .expect("Failed to run valerter");

    assert!(
        output.status.success(),
        "shipped config '{}' must pass --validate (exit 0)\nstdout: {}\nstderr: {}",
        config_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// Test: every shipped examples/<name>/config.yaml passes --validate
// Iterates so new example folders are picked up automatically.
// Sets placeholder env vars so examples that reference ${...} secrets validate
// without hitting the network (--validate does not actually call any backend).
#[test]
fn shipped_examples_pass_validate() {
    let examples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");

    let entries = std::fs::read_dir(&examples_dir).expect("Failed to read examples/ directory");

    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.expect("Failed to read examples/ entry");
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let config_path = path.join("config.yaml");
        if !config_path.exists() {
            continue;
        }

        let output = Command::new(valerter_binary())
            .args(["--validate", "-c"])
            .arg(&config_path)
            // Placeholders for examples that reference ${VAR} secrets.
            // --validate does not perform any network call, so values can be dummies.
            .env("WEBHOOK_URL", "https://mattermost.example.com/hooks/dummy")
            .env("VL_PROD_USER", "dummy_user")
            .env("VL_PROD_PASS", "dummy_pass")
            .env("VL_PROD_TOKEN", "dummy_token")
            .env("SMTP_USER", "dummy_smtp_user")
            .env("SMTP_PASSWORD", "dummy_smtp_pass")
            .env("TELEGRAM_BOT_TOKEN", "dummy_bot_token")
            .output()
            .expect("Failed to run valerter");

        assert!(
            output.status.success(),
            "shipped example '{}' must pass --validate (exit 0)\nstdout: {}\nstderr: {}",
            config_path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        checked += 1;
    }

    assert!(
        checked >= 1,
        "expected at least one examples/<name>/config.yaml to validate, found 0 in {}",
        examples_dir.display()
    );
}

// Test: --validate with minimal config (README example) passes
#[test]
fn validate_minimal_config_exits_success() {
    let output = Command::new(valerter_binary())
        .args(["--validate", "-c"])
        .arg(fixture_path("config_minimal.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        output.status.success(),
        "valerter --validate should exit with code 0 for minimal config (README example)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Configuration is valid"),
        "Output should indicate valid config: {}",
        stdout
    );
}

// Test: --validate rejects a rule targeting an undeclared notifier
#[test]
fn validate_unknown_destination_exits_failure() {
    let output = run_validate("config_unknown_destination.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Destination validation error"),
        "stderr should log a destination validation error: {}",
        stderr
    );
    assert!(
        stderr.contains("rule 'r': unknown notifier 'nope'"),
        "stderr should name the rule and the unknown notifier: {}",
        stderr
    );
    assert!(
        stderr.contains("Destination validation failed: 1 errors"),
        "stderr should end with the startup failure message: {}",
        stderr
    );
}

// Test: --validate resolves notifier environment variables
#[test]
fn validate_notifier_undefined_env_var_exits_failure() {
    let output = run_validate("config_notifier_undefined_env.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Notifier configuration error"),
        "stderr should log a notifier configuration error: {}",
        stderr
    );
    assert!(
        stderr.contains(
            "invalid notifier 'mattermost-ops': webhook_url: invalid configuration: \
             undefined environment variable: VALERTER_TEST_UNSET_VAR"
        ),
        "stderr should report the undefined variable: {}",
        stderr
    );
    assert!(
        stderr.contains("Failed to create notifiers: 1 errors"),
        "stderr should end with the startup failure message: {}",
        stderr
    );
}

// Test: --validate reads the email body_template_file
#[test]
fn validate_missing_body_template_file_exits_failure() {
    let output = run_validate("config_email_missing_body_template_file.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Notifier configuration error"),
        "stderr should log a notifier configuration error: {}",
        stderr
    );
    assert!(
        stderr.contains("body_template_file not found"),
        "stderr should report the missing body_template_file: {}",
        stderr
    );
}

// Test: --validate checks email_body_html for email destinations
#[test]
fn validate_mode_email_missing_email_body_html_exits_failure() {
    let output = run_validate("config_email_missing_email_body_html.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Email template validation error"),
        "stderr should log an email template validation error: {}",
        stderr
    );
    assert!(
        stderr.contains(
            "template 'alert' requires email_body_html field when used with \
             email destination 'email-alerts' (rule 'error_alert')"
        ),
        "stderr should name the template, destination and rule: {}",
        stderr
    );
}

// Test: --validate reports errors from several preflight stages in one pass
#[test]
fn validate_reports_errors_from_every_stage() {
    let output = run_validate("config_multi_stage_errors.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("undefined environment variable: VALERTER_TEST_UNSET_VAR"),
        "stderr should report the notifier error: {}",
        stderr
    );
    assert!(
        stderr.contains("rule 'r': unknown notifier 'nope'"),
        "stderr should report the unknown destination: {}",
        stderr
    );
    assert!(
        !stderr.contains("unknown notifier 'mattermost-ops'")
            && !stderr.contains("'mattermost-ops', 'nope'"),
        "a declared notifier that failed to build must not be reported as unknown: {}",
        stderr
    );
}

// Test: --validate emits the mattermost_channel warning and still succeeds
#[test]
fn validate_warns_unused_mattermost_channel() {
    let output = run_validate("config_mattermost_channel_unused.yaml", &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "a warning must not fail --validate\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("mattermost_channel ignored - no mattermost notifier in destinations"),
        "stderr should warn about the ignored mattermost_channel: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("  Notifiers: 1 [webhook-ops=webhook]"),
        "stdout should list notifiers with their type: {}",
        stdout
    );
}

// Test: --validate redacts credentials and query strings of source URLs
#[test]
fn validate_redacts_source_url_secrets() {
    let output = run_validate(
        "config_source_url_secrets.yaml",
        &[
            ("VL_USER", "dummyvluser"),
            ("VL_PASS", "dummyvlpass"),
            ("VL_TOKEN", "dummyvltoken"),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "valerter --validate should succeed\nstderr: {}",
        stderr
    );
    assert!(
        stdout.contains(
            "  VictoriaLogs sources: 2 [default=http://localhost:9428, \
             prod=http://***@vl.invalid:9428/?***]"
        ),
        "source URLs should be redacted (plain URL untouched): {}",
        stdout
    );
    assert!(
        stdout.contains("  Notifiers: 2 [email-ops=email, mattermost-ops=mattermost]"),
        "stdout should list notifiers sorted by name: {}",
        stdout
    );
    for leaked in ["dummyvluser", "dummyvlpass", "dummyvltoken", "token="] {
        assert!(
            !stdout.contains(leaked) && !stderr.contains(leaked),
            "'{}' must not appear in the output\nstdout: {}\nstderr: {}",
            leaked,
            stdout,
            stderr
        );
    }
}

// Test: --validate makes no network call (every host is unresolvable)
#[test]
fn validate_makes_no_network_call() {
    let start = Instant::now();
    let output = run_validate(
        "config_source_url_secrets.yaml",
        &[
            ("VL_USER", "dummyvluser"),
            ("VL_PASS", "dummyvlpass"),
            ("VL_TOKEN", "dummyvltoken"),
        ],
    );
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "valerter --validate should succeed against unreachable hosts\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "--validate took {:?}, it should not attempt any connection",
        elapsed
    );
}

// Test: --validate render-tests notifier body templates (preflight)
#[test]
fn validate_webhook_body_template_unknown_filter_exits_failure() {
    let output = run_validate("config_webhook_body_template_unknown_filter.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Notifier configuration error"),
        "stderr should log a notifier configuration error: {}",
        stderr
    );
    assert!(
        stderr.contains("invalid notifier 'wh': body_template render:"),
        "stderr should report the body_template render error: {}",
        stderr
    );
    assert!(
        stderr.contains("nosuchfilter"),
        "stderr should name the unknown filter: {}",
        stderr
    );
}

// Test: --validate rejects an unsupported Telegram parse_mode (preflight)
#[test]
fn validate_telegram_unsupported_parse_mode_exits_failure() {
    let output = run_validate("config_telegram_unsupported_parse_mode.yaml", &[]);
    let stderr = assert_preflight_failure(&output);

    assert!(
        stderr.contains("Notifier configuration error"),
        "stderr should log a notifier configuration error: {}",
        stderr
    );
    assert!(
        stderr.contains(
            "invalid notifier 'tg': parse_mode 'Markdown2' is not supported \
             (expected HTML, MarkdownV2 or Markdown)"
        ),
        "stderr should report the unsupported parse_mode: {}",
        stderr
    );
}
