//! Integration tests for the --validate CLI mode.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

static BUILD_ONCE: Once = Once::new();

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn valerter_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("valerter")
}

/// Build the binary once for all tests (Fix M2)
fn ensure_binary_built() {
    BUILD_ONCE.call_once(|| {
        let status = Command::new("cargo")
            .args(["build", "--bin", "valerter"])
            .status()
            .expect("Failed to build valerter");
        assert!(status.success(), "Failed to build valerter");
    });
}

// Test 6.5: --validate with valid config exits with code 0
#[test]
fn validate_valid_config_exits_success() {
    ensure_binary_built();

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
        stdout.contains("VictoriaLogs URL"),
        "Output should show VictoriaLogs URL: {}",
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
}

// Test 6.6: --validate with invalid config exits with code 1
#[test]
fn validate_invalid_regex_exits_failure() {
    ensure_binary_built();

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
    ensure_binary_built();

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
    ensure_binary_built();

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

// Test: email destination with template missing body_html fails startup
// This validates AC2: fail-fast validation prevents runtime errors
// Note: This test runs valerter normally (not --validate) because the body_html
// validation happens after config compilation when creating the NotifierRegistry.
#[test]
fn validate_email_missing_body_html_exits_failure() {
    ensure_binary_built();

    let output = Command::new(valerter_binary())
        .args(["-c"])
        .arg(fixture_path("config_email_missing_body_html.yaml"))
        .output()
        .expect("Failed to run valerter");

    assert!(
        !output.status.success(),
        "valerter should exit with non-zero code for email destination without body_html"
    );

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 1,
        "Exit code should be 1 for missing body_html validation failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("body_html"),
        "Error message should mention body_html requirement: {}",
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
    ensure_binary_built();

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
    ensure_binary_built();

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
    ensure_binary_built();

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

// Test: --validate with minimal config (README example) passes
#[test]
fn validate_minimal_config_exits_success() {
    ensure_binary_built();

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
