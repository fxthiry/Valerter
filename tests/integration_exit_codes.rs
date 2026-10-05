//! Integration tests for the daemon exit codes when nothing would be watched.
//!
//! A configuration whose rules are all disabled must be refused both by
//! `--validate` and at daemon startup, with exit code 1, so that systemd
//! (`Restart=on-failure`) restarts the unit and shows it as failed.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
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

/// Run valerter with `args`, killing it if it outlives `timeout`.
fn run_with_timeout(args: &[&str], timeout: Duration) -> Output {
    let mut child = Command::new(valerter_binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to run valerter");

    let start = Instant::now();
    loop {
        if child.try_wait().expect("Failed to poll valerter").is_some() {
            break;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let output = child.wait_with_output().expect("Failed to collect output");
            panic!(
                "valerter did not exit within {:?}\nstderr: {}",
                timeout,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("Failed to collect output")
}

#[test]
fn validate_all_rules_disabled_exits_failure() {
    let config = fixture_path("config_all_rules_disabled.yaml");

    let output = run_with_timeout(
        &["--validate", "-c", config.to_str().unwrap()],
        Duration::from_secs(10),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "valerter --validate should exit with code 1\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("all rules are disabled"),
        "stderr should explain that all rules are disabled: {}",
        stderr
    );
}

#[test]
fn daemon_all_rules_disabled_exits_failure_without_starting_engine() {
    let config = fixture_path("config_all_rules_disabled.yaml");

    let output = run_with_timeout(&["-c", config.to_str().unwrap()], Duration::from_secs(10));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "daemon should exit with code 1\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("all rules are disabled"),
        "stderr should explain that all rules are disabled: {}",
        stderr
    );
    assert!(
        !stderr.contains("valerter starting") && !stderr.contains("Rule engine started"),
        "the engine must not be started: {}",
        stderr
    );
}
