//! Integration tests for the graceful shutdown of the daemon.
//!
//! The real binary runs against a wiremock VictoriaLogs source and a wiremock
//! webhook, and receives real signals: on SIGTERM it drains its notification
//! queues before exiting, and a second SIGTERM forces an immediate exit.
//!
//! The tests synchronize on stderr log lines and on the requests received by
//! the mocks, never on fixed sleeps.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Upper bound for every wait of these tests (CI machines can be slow).
const WAIT: Duration = Duration::from_secs(30);

fn valerter_binary() -> PathBuf {
    // Built by cargo for integration tests (also under tarpaulin), no manual build needed.
    PathBuf::from(env!("CARGO_BIN_EXE_valerter"))
}

/// Write a config with one rule on `vl_url` notifying the webhook `hook_url`.
fn write_config(dir: &Path, vl_url: &str, hook_url: &str) -> PathBuf {
    let config = format!(
        r#"
victorialogs:
  default:
    url: "{vl_url}"

notifiers:
  hook:
    type: webhook
    url: "{hook_url}"

metrics:
  enabled: false

defaults:
  throttle:
    count: 100
    window: 60s

templates:
  default_alert:
    title: "shutdown test"
    body: "{{{{ _msg }}}}"

rules:
  - name: "shutdown_rule"
    query: "error"
    parser:
      regex: '(?P<message>.*)'
    notify:
      template: "default_alert"
      destinations:
        - "hook"
"#
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    path
}

/// VictoriaLogs source emitting `count` matching lines on its first tail
/// connection, then empty streams.
async fn start_vl(count: usize) -> MockServer {
    let server = MockServer::start().await;
    let body: String = (0..count)
        .map(|i| {
            format!(
                "{{\"_msg\":\"error line {i}\",\"_time\":\"2026-01-15T10:49:35.{i:03}Z\",\"_stream\":\"{{app=\\\"test\\\"}}\"}}\n"
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.into_bytes(), "application/x-ndjson"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/select/logsql/tail"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"", "application/x-ndjson"))
        .mount(&server)
        .await;
    server
}

/// Webhook answering every request after `delay`.
async fn start_webhook(delay: Duration) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_delay(delay))
        .mount(&server)
        .await;
    server
}

/// Running daemon with its stderr lines forwarded by a reader thread.
struct Daemon {
    child: Child,
    lines: mpsc::Receiver<String>,
    stderr: Vec<String>,
}

impl Daemon {
    fn start(config: &Path) -> Self {
        let mut child = Command::new(valerter_binary())
            .args(["-c", config.to_str().unwrap()])
            // `Alert enqueued` is a trace log of the queue.
            .env("RUST_LOG", "info,valerter::notify::queue=trace")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to run valerter");
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            stderr: Vec::new(),
        }
    }

    /// Wait until `count` stderr lines (in total) contain `needle`.
    fn wait_for_lines(&mut self, needle: &str, count: usize) {
        let deadline = Instant::now() + WAIT;
        while self.stderr.iter().filter(|l| l.contains(needle)).count() < count {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => self.stderr.push(line),
                Err(_) => {
                    let _ = self.child.kill();
                    panic!(
                        "{count} line(s) containing `{needle}` not seen\nstderr:\n{}",
                        self.stderr.join("\n")
                    );
                }
            }
        }
    }

    fn wait_for_line(&mut self, needle: &str) {
        self.wait_for_lines(needle, 1);
    }

    fn sigterm(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("Failed to run kill");
        assert!(status.success(), "kill -TERM failed");
    }

    /// Wait for the process to exit, then collect the rest of stderr.
    fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("Failed to poll valerter") {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.stderr.extend(self.lines.try_iter());
                panic!(
                    "valerter did not exit within {timeout:?}\nstderr:\n{}",
                    self.stderr.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // The reader thread ends at EOF, once the process is gone.
        self.stderr.extend(self.lines.iter());
        status
    }

    fn stderr(&self) -> String {
        self.stderr.join("\n")
    }

    /// Index of the first stderr line containing `needle`.
    fn position(&self, needle: &str) -> usize {
        self.stderr
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("`{needle}` not logged\nstderr:\n{}", self.stderr()))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn webhook_requests(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

#[tokio::test]
async fn sigterm_without_pending_alert_exits_immediately() {
    let vl = start_vl(0).await;
    let hook = start_webhook(Duration::ZERO).await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &vl.uri(), &format!("{}/hook", hook.uri()));

    let mut daemon = Daemon::start(&config);
    daemon.wait_for_line("Rule engine started");
    daemon.sigterm();
    let status = daemon.wait_exit(Duration::from_secs(5));

    let stderr = daemon.stderr();
    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert!(daemon.position("Received SIGTERM") < daemon.position("All rule tasks stopped"));
    assert!(
        daemon.position("All rule tasks stopped")
            < daemon.position("Waiting for notification worker to drain queue...")
    );
    assert!(
        daemon.position("Notification queue drained")
            < daemon.position("valerter shutdown complete")
    );
    assert!(!stderr.contains("Shutdown drain timeout reached"));
}

#[tokio::test]
async fn sigterm_delivers_queued_alerts_before_exiting() {
    const ALERTS: usize = 5;
    let vl = start_vl(ALERTS).await;
    let hook = start_webhook(Duration::from_secs(1)).await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &vl.uri(), &format!("{}/hook", hook.uri()));

    let mut daemon = Daemon::start(&config);
    // Every alert is queued; with a 1 s webhook, at most one is in flight.
    daemon.wait_for_lines("Alert enqueued", ALERTS);
    daemon.sigterm();
    let status = daemon.wait_exit(WAIT);

    let stderr = daemon.stderr();
    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(
        webhook_requests(&hook).await,
        ALERTS,
        "every queued alert must be delivered\nstderr:\n{stderr}"
    );
    assert!(
        daemon.position("All rule tasks stopped") < daemon.position("Notification queue drained")
    );
    assert!(
        daemon.position("Notification queue drained")
            < daemon.position("valerter shutdown complete")
    );
}

#[tokio::test]
async fn second_sigterm_forces_immediate_exit() {
    let vl = start_vl(1).await;
    let hook = start_webhook(Duration::from_secs(30)).await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &vl.uri(), &format!("{}/hook", hook.uri()));

    let mut daemon = Daemon::start(&config);
    // Wait for the alert to be in flight on the slow webhook.
    let deadline = Instant::now() + WAIT;
    while webhook_requests(&hook).await == 0 {
        assert!(
            Instant::now() < deadline,
            "webhook never called\nstderr:\n{}",
            daemon.stderr()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    daemon.sigterm();
    daemon.wait_for_line("Waiting for notification worker to drain queue...");
    let start = Instant::now();
    daemon.sigterm();
    let status = daemon.wait_exit(Duration::from_secs(5));
    let elapsed = start.elapsed();

    let stderr = daemon.stderr();
    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        elapsed < Duration::from_secs(2),
        "forced exit took {elapsed:?}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Second shutdown signal received, forcing immediate exit"),
        "stderr:\n{stderr}"
    );
    assert!(!stderr.contains("valerter shutdown complete"));
}
