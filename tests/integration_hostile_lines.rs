//! Integration test: a hostile log line cannot stop the daemon.
//!
//! The real binary runs against a wiremock VictoriaLogs source emitting one
//! line built to overflow a recursive walk: a dotted key of 20,000 segments
//! and a `_msg` of 20,000 nested emphasis delimiters, inserted with `| safe`
//! and `codeblock` in a Markdown body. A stack overflow aborts the process
//! (no panic, no supervision): the alert must instead reach both webhooks and
//! the daemon must still stop cleanly on SIGTERM.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Upper bound for every wait of this test (CI machines can be slow).
const WAIT: Duration = Duration::from_secs(30);

/// Segments of the dotted key, and emphasis delimiters on each side of `_msg`.
const DEPTH: usize = 20_000;

fn valerter_binary() -> PathBuf {
    // Built by cargo for integration tests (also under tarpaulin), no manual build needed.
    PathBuf::from(env!("CARGO_BIN_EXE_valerter"))
}

/// Write a config with one Markdown rule on `vl_url` notifying two webhooks,
/// one per rendering (`html`, `markdown`).
fn write_config(dir: &Path, vl_url: &str, hook_url: &str) -> PathBuf {
    let config = format!(
        r#"
victorialogs:
  default:
    url: "{vl_url}"

notifiers:
  hook-html:
    type: webhook
    url: "{hook_url}/html"
    format: html
  hook-md:
    type: webhook
    url: "{hook_url}/md"
    format: markdown

metrics:
  enabled: false

defaults:
  throttle:
    count: 100
    window: 60s

templates:
  hostile:
    title: "hostile line"
    body_format: markdown
    body: "{{{{ _msg | safe }}}}\n- {{{{ _msg | codeblock }}}}"

rules:
  - name: "hostile_rule"
    query: "error"
    parser:
      regex: '(?P<message>.*)'
    notify:
      template: "hostile"
      destinations:
        - "hook-html"
        - "hook-md"
"#
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    path
}

/// VictoriaLogs source emitting the hostile line on its first tail
/// connection, then empty streams.
async fn start_vl() -> MockServer {
    let mut line = serde_json::Map::new();
    line.insert(
        "_msg".to_string(),
        format!("{}a{}", "*".repeat(DEPTH), "*".repeat(DEPTH)).into(),
    );
    line.insert("_time".to_string(), "2026-01-15T10:49:35.000Z".into());
    line.insert("_stream".to_string(), "{app=\"test\"}".into());
    line.insert(vec!["a"; DEPTH].join("."), "x".into());
    let body = format!("{}\n", serde_json::Value::Object(line));

    let server = MockServer::start().await;
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

async fn start_webhooks() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
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
            .env("RUST_LOG", "info")
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

    fn stderr(&mut self) -> String {
        self.stderr.extend(self.lines.try_iter());
        self.stderr.join("\n")
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
                panic!(
                    "valerter did not exit within {timeout:?}\nstderr:\n{}",
                    self.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // The reader thread ends at EOF, once the process is gone.
        self.stderr.extend(self.lines.iter());
        status
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bodies received on `path`.
async fn bodies(server: &MockServer, path: &str) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == path)
        .map(|r| serde_json::from_slice(&r.body).expect("webhook body is JSON"))
        .collect()
}

#[tokio::test]
async fn hostile_line_is_delivered_and_the_daemon_survives() {
    let vl = start_vl().await;
    let hooks = start_webhooks().await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &vl.uri(), &hooks.uri());

    let mut daemon = Daemon::start(&config);
    let deadline = Instant::now() + WAIT;
    while bodies(&hooks, "/html").await.is_empty() || bodies(&hooks, "/md").await.is_empty() {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            panic!(
                "valerter exited with {status}\nstderr:\n{}",
                daemon.stderr()
            );
        }
        assert!(
            Instant::now() < deadline,
            "the alert never reached both webhooks\nstderr:\n{}",
            daemon.stderr()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    for path in ["/html", "/md"] {
        let body = &bodies(&hooks, path).await[0]["body"];
        let body = body.as_str().expect("body is a string");
        assert!(
            body.contains('a'),
            "{path}: {}",
            &body[..body.len().min(200)]
        );
    }
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "the daemon must still run\nstderr:\n{}",
        daemon.stderr()
    );

    daemon.sigterm();
    let status = daemon.wait_exit(WAIT);
    let stderr = daemon.stderr();
    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert!(
        stderr.contains("skipping dotted-key expansion: too many segments"),
        "stderr:\n{stderr}"
    );
}
