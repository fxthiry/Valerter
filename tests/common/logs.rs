//! Capture of `tracing` output in integration tests.
//!
//! Same model as `CapturedLogs` in `src/notify/mattermost.rs`. The subscriber
//! is installed for the current thread only: use it from a `#[tokio::test]`
//! (current-thread runtime) and keep the returned guard alive.

use std::sync::{Arc, Mutex};

use tracing::subscriber::DefaultGuard;

/// Log lines written by `tracing` during a test.
#[derive(Clone, Default)]
pub struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    /// Everything logged so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Captures every event at `level` or above on the current thread until the
/// guard is dropped.
pub fn capture_logs(level: tracing::Level) -> (CapturedLogs, DefaultGuard) {
    let logs = CapturedLogs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(level)
        .finish();
    (logs, tracing::subscriber::set_default(subscriber))
}
