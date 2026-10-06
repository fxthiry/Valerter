//! Warning logged when a dotted key has too many segments to be unflattened.
//!
//! Kept in its own test binary: `capture_logs` asserts on a log line emitted
//! by a shared callsite, which other tests running in parallel in the same
//! binary could register while no capturing subscriber exists, hiding it from
//! the capture.

mod common;

use common::logs::capture_logs;
use valerter::AlertPayload;

#[test]
fn too_many_segments_warns_with_a_truncated_key() {
    let key = vec!["a"; 20_000].join(".");
    let fields = serde_json::json!({ key.clone(): 1 });

    let (logs, guard) = capture_logs(tracing::Level::WARN);
    let log = AlertPayload::log_from_fields(&fields);
    drop(guard);
    let logs = logs.text();

    assert_eq!(log.len(), Some(1), "the key stays flat");
    assert!(
        logs.contains("skipping dotted-key expansion: too many segments"),
        "{logs}"
    );
    assert!(logs.contains("segments=20000"), "{logs}");
    // The key is truncated to 128 bytes in the log.
    assert!(logs.contains(&key[..128]), "{logs}");
    assert!(!logs.contains(&key[..129]), "{} bytes logged", logs.len());
}
