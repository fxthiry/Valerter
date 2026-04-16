//! Consistency checks between `tests/fixtures/vl_events/index.yaml` and the
//! filesystem. This is the gate that keeps the corpus honest: no orphaned
//! files, no phantom entries, every fixture parses, every fixture carries the
//! VL-mandatory fields.

use std::collections::BTreeSet;

mod common;

use common::vl_events::{
    all_fixtures, filesystem_fixtures, load_fixtures_by_tag, manifest_entries,
};

/// Required top-level fields on every `/select/logsql/tail` event.
const REQUIRED_FIELDS: &[&str] = &["_msg", "_time", "_stream"];

#[test]
fn corpus_contains_at_least_fifteen_fixtures() {
    let count = manifest_entries().len();
    assert!(
        count >= 15,
        "spec requires at least 15 fixtures, found {}",
        count
    );
}

#[test]
fn index_and_filesystem_agree() {
    let index_names: BTreeSet<String> = manifest_entries().keys().cloned().collect();
    let disk_names: BTreeSet<String> = filesystem_fixtures().into_iter().collect();

    let orphans: Vec<&String> = disk_names.difference(&index_names).collect();
    let phantoms: Vec<&String> = index_names.difference(&disk_names).collect();

    assert!(
        orphans.is_empty(),
        "orphan fixtures on disk without an index.yaml entry: {:?}. \
         Either add them to tests/fixtures/vl_events/index.yaml or delete them.",
        orphans
    );
    assert!(
        phantoms.is_empty(),
        "phantom fixtures declared in index.yaml but missing on disk: {:?}. \
         Either create the file or remove the entry from index.yaml.",
        phantoms
    );
}

#[test]
fn every_fixture_parses_as_json() {
    // `all_fixtures()` already panics on parse error; this test just exercises
    // every file so CI surfaces the panic with a clear path.
    let loaded = all_fixtures();
    assert!(!loaded.is_empty(), "no fixtures discovered");
    for (name, value) in &loaded {
        assert!(
            value.is_object(),
            "fixture {} parsed but is not a JSON object (got {})",
            name,
            match value {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "bool",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
            }
        );
    }
}

#[test]
fn every_fixture_is_single_line_json() {
    // VL's /select/logsql/tail emits one event per line; the corpus must
    // mirror that shape so consumers can copy-paste fixtures into mocks.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vl_events");
    for name in filesystem_fixtures() {
        let path = dir.join(&name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        // Allow a single trailing newline (POSIX convention) but no embedded
        // newlines: the JSON payload itself must be on one line.
        let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
        assert!(
            !trimmed.contains('\n'),
            "fixture {} spans multiple lines. VL tail output is one JSON per \
             line; fixtures must match.",
            name
        );
    }
}

#[test]
fn every_fixture_has_required_vl_fields() {
    // Self-contained: do not assume parses_as_json ran first. `cargo test`
    // parallelises tests by default, so cross-test dependencies via panic
    // messages are unreliable.
    for (name, value) in all_fixtures() {
        let obj = value.as_object().unwrap_or_else(|| {
            panic!(
                "fixture {} is not a top-level JSON object (see also parses_as_json test)",
                name
            )
        });
        for field in REQUIRED_FIELDS {
            assert!(
                obj.contains_key(*field),
                "fixture {} is missing required VL field `{}`",
                name,
                field
            );
        }
        // _msg must be a non-empty string so the smoke test can render it.
        let msg = obj
            .get("_msg")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("fixture {} has non-string _msg", name));
        assert!(
            !msg.is_empty(),
            "fixture {} has empty _msg (not useful for template smoke tests)",
            name
        );
    }
}

#[test]
fn every_entry_has_description_source_and_tags() {
    for (name, entry) in manifest_entries() {
        assert!(
            !entry.description.trim().is_empty(),
            "fixture {} has an empty description",
            name
        );
        assert!(
            !entry.source_system.trim().is_empty(),
            "fixture {} has an empty source_system",
            name
        );
        assert!(
            !entry.tags.is_empty(),
            "fixture {} has no tags (require at least one for discoverability)",
            name
        );
    }
}

#[test]
fn tag_lookup_returns_empty_for_unknown() {
    // Contract from the spec: unknown tags yield an empty Vec, caller asserts.
    let hits = load_fixtures_by_tag("this_tag_does_not_exist_anywhere_xyz");
    assert!(hits.is_empty(), "expected empty result for unknown tag");
}

#[test]
fn dotted_keys_tag_is_populated() {
    // The corpus exists primarily to catch regressions like #25. If this
    // tag ever ends up empty, the smoke test below becomes a no-op.
    let hits = load_fixtures_by_tag("dotted_keys");
    assert!(
        !hits.is_empty(),
        "no fixtures tagged `dotted_keys` — the regression harness for #25 \
         would silently skip"
    );
}
