//! Loader for the versioned VictoriaLogs event fixture corpus.
//!
//! Fixtures live under `tests/fixtures/vl_events/*.json`, one anonymised
//! one-line JSON event per file. `index.yaml` in the same directory is the
//! authoritative manifest: it documents each fixture (description,
//! `source_system`, `tags`, `prevents_regression_for`).
//!
//! The manifest is parsed once per test crate via `OnceLock`.
//!
//! # Panics
//!
//! Helpers panic aggressively on misuse (missing fixture file, fixture not
//! listed in the index, malformed manifest). The assumption is that these
//! are programmer errors in tests, not runtime failures to recover from.
//! The consistency test `vl_fixtures_consistency.rs` catches them in CI.
//!
//! # Examples
//!
//! ```ignore
//! mod common;
//! use common::vl_events::{load_fixture, load_fixtures_by_tag};
//!
//! let event = load_fixture("nginx_http_400.json");
//! assert_eq!(event["_stream"].as_str().is_some(), true);
//!
//! let dotted = load_fixtures_by_tag("dotted_keys");
//! assert!(!dotted.is_empty());
//! ```

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Relative path (from crate root) to the fixture directory.
const FIXTURES_DIR: &str = "tests/fixtures/vl_events";

/// Filename of the manifest inside `FIXTURES_DIR`.
const INDEX_FILENAME: &str = "index.yaml";

/// One manifest entry as declared in `index.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureEntry {
    pub description: String,
    pub source_system: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub prevents_regression_for: Vec<String>,
}

/// Root of the manifest document.
#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    fixtures: BTreeMap<String, FixtureEntry>,
}

/// Cache: manifest parsed once per test crate.
static MANIFEST: OnceLock<BTreeMap<String, FixtureEntry>> = OnceLock::new();

/// Absolute path to the fixture directory.
fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join(FIXTURES_DIR)
}

/// Load and cache the manifest.
fn manifest() -> &'static BTreeMap<String, FixtureEntry> {
    MANIFEST.get_or_init(|| {
        let path = fixtures_dir().join(INDEX_FILENAME);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("failed to read fixture manifest {}: {}", path.display(), e)
        });
        let parsed: Manifest = serde_yaml::from_str(&raw).unwrap_or_else(|e| {
            panic!("failed to parse fixture manifest {}: {}", path.display(), e)
        });
        parsed.fixtures
    })
}

/// Return the full manifest (for consistency tests).
pub fn manifest_entries() -> &'static BTreeMap<String, FixtureEntry> {
    manifest()
}

/// Read and parse a fixture by stem (e.g. `"nginx_http_400"`) or by full
/// filename (e.g. `"nginx_http_400.json"`). The `.json` suffix is optional.
///
/// # Panics
///
/// Panics if the fixture is not listed in `index.yaml`, if the file is
/// missing, or if it is not valid JSON.
pub fn load_fixture(name: &str) -> Value {
    let filename = if name.ends_with(".json") {
        name.to_string()
    } else {
        format!("{}.json", name)
    };
    if !manifest().contains_key(&filename) {
        panic!(
            "fixture '{}' is not declared in {}/{}. Add it to the manifest \
             or pick an existing name.",
            name, FIXTURES_DIR, INDEX_FILENAME
        );
    }
    load_fixture_from_disk(&filename)
}

/// Read and parse a fixture file from disk without checking the manifest.
///
/// Used internally to catch the "listed in index but missing on disk" case
/// with a clearer message than a plain IO error.
fn load_fixture_from_disk(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "fixture '{}' declared in index but missing on disk ({}): {}",
            name,
            path.display(),
            e
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("fixture '{}' is not valid JSON: {}", name, e))
}

/// Return every fixture listed in the manifest as `(name, value)`.
///
/// Ordering is stable (manifest keys are a `BTreeMap`).
pub fn all_fixtures() -> Vec<(String, Value)> {
    manifest()
        .keys()
        .map(|name| (name.clone(), load_fixture_from_disk(name)))
        .collect()
}

/// Return all fixtures whose manifest entry has `tag` in its `tags` list.
///
/// Returns an empty `Vec` for an unknown tag; callers that expect a
/// non-empty result should assert it themselves.
pub fn load_fixtures_by_tag(tag: &str) -> Vec<(String, Value)> {
    manifest()
        .iter()
        .filter(|(_, entry)| entry.tags.iter().any(|t| t == tag))
        .map(|(name, _)| (name.clone(), load_fixture_from_disk(name)))
        .collect()
}

/// Return all fixtures whose manifest entry has `source_system == system`.
///
/// Empty `Vec` for unknown systems; callers assert the expected size.
pub fn load_fixtures_by_source_system(system: &str) -> Vec<(String, Value)> {
    manifest()
        .iter()
        .filter(|(_, entry)| entry.source_system == system)
        .map(|(name, _)| (name.clone(), load_fixture_from_disk(name)))
        .collect()
}

/// Return the set of filenames physically present in `FIXTURES_DIR`,
/// excluding the manifest itself. Used by the consistency test.
pub fn filesystem_fixtures() -> Vec<String> {
    let dir = fixtures_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read fixture directory {}: {}", dir.display(), e));
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name == INDEX_FILENAME {
                None
            } else if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                Some(file_name)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names
}
