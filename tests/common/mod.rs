//! Shared helpers for integration tests.
//!
//! Each file under `tests/` compiles as its own crate, so shared helpers live
//! here and are pulled in via `mod common;` from the consuming test file.
//!
//! The `#[allow(dead_code)]` below is intentional: not every consumer uses
//! every sub-module, and Cargo's per-test-crate compilation would otherwise
//! flag unused items.

#![allow(dead_code)]

pub mod vl_events;
