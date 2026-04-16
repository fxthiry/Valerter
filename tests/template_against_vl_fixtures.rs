//! Parameterised template × fixture integration tests.
//!
//! Demonstrates how the corpus plugs into the `TemplateEngine` and catches
//! regressions that motivated the chore:
//!   - #25: `{{ nginx.http.request_id }}` against flat-dotted keys.
//!   - empty-field rendering against `edge_empty_fields.json`.
//!
//! The existing inline-event tests (e.g. `integration_notify.rs`) are left
//! untouched; this file is purely additive.

use std::collections::HashMap;

use valerter::config::CompiledTemplate;
use valerter::template::TemplateEngine;

mod common;

use common::vl_events::{
    all_fixtures, load_fixture, load_fixtures_by_source_system, load_fixtures_by_tag,
};

/// Build a single-template engine wired to `{{ title_tpl }}` / `{{ body_tpl }}`.
fn engine_with(title_tpl: &str, body_tpl: &str) -> TemplateEngine {
    let mut templates = HashMap::new();
    templates.insert(
        "t".to_string(),
        CompiledTemplate {
            title: title_tpl.to_string(),
            body: body_tpl.to_string(),
            email_body_html: None,
            accent_color: None,
        },
    );
    TemplateEngine::new(templates)
}

#[test]
fn smoke_every_fixture_renders_msg_and_time_matching_event() {
    // For every fixture, render `{{ _msg }} @ {{ _time }}` and assert the
    // output matches what the event literally carries. Stronger than a bare
    // `!is_empty()` assertion: catches silent drift if templating or unflat-
    // tening starts mangling top-level fields.
    let engine = engine_with("{{ _msg }}", "{{ _msg }} @ {{ _time }}");
    for (name, value) in all_fixtures() {
        let msg = value
            .as_object()
            .and_then(|o| o.get("_msg"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("fixture {} missing string _msg", name));
        let time = value
            .as_object()
            .and_then(|o| o.get("_time"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("fixture {} missing string _time", name));
        let expected = format!("{} @ {}", msg, time);
        let rendered = engine
            .render("t", &value, "smoke", "vlprod")
            .unwrap_or_else(|e| panic!("fixture {} failed to render: {}", name, e));
        assert_eq!(
            rendered.body, expected,
            "fixture {} rendered body did not match the event's _msg/_time",
            name
        );
        assert_eq!(
            rendered.title, msg,
            "fixture {} rendered title drifted",
            name
        );
    }
}

#[test]
fn regression_gh25_dotted_keys_render_their_value() {
    // Regression guard for #25: `{{ nginx.http.request_id }}` must render
    // the flat-dotted value from the event. Before the fix, minijinja
    // treated `nginx.http.request_id` as nested attribute lookup and the
    // expression resolved to empty under Lenient undefined behaviour.
    let engine = engine_with("req", "{{ nginx.http.request_id }}");
    let hits = load_fixtures_by_tag("dotted_keys");
    assert!(
        !hits.is_empty(),
        "expected at least one `dotted_keys` fixture for #25 regression"
    );
    let mut checked_any = false;
    for (name, value) in hits {
        // Skip fixtures that don't carry the specific dotted key we test.
        let expected = value
            .as_object()
            .and_then(|o| o.get("nginx.http.request_id"))
            .and_then(|v| v.as_str());
        let Some(expected) = expected else {
            continue;
        };
        let rendered = engine
            .render("t", &value, "gh25", "vlprod")
            .unwrap_or_else(|e| panic!("fixture {} failed to render for #25: {}", name, e));
        assert_eq!(
            rendered.body, expected,
            "fixture {} did not surface nginx.http.request_id via template",
            name
        );
        checked_any = true;
    }
    assert!(
        checked_any,
        "no dotted_keys fixture carried `nginx.http.request_id`; add one or \
         retag the existing nginx fixtures"
    );
}

#[test]
fn regression_empty_fields_render_as_empty_string() {
    // `edge_empty_fields.json` carries `request_id: ""`. Templates that
    // reference these must render to empty string (not fail, not produce
    // `"None"`, etc.). This is the contract the empty-guard in #26 relies on.
    let engine = engine_with("t", "[{{ request_id }}][{{ user_id }}][{{ error }}]");
    let event = load_fixture("edge_empty_fields.json");
    let rendered = engine
        .render("t", &event, "empty_fields", "vlprod")
        .expect("render should succeed with lenient undefined");
    assert_eq!(rendered.body, "[][][]");
}

#[test]
fn raw_source_fixtures_render_missing_as_empty_under_lenient() {
    // Fixtures whose manifest source_system is `raw` carry no structured
    // fields beyond the VL envelope. Rendering `{{ _msg }}` must still
    // work, and rendering `{{ missing_field }}` must yield empty under
    // Lenient (not error). This protects against accidental Strict flips.
    let engine = engine_with("{{ _msg }}", "{{ unknown_field_that_does_not_exist }}");
    let fixtures = load_fixtures_by_source_system("raw");
    assert!(
        !fixtures.is_empty(),
        "expected at least one fixture with source_system: raw"
    );
    for (name, value) in fixtures {
        let rendered = engine
            .render("t", &value, "raw", "vlprod")
            .unwrap_or_else(|e| panic!("fixture {} failed lenient render: {}", name, e));
        assert!(!rendered.title.is_empty(), "title empty for {}", name);
        assert!(
            rendered.body.is_empty(),
            "body should be empty string for missing field (fixture {})",
            name
        );
    }
}

#[test]
fn unicode_fixture_preserves_cjk_and_emoji() {
    // Render the unicode fixture via `{{ _msg }}` and check the raw bytes
    // survive. This catches encoding bugs in the template pipeline.
    let engine = engine_with("{{ _msg }}", "{{ _msg }}");
    let event = load_fixture("edge_unicode_msg.json");
    let rendered = engine
        .render("t", &event, "unicode", "vlprod")
        .expect("render should succeed on unicode event");
    assert!(rendered.body.contains("支付失败"), "lost CJK codepoints");
    assert!(rendered.body.contains('\u{2705}'), "lost emoji codepoint");
}
