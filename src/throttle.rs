//! Alert throttling with LRU cache and configurable key templates.
//!
//! This module implements rate limiting for alerts using moka LRU cache.
//! Each rule can have a throttle configuration that limits how many alerts
//! with the same key can pass through within a time window.
//!
//! # Architecture
//!
//! The throttler uses:
//! - **moka sync cache**: Thread-safe LRU cache with automatic TTL expiration
//! - **minijinja**: Template rendering for dynamic throttle keys
//! - **Atomic counters**: Lock-free counting within cache entries
//!
//! # Scope
//!
//! State is split in two:
//! - [`ThrottleStore`]: one per rule, shared by every `(rule, source)` task of
//!   that rule. Two sources rendering the same key increment the same counter,
//!   so `throttle.key: "{{ rule_name }}"` dedups across sources. The default
//!   key `<rule>-<source>:global` embeds the source name, which keeps
//!   per-source isolation without any configuration.
//! - [`Throttler`]: one per task, a view on the rule's store that carries the
//!   task's `vl_source` (render context, default key, metric labels).
//!
//! # Window
//!
//! The window is fixed, not sliding: a key's counter is created by its first
//! event and expires `window` later (moka `time_to_live`), whatever happened
//! in between.
//!
//! # Reset on reconnection
//!
//! [`Throttler::reset`] only drops the counters fed exclusively by the task's
//! own source. Counters another source has contributed to are kept, so one
//! source reconnecting does not wipe the dedup state of the others.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use valerter::throttle::{ThrottleResult, ThrottleStore, Throttler};
//! use serde_json::json;
//!
//! let store = Arc::new(ThrottleStore::new(config.window, 10_000));
//! let throttler = Throttler::with_store(store, Some(&config), "my_rule", "vlprod");
//! let fields = json!({"host": "SW-01", "port": "Gi0/1"});
//!
//! match throttler.check(&fields) {
//!     ThrottleResult::Pass => { /* send notification */ }
//!     ThrottleResult::Throttled => { /* skip */ }
//! }
//! ```

use crate::config::CompiledThrottle;
use minijinja::Environment;
use moka::sync::Cache;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

/// Maximum number of throttle keys per source of a rule, to prevent OOM
/// (FR25). A rule's store holds `DEFAULT_MAX_CAPACITY * source_count` keys.
pub(crate) const DEFAULT_MAX_CAPACITY: u64 = 10_000;

/// Window used by a pass-through throttler (no throttle config).
const PASS_THROUGH_WINDOW: Duration = Duration::from_secs(60);

/// Result of throttle check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleResult {
    /// Alert passes through (not throttled).
    Pass,
    /// Alert is throttled (blocked).
    Throttled,
}

/// One throttle key's state within its current window.
#[derive(Debug)]
pub struct ThrottleEntry {
    /// Alerts seen for this key in the current window.
    count: AtomicU32,
    /// Source whose event created the entry.
    owner: Arc<str>,
    /// Set once a source other than `owner` has hit the entry. A shared entry
    /// survives the owner's reconnection reset.
    shared: AtomicBool,
}

impl ThrottleEntry {
    fn new(owner: Arc<str>) -> Self {
        Self {
            count: AtomicU32::new(0),
            owner,
            shared: AtomicBool::new(false),
        }
    }
}

/// Throttle state of one rule, shared by all its `(rule, source)` tasks.
///
/// Moka handles expiration automatically - when an entry's TTL expires,
/// it's evicted and the next alert for that key starts fresh.
pub struct ThrottleStore {
    /// Cache: rendered key -> entry for the current window.
    cache: Cache<String, Arc<ThrottleEntry>>,
}

impl ThrottleStore {
    /// Create a store whose entries live `window` after their first event,
    /// holding at most `max_capacity` keys (AD-25 / FR25).
    pub fn new(window: Duration, max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(window)
            .max_capacity(max_capacity)
            .support_invalidation_closures()
            .build();
        Self { cache }
    }

    /// Maximum number of keys the store holds (tests only).
    #[cfg(test)]
    pub(crate) fn max_capacity(&self) -> Option<u64> {
        self.cache.policy().max_capacity()
    }
}

impl std::fmt::Debug for ThrottleStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThrottleStore")
            .field("entry_count", &self.cache.entry_count())
            .finish()
    }
}

/// Per-task view on a rule's [`ThrottleStore`].
///
/// # Thread Safety
///
/// The throttler is thread-safe and can be shared across async tasks.
/// Counters are atomics inside the cache entries, so increments are lock-free.
pub struct Throttler {
    /// Throttle state of the rule, shared with the rule's other sources.
    store: Arc<ThrottleStore>,
    /// Jinja template for generating throttle key.
    key_template: Option<String>,
    /// Maximum alerts per window.
    max_count: u32,
    /// Rule name for logging and metrics (Arc to avoid cloning).
    rule_name: Arc<str>,
    /// VL source name bound to this throttler (per-task). Part of the default
    /// key, owner of the entries this task creates, and metric label.
    vl_source: Arc<str>,
    /// Pre-created Jinja environment for template rendering (H1 fix).
    jinja_env: Environment<'static>,
}

impl Throttler {
    /// Create a Throttler backed by a private store.
    ///
    /// # Arguments
    ///
    /// * `config` - Optional throttle configuration. If None, creates a pass-through throttler.
    /// * `rule_name` - Name of the rule for logging and metrics.
    /// * `vl_source` - VL source name bound to the task (injected into render
    ///   context so `{{ vl_source }}` works in `throttle.key` and the default
    ///   key is per-source by construction).
    pub fn new(config: Option<&CompiledThrottle>, rule_name: &str, vl_source: &str) -> Self {
        Self::with_capacity(config, rule_name, vl_source, DEFAULT_MAX_CAPACITY)
    }

    /// Create a Throttler backed by a private store of custom capacity (for testing).
    ///
    /// # Arguments
    ///
    /// * `config` - Optional throttle configuration.
    /// * `rule_name` - Name of the rule for logging and metrics.
    /// * `vl_source` - VL source name bound to this task's throttler.
    /// * `max_capacity` - Maximum number of keys in the cache (FR25).
    pub fn with_capacity(
        config: Option<&CompiledThrottle>,
        rule_name: &str,
        vl_source: &str,
        max_capacity: u64,
    ) -> Self {
        let window = config.map_or(PASS_THROUGH_WINDOW, |t| t.window);
        let store = Arc::new(ThrottleStore::new(window, max_capacity));
        Self::with_store(store, config, rule_name, vl_source)
    }

    /// Create a Throttler for one `(rule, source)` task on the rule's shared store.
    ///
    /// # Arguments
    ///
    /// * `store` - Throttle state of the rule, shared by all its sources. Its
    ///   window must match `config.window`.
    /// * `config` - Optional throttle configuration. If None, creates a pass-through throttler.
    /// * `rule_name` - Name of the rule for logging and metrics.
    /// * `vl_source` - VL source name bound to this task.
    pub fn with_store(
        store: Arc<ThrottleStore>,
        config: Option<&CompiledThrottle>,
        rule_name: &str,
        vl_source: &str,
    ) -> Self {
        let (key_template, max_count) = match config {
            Some(t) => (t.key_template.clone(), t.count),
            None => (None, u32::MAX),
        };

        // M1: `Config::validate()` rejects `count == 0` and a zero `window`, for
        // rule throttles and `defaults.throttle` alike, so these warnings are
        // unreachable from a loaded configuration. They stay as a guard for
        // programmatic callers that build a `CompiledThrottle` directly.
        if let Some(t) = config {
            if t.count == 0 {
                tracing::warn!(
                    rule_name = %rule_name,
                    vl_source = %vl_source,
                    "Throttle count is 0, all alerts after first will be throttled"
                );
            }
            if t.window.is_zero() {
                tracing::warn!(
                    rule_name = %rule_name,
                    vl_source = %vl_source,
                    "Throttle window is 0, entries will expire immediately"
                );
            }
        }

        // H1 fix: Pre-create Jinja environment once
        let mut jinja_env = Environment::new();
        crate::template::filters::register(&mut jinja_env);

        Self {
            store,
            key_template,
            max_count,
            rule_name: Arc::from(rule_name),
            vl_source: Arc::from(vl_source),
            jinja_env,
        }
    }

    /// Check if an alert should pass or be throttled.
    ///
    /// Returns `ThrottleResult::Pass` if the alert should be sent,
    /// `ThrottleResult::Throttled` if it should be blocked.
    ///
    /// # Arguments
    ///
    /// * `fields` - Parsed log fields as JSON value for template rendering.
    pub fn check(&self, fields: &Value) -> ThrottleResult {
        // Render throttle key from template (FR22)
        let key = self.render_key(fields);
        tracing::trace!(throttle_key = %key, "Checking throttle");

        // Get or create entry in the rule's cache. `get_with` serializes
        // concurrent initialization of a key, so two sources never create two
        // counters for the same key.
        let entry = self.store.cache.get_with(key.clone(), || {
            Arc::new(ThrottleEntry::new(Arc::clone(&self.vl_source)))
        });
        if entry.owner != self.vl_source && !entry.shared.load(Ordering::Relaxed) {
            entry.shared.store(true, Ordering::Relaxed);
        }
        let count = entry.count.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::trace!(
            count = count,
            max_count = self.max_count,
            "Throttle count updated"
        );

        // L1: Pre-convert rule_name and vl_source to String once for metrics
        // (required for 'static label storage).
        let rule_name_str = self.rule_name.to_string();
        let vl_source_str = self.vl_source.to_string();

        if count <= self.max_count {
            // M3: Increment metric for passed alerts (gains `vl_source` for
            // multi-source observability — v2.0.0 part 2).
            metrics::counter!(
                "valerter_alerts_passed_total",
                "rule_name" => rule_name_str,
                "vl_source" => vl_source_str,
            )
            .increment(1);

            ThrottleResult::Pass
        } else {
            // Log at DEBUG level (throttling is normal behavior)
            tracing::debug!(
                rule_name = %self.rule_name,
                vl_source = %self.vl_source,
                throttle_key = %key,
                count = count,
                max_count = self.max_count,
                "Alert throttled"
            );

            // Increment metric (FR23, FR24); labelled with the source whose
            // event was blocked, even when the counter is shared.
            metrics::counter!(
                "valerter_alerts_throttled_total",
                "rule_name" => rule_name_str,
                "vl_source" => vl_source_str,
            )
            .increment(1);

            ThrottleResult::Throttled
        }
    }

    /// Render the throttle key from template and fields.
    ///
    /// If no template is configured, returns the per-source default key
    /// `"{rule}-{source}:global"` so multi-source deployments see isolated
    /// throttle buckets without any config. If rendering fails, logs a
    /// warning and returns a fallback key.
    fn render_key(&self, fields: &Value) -> String {
        match &self.key_template {
            Some(template) => {
                // Inject synthetic `rule_name` (issue #31) and `vl_source`
                // (multi-source v2.0.0). Synthetic values win over any event
                // field with the same name, matching layer 1/2 template
                // behavior.
                let enriched_ctx = enrich_with_context(fields, &self.rule_name, &self.vl_source);
                match self.jinja_env.render_str(template, &enriched_ctx) {
                    Ok(key) => {
                        tracing::trace!(rendered_key = %key, "Throttle key rendered");
                        key
                    }
                    Err(e) => {
                        tracing::warn!(
                            rule_name = %self.rule_name,
                            vl_source = %self.vl_source,
                            template = %template,
                            error = %e,
                            "Failed to render throttle key, using fallback"
                        );
                        format!("{}:error", self.rule_name)
                    }
                }
            }
            None => {
                // Default key is per-(rule, source) so buckets are isolated
                // per-source by construction. Equivalent to rendering
                // `"{{ rule_name }}-{{ vl_source }}:global"` via Jinja, but
                // inlined to avoid the render round-trip on every call.
                format!("{}-{}:global", self.rule_name, self.vl_source)
            }
        }
    }

    /// Reset the throttle entries fed only by this task's source.
    ///
    /// Called after VictoriaLogs reconnection (FR7) to clear stale state.
    /// Entries another source of the rule has contributed to are kept, so the
    /// reconnection of one source does not drop the others' dedup state.
    pub fn reset(&self) {
        let vl_source = Arc::clone(&self.vl_source);
        let result = self.store.cache.invalidate_entries_if(move |_, entry| {
            entry.owner == vl_source && !entry.shared.load(Ordering::Relaxed)
        });
        if let Err(e) = result {
            // Unreachable: every store enables invalidation closures.
            tracing::warn!(
                rule_name = %self.rule_name,
                vl_source = %self.vl_source,
                error = %e,
                "Failed to reset throttle cache"
            );
            return;
        }
        tracing::debug!(
            rule_name = %self.rule_name,
            vl_source = %self.vl_source,
            "Throttle cache reset"
        );
    }
}

/// Whether a `throttle.key` template references the `vl_source` variable.
///
/// Static analysis of the template's undeclared variables, no render: a
/// literal string containing `vl_source` does not count, `{{ vl_source | upper }}`
/// does. Returns `None` when the template does not compile.
pub fn key_references_vl_source(key_template: &str) -> Option<bool> {
    let env = Environment::new();
    let template = env.template_from_str(key_template).ok()?;
    Some(template.undeclared_variables(false).contains("vl_source"))
}

/// Unflatten dotted event keys (issue #25) then inject the synthetic
/// `rule_name` (issue #31) and `vl_source` (v2.0.0 multi-source) keys.
/// Matches the layer 1 template rendering path so users can reference both
/// dotted event fields (`{{ nginx.http.status }}`) and the synthetic keys
/// inside a `throttle.key` template consistently.
///
/// Returns the original value unchanged if it is not a JSON object (should
/// not happen in practice, VL events are always objects). Synthetic values
/// win over any event field literally named `rule_name` or `vl_source`.
fn enrich_with_context(fields: &Value, rule_name: &str, vl_source: &str) -> Value {
    let mut ctx = crate::parser::unflatten_dotted_keys(fields);
    if let Some(obj) = ctx.as_object_mut() {
        obj.insert(
            "rule_name".to_string(),
            Value::String(rule_name.to_string()),
        );
        obj.insert(
            "vl_source".to_string(),
            Value::String(vl_source.to_string()),
        );
    }
    ctx
}

impl std::fmt::Debug for Throttler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Throttler")
            .field("key_template", &self.key_template)
            .field("max_count", &self.max_count)
            .field("rule_name", &self.rule_name)
            .field("cache_entry_count", &self.store.cache.entry_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_config(key: Option<&str>, count: u32, window_secs: u64) -> CompiledThrottle {
        CompiledThrottle {
            key_template: key.map(String::from),
            count,
            window: Duration::from_secs(window_secs),
        }
    }

    // ===================================================================
    // Task 6.1: Test rendu clé avec template simple {{ host }}
    // ===================================================================

    #[test]
    fn render_key_with_simple_template() {
        let config = make_config(Some("{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01", "port": "Gi0/1"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "SW-01");
    }

    #[test]
    fn render_key_applies_valerter_filters() {
        let config = make_config(Some("{{ host | md_escape }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let key = throttler.render_key(&json!({"host": "web_01"}));

        assert_eq!(key, r"web\_01");
    }

    // ===================================================================
    // Task 6.2: Test rendu clé avec template composé {{ host }}-{{ port }}
    // ===================================================================

    #[test]
    fn render_key_with_composite_template() {
        let config = make_config(Some("{{ host }}-{{ port }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01", "port": "Gi0/1"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "SW-01-Gi0/1");
    }

    // ===================================================================
    // Task 6.3: Test rendu clé avec champ manquant -> clé avec valeur vide
    // ===================================================================

    #[test]
    fn render_key_with_missing_field_returns_empty_value() {
        let config = make_config(Some("{{ host }}-{{ missing }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});
        let key = throttler.render_key(&fields);

        // minijinja renders missing variables as empty string by default
        assert_eq!(key, "SW-01-");
    }

    // ===================================================================
    // Task 6.4: Test throttling: première alerte passe
    // ===================================================================

    #[test]
    fn first_alert_passes() {
        let config = make_config(Some("{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});
        let result = throttler.check(&fields);

        assert_eq!(result, ThrottleResult::Pass);
    }

    // ===================================================================
    // Task 6.5: Test throttling: alertes jusqu'à count passent
    // ===================================================================

    #[test]
    fn alerts_up_to_count_pass() {
        let config = make_config(Some("{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});

        // First 3 should pass (count = 3)
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
    }

    // ===================================================================
    // Task 6.6: Test throttling: alerte count+1 est throttlée
    // ===================================================================

    #[test]
    fn alert_after_count_is_throttled() {
        let config = make_config(Some("{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});

        // First 3 pass
        throttler.check(&fields);
        throttler.check(&fields);
        throttler.check(&fields);

        // 4th should be throttled
        assert_eq!(throttler.check(&fields), ThrottleResult::Throttled);
    }

    // ===================================================================
    // Task 6.7: Test expiration TTL (utiliser tokio::time::pause())
    // ===================================================================

    #[tokio::test]
    async fn ttl_expiration_resets_counter() {
        // Note: moka uses background threads for TTL, not tokio time.
        // We use a very short window and actual sleep for this test.
        let config = CompiledThrottle {
            key_template: Some("{{ host }}".to_string()),
            count: 2,
            window: Duration::from_millis(100), // Very short for testing
        };
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});

        // Fill up to max
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Throttled);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Sync moka's internal state (run_pending_tasks is needed for sync cache)
        throttler.store.cache.run_pending_tasks();

        // After TTL, entry should be evicted and counter reset
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
    }

    // ===================================================================
    // Task 6.8: Test cache LRU eviction avec capacité limitée (H2 fix)
    // ===================================================================

    #[test]
    fn lru_eviction_with_limited_capacity() {
        // H2 fix: Create throttler with SMALL capacity to actually test eviction
        let config = make_config(Some("{{ key }}"), 2, 3600);

        // Use with_capacity to set a small max (5 keys)
        let throttler = Throttler::with_capacity(Some(&config), "test_rule", "vlprod", 5);

        // Fill cache with 5 different keys, each gets 2 alerts (at max)
        for i in 0..5 {
            let fields = json!({"key": format!("key-{}", i)});
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass); // count=1
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass); // count=2
        }

        // Sync moka's internal state
        throttler.store.cache.run_pending_tasks();

        // Now add more keys - this should trigger eviction of old keys
        for i in 5..10 {
            let fields = json!({"key": format!("key-{}", i)});
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        }

        // Sync again
        throttler.store.cache.run_pending_tasks();

        // Cache size should be bounded (may be slightly over due to async eviction)
        let entry_count = throttler.store.cache.entry_count();
        assert!(
            entry_count <= 10,
            "Cache should be bounded, got {} entries",
            entry_count
        );

        // Key-0 should have been evicted, so it starts fresh (count=1, passes)
        let fields_key0 = json!({"key": "key-0"});
        assert_eq!(
            throttler.check(&fields_key0),
            ThrottleResult::Pass,
            "key-0 should pass after eviction (fresh start)"
        );
    }

    // ===================================================================
    // Task 6.9: Test sans template de clé: utilise clé globale
    // ===================================================================

    #[test]
    fn no_key_template_uses_global_key() {
        let config = make_config(None, 2, 60);
        let throttler = Throttler::new(Some(&config), "my_rule", "vlprod");

        let fields1 = json!({"host": "SW-01"});
        let fields2 = json!({"host": "SW-02"});

        // Both should use the same per-source default key
        // "my_rule-vlprod:global" - cross-host but not cross-source.
        assert_eq!(throttler.check(&fields1), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields2), ThrottleResult::Pass);
        // Third from either should be throttled (same default key)
        assert_eq!(throttler.check(&fields1), ThrottleResult::Throttled);
    }

    #[test]
    fn default_key_format_is_rule_dash_source_global() {
        // Spec: default throttle key is `{rule}-{source}:global`.
        // Used to be `{rule}:global` (pre-v2.0.0); breaking change for
        // multi-source deployments and locks per-source bucket isolation.
        let config = make_config(None, 2, 60);
        let throttler = Throttler::new(Some(&config), "my_rule", "vlprod");

        let fields = json!({});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "my_rule-vlprod:global");
    }

    #[test]
    fn default_key_isolates_buckets_per_source() {
        // Two throttlers with the same rule but different sources must
        // produce different default keys, so buckets are isolated per-source.
        let config = make_config(None, 2, 60);
        let throttler_a = Throttler::new(Some(&config), "VM_OFF", "vlprod");
        let throttler_b = Throttler::new(Some(&config), "VM_OFF", "vldev");

        let fields = json!({});
        assert_eq!(throttler_a.render_key(&fields), "VM_OFF-vlprod:global");
        assert_eq!(throttler_b.render_key(&fields), "VM_OFF-vldev:global");
    }

    // ===================================================================
    // Task 6.10: Test champs nested dans template {{ data.server.name }}
    // ===================================================================

    #[test]
    fn render_key_with_nested_fields() {
        let config = make_config(Some("{{ data.server.name }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({
            "data": {
                "server": {
                    "name": "prod-server-01"
                }
            }
        });
        let key = throttler.render_key(&fields);

        assert_eq!(key, "prod-server-01");
    }

    // ===================================================================
    // Additional tests
    // ===================================================================

    #[test]
    fn different_keys_are_throttled_independently() {
        let config = make_config(Some("{{ host }}"), 2, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let sw01 = json!({"host": "SW-01"});
        let sw02 = json!({"host": "SW-02"});

        // SW-01: 2 pass, 3rd throttled
        assert_eq!(throttler.check(&sw01), ThrottleResult::Pass);
        assert_eq!(throttler.check(&sw01), ThrottleResult::Pass);
        assert_eq!(throttler.check(&sw01), ThrottleResult::Throttled);

        // SW-02: still has its own count, first 2 should pass
        assert_eq!(throttler.check(&sw02), ThrottleResult::Pass);
        assert_eq!(throttler.check(&sw02), ThrottleResult::Pass);
        assert_eq!(throttler.check(&sw02), ThrottleResult::Throttled);
    }

    #[test]
    fn no_config_passes_all() {
        let throttler = Throttler::new(None, "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});

        // With max_count = u32::MAX, should never throttle
        for _ in 0..1000 {
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        }
    }

    #[test]
    fn reset_clears_all_entries() {
        let config = make_config(Some("{{ host }}"), 2, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01"});

        // Fill up
        throttler.check(&fields);
        throttler.check(&fields);
        assert_eq!(throttler.check(&fields), ThrottleResult::Throttled);

        // Reset
        throttler.reset();

        // Should pass again
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
    }

    #[test]
    fn debug_format_shows_useful_info() {
        let config = make_config(Some("{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let debug = format!("{:?}", throttler);

        assert!(debug.contains("Throttler"));
        assert!(debug.contains("key_template"));
        assert!(debug.contains("{{ host }}"));
        assert!(debug.contains("max_count"));
        assert!(debug.contains("test_rule"));
    }

    // ===================================================================
    // Issue #31: rule_name injected into throttle key render context so
    // users can write `{{ rule_name }}` in throttle.key and get per-rule
    // buckets even when sharing a key_template across multiple rules.
    // ===================================================================

    #[test]
    fn render_key_includes_rule_name() {
        let config = make_config(Some("{{ rule_name }}-{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"host": "SW-01"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "VM_OFF-SW-01");
    }

    #[test]
    fn render_key_resolves_dotted_event_fields_via_unflatten() {
        // Issue #25 + #31: the throttle key must see dotted event keys unflat-
        // tened the same way template rendering does, so `{{ nginx.http.status }}`
        // works here too (not just in `title`/`body`).
        let config = make_config(Some("{{ rule_name }}-{{ nginx.http.status_code }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"nginx.http.status_code": "404"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "VM_OFF-404");
    }

    #[test]
    fn render_key_rule_name_synthetic_overrides_event_field() {
        // Collision policy: synthetic rule_name wins over any event field
        // literally named "rule_name".
        let config = make_config(Some("{{ rule_name }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"rule_name": "event-value", "host": "SW-01"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "VM_OFF");
    }

    // ===================================================================
    // v2.0.0: vl_source injected into throttle key render context
    // ===================================================================

    #[test]
    fn render_key_includes_vl_source() {
        let config = make_config(Some("{{ rule_name }}-{{ vl_source }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"host": "SW-01"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "VM_OFF-vlprod");
    }

    #[test]
    fn render_key_vl_source_synthetic_overrides_event_field() {
        // Collision policy: synthetic vl_source wins over any event field
        // literally named "vl_source" (matches rule_name collision policy).
        let config = make_config(Some("{{ vl_source }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"vl_source": "evil", "host": "SW-01"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "vlprod");
    }

    #[test]
    fn render_key_custom_template_with_both_synthetics() {
        let config = make_config(Some("{{ rule_name }}-{{ vl_source }}-{{ host }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "VM_OFF", "vlprod");

        let fields = json!({"host": "SW-01"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "VM_OFF-vlprod-SW-01");
    }

    #[test]
    fn template_error_uses_fallback_key() {
        // Unknown filters are rejected at load time; only errors that depend
        // on the event's values reach the fallback, e.g. arithmetic on a
        // string field.
        let config = make_config(Some("{{ port + 1 }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule", "vlprod");

        let fields = json!({"host": "SW-01", "port": "Gi0/1"});
        let key = throttler.render_key(&fields);

        // Should use error fallback
        assert_eq!(key, "test_rule:error");
    }

    // ===================================================================
    // Per-rule store shared by the rule's (rule, source) tasks
    // ===================================================================

    /// Two task views on one rule store, as the engine builds them.
    fn shared_pair(config: &CompiledThrottle) -> (Throttler, Throttler) {
        let store = Arc::new(ThrottleStore::new(config.window, DEFAULT_MAX_CAPACITY * 2));
        let prod = Throttler::with_store(Arc::clone(&store), Some(config), "VM_OFF", "vlprod");
        let dev = Throttler::with_store(store, Some(config), "VM_OFF", "vldev");
        (prod, dev)
    }

    #[test]
    fn shared_store_rule_name_key_dedups_across_sources() {
        let config = make_config(Some("{{ rule_name }}"), 1, 60);
        let (prod, dev) = shared_pair(&config);

        let fields = json!({"host": "SW-01"});
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Throttled);
    }

    #[test]
    fn shared_store_default_key_isolates_sources() {
        let config = make_config(None, 1, 60);
        let (prod, dev) = shared_pair(&config);

        let fields = json!({"host": "SW-01"});
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Pass);
        assert_eq!(prod.check(&fields), ThrottleResult::Throttled);
        assert_eq!(dev.check(&fields), ThrottleResult::Throttled);
    }

    #[test]
    fn shared_store_custom_key_without_vl_source_is_shared() {
        let config = make_config(Some("{{ host }}"), 1, 60);
        let (prod, dev) = shared_pair(&config);

        let fields = json!({"host": "SW-01"});
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Throttled);
    }

    #[test]
    fn shared_store_custom_key_with_vl_source_is_isolated() {
        let config = make_config(Some("{{ vl_source }}-{{ host }}"), 1, 60);
        let (prod, dev) = shared_pair(&config);

        let fields = json!({"host": "SW-01"});
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Pass);
    }

    #[test]
    fn distinct_rule_stores_never_share_counters() {
        let config = make_config(Some("{{ host }}"), 1, 60);
        let r1 = Throttler::new(Some(&config), "r1", "vlprod");
        let r2 = Throttler::new(Some(&config), "r2", "vlprod");

        let fields = json!({"host": "SW-01"});
        assert_eq!(r1.check(&fields), ThrottleResult::Pass);
        assert_eq!(r2.check(&fields), ThrottleResult::Pass);
    }

    #[test]
    fn reset_drops_only_keys_fed_exclusively_by_the_source() {
        let config = make_config(Some("{{ host }}"), 1, 60);
        let (prod, dev) = shared_pair(&config);

        let prod_only = json!({"host": "prod-only"});
        let dev_only = json!({"host": "dev-only"});
        let both = json!({"host": "both"});

        assert_eq!(prod.check(&prod_only), ThrottleResult::Pass);
        assert_eq!(dev.check(&dev_only), ThrottleResult::Pass);
        assert_eq!(prod.check(&both), ThrottleResult::Pass);
        assert_eq!(dev.check(&both), ThrottleResult::Throttled);

        prod.reset();

        // Fed by vlprod only: dropped, so the next event passes.
        assert_eq!(prod.check(&prod_only), ThrottleResult::Pass);
        // Opened by vldev: kept, so vlprod is still blocked.
        assert_eq!(prod.check(&dev_only), ThrottleResult::Throttled);
        // Fed by both sources: kept.
        assert_eq!(prod.check(&both), ThrottleResult::Throttled);
        assert_eq!(dev.check(&both), ThrottleResult::Throttled);
    }

    #[test]
    fn reset_with_default_key_keeps_other_sources_buckets() {
        let config = make_config(None, 1, 60);
        let (prod, dev) = shared_pair(&config);

        let fields = json!({});
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Pass);

        prod.reset();

        // `VM_OFF-vlprod:global` dropped, `VM_OFF-vldev:global` kept.
        assert_eq!(prod.check(&fields), ThrottleResult::Pass);
        assert_eq!(dev.check(&fields), ThrottleResult::Throttled);
    }

    #[test]
    fn throttled_metric_carries_the_blocked_source() {
        let config = make_config(Some("{{ rule_name }}"), 1, 60);
        let (prod, dev) = shared_pair(&config);

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let fields = json!({});
            assert_eq!(prod.check(&fields), ThrottleResult::Pass);
            assert_eq!(dev.check(&fields), ThrottleResult::Throttled);
        });

        let rendered = handle.render();
        assert!(
            rendered.contains(
                "valerter_alerts_throttled_total{rule_name=\"VM_OFF\",vl_source=\"vldev\"} 1"
            ),
            "missing throttled series for vldev in:\n{rendered}"
        );
        assert!(
            !rendered.contains(
                "valerter_alerts_throttled_total{rule_name=\"VM_OFF\",vl_source=\"vlprod\"}"
            ),
            "unexpected throttled series for vlprod in:\n{rendered}"
        );
    }

    // ===================================================================
    // Static detection of `vl_source` in a throttle key
    // ===================================================================

    #[test]
    fn key_references_vl_source_detects_variable_references() {
        assert_eq!(key_references_vl_source("{{ rule_name }}"), Some(false));
        assert_eq!(key_references_vl_source("{{ host }}"), Some(false));
        assert_eq!(
            key_references_vl_source("{{ vl_source }}-{{ host }}"),
            Some(true)
        );
        assert_eq!(
            key_references_vl_source("{{ vl_source | upper }}"),
            Some(true)
        );
    }

    #[test]
    fn key_references_vl_source_ignores_literal_text() {
        assert_eq!(
            key_references_vl_source("vl_source-{{ host }}"),
            Some(false)
        );
        assert_eq!(
            key_references_vl_source("{{ \"vl_source\" }}-{{ host }}"),
            Some(false)
        );
    }

    #[test]
    fn key_references_vl_source_returns_none_on_invalid_template() {
        assert_eq!(key_references_vl_source("{{ host "), None);
    }
}
