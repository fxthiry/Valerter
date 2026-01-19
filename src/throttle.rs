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
//! # Example
//!
//! ```ignore
//! use valerter::throttle::{Throttler, ThrottleResult};
//! use serde_json::json;
//!
//! let throttler = Throttler::new(Some(&config), "my_rule");
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Default maximum capacity for throttle cache to prevent OOM (FR25).
const DEFAULT_MAX_CAPACITY: u64 = 10_000;

/// Result of throttle check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleResult {
    /// Alert passes through (not throttled).
    Pass,
    /// Alert is throttled (blocked).
    Throttled,
}

/// Throttler for a single rule, using moka LRU cache with TTL.
///
/// Moka handles expiration automatically - when an entry's TTL expires,
/// it's evicted and the next alert for that key starts fresh.
///
/// # Thread Safety
///
/// The throttler is thread-safe and can be shared across async tasks.
/// It uses `Arc<AtomicU32>` for lock-free counter increments.
pub struct Throttler {
    /// Cache: key -> current count in window.
    /// Using Arc<AtomicU32> for thread-safe increment with proper sharing.
    cache: Cache<String, Arc<AtomicU32>>,
    /// Jinja template for generating throttle key.
    key_template: Option<String>,
    /// Maximum alerts per window.
    max_count: u32,
    /// Rule name for logging and metrics (Arc to avoid cloning).
    rule_name: Arc<str>,
    /// Pre-created Jinja environment for template rendering (H1 fix).
    jinja_env: Environment<'static>,
}

impl Throttler {
    /// Create a new Throttler from compiled config.
    ///
    /// # Arguments
    ///
    /// * `config` - Optional throttle configuration. If None, creates a pass-through throttler.
    /// * `rule_name` - Name of the rule for logging and metrics.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let throttler = Throttler::new(Some(&compiled_throttle), "my_rule");
    /// ```
    pub fn new(config: Option<&CompiledThrottle>, rule_name: &str) -> Self {
        Self::with_capacity(config, rule_name, DEFAULT_MAX_CAPACITY)
    }

    /// Create a new Throttler with custom max capacity (for testing).
    ///
    /// # Arguments
    ///
    /// * `config` - Optional throttle configuration.
    /// * `rule_name` - Name of the rule for logging and metrics.
    /// * `max_capacity` - Maximum number of keys in the cache (FR25).
    pub fn with_capacity(
        config: Option<&CompiledThrottle>,
        rule_name: &str,
        max_capacity: u64,
    ) -> Self {
        let (key_template, max_count, window) = match config {
            Some(t) => (t.key_template.clone(), t.count, t.window),
            None => (None, u32::MAX, Duration::from_secs(60)),
        };

        // M1: Validate configuration - log warning for edge cases
        if let Some(t) = config {
            if t.count == 0 {
                tracing::warn!(
                    rule_name = %rule_name,
                    "Throttle count is 0, all alerts after first will be throttled"
                );
            }
            if t.window.is_zero() {
                tracing::warn!(
                    rule_name = %rule_name,
                    "Throttle window is 0, entries will expire immediately"
                );
            }
        }

        // Configure moka cache with TTL and max capacity (AD-25 / FR25)
        let cache = Cache::builder()
            .time_to_live(window)
            .max_capacity(max_capacity)
            .build();

        // H1 fix: Pre-create Jinja environment once
        let jinja_env = Environment::new();

        Self {
            cache,
            key_template,
            max_count,
            rule_name: Arc::from(rule_name),
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

        // Get or create entry in cache
        let entry = self
            .cache
            .get_with(key.clone(), || Arc::new(AtomicU32::new(0)));
        let count = entry.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::trace!(count = count, max_count = self.max_count, "Throttle count updated");

        // L1: Pre-convert rule_name to String once for metrics (required for 'static)
        let rule_name_str = self.rule_name.to_string();

        if count <= self.max_count {
            // M3: Increment metric for passed alerts
            metrics::counter!(
                "valerter_alerts_passed_total",
                "rule_name" => rule_name_str
            )
            .increment(1);

            ThrottleResult::Pass
        } else {
            // Log at DEBUG level (throttling is normal behavior)
            tracing::debug!(
                rule_name = %self.rule_name,
                throttle_key = %key,
                count = count,
                max_count = self.max_count,
                "Alert throttled"
            );

            // Increment metric (FR23, FR24)
            metrics::counter!(
                "valerter_alerts_throttled_total",
                "rule_name" => rule_name_str
            )
            .increment(1);

            ThrottleResult::Throttled
        }
    }

    /// Render the throttle key from template and fields.
    ///
    /// If no template is configured, returns a global key for the rule.
    /// If template rendering fails, logs a warning and returns a fallback key.
    fn render_key(&self, fields: &Value) -> String {
        match &self.key_template {
            Some(template) => {
                // H1 fix: Use pre-created jinja_env instead of creating new one
                match self.jinja_env.render_str(template, fields) {
                    Ok(key) => {
                        tracing::trace!(rendered_key = %key, "Throttle key rendered");
                        key
                    }
                    Err(e) => {
                        // Template error - log and use fallback
                        tracing::warn!(
                            rule_name = %self.rule_name,
                            template = %template,
                            error = %e,
                            "Failed to render throttle key, using fallback"
                        );
                        format!("{}:error", self.rule_name)
                    }
                }
            }
            None => {
                // No template = global throttle for the rule
                format!("{}:global", self.rule_name)
            }
        }
    }

    /// Reset all throttle entries for this rule.
    ///
    /// Called after VictoriaLogs reconnection (FR7) to clear stale state.
    pub fn reset(&self) {
        let entry_count = self.cache.entry_count();
        self.cache.invalidate_all();
        tracing::debug!(rule_name = %self.rule_name, entries_cleared = entry_count, "Throttle cache reset");
    }
}

impl std::fmt::Debug for Throttler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Throttler")
            .field("key_template", &self.key_template)
            .field("max_count", &self.max_count)
            .field("rule_name", &self.rule_name)
            .field("cache_entry_count", &self.cache.entry_count())
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
        let throttler = Throttler::new(Some(&config), "test_rule");

        let fields = json!({"host": "SW-01", "port": "Gi0/1"});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "SW-01");
    }

    // ===================================================================
    // Task 6.2: Test rendu clé avec template composé {{ host }}-{{ port }}
    // ===================================================================

    #[test]
    fn render_key_with_composite_template() {
        let config = make_config(Some("{{ host }}-{{ port }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

        let fields = json!({"host": "SW-01"});

        // Fill up to max
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Throttled);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Sync moka's internal state (run_pending_tasks is needed for sync cache)
        throttler.cache.run_pending_tasks();

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
        let throttler = Throttler::with_capacity(Some(&config), "test_rule", 5);

        // Fill cache with 5 different keys, each gets 2 alerts (at max)
        for i in 0..5 {
            let fields = json!({"key": format!("key-{}", i)});
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass); // count=1
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass); // count=2
        }

        // Sync moka's internal state
        throttler.cache.run_pending_tasks();

        // Now add more keys - this should trigger eviction of old keys
        for i in 5..10 {
            let fields = json!({"key": format!("key-{}", i)});
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        }

        // Sync again
        throttler.cache.run_pending_tasks();

        // Cache size should be bounded (may be slightly over due to async eviction)
        let entry_count = throttler.cache.entry_count();
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
        let throttler = Throttler::new(Some(&config), "my_rule");

        let fields1 = json!({"host": "SW-01"});
        let fields2 = json!({"host": "SW-02"});

        // Both should use the same global key "my_rule:global"
        assert_eq!(throttler.check(&fields1), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields2), ThrottleResult::Pass);
        // Third from either should be throttled (same global key)
        assert_eq!(throttler.check(&fields1), ThrottleResult::Throttled);
    }

    #[test]
    fn global_key_format() {
        let config = make_config(None, 2, 60);
        let throttler = Throttler::new(Some(&config), "my_rule");

        let fields = json!({});
        let key = throttler.render_key(&fields);

        assert_eq!(key, "my_rule:global");
    }

    // ===================================================================
    // Task 6.10: Test champs nested dans template {{ data.server.name }}
    // ===================================================================

    #[test]
    fn render_key_with_nested_fields() {
        let config = make_config(Some("{{ data.server.name }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(None, "test_rule");

        let fields = json!({"host": "SW-01"});

        // With max_count = u32::MAX, should never throttle
        for _ in 0..1000 {
            assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        }
    }

    #[test]
    fn reset_clears_all_entries() {
        let config = make_config(Some("{{ host }}"), 2, 60);
        let throttler = Throttler::new(Some(&config), "test_rule");

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
        let throttler = Throttler::new(Some(&config), "test_rule");

        let debug = format!("{:?}", throttler);

        assert!(debug.contains("Throttler"));
        assert!(debug.contains("key_template"));
        assert!(debug.contains("{{ host }}"));
        assert!(debug.contains("max_count"));
        assert!(debug.contains("test_rule"));
    }

    #[test]
    fn template_error_uses_fallback_key() {
        // Invalid template syntax that minijinja can't render
        let config = make_config(Some("{{ nonexistent_filter | bad_filter }}"), 3, 60);
        let throttler = Throttler::new(Some(&config), "test_rule");

        let fields = json!({"host": "SW-01"});
        let key = throttler.render_key(&fields);

        // Should use error fallback
        assert_eq!(key, "test_rule:error");
    }
}
