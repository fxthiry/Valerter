//! Rule engine for orchestrating multiple alerting rules.
//!
//! This module implements the core rule orchestration logic for valerter.
//! Each rule runs as an independent Tokio task, providing isolation:
//! - Errors in one rule don't affect others (FR35, FR36)
//! - Panics are captured and logged (AC #4)
//! - Each rule has its own reconnection backoff
//!
//! # Architecture
//!
//! ```text
//! main.rs
//!     |
//!     v
//! engine.rs (RuleEngine)
//!     |
//!     +-- spawn --> run_rule(rule_1) --> tail.rs --> parser.rs --> throttle.rs --> template.rs --> notify.rs
//!     +-- spawn --> run_rule(rule_2) --> ...
//!     +-- spawn --> run_rule(rule_n) --> ...
//! ```
//!
//! # Example
//!
//! ```ignore
//! use valerter::engine::RuleEngine;
//! use tokio_util::sync::CancellationToken;
//!
//! let engine = RuleEngine::new(runtime_config, http_client, queue);
//! let cancel = CancellationToken::new();
//!
//! // Run until cancelled
//! engine.run(cancel).await?;
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, trace, warn};

use crate::config::{CompiledRule, CompiledThrottle, RuntimeConfig, VlSourceConfig};
use crate::error::RuleError;
use crate::notify::{AlertPayload, NotificationQueue};
use crate::parser::{RuleParser, record_log_matched, record_parse_error};
use crate::tail::{ReconnectCallback, TailClient, TailConfig};
use crate::template::TemplateEngine;
use crate::throttle::{ThrottleResult, Throttler};

/// Delay before restarting a rule after panic (AD-07 inspired).
const PANIC_RESTART_DELAY: Duration = Duration::from_secs(5);

/// Resolve the set of `(source_name, source_config)` pairs to spawn for a rule.
///
/// - Empty `rule.vl_sources`: fan out across every configured source.
/// - Non-empty `rule.vl_sources`: restrict to the named subset, preserving
///   BTreeMap iteration order so the spawn order is deterministic regardless
///   of the order names appear in the rule's list.
///
/// Unknown source names must have been rejected at `Config::validate()` time;
/// any mismatch here is silently ignored (treated as defensive filtering).
pub(crate) fn resolve_sources(
    rule: &CompiledRule,
    sources: &BTreeMap<String, VlSourceConfig>,
) -> Vec<(String, VlSourceConfig)> {
    if rule.vl_sources.is_empty() {
        return sources
            .iter()
            .map(|(name, cfg)| (name.clone(), cfg.clone()))
            .collect();
    }
    sources
        .iter()
        .filter(|(name, _)| rule.vl_sources.iter().any(|r| r == *name))
        .map(|(name, cfg)| (name.clone(), cfg.clone()))
        .collect()
}

/// Context needed to spawn a single `(rule, source)` task.
/// Stored to allow respawning after panic.
#[derive(Clone)]
struct RuleSpawnContext {
    rule: CompiledRule,
    vl_source_name: String,
    vl_source_config: VlSourceConfig,
    queue: NotificationQueue,
    template_engine: Arc<TemplateEngine>,
    default_throttle: CompiledThrottle,
    /// Timezone for formatting log timestamps.
    timestamp_timezone: String,
}

/// Rule engine that orchestrates all alert rules.
///
/// The engine spawns independent tasks for each enabled rule and supervises
/// them using `JoinSet`. This provides:
/// - Task isolation (one rule's error doesn't affect others)
/// - Panic detection and logging
/// - Automatic restart after panic (AC #4)
/// - Graceful shutdown via cancellation token
pub struct RuleEngine {
    /// Runtime configuration with compiled rules.
    runtime_config: RuntimeConfig,
    /// Notification queue for sending alerts.
    queue: NotificationQueue,
}

impl RuleEngine {
    /// Create a new RuleEngine.
    ///
    /// # Arguments
    ///
    /// * `runtime_config` - Compiled runtime configuration with rules.
    /// * `_http_client` - HTTP client (unused, kept for API compatibility).
    /// * `queue` - Notification queue for sending alerts.
    pub fn new(
        runtime_config: RuntimeConfig,
        _http_client: reqwest::Client,
        queue: NotificationQueue,
    ) -> Self {
        Self {
            runtime_config,
            queue,
        }
    }

    /// Run the engine until cancelled.
    ///
    /// Spawns a task per enabled rule and supervises them via `JoinSet`.
    /// Handles:
    /// - Normal task completion (shouldn't happen - rules run forever)
    /// - Fatal errors (logged, task not restarted)
    /// - Panics (logged as CRITICAL, task restarted after delay)
    /// - Cancellation (graceful shutdown)
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when cancelled, or propagates fatal errors.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), RuleError> {
        let mut tasks: JoinSet<(String, String, Result<(), RuleError>)> = JoinSet::new();
        // Map AbortHandle ID to (rule_name, vl_source_name, spawn_context) for
        // respawn after panic. Each `(rule, source)` pair is a distinct task.
        let mut handle_to_context: HashMap<tokio::task::Id, (String, String, RuleSpawnContext)> =
            HashMap::new();

        // Spawn a task per (enabled rule, resolved source) pair
        let spawned_count =
            self.spawn_rule_tasks(&mut tasks, &mut handle_to_context, cancel.clone());

        if spawned_count == 0 {
            warn!("No enabled rules found, engine will exit");
            return Ok(());
        }

        info!(
            task_count = spawned_count,
            "Rule engine started, supervising rule-source tasks"
        );

        // Supervision loop
        self.supervise_tasks(&mut tasks, &mut handle_to_context, cancel)
            .await
    }

    /// Spawn tasks for all enabled `(rule, source)` pairs.
    ///
    /// Returns the number of tasks spawned.
    fn spawn_rule_tasks(
        &self,
        tasks: &mut JoinSet<(String, String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, String, RuleSpawnContext)>,
        cancel: CancellationToken,
    ) -> usize {
        let mut count = 0;

        // Create shared template engine for all rules
        let template_engine = Arc::new(TemplateEngine::new(self.runtime_config.templates.clone()));

        // Get default throttle config
        let default_throttle = CompiledThrottle {
            key_template: self.runtime_config.defaults.throttle.key.clone(),
            count: self.runtime_config.defaults.throttle.count,
            window: self.runtime_config.defaults.throttle.window,
        };

        for rule in &self.runtime_config.rules {
            if !rule.enabled {
                debug!(rule_name = %rule.name, "Rule disabled, skipping");
                continue;
            }

            let resolved = resolve_sources(rule, &self.runtime_config.victorialogs);
            if resolved.is_empty() {
                // Should not happen: validation rejects zero sources at load.
                warn!(
                    rule_name = %rule.name,
                    "Rule resolved to zero sources, skipping"
                );
                continue;
            }

            for (source_name, source_cfg) in resolved {
                trace!(
                    rule_name = %rule.name,
                    vl_source = %source_name,
                    "Spawning (rule, source) task"
                );

                let ctx = RuleSpawnContext {
                    rule: rule.clone(),
                    vl_source_name: source_name.clone(),
                    vl_source_config: source_cfg,
                    queue: self.queue.clone(),
                    template_engine: Arc::clone(&template_engine),
                    default_throttle: default_throttle.clone(),
                    timestamp_timezone: self.runtime_config.defaults.timestamp_timezone.clone(),
                };

                Self::spawn_single_rule(tasks, handle_to_context, &ctx, cancel.clone());
                count += 1;
            }
        }

        count
    }

    /// Spawn a single `(rule, source)` task and track its handle.
    fn spawn_single_rule(
        tasks: &mut JoinSet<(String, String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, String, RuleSpawnContext)>,
        ctx: &RuleSpawnContext,
        cancel: CancellationToken,
    ) {
        let rule_name_owned = ctx.rule.name.clone();
        let vl_source_owned = ctx.vl_source_name.clone();
        let ctx_clone = ctx.clone();

        let abort_handle = tasks.spawn(async move {
            let rule_name_for_return = ctx_clone.rule.name.clone();
            let vl_source_for_return = ctx_clone.vl_source_name.clone();
            let result = run_rule(ctx_clone, cancel).await;
            (rule_name_for_return, vl_source_for_return, result)
        });

        // Track context by task ID for respawn
        handle_to_context.insert(
            abort_handle.id(),
            (rule_name_owned, vl_source_owned, ctx.clone()),
        );
    }

    /// Supervise running tasks and handle completion/errors/panics.
    async fn supervise_tasks(
        &self,
        tasks: &mut JoinSet<(String, String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, String, RuleSpawnContext)>,
        cancel: CancellationToken,
    ) -> Result<(), RuleError> {
        loop {
            tokio::select! {
                Some(result) = tasks.join_next_with_id() => {
                    match result {
                        Ok((task_id, (rule_name, vl_source, Ok(_)))) => {
                            // Task completed normally (shouldn't happen - rules run forever)
                            info!(rule_name = %rule_name, vl_source = %vl_source, "Rule task completed normally");
                            handle_to_context.remove(&task_id);
                        }
                        Ok((task_id, (rule_name, vl_source, Err(e)))) => {
                            // Fatal error from rule — scoped to this (rule, source) pair only.
                            // Other pairs keep running (per-source isolation).
                            error!(
                                rule_name = %rule_name,
                                vl_source = %vl_source,
                                error = %e,
                                "Rule task failed fatally"
                            );
                            metrics::counter!(
                                "valerter_rule_errors_total",
                                "rule_name" => rule_name
                            ).increment(1);
                            handle_to_context.remove(&task_id);
                        }
                        Err(join_error) if join_error.is_panic() => {
                            let task_id = join_error.id();
                            if let Some((rule_name, vl_source, ctx)) = handle_to_context.remove(&task_id) {
                                error!(
                                    rule_name = %rule_name,
                                    vl_source = %vl_source,
                                    error = %join_error,
                                    "Rule task panicked - CRITICAL"
                                );

                                metrics::counter!(
                                    "valerter_rule_panics_total",
                                    "rule_name" => rule_name.clone()
                                ).increment(1);

                                if !cancel.is_cancelled() {
                                    info!(
                                        rule_name = %rule_name,
                                        vl_source = %vl_source,
                                        delay_secs = PANIC_RESTART_DELAY.as_secs(),
                                        "Respawning rule-source task after panic delay"
                                    );
                                    tokio::time::sleep(PANIC_RESTART_DELAY).await;

                                    if !cancel.is_cancelled() {
                                        Self::spawn_single_rule(
                                            tasks,
                                            handle_to_context,
                                            &ctx,
                                            cancel.clone(),
                                        );
                                        info!(rule_name = %rule_name, vl_source = %vl_source, "Rule-source task respawned after panic");
                                    }
                                }
                            } else {
                                error!(
                                    error = %join_error,
                                    "Rule task panicked but context not found - CRITICAL"
                                );
                                metrics::counter!("valerter_rule_panics_total", "rule_name" => "unknown").increment(1);
                            }
                        }
                        Err(join_error) => {
                            let task_id = join_error.id();
                            tracing::debug!(error = %join_error, "Rule task cancelled");
                            handle_to_context.remove(&task_id);
                        }
                    }

                    if tasks.is_empty() && !cancel.is_cancelled() {
                        warn!("All rule tasks completed unexpectedly");
                        return Ok(());
                    }
                }
                _ = cancel.cancelled() => {
                    info!("Shutdown signal received, aborting all rules");
                    tasks.abort_all();

                    while tasks.join_next().await.is_some() {}

                    info!("All rule tasks stopped");
                    return Ok(());
                }
            }
        }
    }
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleEngine")
            .field("rule_count", &self.runtime_config.rules.len())
            .field(
                "enabled_count",
                &self
                    .runtime_config
                    .rules
                    .iter()
                    .filter(|r| r.enabled)
                    .count(),
            )
            .finish()
    }
}

/// Callback to reset throttle cache on VictoriaLogs reconnection (FR7).
struct ThrottleResetCallback {
    throttler: Arc<Throttler>,
}

impl ThrottleResetCallback {
    fn new(throttler: Arc<Throttler>) -> Self {
        Self { throttler }
    }
}

impl ReconnectCallback for ThrottleResetCallback {
    fn on_reconnect(&self, _rule_name: &str) {
        self.throttler.reset();
    }
}

/// Run a single rule task with full pipeline processing.
///
/// This function implements the complete rule processing loop:
/// 1. Connect to VictoriaLogs with reconnection handling
/// 2. Parse each log line
/// 3. Check throttle
/// 4. Render template
/// 5. Send to notification queue
///
/// The function runs until cancelled or a fatal error occurs.
/// All recoverable errors are logged and the loop continues (Log+Continue pattern).
async fn run_rule(ctx: RuleSpawnContext, cancel: CancellationToken) -> Result<(), RuleError> {
    let span = tracing::info_span!(
        "run_rule",
        rule_name = %ctx.rule.name,
        vl_source = %ctx.vl_source_name
    );

    async move {
        debug!("Rule-source task started");

        // Create parser for this rule
        let parser = RuleParser::from_compiled(&ctx.rule.parser);
        debug!(
            has_regex = ctx.rule.parser.regex.is_some(),
            has_json = ctx.rule.parser.json.is_some(),
            "Parser initialized"
        );

        // Create throttler for this (rule, source) pair. Each task owns its
        // throttler: when no custom key_template is set, the default key path
        // uses (rule_name, vl_source) so buckets are naturally isolated per
        // source without cross-contamination.
        let throttle_config = ctx.rule.throttle.as_ref().unwrap_or(&ctx.default_throttle);
        let throttler = Arc::new(Throttler::new(
            Some(throttle_config),
            &ctx.rule.name,
            &ctx.vl_source_name,
        ));
        debug!(
            throttle_count = throttle_config.count,
            throttle_window_secs = throttle_config.window.as_secs(),
            "Throttler initialized"
        );

        // Get template name and destinations for this rule (both are now required)
        let template_name = ctx.rule.notify.template.clone();
        let destinations = ctx.rule.notify.destinations.clone();
        debug!(
            template_name = %template_name,
            destination_count = destinations.len(),
            "Notify config loaded"
        );

        // Wrap parser in Arc for sharing across closure invocations
        let parser = Arc::new(parser);

        // Create callback for throttle reset on reconnection
        let reconnect_callback = ThrottleResetCallback::new(Arc::clone(&throttler));

        // Create TailClient for this VictoriaLogs source
        let tail_config = TailConfig::from_source(&ctx.vl_source_config, ctx.rule.query.clone());

        let mut tail_client = TailClient::new(tail_config).map_err(RuleError::Stream)?;

        // Stream with reconnection - runs until cancelled
        let rule_name = ctx.rule.name.clone();
        let vl_source = Arc::new(ctx.vl_source_name.clone());
        let template_name = Arc::new(template_name);
        let destinations = Arc::new(destinations);
        let template_engine = ctx.template_engine;
        let queue = ctx.queue;
        let timestamp_timezone = Arc::new(ctx.timestamp_timezone.clone());

        let stream_result = tail_client
            .stream_with_reconnect(&rule_name, Some(&reconnect_callback), |line| {
                // Process each log line
                let queue = queue.clone();
                let parser = Arc::clone(&parser);
                let throttler = Arc::clone(&throttler);
                let template_engine = Arc::clone(&template_engine);
                let template_name = Arc::clone(&template_name);
                let rule_name = rule_name.clone();
                let vl_source = Arc::clone(&vl_source);
                let destinations = Arc::clone(&destinations);
                let timestamp_timezone = Arc::clone(&timestamp_timezone);

                async move {
                    if let Err(e) = process_log_line(
                        &line,
                        &parser,
                        &throttler,
                        &template_engine,
                        &template_name,
                        &rule_name,
                        &vl_source,
                        &destinations,
                        &queue,
                        &timestamp_timezone,
                    )
                    .await
                    {
                        debug!(
                            rule_name = %rule_name,
                            vl_source = %vl_source,
                            error = %e,
                            "Failed to process log line, continuing"
                        );
                    }
                    Ok(())
                }
            })
            .await;

        if cancel.is_cancelled() {
            info!("Rule-source task stopping due to cancellation");
            return Ok(());
        }

        stream_result.map_err(RuleError::Stream)
    }
    .instrument(span)
    .await
}

/// Process a single log line through the pipeline.
///
/// Pipeline: parse -> throttle -> template -> queue
///
/// Returns Ok(()) if the line was processed (even if throttled).
/// Returns Err only for unexpected errors.
#[allow(clippy::too_many_arguments)]
async fn process_log_line(
    line: &str,
    parser: &RuleParser,
    throttler: &Throttler,
    template_engine: &TemplateEngine,
    template_name: &str,
    rule_name: &str,
    vl_source: &str,
    destinations: &[String],
    queue: &NotificationQueue,
    timestamp_timezone: &str,
) -> Result<(), ProcessError> {
    trace!(line_len = line.len(), "Processing log line");

    // Step 1: Parse the log line
    let fields = match parser.parse(line) {
        Ok(f) => {
            trace!(
                field_count = f.as_object().map(|o| o.len()).unwrap_or(0),
                "Parse successful"
            );
            f
        }
        Err(e) => {
            record_parse_error(rule_name, &e);
            return Err(ProcessError::Parse);
        }
    };

    // Step 1.5: Record successful match (before throttle check)
    record_log_matched(rule_name);

    // Step 2: Check throttle (renders key with both rule_name and vl_source)
    match throttler.check(&fields) {
        ThrottleResult::Pass => { /* continue */ }
        ThrottleResult::Throttled => {
            return Ok(());
        }
    }

    // Step 3: Render template (layer 1 sees both rule_name and vl_source)
    let rendered =
        template_engine.render_with_fallback(template_name, &fields, rule_name, vl_source);

    // Step 4: Extract _time from parsed fields for log timestamp
    let log_timestamp = fields
        .get("_time")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            warn!(
                rule_name = %rule_name,
                vl_source = %vl_source,
                "Missing _time field in log, using current time"
            );
            chrono::Utc::now().to_rfc3339()
        });

    let log_timestamp_formatted =
        crate::notify::format_log_timestamp(&log_timestamp, timestamp_timezone);

    // Step 5: Send to queue with destinations (Story 6.3)
    let payload = AlertPayload {
        message: rendered,
        rule_name: rule_name.to_string(),
        vl_source: vl_source.to_string(),
        destinations: destinations.to_vec(),
        log_timestamp,
        log_timestamp_formatted,
    };

    if let Err(e) = queue.send(payload) {
        warn!(
            rule_name = %rule_name,
            vl_source = %vl_source,
            error = %e,
            "Failed to send to notification queue"
        );
        return Err(ProcessError::Queue);
    }

    trace!("Alert queued successfully");
    Ok(())
}

/// Internal error type for process_log_line.
///
/// Not exposed publicly - just used to distinguish error types for logging.
#[derive(Debug)]
enum ProcessError {
    Parse,
    Queue,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Parse => write!(f, "parse error"),
            ProcessError::Queue => write!(f, "queue error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CompiledParser, CompiledRule, CompiledTemplate, DefaultsConfig, MetricsConfig,
        NotifyConfig, ThrottleConfig, VlSourceConfig,
    };
    use std::collections::{BTreeMap, HashMap};

    fn make_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create test client")
    }

    fn make_test_queue() -> NotificationQueue {
        NotificationQueue::new(10)
    }

    fn make_test_rule(name: &str, enabled: bool) -> CompiledRule {
        CompiledRule {
            name: name.to_string(),
            enabled,
            query: "_stream:test".to_string(),
            parser: CompiledParser {
                regex: None,
                json: None,
            },
            throttle: None,
            notify: NotifyConfig {
                template: "default".to_string(),
                mattermost_channel: None,
                destinations: vec!["mattermost-test".to_string()],
            },
            vl_sources: Vec::new(),
        }
    }

    fn make_test_runtime_config(rules: Vec<CompiledRule>) -> RuntimeConfig {
        let mut sources = BTreeMap::new();
        sources.insert(
            "default".to_string(),
            VlSourceConfig {
                url: "http://localhost:9428".to_string(),
                basic_auth: None,
                headers: None,
                tls: None,
            },
        );
        RuntimeConfig {
            victorialogs: sources,
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                timestamp_timezone: "UTC".to_string(),
            },
            templates: {
                let mut t = HashMap::new();
                t.insert(
                    "default".to_string(),
                    CompiledTemplate {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        email_body_html: None,
                        accent_color: None,
                    },
                );
                t
            },
            rules,
            metrics: MetricsConfig::default(),
            notifiers: None,
            config_dir: std::path::PathBuf::from("."),
        }
    }

    // ===================================================================
    // Task 1.1: Test création RuleEngine
    // ===================================================================

    #[test]
    fn engine_new_creates_instance() {
        let config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        let client = make_test_client();
        let queue = make_test_queue();

        let engine = RuleEngine::new(config, client, queue);

        // Just verify it creates without panic
        let debug = format!("{:?}", engine);
        assert!(debug.contains("RuleEngine"));
        assert!(debug.contains("rule_count"));
    }

    // ===================================================================
    // Task 1.2: Test RuleEngine::new with config, client, queue
    // ===================================================================

    #[test]
    fn engine_debug_shows_rule_counts() {
        let rules = vec![
            make_test_rule("rule1", true),
            make_test_rule("rule2", true),
            make_test_rule("rule3", false), // disabled
        ];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();

        let engine = RuleEngine::new(config, client, queue);
        let debug = format!("{:?}", engine);

        assert!(debug.contains("rule_count"));
        assert!(debug.contains("enabled_count"));
    }

    // ===================================================================
    // Task 1.3: Test RuleEngine::run spawns tasks per enabled rule
    // ===================================================================

    #[tokio::test]
    async fn engine_run_spawns_enabled_rules_only() {
        let rules = vec![
            make_test_rule("enabled_rule", true),
            make_test_rule("disabled_rule", false),
        ];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();
        let _rx = queue.subscribe(); // Keep queue alive

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        // Start engine in background
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

        // Give it time to spawn tasks
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel and wait
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;

        assert!(result.is_ok(), "Engine should shutdown within 1 second");
    }

    // ===================================================================
    // Task 1.4: Test graceful shutdown via cancellation
    // ===================================================================

    #[tokio::test]
    async fn engine_run_graceful_shutdown() {
        let rules = vec![make_test_rule("rule1", true)];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();
        let _rx = queue.subscribe();

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { engine.run(cancel_clone).await });

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel
        cancel.cancel();

        // Should complete quickly
        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok(), "Engine should shutdown gracefully");

        let inner = result.unwrap();
        assert!(inner.is_ok(), "Engine should return Ok");
    }

    // ===================================================================
    // Task 1.5: Test engine with no enabled rules
    // ===================================================================

    #[tokio::test]
    async fn engine_run_no_enabled_rules_exits() {
        let rules = vec![
            make_test_rule("disabled1", false),
            make_test_rule("disabled2", false),
        ];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();
        let _rx = queue.subscribe();

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        // Should exit immediately since no rules are enabled
        let result = engine.run(cancel).await;

        assert!(
            result.is_ok(),
            "Engine should return Ok with no enabled rules"
        );
    }

    // ===================================================================
    // Task 1.5: Test JoinSet supervision detects task completion
    // ===================================================================

    #[tokio::test]
    async fn engine_supervision_detects_completion() {
        let rules = vec![make_test_rule("rule1", true)];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();
        let _rx = queue.subscribe();

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        // Start and immediately cancel
        let cancel_clone = cancel.clone();
        cancel.cancel();

        let result = engine.run(cancel_clone).await;
        assert!(result.is_ok());
    }

    // ===================================================================
    // Additional tests for edge cases
    // ===================================================================

    #[tokio::test]
    async fn engine_run_with_empty_rules() {
        let config = make_test_runtime_config(vec![]);
        let client = make_test_client();
        let queue = make_test_queue();
        let _rx = queue.subscribe();

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        let result = engine.run(cancel).await;
        assert!(
            result.is_ok(),
            "Engine should handle empty rules gracefully"
        );
    }

    // ===================================================================
    // Task 2: Tests for process_log_line
    // ===================================================================

    fn make_test_templates() -> HashMap<String, CompiledTemplate> {
        let mut t = HashMap::new();
        t.insert(
            "default".to_string(),
            CompiledTemplate {
                title: "Alert: {{ _msg }}".to_string(),
                body: "Log: {{ _msg }}".to_string(),
                email_body_html: None,
                accent_color: Some("#ff0000".to_string()),
            },
        );
        t
    }

    #[tokio::test]
    async fn process_log_line_success() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 10,
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule", "vlprod");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test message"}"#;

        // Test with explicit destinations (Story 6.3)
        let destinations = vec!["mattermost-infra".to_string()];
        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &destinations,
            &queue,
            "UTC",
        )
        .await;

        assert!(result.is_ok());
        // Check that message was queued
        assert_eq!(queue.len(), 1);
    }

    #[tokio::test]
    async fn process_log_line_invalid_json() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 10,
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule", "vlprod");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let line = "not valid json";

        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &[], // Empty destinations = use default
            &queue,
            "UTC",
        )
        .await;

        // Should return error for invalid JSON
        assert!(result.is_err());
        // Queue should be empty
        assert_eq!(queue.len(), 0);
    }

    #[tokio::test]
    async fn process_log_line_throttled() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 1, // Only allow 1 alert
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule", "vlprod");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test"}"#;

        // First call passes
        let result1 = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &[], // Empty destinations = use default
            &queue,
            "UTC",
        )
        .await;
        assert!(result1.is_ok());
        assert_eq!(queue.len(), 1);

        // Second call is throttled (Ok but nothing queued)
        let result2 = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &[],
            &queue,
            "UTC",
        )
        .await;
        assert!(result2.is_ok());
        // Queue should still have only 1 message
        assert_eq!(queue.len(), 1);
    }

    #[tokio::test]
    async fn process_log_line_with_multiple_destinations() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 10,
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule", "vlprod");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let mut rx = queue.subscribe();

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test"}"#;

        // Test with multiple destinations (Story 6.3)
        let destinations = vec!["mattermost-infra".to_string(), "mattermost-ops".to_string()];
        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &destinations,
            &queue,
            "UTC",
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(queue.len(), 1);

        // Verify the payload has the destinations, timestamps, and vl_source
        let payload = rx.recv().await.unwrap();
        assert_eq!(payload.destinations.len(), 2);
        assert_eq!(payload.destinations[0], "mattermost-infra");
        assert_eq!(payload.destinations[1], "mattermost-ops");
        assert_eq!(payload.log_timestamp, "2026-01-09T10:00:00Z");
        assert_eq!(payload.log_timestamp_formatted, "09/01/2026 10:00:00 UTC");
        assert_eq!(payload.vl_source, "vlprod");
    }

    // ===================================================================
    // Task 3: Tests for panic handling / throttle reset callback
    // ===================================================================

    #[test]
    fn throttle_reset_callback_resets_cache() {
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 1,
            window: Duration::from_secs(60),
        };
        let throttler = Arc::new(Throttler::new(
            Some(&throttle_config),
            "test_rule",
            "vlprod",
        ));
        let callback = ThrottleResetCallback::new(Arc::clone(&throttler));

        // Use up the throttle limit
        let fields = serde_json::json!({"test": "value"});
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
        assert_eq!(throttler.check(&fields), ThrottleResult::Throttled);

        // Reset via callback
        callback.on_reconnect("test_rule");

        // Should pass again after reset
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
    }

    #[test]
    fn process_error_display() {
        assert_eq!(ProcessError::Parse.to_string(), "parse error");
        assert_eq!(ProcessError::Queue.to_string(), "queue error");
    }

    // ===================================================================
    // v2.0.0: resolve_sources multi-source fan-out semantics
    // ===================================================================

    fn sources_map(names: &[&str]) -> BTreeMap<String, VlSourceConfig> {
        let mut m = BTreeMap::new();
        for name in names {
            m.insert(
                (*name).to_string(),
                VlSourceConfig {
                    url: format!("http://{}:9428", name),
                    basic_auth: None,
                    headers: None,
                    tls: None,
                },
            );
        }
        m
    }

    #[test]
    fn resolve_sources_empty_rule_fans_out_to_all_sources() {
        let sources = sources_map(&["vldev", "vlprod"]);
        let rule = make_test_rule("r", true); // vl_sources is empty

        let resolved = resolve_sources(&rule, &sources);

        let names: Vec<&str> = resolved.iter().map(|(n, _)| n.as_str()).collect();
        // BTreeMap ordering → deterministic [vldev, vlprod]
        assert_eq!(names, vec!["vldev", "vlprod"]);
    }

    #[test]
    fn resolve_sources_with_subset_restricts_to_named_sources() {
        let sources = sources_map(&["vldev", "vlprod", "vlstaging"]);
        let mut rule = make_test_rule("r", true);
        rule.vl_sources = vec!["vlprod".to_string()];

        let resolved = resolve_sources(&rule, &sources);

        let names: Vec<&str> = resolved.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["vlprod"]);
    }

    #[test]
    fn resolve_sources_preserves_btreemap_order_regardless_of_rule_list_order() {
        // Rule lists sources in reverse alphabetical order; resolver must
        // still emit them in BTreeMap (deterministic) order.
        let sources = sources_map(&["vldev", "vlprod", "vlstaging"]);
        let mut rule = make_test_rule("r", true);
        rule.vl_sources = vec!["vlstaging".to_string(), "vldev".to_string()];

        let resolved = resolve_sources(&rule, &sources);

        let names: Vec<&str> = resolved.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["vldev", "vlstaging"]);
    }
}
