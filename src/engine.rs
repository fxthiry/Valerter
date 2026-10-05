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
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, trace, warn};

use crate::config::{CompiledRule, CompiledThrottle, RuntimeConfig, VlSourceConfig};
use crate::error::RuleError;
use crate::notify::{AlertPayload, NotificationQueue};
use crate::parser::{RuleParser, record_log_matched, record_parse_error};
use crate::tail::{ReconnectCallback, TailClient, TailConfig};
use crate::template::TemplateEngine;
use crate::throttle::{
    DEFAULT_MAX_CAPACITY, ThrottleResult, ThrottleStore, Throttler, key_references_vl_source,
};

/// Delay before restarting a task after its first consecutive panic.
const PANIC_RESTART_BASE_DELAY: Duration = Duration::from_secs(5);

/// Upper bound of the restart delay after repeated panics.
const PANIC_RESTART_MAX_DELAY: Duration = Duration::from_secs(300);

/// Run time after which a task that panics again starts a new panic series.
const PANIC_STABLE_RUN_RESET: Duration = Duration::from_secs(600);

/// Restart delay after the `consecutive_panics`-th consecutive panic of a
/// task: 5 s, doubled per panic, capped at 5 min (saturating, so any count is
/// safe).
fn panic_restart_delay(consecutive_panics: u32) -> Duration {
    let factor = 2u32
        .checked_pow(consecutive_panics.saturating_sub(1))
        .unwrap_or(u32::MAX);
    PANIC_RESTART_BASE_DELAY
        .saturating_mul(factor)
        .min(PANIC_RESTART_MAX_DELAY)
}

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
pub(crate) struct RuleSpawnContext {
    rule: CompiledRule,
    vl_source_name: String,
    vl_source_config: VlSourceConfig,
    queue: NotificationQueue,
    template_engine: Arc<TemplateEngine>,
    default_throttle: CompiledThrottle,
    /// Throttle state of the rule, shared by all its sources. Kept across a
    /// respawn after panic.
    throttle_store: Arc<ThrottleStore>,
    /// Timezone for formatting log timestamps.
    timestamp_timezone: String,
}

impl RuleSpawnContext {
    /// Throttle config in effect for the rule (`rule.throttle` or defaults).
    fn throttle_config(&self) -> &CompiledThrottle {
        self.rule
            .throttle
            .as_ref()
            .unwrap_or(&self.default_throttle)
    }

    /// Build this task's view on the rule's shared throttle store.
    fn throttler(&self) -> Throttler {
        Throttler::with_store(
            Arc::clone(&self.throttle_store),
            Some(self.throttle_config()),
            &self.rule.name,
            &self.vl_source_name,
        )
    }
}

/// Supervision state of one running (or restart-pending) `(rule, source)`
/// task, keyed by its Tokio task ID.
struct TrackedTask {
    rule_name: String,
    vl_source: String,
    ctx: RuleSpawnContext,
    /// Consecutive panics that led to this spawn (0 for the initial spawn).
    consecutive_panics: u32,
    /// When the task starts running, i.e. once its restart delay has elapsed.
    started_at: Instant,
}

/// Tasks supervised by the engine, by Tokio task ID.
type TaskMap = HashMap<tokio::task::Id, TrackedTask>;

/// Custom throttle key of a rule whose counter is shared across its sources.
///
/// Returns the key template when the rule targets at least two sources and
/// its effective throttle key does not reference `vl_source`. The default key
/// embeds the source, and a key that does not compile is left to config
/// validation: both return `None`.
fn shared_throttle_key<'a>(
    rule: &'a CompiledRule,
    default_throttle: &'a CompiledThrottle,
    source_count: usize,
) -> Option<&'a str> {
    if source_count < 2 {
        return None;
    }
    let throttle = rule.throttle.as_ref().unwrap_or(default_throttle);
    let key = throttle.key_template.as_deref()?;
    (key_references_vl_source(key) == Some(false)).then_some(key)
}

/// Future returned by a [`RuleRunner`] for one `(rule, source)` task.
pub(crate) type RuleTaskFuture = Pin<Box<dyn Future<Output = Result<(), RuleError>> + Send>>;

/// Factory that builds the future run by each `(rule, source)` task.
///
/// `run_rule` is the production implementation; tests substitute a scripted
/// runner to exercise task endings (fatal error, completion) without network.
pub(crate) type RuleRunner =
    Arc<dyn Fn(RuleSpawnContext, CancellationToken) -> RuleTaskFuture + Send + Sync>;

/// Default [`RuleRunner`]: the full streaming pipeline.
fn default_rule_runner() -> RuleRunner {
    Arc::new(|ctx, cancel| Box::pin(run_rule(ctx, cancel)))
}

/// Rule engine that orchestrates all alert rules.
///
/// The engine spawns independent tasks for each enabled rule and supervises
/// them using `JoinSet`. This provides:
/// - Task isolation (one rule's error doesn't affect others)
/// - Panic detection and logging
/// - Automatic restart after panic, with exponential backoff (AC #4)
/// - Graceful shutdown via cancellation token
pub struct RuleEngine {
    /// Runtime configuration with compiled rules.
    runtime_config: RuntimeConfig,
    /// Notification queue for sending alerts.
    queue: NotificationQueue,
    /// Factory for the per-`(rule, source)` task future.
    runner: RuleRunner,
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
            runner: default_rule_runner(),
        }
    }

    /// Replace the task factory (tests only).
    #[cfg(test)]
    pub(crate) fn with_runner(mut self, runner: RuleRunner) -> Self {
        self.runner = runner;
        self
    }

    /// Run the engine until cancelled.
    ///
    /// Spawns a task per enabled rule and supervises them via `JoinSet`.
    /// Handles:
    /// - Normal task completion (shouldn't happen - rules run forever)
    /// - Fatal errors (logged, task not restarted)
    /// - Panics (logged as CRITICAL, task restarted after a backoff delay)
    /// - Cancellation (graceful shutdown)
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` only when cancelled. Returns
    /// [`RuleError::NoEnabledRules`] when no task could be spawned and
    /// [`RuleError::AllTasksStopped`] when every task ended without a
    /// cancellation, so the daemon exits non-zero instead of silently
    /// watching nothing.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), RuleError> {
        let mut tasks: JoinSet<(String, String, Result<(), RuleError>)> = JoinSet::new();
        // Map task ID to the `(rule, source)` pair, its spawn context and its
        // panic history, for respawn after panic. Each pair is a distinct task.
        let mut handle_to_context = TaskMap::new();

        // Spawn a task per (enabled rule, resolved source) pair
        let spawned_count =
            self.spawn_rule_tasks(&mut tasks, &mut handle_to_context, cancel.clone());

        if spawned_count == 0 {
            error!("No enabled rules found, engine will exit");
            return Err(RuleError::NoEnabledRules);
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
        handle_to_context: &mut TaskMap,
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

            if let Some(key) = shared_throttle_key(rule, &default_throttle, resolved.len()) {
                info!(
                    rule_name = %rule.name,
                    source_count = resolved.len(),
                    throttle_key = %key,
                    "Throttle key does not reference vl_source: its counter is shared across the rule's sources; add {{{{ vl_source }}}} to the key to isolate them"
                );
            }

            // One throttle store per rule, shared by its (rule, source) tasks
            // and kept in their spawn context across a respawn after panic.
            let throttle_window = rule.throttle.as_ref().unwrap_or(&default_throttle).window;
            let throttle_store = Arc::new(ThrottleStore::new(
                throttle_window,
                DEFAULT_MAX_CAPACITY * resolved.len() as u64,
            ));

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
                    throttle_store: Arc::clone(&throttle_store),
                    timestamp_timezone: self.runtime_config.defaults.timestamp_timezone.clone(),
                };

                Self::spawn_single_rule(
                    tasks,
                    handle_to_context,
                    &self.runner,
                    ctx,
                    cancel.clone(),
                    0,
                );
                count += 1;
            }
        }

        count
    }

    /// Spawn a single `(rule, source)` task and track its handle.
    ///
    /// After a panic (`consecutive_panics > 0`) the task first waits its
    /// restart delay, so the supervision loop never sleeps: the pending task
    /// stays in the `JoinSet` (it counts as active) and a cancellation ends
    /// the wait at once, without running the rule.
    fn spawn_single_rule(
        tasks: &mut JoinSet<(String, String, Result<(), RuleError>)>,
        handle_to_context: &mut TaskMap,
        runner: &RuleRunner,
        ctx: RuleSpawnContext,
        cancel: CancellationToken,
        consecutive_panics: u32,
    ) {
        let delay = if consecutive_panics == 0 {
            Duration::ZERO
        } else {
            panic_restart_delay(consecutive_panics)
        };
        let ctx_clone = ctx.clone();
        let runner = Arc::clone(runner);

        let abort_handle = tasks.spawn(async move {
            let rule_name_for_return = ctx_clone.rule.name.clone();
            let vl_source_for_return = ctx_clone.vl_source_name.clone();
            if !delay.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.cancelled() => {
                        return (rule_name_for_return, vl_source_for_return, Ok(()));
                    }
                }
                info!(
                    rule_name = %rule_name_for_return,
                    vl_source = %vl_source_for_return,
                    "Rule-source task respawned after panic"
                );
            }
            // Build the future inside the task so a panic in the factory is
            // caught by the JoinSet like any other task panic.
            let result = runner(ctx_clone, cancel).await;
            (rule_name_for_return, vl_source_for_return, result)
        });

        // Track context by task ID for respawn
        handle_to_context.insert(
            abort_handle.id(),
            TrackedTask {
                rule_name: ctx.rule.name.clone(),
                vl_source: ctx.vl_source_name.clone(),
                ctx,
                consecutive_panics,
                started_at: Instant::now() + delay,
            },
        );
    }

    /// Supervise running tasks and handle completion/errors/panics.
    async fn supervise_tasks(
        &self,
        tasks: &mut JoinSet<(String, String, Result<(), RuleError>)>,
        handle_to_context: &mut TaskMap,
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
                                "rule_name" => rule_name,
                                "vl_source" => vl_source,
                            ).increment(1);
                            handle_to_context.remove(&task_id);
                        }
                        Err(join_error) if join_error.is_panic() => {
                            let task_id = join_error.id();
                            if let Some(tracked) = handle_to_context.remove(&task_id) {
                                let TrackedTask { rule_name, vl_source, ctx, .. } = &tracked;
                                error!(
                                    rule_name = %rule_name,
                                    vl_source = %vl_source,
                                    error = %join_error,
                                    "Rule task panicked - CRITICAL"
                                );

                                metrics::counter!(
                                    "valerter_rule_panics_total",
                                    "rule_name" => rule_name.clone(),
                                    "vl_source" => vl_source.clone(),
                                ).increment(1);

                                if !cancel.is_cancelled() {
                                    // A task that ran long enough starts a new
                                    // panic series; there is no restart limit.
                                    let consecutive_panics = if tracked.started_at.elapsed()
                                        >= PANIC_STABLE_RUN_RESET
                                    {
                                        1
                                    } else {
                                        tracked.consecutive_panics.saturating_add(1)
                                    };
                                    info!(
                                        rule_name = %rule_name,
                                        vl_source = %vl_source,
                                        delay_secs = panic_restart_delay(consecutive_panics).as_secs(),
                                        consecutive_panics,
                                        "Respawning rule-source task after panic delay"
                                    );
                                    Self::spawn_single_rule(
                                        tasks,
                                        handle_to_context,
                                        &self.runner,
                                        ctx.clone(),
                                        cancel.clone(),
                                        consecutive_panics,
                                    );
                                }
                            } else {
                                error!(
                                    error = %join_error,
                                    "Rule task panicked but context not found - CRITICAL"
                                );
                                metrics::counter!(
                                    "valerter_rule_panics_total",
                                    "rule_name" => "unknown",
                                    "vl_source" => "unknown",
                                )
                                .increment(1);
                            }
                        }
                        Err(join_error) => {
                            let task_id = join_error.id();
                            tracing::debug!(error = %join_error, "Rule task cancelled");
                            handle_to_context.remove(&task_id);
                        }
                    }

                    // A task waiting for its restart delay is still in the
                    // set, so it keeps this check from firing.
                    if tasks.is_empty() && !cancel.is_cancelled() {
                        error!("All rule tasks completed unexpectedly");
                        return Err(RuleError::AllTasksStopped);
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
    fn on_reconnect(&self, _rule_name: &str, _vl_source: &str) {
        // The throttle store is shared by the rule's sources, but this
        // task's Throttler is bound to its own source: the reset only drops
        // keys fed exclusively by the source that just recovered.
        self.throttler.reset();
    }
}

/// Run a single rule task with full pipeline processing.
///
/// This function implements the complete rule processing loop:
/// 1. Connect to VictoriaLogs with reconnection handling
/// 2. Parse each log line
/// 3. Check throttle (on the rule's store, shared with its other sources)
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

        // Create this task's throttler on the rule's shared store. Keys are
        // counted across the rule's sources; the default key embeds
        // vl_source, so default buckets stay isolated per source.
        let throttle_config = ctx.throttle_config();
        let throttler = Arc::new(ctx.throttler());
        debug!(
            throttle_count = throttle_config.count,
            throttle_window_secs = throttle_config.window.as_secs(),
            "Throttler initialized"
        );

        // Get template name and destinations for this rule (both are now required)
        let template_name = ctx.rule.notify.template.clone();
        let destinations = ctx.rule.notify.destinations.clone();
        let mattermost_channel = ctx.rule.notify.mattermost_channel.clone();
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
        if tail_config.custom_authorization_overrides_basic_auth() {
            warn!(
                rule_name = %ctx.rule.name,
                vl_source = %ctx.vl_source_name,
                "Custom Authorization header overrides basic_auth for this VictoriaLogs source"
            );
        }

        let mut tail_client = TailClient::new(tail_config).map_err(RuleError::Stream)?;

        // Stream with reconnection - runs until cancelled
        let rule_name = ctx.rule.name.clone();
        let vl_source = Arc::new(ctx.vl_source_name.clone());
        let template_name = Arc::new(template_name);
        let destinations = Arc::new(destinations);
        let mattermost_channel = Arc::new(mattermost_channel);
        let template_engine = ctx.template_engine;
        let queue = ctx.queue;
        let timestamp_timezone = Arc::new(ctx.timestamp_timezone.clone());

        let stream_result = tail_client
            .stream_with_reconnect(
                &rule_name,
                vl_source.as_str(),
                Some(&reconnect_callback),
                |line| {
                    // Process each log line
                    let queue = queue.clone();
                    let parser = Arc::clone(&parser);
                    let throttler = Arc::clone(&throttler);
                    let template_engine = Arc::clone(&template_engine);
                    let template_name = Arc::clone(&template_name);
                    let rule_name = rule_name.clone();
                    let vl_source = Arc::clone(&vl_source);
                    let destinations = Arc::clone(&destinations);
                    let mattermost_channel = Arc::clone(&mattermost_channel);
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
                            mattermost_channel.as_deref(),
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
                },
            )
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
    mattermost_channel: Option<&str>,
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
            record_parse_error(rule_name, vl_source, &e);
            return Err(ProcessError::Parse);
        }
    };

    // Step 1.5: Record successful match (before throttle check)
    record_log_matched(rule_name, vl_source);

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
        mattermost_channel: mattermost_channel.map(str::to_string),
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

    /// Notifier that accepts every alert without sending anything.
    struct NoopNotifier(&'static str);

    #[async_trait::async_trait]
    impl crate::notify::Notifier for NoopNotifier {
        fn name(&self) -> &str {
            self.0
        }

        fn notifier_type(&self) -> &str {
            "noop"
        }

        async fn send(&self, _alert: &AlertPayload) -> Result<(), crate::error::NotifyError> {
            Ok(())
        }
    }

    /// Queue routing to the destinations used by these tests (no worker:
    /// alerts stay pending so tests can inspect them).
    fn make_test_queue() -> NotificationQueue {
        let mut registry = crate::notify::NotifierRegistry::new();
        for name in ["mattermost-test", "mattermost-infra", "mattermost-ops"] {
            registry.register(Arc::new(NoopNotifier(name))).unwrap();
        }
        NotificationQueue::new(10, &registry)
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
                max_streams: crate::config::DEFAULT_MAX_STREAMS,
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

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        // Should exit immediately since no rules are enabled
        let result = engine.run(cancel).await;

        assert!(
            matches!(result, Err(RuleError::NoEnabledRules)),
            "Engine should return NoEnabledRules with no enabled rules, got {:?}",
            result
        );
    }

    // ===================================================================
    // Task 1.5: engine run with a token cancelled before it starts
    // ===================================================================

    #[tokio::test]
    async fn engine_run_returns_ok_when_cancelled_before_start() {
        let rules = vec![make_test_rule("rule1", true)];
        let config = make_test_runtime_config(rules);
        let client = make_test_client();
        let queue = make_test_queue();

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

        let engine = RuleEngine::new(config, client, queue);
        let cancel = CancellationToken::new();

        let result = engine.run(cancel).await;
        assert!(
            matches!(result, Err(RuleError::NoEnabledRules)),
            "Engine should return NoEnabledRules with empty rules, got {:?}",
            result
        );
    }

    /// Runner whose tasks all fail fatally right away.
    fn failing_runner() -> RuleRunner {
        Arc::new(|_ctx, _cancel| {
            Box::pin(async {
                Err(RuleError::Stream(
                    crate::error::StreamError::ConnectionFailed("scripted failure".to_string()),
                ))
            })
        })
    }

    #[test]
    fn engine_run_all_tasks_failed_returns_all_tasks_stopped() {
        // Two sources so the engine supervises several tasks that all fail.
        let mut config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        config.victorialogs.insert(
            "other".to_string(),
            VlSourceConfig {
                url: "http://localhost:9429".to_string(),
                basic_auth: None,
                headers: None,
                tls: None,
            },
        );
        let queue = make_test_queue();
        let engine =
            RuleEngine::new(config, make_test_client(), queue).with_runner(failing_runner());
        let cancel = CancellationToken::new();

        // Local recorder + current-thread runtime: the supervision loop runs
        // on this thread, so its counter increments land in this recorder.
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(1), engine.run(cancel.clone())).await
            })
        });

        let result = result.expect("engine should return promptly once all tasks stopped");
        assert!(
            matches!(result, Err(RuleError::AllTasksStopped)),
            "expected AllTasksStopped, got {:?}",
            result
        );
        assert!(!cancel.is_cancelled());

        let rendered = handle.render();
        for source in ["default", "other"] {
            let series = format!(
                "valerter_rule_errors_total{{rule_name=\"rule1\",vl_source=\"{source}\"}} 1"
            );
            assert!(
                rendered.contains(&series),
                "missing {series} in:\n{rendered}"
            );
        }
    }

    #[tokio::test]
    async fn engine_run_with_custom_runner_stops_on_cancel() {
        // A runner that waits for cancellation behaves like the real pipeline.
        let runner: RuleRunner = Arc::new(|_ctx, cancel| {
            Box::pin(async move {
                cancel.cancelled().await;
                Ok(())
            })
        });
        let config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        let queue = make_test_queue();
        let engine = RuleEngine::new(config, make_test_client(), queue).with_runner(runner);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { engine.run(cancel_clone).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("engine should stop within 1 second")
            .unwrap();
        assert!(result.is_ok(), "cancelled engine should return Ok");
    }

    // ===================================================================
    // Restart after panic (virtual time)
    // ===================================================================

    /// One run of a scripted `(rule, source)` task. Once a source's script is
    /// exhausted, its task runs until cancelled.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// Panic as soon as the task starts.
        Panic,
        /// Run for the given time, then panic.
        PanicAfter(Duration),
        /// Run for the given time, then fail fatally.
        FailAfter(Duration),
    }

    /// Per-source script of a [`scripted_runner`] and the start time of every
    /// task it ran.
    #[derive(Default)]
    struct Script {
        steps: std::sync::Mutex<HashMap<String, std::collections::VecDeque<Step>>>,
        starts: std::sync::Mutex<Vec<(String, Instant)>>,
    }

    impl Script {
        /// Start times of the tasks run for `source`, in order.
        fn starts_of(&self, source: &str) -> Vec<Instant> {
            self.starts
                .lock()
                .unwrap()
                .iter()
                .filter(|(s, _)| s == source)
                .map(|(_, at)| *at)
                .collect()
        }
    }

    /// Runner that follows a script per source name (panic, fatal error or
    /// idle until cancelled) and records when each task starts.
    fn scripted_runner(steps: &[(&str, &[Step])]) -> (RuleRunner, Arc<Script>) {
        let script = Arc::new(Script::default());
        *script.steps.lock().unwrap() = steps
            .iter()
            .map(|(source, steps)| (source.to_string(), steps.iter().copied().collect()))
            .collect();
        let shared = Arc::clone(&script);
        let runner: RuleRunner = Arc::new(move |ctx, cancel| {
            let script = Arc::clone(&shared);
            Box::pin(async move {
                let source = ctx.vl_source_name.clone();
                script
                    .starts
                    .lock()
                    .unwrap()
                    .push((source.clone(), Instant::now()));
                let step = script
                    .steps
                    .lock()
                    .unwrap()
                    .get_mut(&source)
                    .and_then(|steps| steps.pop_front());
                match step {
                    Some(Step::Panic) => panic!("scripted panic"),
                    Some(Step::PanicAfter(after)) => {
                        tokio::time::sleep(after).await;
                        panic!("scripted panic");
                    }
                    Some(Step::FailAfter(after)) => {
                        tokio::time::sleep(after).await;
                        Err(RuleError::Stream(
                            crate::error::StreamError::ConnectionFailed(
                                "scripted failure".to_string(),
                            ),
                        ))
                    }
                    None => {
                        cancel.cancelled().await;
                        Ok(())
                    }
                }
            })
        });
        (runner, script)
    }

    /// Engine running `rule1` on the given sources with `runner`.
    fn engine_on_sources(sources: &[&str], runner: RuleRunner) -> RuleEngine {
        let mut config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        config.victorialogs = sources_map(sources);
        RuleEngine::new(config, make_test_client(), make_test_queue()).with_runner(runner)
    }

    /// Prometheus recorder installed for the current thread (the tests below
    /// run on a current-thread runtime, so every task records into it).
    fn local_recorder() -> (
        metrics::LocalRecorderGuard<'static>,
        metrics_exporter_prometheus::PrometheusHandle,
    ) {
        let recorder: &'static _ = Box::leak(Box::new(
            metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder(),
        ));
        let handle = recorder.handle();
        (metrics::set_default_local_recorder(recorder), handle)
    }

    #[test]
    fn panic_restart_delay_doubles_up_to_five_minutes() {
        let delays: Vec<u64> = (1..=9).map(|n| panic_restart_delay(n).as_secs()).collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(panic_restart_delay(33).as_secs(), 300);
        assert_eq!(panic_restart_delay(u32::MAX).as_secs(), 300);
    }

    #[tokio::test(start_paused = true)]
    async fn supervision_keeps_running_during_panic_restart_delay() {
        let (_guard, metrics) = local_recorder();
        let (runner, script) = scripted_runner(&[
            ("vla", &[Step::Panic]),
            ("vlb", &[Step::FailAfter(Duration::from_secs(1))]),
        ]);
        let engine = engine_on_sources(&["vla", "vlb"], runner);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        // vla waits for its 5 s restart delay; vlb's fatal error at 1 s is
        // handled meanwhile.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let rendered = metrics.render();
        assert!(
            rendered
                .contains("valerter_rule_errors_total{rule_name=\"rule1\",vl_source=\"vlb\"} 1"),
            "fatal error not handled during the restart delay:\n{rendered}"
        );
        assert!(
            rendered
                .contains("valerter_rule_panics_total{rule_name=\"rule1\",vl_source=\"vla\"} 1"),
            "panic not counted:\n{rendered}"
        );

        // Shutdown during the delay returns at once, without a restart.
        let before = Instant::now();
        cancel.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "cancelled engine should return Ok");
        assert_eq!(Instant::now(), before, "shutdown waited for the delay");
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            script.starts_of("vla").len(),
            1,
            "task restarted after shutdown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn simultaneous_panics_restart_after_their_own_delay() {
        let (runner, script) = scripted_runner(&[("vla", &[Step::Panic]), ("vlb", &[Step::Panic])]);
        let engine = engine_on_sources(&["vla", "vlb"], runner);
        let cancel = CancellationToken::new();
        let t0 = Instant::now();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        tokio::time::sleep(Duration::from_secs(6)).await;
        let restarted = t0 + Duration::from_secs(5);
        assert_eq!(script.starts_of("vla"), [t0, restarted]);
        assert_eq!(script.starts_of("vlb"), [t0, restarted]);

        cancel.cancel();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn task_waiting_for_restart_counts_as_active() {
        let (runner, script) = scripted_runner(&[
            ("vla", &[Step::Panic]),
            ("vlb", &[Step::FailAfter(Duration::from_secs(1))]),
        ]);
        let engine = engine_on_sources(&["vla", "vlb"], runner);
        let cancel = CancellationToken::new();
        let t0 = Instant::now();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        // At 2 s vlb has stopped and vla only waits for its restart.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!handle.is_finished(), "engine reported all tasks stopped");

        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(script.starts_of("vla"), [t0, t0 + Duration::from_secs(5)]);
        assert!(!handle.is_finished());

        cancel.cancel();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_panics_back_off_exponentially_without_limit() {
        let (_guard, metrics) = local_recorder();
        let (runner, script) = scripted_runner(&[("vla", &[Step::Panic; 12])]);
        let engine = engine_on_sources(&["vla"], runner);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        // 5+10+20+40+80+160 s, then 6 × 300 s: 2115 s for 12 panics.
        tokio::time::sleep(Duration::from_secs(2200)).await;
        let starts = script.starts_of("vla");
        let delays: Vec<u64> = starts.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
        assert_eq!(
            delays,
            [5, 10, 20, 40, 80, 160, 300, 300, 300, 300, 300, 300]
        );

        let rendered = metrics.render();
        assert!(
            rendered
                .contains("valerter_rule_panics_total{rule_name=\"rule1\",vl_source=\"vla\"} 12"),
            "expected 12 panics:\n{rendered}"
        );
        assert!(
            !rendered.contains("valerter_rule_errors_total"),
            "panics must not count as errors:\n{rendered}"
        );

        cancel.cancel();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn stable_run_resets_panic_backoff() {
        let (runner, script) = scripted_runner(&[
            // Runs 10 min after its second restart: the next panic is a first one.
            (
                "vla",
                &[
                    Step::Panic,
                    Step::Panic,
                    Step::PanicAfter(Duration::from_secs(600)),
                    Step::Panic,
                ],
            ),
            // Runs 1 s less: the backoff keeps growing.
            (
                "vlb",
                &[
                    Step::Panic,
                    Step::Panic,
                    Step::PanicAfter(Duration::from_secs(599)),
                ],
            ),
        ]);
        let engine = engine_on_sources(&["vla", "vlb"], runner);
        let cancel = CancellationToken::new();
        let t0 = Instant::now();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        tokio::time::sleep(Duration::from_secs(700)).await;
        let secs = |starts: Vec<Instant>| -> Vec<u64> {
            starts.iter().map(|at| (*at - t0).as_secs()).collect()
        };
        // vla: panics at 615 s after 600 s of run, restarts 5 s later, then
        // its next immediate panic waits 10 s.
        assert_eq!(secs(script.starts_of("vla")), [0, 5, 15, 620, 630]);
        // vlb: panics at 614 s, third consecutive panic, restarts 20 s later.
        assert_eq!(secs(script.starts_of("vlb")), [0, 5, 15, 634]);

        cancel.cancel();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn respawn_after_panic_keeps_the_throttle_store() {
        let stores: Arc<std::sync::Mutex<Vec<Arc<ThrottleStore>>>> = Arc::default();
        let runner: RuleRunner = {
            let stores = Arc::clone(&stores);
            Arc::new(move |ctx, cancel| {
                let first = {
                    let mut stores = stores.lock().unwrap();
                    stores.push(Arc::clone(&ctx.throttle_store));
                    stores.len() == 1
                };
                Box::pin(async move {
                    assert!(!first, "scripted panic");
                    cancel.cancelled().await;
                    Ok(())
                })
            })
        };
        let engine = engine_on_sources(&["vla"], runner);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { engine.run(cancel).await }
        });

        tokio::time::sleep(Duration::from_secs(6)).await;
        {
            let stores = stores.lock().unwrap();
            assert_eq!(stores.len(), 2, "task not restarted");
            assert!(Arc::ptr_eq(&stores[0], &stores[1]));
        }

        cancel.cancel();
        assert!(handle.await.unwrap().is_ok());
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
        let queue = make_test_queue();

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
            None,
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
        let queue = make_test_queue();

        let line = "not valid json";

        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "vlprod",
            &["mattermost-test".to_string()],
            None,
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
        let queue = make_test_queue();

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
            &["mattermost-test".to_string()],
            None,
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
            &["mattermost-test".to_string()],
            None,
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
        let queue = make_test_queue();

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
            None,
            &queue,
            "UTC",
        )
        .await;

        assert!(result.is_ok());
        // One pending delivery per destination
        assert_eq!(queue.len(), 2);

        // Verify the payload has the destinations, timestamps, and vl_source
        let payload = queue.take_pending("mattermost-ops").unwrap();
        assert_eq!(payload.destinations.len(), 2);
        assert_eq!(payload.destinations[0], "mattermost-infra");
        assert_eq!(payload.destinations[1], "mattermost-ops");
        assert_eq!(payload.log_timestamp, "2026-01-09T10:00:00Z");
        assert_eq!(payload.log_timestamp_formatted, "09/01/2026 10:00:00 UTC");
        assert_eq!(payload.vl_source, "vlprod");
        assert_eq!(payload.mattermost_channel, None);
    }

    #[tokio::test]
    async fn process_log_line_carries_rule_mattermost_channel() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 10,
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule", "vlprod");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = make_test_queue();
        let destinations = vec!["mattermost-test".to_string()];

        for (line, channel) in [
            (
                r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"with"}"#,
                Some("alerts"),
            ),
            (
                r#"{"_time":"2026-01-09T10:00:01Z","_stream":"{}","_msg":"without"}"#,
                None,
            ),
        ] {
            process_log_line(
                line,
                &parser,
                &throttler,
                &template_engine,
                "default",
                "test_rule",
                "vlprod",
                &destinations,
                channel,
                &queue,
                "UTC",
            )
            .await
            .unwrap();

            let payload = queue.take_pending("mattermost-test").unwrap();
            assert_eq!(payload.mattermost_channel.as_deref(), channel);
        }
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
        callback.on_reconnect("test_rule", "vlprod");

        // Should pass again after reset
        assert_eq!(throttler.check(&fields), ThrottleResult::Pass);
    }

    #[test]
    fn throttle_reset_callback_keeps_keys_opened_by_another_source() {
        let throttle_config = CompiledThrottle {
            key_template: Some("{{ rule_name }}".to_string()),
            count: 1,
            window: Duration::from_secs(60),
        };
        let store = Arc::new(ThrottleStore::new(throttle_config.window, 20_000));
        let prod = Arc::new(Throttler::with_store(
            Arc::clone(&store),
            Some(&throttle_config),
            "test_rule",
            "vlprod",
        ));
        let dev = Arc::new(Throttler::with_store(
            store,
            Some(&throttle_config),
            "test_rule",
            "vldev",
        ));
        let prod_callback = ThrottleResetCallback::new(Arc::clone(&prod));
        let _dev_callback = ThrottleResetCallback::new(Arc::clone(&dev));

        // vldev opens the shared key, then vlprod reconnects.
        let fields = serde_json::json!({"test": "value"});
        assert_eq!(dev.check(&fields), ThrottleResult::Pass);
        prod_callback.on_reconnect("test_rule", "vlprod");

        assert_eq!(prod.check(&fields), ThrottleResult::Throttled);
    }

    /// Spawn the engine's tasks with an idle runner and return their spawn
    /// contexts, ordered by source name. Must run inside a Tokio runtime.
    fn spawned_contexts(config: RuntimeConfig) -> Vec<RuleSpawnContext> {
        let queue = make_test_queue();
        let idle: RuleRunner = Arc::new(|_ctx, cancel| {
            Box::pin(async move {
                cancel.cancelled().await;
                Ok(())
            })
        });
        let engine = RuleEngine::new(config, make_test_client(), queue).with_runner(idle);
        let mut tasks = JoinSet::new();
        let mut handle_to_context = HashMap::new();
        engine.spawn_rule_tasks(&mut tasks, &mut handle_to_context, CancellationToken::new());
        tasks.abort_all();

        let mut contexts: Vec<RuleSpawnContext> = handle_to_context
            .into_values()
            .map(|tracked| tracked.ctx)
            .collect();
        contexts.sort_by(|a, b| a.vl_source_name.cmp(&b.vl_source_name));
        contexts
    }

    #[tokio::test]
    async fn rule_tasks_share_one_throttle_store() {
        let mut config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        config.victorialogs = sources_map(&["vldev", "vlprod"]);

        let contexts = spawned_contexts(config);

        assert_eq!(contexts.len(), 2);
        assert!(Arc::ptr_eq(
            &contexts[0].throttle_store,
            &contexts[1].throttle_store
        ));
    }

    #[tokio::test]
    async fn respawned_task_keeps_the_rule_throttle_counters() {
        let mut config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        config.defaults.throttle.count = 1;

        let contexts = spawned_contexts(config);
        let ctx = &contexts[0];

        let fields = serde_json::json!({"test": "value"});
        let first = ctx.throttler();
        assert_eq!(first.check(&fields), ThrottleResult::Pass);
        drop(first);

        // A respawn after panic rebuilds the throttler from the stored context.
        let respawned = ctx.clone().throttler();
        assert_eq!(respawned.check(&fields), ThrottleResult::Throttled);
    }

    #[tokio::test]
    async fn throttle_store_capacity_scales_with_source_count() {
        let mut config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        config.victorialogs = sources_map(&["vldev", "vlprod", "vlstaging"]);
        let contexts = spawned_contexts(config);
        assert_eq!(contexts.len(), 3);
        assert_eq!(contexts[0].throttle_store.max_capacity(), Some(30_000));

        let config = make_test_runtime_config(vec![make_test_rule("rule1", true)]);
        let contexts = spawned_contexts(config);
        assert_eq!(contexts[0].throttle_store.max_capacity(), Some(10_000));
    }

    // ===================================================================
    // Startup INFO log for a throttle key shared across sources
    // ===================================================================

    fn throttle_with_key(key: Option<&str>) -> CompiledThrottle {
        CompiledThrottle {
            key_template: key.map(String::from),
            count: 1,
            window: Duration::from_secs(60),
        }
    }

    #[test]
    fn shared_throttle_key_flags_rule_name_key_on_two_sources() {
        let mut rule = make_test_rule("VM_OFF", true);
        rule.throttle = Some(throttle_with_key(Some("{{ rule_name }}")));
        let defaults = throttle_with_key(None);

        assert_eq!(
            shared_throttle_key(&rule, &defaults, 2),
            Some("{{ rule_name }}")
        );
    }

    #[test]
    fn shared_throttle_key_flags_key_inherited_from_defaults() {
        let rule = make_test_rule("VM_OFF", true);
        let defaults = throttle_with_key(Some("{{ host }}"));

        assert_eq!(shared_throttle_key(&rule, &defaults, 2), Some("{{ host }}"));
    }

    #[test]
    fn shared_throttle_key_ignores_isolated_default_or_single_source_keys() {
        let defaults = throttle_with_key(None);

        let mut with_source = make_test_rule("r", true);
        with_source.throttle = Some(throttle_with_key(Some("{{ vl_source }}-{{ host }}")));
        assert_eq!(shared_throttle_key(&with_source, &defaults, 2), None);

        let mut default_key = make_test_rule("r", true);
        default_key.throttle = Some(throttle_with_key(None));
        assert_eq!(shared_throttle_key(&default_key, &defaults, 2), None);
        assert_eq!(
            shared_throttle_key(&make_test_rule("r", true), &defaults, 2),
            None
        );

        let mut single = make_test_rule("r", true);
        single.throttle = Some(throttle_with_key(Some("{{ rule_name }}")));
        assert_eq!(shared_throttle_key(&single, &defaults, 1), None);
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
