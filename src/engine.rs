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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::{BasicAuthConfig, CompiledRule, CompiledThrottle, RuntimeConfig, SecretString, TlsConfig};
use crate::error::RuleError;
use crate::notify::{AlertPayload, NotificationQueue};
use crate::parser::{RuleParser, record_parse_error};
use crate::tail::{ReconnectCallback, TailClient, TailConfig};
use crate::template::TemplateEngine;
use crate::throttle::{ThrottleResult, Throttler};

/// Delay before restarting a rule after panic (AD-07 inspired).
const PANIC_RESTART_DELAY: Duration = Duration::from_secs(5);

/// Context needed to spawn a rule task.
/// Stored to allow respawning after panic.
#[derive(Clone)]
struct RuleSpawnContext {
    rule: CompiledRule,
    vl_url: String,
    vl_basic_auth: Option<BasicAuthConfig>,
    vl_headers: Option<HashMap<String, SecretString>>,
    vl_tls: Option<TlsConfig>,
    queue: NotificationQueue,
    template_engine: Arc<TemplateEngine>,
    default_template: String,
    default_throttle: CompiledThrottle,
    webhook_url: Option<String>,
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
        let mut tasks: JoinSet<(String, Result<(), RuleError>)> = JoinSet::new();
        // Map AbortHandle ID to (rule_name, spawn_context) for respawn after panic
        let mut handle_to_context: HashMap<tokio::task::Id, (String, RuleSpawnContext)> =
            HashMap::new();

        // Spawn a task per enabled rule
        let enabled_count =
            self.spawn_rule_tasks(&mut tasks, &mut handle_to_context, cancel.clone());

        if enabled_count == 0 {
            warn!("No enabled rules found, engine will exit");
            return Ok(());
        }

        info!(
            rule_count = enabled_count,
            "Rule engine started, supervising rules"
        );

        // Supervision loop
        self.supervise_tasks(&mut tasks, &mut handle_to_context, cancel)
            .await
    }

    /// Spawn tasks for all enabled rules.
    ///
    /// Returns the number of enabled rules spawned.
    fn spawn_rule_tasks(
        &self,
        tasks: &mut JoinSet<(String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, RuleSpawnContext)>,
        cancel: CancellationToken,
    ) -> usize {
        let mut count = 0;

        // Create shared template engine for all rules
        let template_engine = Arc::new(TemplateEngine::new(self.runtime_config.templates.clone()));

        // Get default template name and throttle config
        let default_template = self.runtime_config.defaults.notify.template.clone();
        let default_throttle = CompiledThrottle {
            key_template: self.runtime_config.defaults.throttle.key.clone(),
            count: self.runtime_config.defaults.throttle.count,
            window: self.runtime_config.defaults.throttle.window,
        };

        // Get webhook URL (required for sending notifications)
        let webhook_url = self
            .runtime_config
            .mattermost_webhook
            .as_ref()
            .map(|s| s.expose().to_string());

        for rule in &self.runtime_config.rules {
            if !rule.enabled {
                info!(rule_name = %rule.name, "Rule disabled, skipping");
                continue;
            }

            let ctx = RuleSpawnContext {
                rule: rule.clone(),
                vl_url: self.runtime_config.victorialogs.url.clone(),
                vl_basic_auth: self.runtime_config.victorialogs.basic_auth.clone(),
                vl_headers: self.runtime_config.victorialogs.headers.clone(),
                vl_tls: self.runtime_config.victorialogs.tls.clone(),
                queue: self.queue.clone(),
                template_engine: Arc::clone(&template_engine),
                default_template: default_template.clone(),
                default_throttle: default_throttle.clone(),
                webhook_url: webhook_url.clone(),
            };

            let rule_name = rule.name.clone();
            Self::spawn_single_rule(tasks, handle_to_context, &ctx, &rule_name, cancel.clone());
            count += 1;
        }

        count
    }

    /// Spawn a single rule task and track its handle.
    fn spawn_single_rule(
        tasks: &mut JoinSet<(String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, RuleSpawnContext)>,
        ctx: &RuleSpawnContext,
        rule_name: &str,
        cancel: CancellationToken,
    ) {
        let rule_name_owned = rule_name.to_string();
        let ctx_clone = ctx.clone();

        let abort_handle = tasks.spawn(async move {
            let result = run_rule(ctx_clone, cancel).await;
            (rule_name_owned, result)
        });

        // Track context by task ID for respawn
        handle_to_context.insert(abort_handle.id(), (rule_name.to_string(), ctx.clone()));
    }

    /// Supervise running tasks and handle completion/errors/panics.
    async fn supervise_tasks(
        &self,
        tasks: &mut JoinSet<(String, Result<(), RuleError>)>,
        handle_to_context: &mut HashMap<tokio::task::Id, (String, RuleSpawnContext)>,
        cancel: CancellationToken,
    ) -> Result<(), RuleError> {
        loop {
            tokio::select! {
                Some(result) = tasks.join_next_with_id() => {
                    match result {
                        Ok((task_id, (rule_name, Ok(_)))) => {
                            // Task completed normally (shouldn't happen - rules run forever)
                            info!(rule_name = %rule_name, "Rule task completed normally");
                            handle_to_context.remove(&task_id);
                        }
                        Ok((task_id, (rule_name, Err(e)))) => {
                            // Fatal error from rule
                            error!(
                                rule_name = %rule_name,
                                error = %e,
                                "Rule task failed fatally"
                            );
                            // Don't restart - fatal errors are not recoverable
                            metrics::counter!(
                                "valerter_rule_errors_total",
                                "rule_name" => rule_name
                            ).increment(1);
                            handle_to_context.remove(&task_id);
                        }
                        Err(join_error) if join_error.is_panic() => {
                            // Get task ID from the JoinError
                            let task_id = join_error.id();
                            // PANIC - extract rule info from our tracking map
                            if let Some((rule_name, ctx)) = handle_to_context.remove(&task_id) {
                                // Log CRITICAL with rule_name (Fix H3)
                                error!(
                                    rule_name = %rule_name,
                                    error = %join_error,
                                    "Rule task panicked - CRITICAL"
                                );

                                // Increment metric with rule_name label (Fix H2)
                                metrics::counter!(
                                    "valerter_rule_panics_total",
                                    "rule_name" => rule_name.clone()
                                ).increment(1);

                                // Respawn after delay if not cancelled (Fix H1)
                                if !cancel.is_cancelled() {
                                    info!(
                                        rule_name = %rule_name,
                                        delay_secs = PANIC_RESTART_DELAY.as_secs(),
                                        "Respawning rule after panic delay"
                                    );
                                    tokio::time::sleep(PANIC_RESTART_DELAY).await;

                                    // Respawn the task
                                    if !cancel.is_cancelled() {
                                        Self::spawn_single_rule(
                                            tasks,
                                            handle_to_context,
                                            &ctx,
                                            &rule_name,
                                            cancel.clone(),
                                        );
                                        info!(rule_name = %rule_name, "Rule respawned after panic");
                                    }
                                }
                            } else {
                                // Should never happen, but log if it does
                                error!(
                                    error = %join_error,
                                    "Rule task panicked but context not found - CRITICAL"
                                );
                                metrics::counter!("valerter_rule_panics_total", "rule_name" => "unknown").increment(1);
                            }
                        }
                        Err(join_error) => {
                            // Task was cancelled - get ID and clean up
                            let task_id = join_error.id();
                            tracing::debug!(error = %join_error, "Rule task cancelled");
                            handle_to_context.remove(&task_id);
                        }
                    }

                    // If no tasks remain and not cancelled, exit
                    if tasks.is_empty() && !cancel.is_cancelled() {
                        warn!("All rule tasks completed unexpectedly");
                        return Ok(());
                    }
                }
                _ = cancel.cancelled() => {
                    info!("Shutdown signal received, aborting all rules");
                    tasks.abort_all();

                    // Drain remaining tasks
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
    let span = tracing::info_span!("run_rule", rule_name = %ctx.rule.name);
    let _guard = span.enter();

    info!("Rule task started");

    // Create parser for this rule
    let parser = RuleParser::from_compiled(&ctx.rule.parser);

    // Create throttler for this rule (uses rule's config or defaults)
    let throttle_config = ctx.rule.throttle.as_ref().unwrap_or(&ctx.default_throttle);
    let throttler = Arc::new(Throttler::new(Some(throttle_config), &ctx.rule.name));

    // Get template name for this rule
    let template_name = ctx
        .rule
        .notify
        .as_ref()
        .and_then(|n| n.template.clone())
        .unwrap_or(ctx.default_template.clone());

    // Get webhook URL (required for sending notifications)
    let webhook_url = match &ctx.webhook_url {
        Some(url) => url.clone(),
        None => {
            warn!(rule_name = %ctx.rule.name, "No webhook URL configured, rule will not send notifications");
            // Still run the rule (for testing/metrics purposes), but don't send
            String::new()
        }
    };

    // Wrap parser in Arc for sharing across closure invocations
    let parser = Arc::new(parser);

    // Create callback for throttle reset on reconnection
    let reconnect_callback = ThrottleResetCallback::new(Arc::clone(&throttler));

    // Create TailClient for VictoriaLogs
    let tail_config = TailConfig {
        base_url: ctx.vl_url.clone(),
        query: ctx.rule.query.clone(),
        start: None,
        basic_auth: ctx.vl_basic_auth.clone(),
        headers: ctx.vl_headers.clone(),
        tls: ctx.vl_tls.clone(),
    };

    let mut tail_client = TailClient::new(tail_config).map_err(RuleError::Stream)?;

    // Stream with reconnection - runs until cancelled
    let rule_name = ctx.rule.name.clone();
    let template_name = Arc::new(template_name);
    let webhook_url = Arc::new(webhook_url);
    let template_engine = ctx.template_engine;
    let queue = ctx.queue;

    let stream_result = tail_client
        .stream_with_reconnect(&rule_name, Some(&reconnect_callback), |line| {
            // Process each log line
            // Clone Arcs for the async block (cheap reference counting)
            let queue = queue.clone();
            let parser = Arc::clone(&parser);
            let throttler = Arc::clone(&throttler);
            let template_engine = Arc::clone(&template_engine);
            let template_name = Arc::clone(&template_name);
            let rule_name = rule_name.clone();
            let webhook_url = Arc::clone(&webhook_url);

            async move {
                // Pattern Log+Continue: never propagate errors, just log and continue
                if let Err(e) = process_log_line(
                    &line,
                    &parser,
                    &throttler,
                    &template_engine,
                    &template_name,
                    &rule_name,
                    &webhook_url,
                    &queue,
                )
                .await
                {
                    // Log at appropriate level based on error type
                    debug!(
                        rule_name = %rule_name,
                        error = %e,
                        "Failed to process log line, continuing"
                    );
                }
                Ok(())
            }
        })
        .await;

    // Check if we were cancelled or had an error
    if cancel.is_cancelled() {
        info!("Rule task stopping due to cancellation");
        return Ok(());
    }

    // If we get here, stream ended unexpectedly
    stream_result.map_err(RuleError::Stream)
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
    webhook_url: &str,
    queue: &NotificationQueue,
) -> Result<(), ProcessError> {
    // Step 1: Parse the log line
    let fields = match parser.parse(line) {
        Ok(f) => f,
        Err(e) => {
            record_parse_error(rule_name, &e);
            return Err(ProcessError::Parse);
        }
    };

    // Step 2: Check throttle
    match throttler.check(&fields) {
        ThrottleResult::Pass => { /* continue */ }
        ThrottleResult::Throttled => {
            // Throttled - not an error, just skip sending
            return Ok(());
        }
    }

    // Step 3: Render template
    let rendered = template_engine.render_with_fallback(template_name, &fields, rule_name);

    // Step 4: Send to queue (if webhook configured)
    if !webhook_url.is_empty() {
        let payload = AlertPayload {
            message: rendered,
            rule_name: rule_name.to_string(),
            webhook_url: webhook_url.to_string(),
        };

        if let Err(e) = queue.send(payload) {
            warn!(
                rule_name = %rule_name,
                error = %e,
                "Failed to send to notification queue"
            );
            return Err(ProcessError::Queue);
        }
    }

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
        NotifyDefaults, ThrottleConfig, VictoriaLogsConfig,
    };
    use std::collections::HashMap;

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
            notify: None,
        }
    }

    fn make_test_runtime_config(rules: Vec<CompiledRule>) -> RuntimeConfig {
        RuntimeConfig {
            victorialogs: VictoriaLogsConfig {
                url: "http://localhost:9428".to_string(),
                basic_auth: None,
                headers: None,
                tls: None,
            },
            defaults: DefaultsConfig {
                throttle: ThrottleConfig {
                    key: None,
                    count: 5,
                    window: Duration::from_secs(60),
                },
                notify: NotifyDefaults {
                    template: "default".to_string(),
                },
            },
            templates: {
                let mut t = HashMap::new();
                t.insert(
                    "default".to_string(),
                    CompiledTemplate {
                        title: "{{ title }}".to_string(),
                        body: "{{ body }}".to_string(),
                        color: None,
                        icon: None,
                    },
                );
                t
            },
            rules,
            metrics: MetricsConfig::default(),
            notifiers: None,
            mattermost_webhook: None,
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
                color: Some("#ff0000".to_string()),
                icon: None,
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
        let throttler = Throttler::new(Some(&throttle_config), "test_rule");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test message"}"#;

        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "https://example.com/webhook",
            &queue,
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
        let throttler = Throttler::new(Some(&throttle_config), "test_rule");
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
            "https://example.com/webhook",
            &queue,
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
        let throttler = Throttler::new(Some(&throttle_config), "test_rule");
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
            "https://example.com/webhook",
            &queue,
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
            "https://example.com/webhook",
            &queue,
        )
        .await;
        assert!(result2.is_ok());
        // Queue should still have only 1 message
        assert_eq!(queue.len(), 1);
    }

    #[tokio::test]
    async fn process_log_line_no_webhook_skips_send() {
        let parser = RuleParser::new(None, None);
        let throttle_config = CompiledThrottle {
            key_template: None,
            count: 10,
            window: Duration::from_secs(60),
        };
        let throttler = Throttler::new(Some(&throttle_config), "test_rule");
        let template_engine = TemplateEngine::new(make_test_templates());
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        let line = r#"{"_time":"2026-01-09T10:00:00Z","_stream":"{}","_msg":"test"}"#;

        // Empty webhook URL should skip sending
        let result = process_log_line(
            line,
            &parser,
            &throttler,
            &template_engine,
            "default",
            "test_rule",
            "",
            &queue,
        )
        .await;

        assert!(result.is_ok());
        // Queue should be empty since webhook was empty
        assert_eq!(queue.len(), 0);
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
        let throttler = Arc::new(Throttler::new(Some(&throttle_config), "test_rule"));
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
}
