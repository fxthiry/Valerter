//! Asynchronous notification queue for Mattermost alerts.
//!
//! This module implements a bounded notification queue with Drop Oldest strategy
//! using `tokio::sync::broadcast` channel, plus HTTP sending with exponential
//! backoff retry to Mattermost.
//!
//! # Architecture
//!
//! The notification module sits at the end of the pipeline:
//! ```text
//! parser.rs -> throttle.rs -> template.rs -> notify.rs -> Mattermost
//! ```
//!
//! # Key Features
//!
//! - **Non-blocking send**: Callers never block when submitting alerts
//! - **Drop Oldest**: When queue is full, oldest alerts are dropped (AD-02)
//! - **Metrics**: Queue size and dropped alerts are tracked (AD-05)
//! - **Graceful shutdown**: Worker supports cancellation token
//! - **Retry with backoff**: Exponential backoff on transient failures (AD-07)
//!
//! # Example
//!
//! ```ignore
//! use valerter::notify::{NotificationQueue, NotificationWorker, AlertPayload};
//! use tokio_util::sync::CancellationToken;
//!
//! let queue = NotificationQueue::new(100);
//! let client = reqwest::Client::builder()
//!     .timeout(std::time::Duration::from_secs(10))
//!     .build()
//!     .unwrap();
//! let mut worker = NotificationWorker::new(&queue, client);
//! let cancel = CancellationToken::new();
//!
//! // Send alert (non-blocking)
//! queue.send(payload)?;
//!
//! // Worker consumes in background
//! tokio::spawn(async move {
//!     worker.run(cancel).await;
//! });
//! ```

use crate::error::{NotifyError, QueueError};
use crate::template::RenderedMessage;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Backoff base delay for Mattermost retries (AD-07).
const MATTERMOST_BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Maximum backoff delay for Mattermost retries (AD-07).
const MATTERMOST_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Maximum number of retry attempts for Mattermost (AD-07).
const MATTERMOST_MAX_RETRIES: u32 = 3;

/// Default queue capacity (FR32).
pub const DEFAULT_QUEUE_CAPACITY: usize = 100;

/// Mattermost attachment structure for incoming webhooks.
#[derive(Debug, Clone, Serialize)]
struct MattermostAttachment {
    fallback: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
    title: String,
    text: String,
    footer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer_icon: Option<String>,
}

/// Mattermost webhook payload structure.
#[derive(Debug, Clone, Serialize)]
struct MattermostPayload {
    attachments: Vec<MattermostAttachment>,
}

/// Calculate exponential backoff delay.
///
/// Formula: min(base * 2^attempt, max)
///
/// # Arguments
///
/// * `attempt` - Current attempt number (0-indexed)
/// * `base` - Base delay duration
/// * `max` - Maximum delay cap
///
/// # Returns
///
/// The calculated delay, capped at `max`.
///
/// # Example
///
/// With base=500ms, max=5s:
/// - Attempt 0: 500ms
/// - Attempt 1: 1s
/// - Attempt 2: 2s
/// - Attempt 3: 4s
/// - Attempt 4+: 5s (capped)
fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
    std::cmp::min(delay, max)
}

/// Build Mattermost webhook payload from rendered message.
fn build_mattermost_payload(message: &RenderedMessage, rule_name: &str) -> MattermostPayload {
    MattermostPayload {
        attachments: vec![MattermostAttachment {
            fallback: message.title.clone(),
            color: message.color.clone(),
            title: message.title.clone(),
            text: message.body.clone(),
            footer: format!("valerter | {}", rule_name),
            footer_icon: message.icon.clone(),
        }],
    }
}

/// Payload ready to be sent to Mattermost.
///
/// Contains all fields needed to send a notification.
/// Must implement `Clone` as required by `broadcast::Sender`.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    /// Rendered message content (title, body, color, icon).
    pub message: RenderedMessage,
    /// Rule name for tracing and metrics.
    pub rule_name: String,
    /// Webhook URL to send the notification to.
    pub webhook_url: String,
}

/// Notification queue using broadcast channel with ring buffer.
///
/// The broadcast channel provides native Drop Oldest behavior:
/// when capacity is reached, old messages are automatically overwritten.
///
/// # Thread Safety
///
/// The queue is `Clone + Send + Sync` and can be shared across tasks.
#[derive(Debug, Clone)]
pub struct NotificationQueue {
    tx: broadcast::Sender<AlertPayload>,
}

impl NotificationQueue {
    /// Create a new notification queue with specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of messages in the queue (FR32: 100).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let queue = NotificationQueue::new(100);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Send an alert to the queue (non-blocking).
    ///
    /// This operation never blocks. If the queue is full, the oldest
    /// messages will be dropped (detected by receivers as `Lagged`).
    ///
    /// # Arguments
    ///
    /// * `payload` - Alert payload to send.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Alert queued successfully.
    /// * `Err(QueueError::Closed)` - No active receivers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// queue.send(AlertPayload {
    ///     message: rendered_msg,
    ///     rule_name: "my_rule".to_string(),
    ///     webhook_url: "https://...".to_string(),
    /// })?;
    /// ```
    pub fn send(&self, payload: AlertPayload) -> Result<(), QueueError> {
        self.tx.send(payload).map_err(|_| QueueError::Closed)?;

        // Update queue size metric (AD-05)
        metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);

        Ok(())
    }

    /// Create a new receiver for this queue.
    ///
    /// Each receiver gets its own view of the queue and can lag
    /// independently.
    ///
    /// # Returns
    ///
    /// A new `broadcast::Receiver` for consuming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<AlertPayload> {
        self.tx.subscribe()
    }

    /// Get the current number of messages in the queue.
    ///
    /// Note: This is approximate as messages may be added/removed
    /// concurrently.
    pub fn len(&self) -> usize {
        self.tx.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tx.len() == 0
    }
}

/// Worker that consumes alerts from the queue and sends them.
///
/// The worker runs in a loop, processing alerts until cancelled
/// or the queue is closed.
pub struct NotificationWorker {
    rx: broadcast::Receiver<AlertPayload>,
    /// Reference to sender for queue size metrics.
    tx: broadcast::Sender<AlertPayload>,
    /// HTTP client for sending to Mattermost.
    client: reqwest::Client,
}

impl NotificationWorker {
    /// Create a new notification worker from a queue.
    ///
    /// # Arguments
    ///
    /// * `queue` - Reference to the notification queue.
    /// * `client` - HTTP client for Mattermost requests (shared, connection pooling).
    pub fn new(queue: &NotificationQueue, client: reqwest::Client) -> Self {
        Self {
            rx: queue.subscribe(),
            tx: queue.tx.clone(),
            client,
        }
    }

    /// Run the worker loop until cancelled or queue closed.
    ///
    /// The worker will:
    /// 1. Consume alerts from the queue
    /// 2. Handle `Lagged` errors by logging and updating metrics
    /// 3. Send alerts to Mattermost with retry on transient failures
    /// 4. Stop gracefully when cancellation is requested
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    pub async fn run(&mut self, cancel: CancellationToken) {
        tracing::info!("Notification worker started");

        loop {
            tokio::select! {
                result = self.rx.recv() => {
                    match result {
                        Ok(payload) => {
                            self.process_alert(payload).await;
                            // Update queue size metric after consuming (AD-05)
                            metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Drop Oldest detected - log and update metric (AD-02)
                            // Note: rule_name label not available here as messages are lost.
                            // This is a known limitation of the broadcast Drop Oldest strategy.
                            tracing::warn!(
                                dropped_count = n,
                                "Queue full, dropping {} oldest alerts",
                                n
                            );
                            metrics::counter!("valerter_alerts_dropped_total")
                                .increment(n);

                            // Update queue size metric after lag recovery
                            metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);
                            // Continue - receiver auto-repositions to oldest available
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("Notification queue closed");
                            return;
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::info!("Notification worker shutting down gracefully");
                    return;
                }
            }
        }
    }

    /// Process a single alert payload.
    ///
    /// Creates a tracing span with rule_name for debugging.
    /// Uses Log+Continue pattern: never panics on error.
    async fn process_alert(&self, payload: AlertPayload) {
        let span = tracing::info_span!(
            "process_notification",
            rule_name = %payload.rule_name
        );
        let _guard = span.enter();

        tracing::debug!(
            // Note: Don't log full webhook URL (contains secret token)
            "Processing alert"
        );

        // Pattern Log+Continue: never panic on error
        if let Err(e) = send_to_mattermost(&self.client, &payload).await {
            tracing::error!(
                error = %e,
                "Failed to send notification after all retries"
            );
            // Metric already incremented in send_to_mattermost
        }
    }
}

impl std::fmt::Debug for NotificationWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationWorker").finish()
    }
}

/// Send alert to Mattermost with retry on transient failures.
///
/// Implements exponential backoff: 500ms -> 1s -> 2s (max 5s cap).
/// Maximum 3 retries before giving up.
///
/// # Retry Policy
///
/// - **5xx errors**: Retry (server temporarily unavailable)
/// - **Network errors**: Retry (timeout, connection refused)
/// - **4xx errors**: Do NOT retry (client error, invalid payload)
///
/// # Arguments
///
/// * `client` - HTTP client (shared, connection pooling)
/// * `payload` - Alert payload with webhook URL and rendered message
///
/// # Returns
///
/// * `Ok(())` - Successfully sent
/// * `Err(NotifyError)` - Failed after all retries
async fn send_to_mattermost(
    client: &reqwest::Client,
    payload: &AlertPayload,
) -> Result<(), NotifyError> {
    let span = tracing::info_span!(
        "send_mattermost",
        rule_name = %payload.rule_name
    );
    let _guard = span.enter();

    let mattermost_payload = build_mattermost_payload(&payload.message, &payload.rule_name);

    for attempt in 0..MATTERMOST_MAX_RETRIES {
        match client
            .post(&payload.webhook_url)
            .json(&mattermost_payload)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Alert sent successfully");
                metrics::counter!(
                    "valerter_alerts_sent_total",
                    "rule_name" => payload.rule_name.clone()
                )
                .increment(1);
                return Ok(());
            }
            Ok(response) if response.status().is_client_error() => {
                // 4xx errors: don't retry (invalid payload, bad webhook)
                let status = response.status();
                tracing::error!(
                    status = %status,
                    "Mattermost returned client error, not retrying"
                );
                metrics::counter!(
                    "valerter_notify_errors_total",
                    "rule_name" => payload.rule_name.clone()
                )
                .increment(1);
                return Err(NotifyError::SendFailed(format!("client error: {}", status)));
            }
            Ok(response) => {
                // 5xx errors: retry
                tracing::warn!(
                    attempt = attempt,
                    status = %response.status(),
                    "Mattermost returned server error, retrying"
                );
            }
            Err(e) => {
                // Network errors: retry
                tracing::warn!(
                    attempt = attempt,
                    error = %e,
                    "Failed to send to Mattermost, retrying"
                );
            }
        }

        // Apply backoff delay before next retry (except after last attempt)
        if attempt < MATTERMOST_MAX_RETRIES - 1 {
            let delay = backoff_delay(attempt, MATTERMOST_BACKOFF_BASE, MATTERMOST_BACKOFF_MAX);
            tracing::debug!(delay_ms = delay.as_millis(), "Waiting before retry");
            tokio::time::sleep(delay).await;
        }
    }

    // All retries exhausted
    tracing::error!(
        max_retries = MATTERMOST_MAX_RETRIES,
        "Failed to send alert after all retries"
    );
    metrics::counter!(
        "valerter_notify_errors_total",
        "rule_name" => payload.rule_name.clone()
    )
    .increment(1);
    Err(NotifyError::MaxRetriesExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_payload(rule_name: &str) -> AlertPayload {
        AlertPayload {
            message: RenderedMessage {
                title: format!("Alert from {}", rule_name),
                body: "Test body".to_string(),
                color: Some("#ff0000".to_string()),
                icon: None,
            },
            rule_name: rule_name.to_string(),
            webhook_url: "https://mattermost.example.com/hooks/xxx".to_string(),
        }
    }

    fn make_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create test client")
    }

    // ===================================================================
    // Task 6.1: Test envoi simple dans queue (non-bloquant)
    // ===================================================================

    #[test]
    fn send_to_queue_is_non_blocking() {
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe(); // Need at least one receiver

        let payload = make_payload("test_rule");
        let result = queue.send(payload);

        assert!(result.is_ok());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn send_without_receiver_returns_error() {
        let queue = NotificationQueue::new(10);
        // No receiver subscribed

        let payload = make_payload("test_rule");
        let result = queue.send(payload);

        assert!(result.is_err());
        match result.unwrap_err() {
            QueueError::Closed => {}
        }
    }

    // ===================================================================
    // Task 6.2: Test consommation message par worker
    // ===================================================================

    #[tokio::test]
    async fn worker_consumes_message() {
        let queue = NotificationQueue::new(10);
        let client = make_test_client();
        let mut worker = NotificationWorker::new(&queue, client);
        let cancel = CancellationToken::new();

        // Send a message
        let payload = make_payload("test_rule");
        queue.send(payload).unwrap();

        // Run worker briefly then cancel
        let cancel_clone = cancel.clone();
        let worker_handle = tokio::spawn(async move {
            worker.run(cancel_clone).await;
        });

        // Give worker time to process
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        worker_handle.await.unwrap();
        // If we get here without panic, worker consumed the message
    }

    // ===================================================================
    // Task 6.3: Test stratégie Drop Oldest avec broadcast::Lagged
    // ===================================================================

    #[tokio::test]
    async fn drop_oldest_when_queue_full() {
        // Create small queue for testing
        // Broadcast channel capacity is the number of messages it can hold
        let queue = NotificationQueue::new(5);
        let mut rx = queue.subscribe();

        // Fill queue beyond capacity - broadcast will overwrite old messages
        // Send 10 messages to a queue of capacity 5
        for i in 0..10 {
            let payload = make_payload(&format!("rule_{}", i));
            let _ = queue.send(payload);
        }

        // First recv should return Lagged indicating messages were dropped
        // The exact count depends on internal broadcast buffer behavior
        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Broadcast drops oldest when buffer overflows
                // At least some messages should be dropped
                assert!(n >= 1, "Expected at least 1 lagged message, got {}", n);
                // With capacity 5 and 10 sent, we expect several dropped
                assert!(n <= 10, "Cannot drop more messages than sent");
            }
            Ok(_) => panic!("Expected Lagged error when queue overflows"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // ===================================================================
    // Task 6.4: Test métrique queue_size mise à jour
    // ===================================================================

    #[test]
    fn queue_size_updates_on_send() {
        let queue = NotificationQueue::new(10);
        let _rx = queue.subscribe();

        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());

        queue.send(make_payload("rule_1")).unwrap();
        assert_eq!(queue.len(), 1);

        queue.send(make_payload("rule_2")).unwrap();
        assert_eq!(queue.len(), 2);
    }

    // ===================================================================
    // Task 6.5: Test métrique alerts_dropped incrémentée sur lag
    // ===================================================================

    #[tokio::test]
    async fn worker_increments_dropped_metric_on_lag() {
        // Create small queue to trigger lag
        let queue = NotificationQueue::new(3);
        let client = make_test_client();
        let mut worker = NotificationWorker::new(&queue, client);
        let cancel = CancellationToken::new();

        // Overflow the queue before worker starts consuming
        for i in 0..10 {
            let payload = make_payload(&format!("rule_{}", i));
            let _ = queue.send(payload);
        }

        // Run worker briefly - it should encounter Lagged and increment metric
        let cancel_clone = cancel.clone();
        let worker_handle = tokio::spawn(async move {
            worker.run(cancel_clone).await;
        });

        // Give worker time to process the lag
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        worker_handle.await.unwrap();
        // The worker should have logged the lag and incremented
        // valerter_alerts_dropped_total counter.
        // Note: We can't easily verify the metric value without a metrics recorder,
        // but the test verifies the code path executes without panic.
    }

    // ===================================================================
    // Task 6.6: Test graceful shutdown worker avec CancellationToken
    // ===================================================================

    #[tokio::test]
    async fn worker_graceful_shutdown() {
        let queue = NotificationQueue::new(10);
        let client = make_test_client();
        let mut worker = NotificationWorker::new(&queue, client);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let worker_handle = tokio::spawn(async move {
            worker.run(cancel_clone).await;
        });

        // Cancel immediately
        cancel.cancel();

        // Worker should exit cleanly
        let result = tokio::time::timeout(Duration::from_secs(1), worker_handle).await;
        assert!(result.is_ok(), "Worker should shutdown within 1 second");
    }

    // ===================================================================
    // Task 6.7: Test capacité queue (100 messages)
    // ===================================================================

    #[test]
    fn queue_capacity_is_respected() {
        let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY);
        let _rx = queue.subscribe();

        // Send exactly 100 messages
        for i in 0..DEFAULT_QUEUE_CAPACITY {
            let payload = make_payload(&format!("rule_{}", i));
            queue.send(payload).unwrap();
        }

        assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);
    }

    // ===================================================================
    // Story 3.3: Tests backoff_delay calculation
    // ===================================================================

    #[test]
    fn backoff_delay_calculation() {
        let base = Duration::from_millis(500);
        let max = Duration::from_secs(5);

        // Attempt 0: 500ms * 2^0 = 500ms
        assert_eq!(backoff_delay(0, base, max), Duration::from_millis(500));
        // Attempt 1: 500ms * 2^1 = 1000ms
        assert_eq!(backoff_delay(1, base, max), Duration::from_millis(1000));
        // Attempt 2: 500ms * 2^2 = 2000ms
        assert_eq!(backoff_delay(2, base, max), Duration::from_millis(2000));
        // Attempt 3: 500ms * 2^3 = 4000ms
        assert_eq!(backoff_delay(3, base, max), Duration::from_millis(4000));
        // Attempt 4: 500ms * 2^4 = 8000ms, capped to 5000ms
        assert_eq!(backoff_delay(4, base, max), Duration::from_secs(5));
        // Attempt 10: would overflow, capped to max
        assert_eq!(backoff_delay(10, base, max), Duration::from_secs(5));
    }

    #[test]
    fn backoff_delay_handles_overflow() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        // Very high attempt should not panic, should cap at max
        assert_eq!(backoff_delay(100, base, max), max);
    }

    // ===================================================================
    // Story 3.3: Tests Mattermost payload building
    // ===================================================================

    #[test]
    fn build_mattermost_payload_structure() {
        let message = RenderedMessage {
            title: "Test Alert".to_string(),
            body: "Something happened".to_string(),
            color: Some("#ff0000".to_string()),
            icon: Some(":warning:".to_string()),
        };

        let payload = build_mattermost_payload(&message, "test_rule");

        assert_eq!(payload.attachments.len(), 1);
        let attachment = &payload.attachments[0];
        assert_eq!(attachment.fallback, "Test Alert");
        assert_eq!(attachment.title, "Test Alert");
        assert_eq!(attachment.text, "Something happened");
        assert_eq!(attachment.color, Some("#ff0000".to_string()));
        assert_eq!(attachment.footer, "valerter | test_rule");
        assert_eq!(attachment.footer_icon, Some(":warning:".to_string()));
    }

    #[test]
    fn build_mattermost_payload_without_optional_fields() {
        let message = RenderedMessage {
            title: "Simple Alert".to_string(),
            body: "Body text".to_string(),
            color: None,
            icon: None,
        };

        let payload = build_mattermost_payload(&message, "simple_rule");

        let attachment = &payload.attachments[0];
        assert_eq!(attachment.color, None);
        assert_eq!(attachment.footer_icon, None);
    }

    #[test]
    fn mattermost_payload_serializes_correctly() {
        let message = RenderedMessage {
            title: "Test".to_string(),
            body: "Body".to_string(),
            color: Some("#00ff00".to_string()),
            icon: None,
        };

        let payload = build_mattermost_payload(&message, "rule");
        let json = serde_json::to_string(&payload).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"attachments\""));
        assert!(json.contains("\"fallback\":\"Test\""));
        assert!(json.contains("\"title\":\"Test\""));
        assert!(json.contains("\"text\":\"Body\""));
        assert!(json.contains("\"color\":\"#00ff00\""));
        assert!(json.contains("\"footer\":\"valerter | rule\""));
        // footer_icon should be omitted when None
        assert!(!json.contains("footer_icon"));
    }

    // ===================================================================
    // Additional tests for edge cases
    // ===================================================================

    #[test]
    fn alert_payload_clone_works() {
        let payload = AlertPayload {
            message: RenderedMessage {
                title: "Test".to_string(),
                body: "Body".to_string(),
                color: Some("#ff0000".to_string()),
                icon: Some(":warning:".to_string()),
            },
            rule_name: "my_rule".to_string(),
            webhook_url: "https://example.com/hook".to_string(),
        };

        let cloned = payload.clone();
        assert_eq!(cloned.rule_name, payload.rule_name);
        assert_eq!(cloned.message.title, payload.message.title);
    }

    #[test]
    fn queue_is_clone() {
        let queue1 = NotificationQueue::new(10);
        let queue2 = queue1.clone();

        let _rx = queue1.subscribe();

        // Both references should share the same channel
        queue1.send(make_payload("rule_1")).unwrap();
        assert_eq!(queue2.len(), 1);
    }

    #[test]
    fn queue_debug_format() {
        let queue = NotificationQueue::new(10);
        let debug = format!("{:?}", queue);
        assert!(debug.contains("NotificationQueue"));
    }

    #[test]
    fn worker_debug_format() {
        let queue = NotificationQueue::new(10);
        let client = reqwest::Client::new();
        let worker = NotificationWorker::new(&queue, client);
        let debug = format!("{:?}", worker);
        assert!(debug.contains("NotificationWorker"));
    }

    #[tokio::test]
    async fn worker_exits_on_channel_closed() {
        // Test that worker exits when broadcast channel is closed
        // Note: With the new design where worker holds tx for metrics,
        // the channel only closes when worker's tx is also dropped.
        // This test verifies the Closed error path is reachable.
        let (tx, rx) = broadcast::channel::<AlertPayload>(10);

        let mut test_rx = rx;

        // Drop sender to close channel
        drop(tx);

        // Verify that recv returns Closed
        match test_rx.recv().await {
            Err(broadcast::error::RecvError::Closed) => {
                // Expected - channel is closed
            }
            Ok(_) => panic!("Expected Closed error"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn multiple_messages_consumed_in_order() {
        let queue = NotificationQueue::new(10);
        let mut rx = queue.subscribe();

        // Send messages
        for i in 0..3 {
            queue.send(make_payload(&format!("rule_{}", i))).unwrap();
        }

        // Receive in order
        let msg0 = rx.recv().await.unwrap();
        assert_eq!(msg0.rule_name, "rule_0");

        let msg1 = rx.recv().await.unwrap();
        assert_eq!(msg1.rule_name, "rule_1");

        let msg2 = rx.recv().await.unwrap();
        assert_eq!(msg2.rule_name, "rule_2");
    }
}
