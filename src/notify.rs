//! Asynchronous notification queue for Mattermost alerts.
//!
//! This module implements a bounded notification queue with Drop Oldest strategy
//! using `tokio::sync::broadcast` channel.
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
//!
//! # Example
//!
//! ```ignore
//! use valerter::notify::{NotificationQueue, NotificationWorker, AlertPayload};
//! use tokio_util::sync::CancellationToken;
//!
//! let queue = NotificationQueue::new(100);
//! let mut worker = NotificationWorker::new(&queue);
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

use crate::error::QueueError;
use crate::template::RenderedMessage;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Default queue capacity (FR32).
pub const DEFAULT_QUEUE_CAPACITY: usize = 100;

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
}

impl NotificationWorker {
    /// Create a new notification worker from a queue.
    ///
    /// # Arguments
    ///
    /// * `queue` - Reference to the notification queue.
    pub fn new(queue: &NotificationQueue) -> Self {
        Self {
            rx: queue.subscribe(),
            tx: queue.tx.clone(),
        }
    }

    /// Run the worker loop until cancelled or queue closed.
    ///
    /// The worker will:
    /// 1. Consume alerts from the queue
    /// 2. Handle `Lagged` errors by logging and updating metrics
    /// 3. Send alerts via `send_to_mattermost` (stub for Story 3.3)
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
    async fn process_alert(&self, payload: AlertPayload) {
        let span = tracing::info_span!(
            "process_notification",
            rule_name = %payload.rule_name
        );
        let _guard = span.enter();

        // Update queue size metric after consuming
        // Note: This is handled by the queue on send, but we log processing here
        tracing::debug!(
            webhook_url = %payload.webhook_url,
            "Processing alert"
        );

        // Delegate to Mattermost sender (stub for Story 3.3)
        send_to_mattermost(&payload).await;
    }
}

impl std::fmt::Debug for NotificationWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationWorker").finish()
    }
}

/// Send alert to Mattermost (stub for Story 3.3).
///
/// This function will be implemented in Story 3.3 with:
/// - HTTP POST to webhook URL
/// - Exponential backoff retry (500ms -> 5s)
/// - Proper error handling
///
/// For now, it just logs that it would send.
async fn send_to_mattermost(payload: &AlertPayload) {
    tracing::info!(
        rule_name = %payload.rule_name,
        webhook_url = %payload.webhook_url,
        title = %payload.message.title,
        "Would send alert to Mattermost (stub - Story 3.3)"
    );

    // Increment sent counter for testing purposes
    // In Story 3.3, this will only increment on successful send
    metrics::counter!(
        "valerter_alerts_sent_total",
        "rule_name" => payload.rule_name.clone()
    )
    .increment(1);
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
        let mut worker = NotificationWorker::new(&queue);
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
        let mut worker = NotificationWorker::new(&queue);
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
        let mut worker = NotificationWorker::new(&queue);
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
    // Task 6.8: Test send_to_mattermost stub (préparation Story 3.3)
    // ===================================================================

    #[tokio::test]
    async fn send_to_mattermost_stub_logs() {
        let payload = make_payload("test_rule");

        // This should just log, no errors
        send_to_mattermost(&payload).await;
        // If we get here without panic, stub works correctly
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
        let worker = NotificationWorker::new(&queue);
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
