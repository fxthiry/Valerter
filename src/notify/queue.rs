//! Notification queue and worker implementation.

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::{AlertPayload, NotifierRegistry};
use crate::error::QueueError;

/// Default queue capacity (FR32).
pub const DEFAULT_QUEUE_CAPACITY: usize = 100;

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
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Send an alert to the queue (non-blocking).
    ///
    /// This operation never blocks. If the queue is full, the oldest
    /// messages will be dropped (detected by receivers as `Lagged`).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Alert queued successfully.
    /// * `Err(QueueError::Closed)` - No active receivers.
    pub fn send(&self, payload: AlertPayload) -> Result<(), QueueError> {
        tracing::trace!(rule_name = %payload.rule_name, "Enqueueing alert");
        self.tx.send(payload).map_err(|_| QueueError::Closed)?;

        // Update queue size metric (AD-05)
        let queue_size = self.tx.len();
        tracing::trace!(queue_size = queue_size, "Alert enqueued");
        metrics::gauge!("valerter_queue_size").set(queue_size as f64);

        Ok(())
    }

    /// Create a new receiver for this queue.
    pub fn subscribe(&self) -> broadcast::Receiver<AlertPayload> {
        self.tx.subscribe()
    }

    /// Get the current number of messages in the queue.
    pub fn len(&self) -> usize {
        self.tx.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tx.len() == 0
    }
}

/// Worker that consumes alerts from the queue and sends them via the registry.
///
/// The worker runs in a loop, processing alerts until cancelled
/// or the queue is closed.
pub struct NotificationWorker {
    rx: broadcast::Receiver<AlertPayload>,
    /// Reference to sender for queue size metrics.
    tx: broadcast::Sender<AlertPayload>,
    /// Registry of notifiers for sending.
    registry: Arc<NotifierRegistry>,
}

impl NotificationWorker {
    /// Create a new notification worker from a queue and registry.
    ///
    /// # Arguments
    ///
    /// * `queue` - Reference to the notification queue.
    /// * `registry` - Registry of available notifiers.
    pub fn new(queue: &NotificationQueue, registry: Arc<NotifierRegistry>) -> Self {
        Self {
            rx: queue.subscribe(),
            tx: queue.tx.clone(),
            registry,
        }
    }

    /// Run the worker loop until cancelled or queue closed.
    ///
    /// The worker will:
    /// 1. Consume alerts from the queue
    /// 2. Handle `Lagged` errors by logging and updating metrics
    /// 3. Send alerts via the appropriate notifier
    /// 4. Stop gracefully when cancellation is requested
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    pub async fn run(&mut self, cancel: CancellationToken) {
        tracing::debug!("Notification worker started");

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
                            tracing::warn!(
                                dropped_count = n,
                                "Queue full, dropping {} oldest alerts",
                                n
                            );
                            metrics::counter!("valerter_alerts_dropped_total")
                                .increment(n);

                            // Update queue size metric after lag recovery
                            metrics::gauge!("valerter_queue_size").set(self.tx.len() as f64);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::debug!("Notification queue closed");
                            return;
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::debug!("Notification worker shutting down gracefully");
                    return;
                }
            }
        }
    }

    /// Process a single alert payload.
    ///
    /// Implements fan-out routing (Story 6.3):
    /// - Sends to ALL specified destinations in parallel (AC #2)
    async fn process_alert(&self, payload: AlertPayload) {
        let span = tracing::info_span!(
            "process_notification",
            rule_name = %payload.rule_name
        );

        async {
            // Use configured destinations (validated at startup to be non-empty)
            let destinations: Vec<&str> = payload.destinations.iter().map(String::as_str).collect();

        tracing::debug!(
            destination_count = destinations.len(),
            destinations = ?destinations,
            "Processing alert with fan-out"
        );

        // AC #2: Send to all destinations in PARALLEL
        // AC #7: each destination failure is independent
        let futures: Vec<_> = destinations
            .iter()
            .filter_map(|dest_name| {
                match self.registry.get(dest_name) {
                    Some(notifier) => Some((dest_name.to_string(), notifier, payload.clone())),
                    None => {
                        // Should never happen if validation passed at startup
                        tracing::error!(
                            notifier = %dest_name,
                            rule_name = %payload.rule_name,
                            "Notifier not found in registry (validation should have caught this)"
                        );
                        metrics::counter!(
                            "valerter_notify_errors_total",
                            "notifier_name" => dest_name.to_string(),
                            "notifier_type" => "unknown",
                            "rule_name" => payload.rule_name.clone()
                        )
                        .increment(1);
                        None
                    }
                }
            })
            .map(|(dest_name, notifier, payload)| async move {
                let result = notifier.send(&payload).await;
                (dest_name, notifier.name().to_string(), result)
            })
            .collect();

        // Execute all sends in parallel and collect results
        let results = join_all(futures).await;

        // Log results (AC #7: each result logged independently)
        for (dest_name, notifier_name, result) in results {
            match result {
                Ok(()) => {
                    tracing::info!(
                        notifier = %notifier_name,
                        rule_name = %payload.rule_name,
                        "Notification sent successfully"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        notifier = %notifier_name,
                        destination = %dest_name,
                        rule_name = %payload.rule_name,
                        "Failed to send notification after all retries"
                    );
                    // Metrics are already recorded in the notifier implementation
                }
            }
        }
        }
        .instrument(span)
        .await
    }
}

impl std::fmt::Debug for NotificationWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationWorker").finish()
    }
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
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
    std::cmp::min(delay, max)
}
