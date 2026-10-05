//! Notification queue and worker implementation.
//!
//! Every notifier of the registry (a "destination") owns a bounded FIFO queue
//! and a dedicated delivery task. [`NotificationQueue::send`] routes an alert
//! into the queue of each of its destinations without ever blocking, and each
//! destination task delivers its own alerts one by one. A slow, unavailable,
//! saturated or panicking destination therefore only delays or loses its own
//! alerts.

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::{AlertPayload, Notifier, NotifierRegistry};
use crate::error::QueueError;

/// Exact capacity of the queue of each destination (FR32).
///
/// Every notifier has its own queue holding at most this many pending
/// alerts; when it is full, the oldest pending alert of that destination is
/// dropped to make room for the new one. The capacity is exact (no rounding
/// to a power of two), so up to `DEFAULT_QUEUE_CAPACITY` × number of
/// notifiers alerts can be pending overall.
pub const DEFAULT_QUEUE_CAPACITY: usize = 100;

/// Mutable state of a destination queue, guarded by its mutex.
#[derive(Debug, Default)]
struct DestinationState {
    alerts: VecDeque<Arc<AlertPayload>>,
    /// Alerts dropped since the worker last logged a drop warning.
    unlogged_drops: u64,
    closed: bool,
}

/// Result of a successful [`DestinationQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushOutcome {
    /// The alert was queued without dropping anything.
    Queued,
    /// The queue was full: its oldest alert was dropped to queue this one.
    DroppedOldest,
}

/// Bounded FIFO queue of a single destination with drop-oldest overflow.
///
/// The lock is only held for short synchronous sections (never across an
/// `.await`); the worker is woken through a [`Notify`].
#[derive(Debug)]
struct DestinationQueue {
    notifier_name: String,
    notifier_type: String,
    capacity: usize,
    state: Mutex<DestinationState>,
    notify: Notify,
    /// Pending alerts across every destination (shared by all queues).
    total: Arc<AtomicUsize>,
}

impl DestinationQueue {
    fn new(
        notifier_name: String,
        notifier_type: String,
        capacity: usize,
        total: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            notifier_name,
            notifier_type,
            capacity,
            state: Mutex::new(DestinationState {
                alerts: VecDeque::with_capacity(capacity),
                ..DestinationState::default()
            }),
            notify: Notify::new(),
            total,
        }
    }

    fn lock(&self) -> MutexGuard<'_, DestinationState> {
        // The critical sections cannot panic halfway, so a poisoned lock
        // still holds a consistent state.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue an alert, dropping the oldest pending one if the queue is full.
    ///
    /// Returns `Err(QueueError::Closed)` once the queue has been closed.
    fn push(&self, alert: Arc<AlertPayload>) -> Result<PushOutcome, QueueError> {
        let outcome = {
            let mut state = self.lock();
            if state.closed {
                return Err(QueueError::Closed);
            }
            let outcome = if state.alerts.len() >= self.capacity {
                state.alerts.pop_front();
                state.unlogged_drops += 1;
                self.record_drop();
                PushOutcome::DroppedOldest
            } else {
                self.total.fetch_add(1, Ordering::Relaxed);
                metrics::gauge!("valerter_queue_size").increment(1.0);
                PushOutcome::Queued
            };
            state.alerts.push_back(alert);
            self.set_len_gauge(state.alerts.len());
            outcome
        };
        self.notify.notify_one();
        Ok(outcome)
    }

    /// Take the oldest pending alert with the number of drops not yet logged.
    fn pop(&self) -> Option<(Arc<AlertPayload>, u64)> {
        let mut state = self.lock();
        let alert = state.alerts.pop_front()?;
        self.total.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!("valerter_queue_size").decrement(1.0);
        self.set_len_gauge(state.alerts.len());
        Some((alert, std::mem::take(&mut state.unlogged_drops)))
    }

    fn len(&self) -> usize {
        self.lock().alerts.len()
    }

    /// Refuse every further alert. Pending alerts stay in the queue.
    fn close(&self) {
        self.lock().closed = true;
    }

    fn record_drop(&self) {
        metrics::counter!("valerter_alerts_dropped_total").increment(1);
        metrics::counter!(
            "valerter_destination_alerts_dropped_total",
            "notifier_name" => self.notifier_name.clone(),
            "notifier_type" => self.notifier_type.clone(),
        )
        .increment(1);
    }

    fn set_len_gauge(&self, len: usize) {
        metrics::gauge!(
            "valerter_destination_queue_size",
            "notifier_name" => self.notifier_name.clone(),
            "notifier_type" => self.notifier_type.clone(),
        )
        .set(len as f64);
    }
}

/// Notification queue routing each alert to the queue of its destinations.
///
/// One bounded queue (exact capacity, drop-oldest) is created per notifier
/// of the registry. Sending never blocks the producer.
///
/// # Thread Safety
///
/// The queue is `Clone + Send + Sync` and can be shared across tasks.
#[derive(Debug, Clone)]
pub struct NotificationQueue {
    destinations: Arc<HashMap<String, Arc<DestinationQueue>>>,
    total: Arc<AtomicUsize>,
}

impl NotificationQueue {
    /// Create one queue of `capacity` alerts per notifier of `registry`.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Exact capacity of each destination queue (FR32: 100).
    /// * `registry` - Registry of the notifiers alerts can be routed to.
    pub fn new(capacity: usize, registry: &NotifierRegistry) -> Self {
        let total = Arc::new(AtomicUsize::new(0));
        let destinations = registry
            .names()
            .filter_map(|name| registry.get(name))
            .map(|notifier| {
                let queue = DestinationQueue::new(
                    notifier.name().to_string(),
                    notifier.notifier_type().to_string(),
                    capacity,
                    Arc::clone(&total),
                );
                (notifier.name().to_string(), Arc::new(queue))
            })
            .collect();
        Self {
            destinations: Arc::new(destinations),
            total,
        }
    }

    /// Send an alert to the queue of each of its destinations (non-blocking).
    ///
    /// When a destination queue is full, its oldest pending alert is dropped.
    /// A destination unknown to the registry is logged, counted and skipped.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Alert queued for every known destination.
    /// * `Err(QueueError::Closed)` - Notification delivery has stopped.
    pub fn send(&self, payload: AlertPayload) -> Result<(), QueueError> {
        tracing::trace!(rule_name = %payload.rule_name, "Enqueueing alert");
        let payload = Arc::new(payload);
        let mut closed = false;

        for dest_name in &payload.destinations {
            let Some(queue) = self.destinations.get(dest_name) else {
                // Should never happen if validation passed at startup
                tracing::error!(
                    notifier = %dest_name,
                    rule_name = %payload.rule_name,
                    "Notifier not found in registry (validation should have caught this)"
                );
                metrics::counter!(
                    "valerter_notify_errors_total",
                    "notifier_name" => dest_name.clone(),
                    "notifier_type" => "unknown",
                    "rule_name" => payload.rule_name.clone(),
                    "vl_source" => payload.vl_source.clone(),
                )
                .increment(1);
                continue;
            };
            if queue.push(Arc::clone(&payload)).is_err() {
                closed = true;
            }
        }

        if closed {
            return Err(QueueError::Closed);
        }
        tracing::trace!(queue_size = self.len(), "Alert enqueued");
        Ok(())
    }

    /// Get the number of pending deliveries across every destination.
    pub fn len(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// Check if no delivery is pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of alerts pending for one destination.
    ///
    /// Returns `None` if the destination is unknown.
    pub fn destination_len(&self, notifier_name: &str) -> Option<usize> {
        self.destinations.get(notifier_name).map(|q| q.len())
    }

    /// Close every destination queue: further sends fail with
    /// [`QueueError::Closed`]. Pending alerts are kept.
    fn close(&self) {
        for queue in self.destinations.values() {
            queue.close();
        }
    }
}

#[cfg(test)]
impl NotificationQueue {
    /// Take the oldest alert pending for `notifier_name` (tests only).
    pub(crate) fn take_pending(&self, notifier_name: &str) -> Option<Arc<AlertPayload>> {
        self.destinations
            .get(notifier_name)?
            .pop()
            .map(|(alert, _)| alert)
    }
}

/// Delivery task of a single destination.
///
/// Delivers the alerts of its queue one by one, in arrival order, until
/// cancelled. Each destination runs its own task, so it can be given its own
/// cancellation token.
struct DestinationWorker {
    queue: Arc<DestinationQueue>,
    notifier: Arc<dyn Notifier>,
}

/// Closes a destination queue when its worker exits, whatever the reason.
struct CloseOnExit(Arc<DestinationQueue>);

impl Drop for CloseOnExit {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl DestinationWorker {
    async fn run(self, cancel: CancellationToken) {
        let _close = CloseOnExit(Arc::clone(&self.queue));
        tracing::debug!(notifier = %self.queue.notifier_name, "Destination worker started");

        loop {
            if cancel.is_cancelled() {
                break;
            }
            match self.queue.pop() {
                Some((alert, dropped)) => {
                    if dropped > 0 {
                        tracing::warn!(
                            dropped_count = dropped,
                            notifier = %self.queue.notifier_name,
                            "Queue full, dropping {} oldest alerts",
                            dropped
                        );
                    }
                    self.deliver(&alert).await;
                }
                None => {
                    tokio::select! {
                        _ = self.queue.notify.notified() => {}
                        _ = cancel.cancelled() => break,
                    }
                }
            }
        }

        tracing::debug!(
            notifier = %self.queue.notifier_name,
            "Destination worker shutting down gracefully"
        );
    }

    /// Send one alert, isolating a panic of the notifier.
    async fn deliver(&self, alert: &AlertPayload) {
        let span = tracing::info_span!(
            "process_notification",
            rule_name = %alert.rule_name,
            notifier = %self.notifier.name()
        );

        async {
            let result = AssertUnwindSafe(self.notifier.send(alert))
                .catch_unwind()
                .await;
            match result {
                Ok(Ok(())) => {
                    tracing::info!(
                        notifier = %self.notifier.name(),
                        rule_name = %alert.rule_name,
                        "Notification sent successfully"
                    );
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        error = %e,
                        notifier = %self.notifier.name(),
                        rule_name = %alert.rule_name,
                        "Failed to send notification after all retries"
                    );
                    // Metrics are already recorded in the notifier implementation
                }
                Err(panic) => {
                    tracing::error!(
                        notifier = %self.notifier.name(),
                        rule_name = %alert.rule_name,
                        panic = %panic_message(panic.as_ref()),
                        "Notifier panicked while sending alert"
                    );
                    for name in [
                        "valerter_notify_errors_total",
                        "valerter_alerts_failed_total",
                    ] {
                        metrics::counter!(
                            name,
                            "rule_name" => alert.rule_name.clone(),
                            "vl_source" => alert.vl_source.clone(),
                            "notifier_name" => self.notifier.name().to_string(),
                            "notifier_type" => self.notifier.notifier_type().to_string(),
                        )
                        .increment(1);
                    }
                }
            }
        }
        .instrument(span)
        .await
    }
}

/// Best-effort text of a panic payload.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = panic.downcast_ref::<&str>() {
        s
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s
    } else {
        "non-string panic payload"
    }
}

/// Worker that delivers queued alerts through the registry.
///
/// [`run`](Self::run) starts one delivery task per destination and returns
/// once all of them have stopped.
pub struct NotificationWorker {
    queue: NotificationQueue,
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
            queue: queue.clone(),
            registry,
        }
    }

    /// Run one delivery task per destination until cancelled.
    ///
    /// Each task delivers the alerts of its destination sequentially, in
    /// arrival order. On cancellation, every task stops once its in-flight
    /// send is over (pending alerts are not sent) and every destination
    /// queue is closed.
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token for graceful shutdown.
    pub async fn run(&mut self, cancel: CancellationToken) {
        tracing::debug!(
            destination_count = self.queue.destinations.len(),
            "Notification worker started"
        );

        let mut tasks = JoinSet::new();
        for (name, queue) in self.queue.destinations.iter() {
            let Some(notifier) = self.registry.get(name) else {
                // Queue and worker built from different registries
                tracing::error!(
                    notifier = %name,
                    "Notifier not found in registry (validation should have caught this)"
                );
                queue.close();
                continue;
            };
            let worker = DestinationWorker {
                queue: Arc::clone(queue),
                notifier,
            };
            tasks.spawn(worker.run(cancel.clone()));
        }

        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                tracing::error!(error = %e, "Destination worker stopped unexpectedly");
            }
        }

        self.queue.close();
        tracing::debug!("Notification worker shutting down gracefully");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::RenderedMessage;

    fn alert(rule_name: &str) -> Arc<AlertPayload> {
        Arc::new(AlertPayload {
            message: RenderedMessage {
                title: rule_name.to_string(),
                body: String::new(),
                email_body_html: None,
                accent_color: None,
            },
            rule_name: rule_name.to_string(),
            vl_source: "vlprod".to_string(),
            destinations: vec!["mm-ops".to_string()],
            log_timestamp: String::new(),
            log_timestamp_formatted: String::new(),
        })
    }

    fn destination(capacity: usize) -> DestinationQueue {
        DestinationQueue::new(
            "mm-ops".to_string(),
            "mattermost".to_string(),
            capacity,
            Arc::new(AtomicUsize::new(0)),
        )
    }

    fn drain_names(queue: &DestinationQueue) -> Vec<String> {
        std::iter::from_fn(|| queue.pop().map(|(a, _)| a.rule_name.clone())).collect()
    }

    #[test]
    fn destination_queue_accepts_capacity_then_drops_exactly_the_oldest() {
        let queue = destination(DEFAULT_QUEUE_CAPACITY);
        for i in 0..DEFAULT_QUEUE_CAPACITY {
            assert_eq!(
                queue.push(alert(&format!("rule_{i}"))),
                Ok(PushOutcome::Queued)
            );
        }
        assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);

        assert_eq!(
            queue.push(alert("rule_100")),
            Ok(PushOutcome::DroppedOldest)
        );
        assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);

        let (first, dropped) = queue.pop().unwrap();
        assert_eq!(first.rule_name, "rule_1");
        assert_eq!(dropped, 1);
        let rest = drain_names(&queue);
        assert_eq!(rest.len(), DEFAULT_QUEUE_CAPACITY - 1);
        assert_eq!(rest.last().unwrap(), "rule_100");
    }

    #[test]
    fn destination_queue_len_caps_at_exact_capacity_not_128() {
        let queue = destination(DEFAULT_QUEUE_CAPACITY);
        for i in 0..200 {
            queue.push(alert(&format!("rule_{i}"))).unwrap();
        }
        assert_eq!(queue.len(), DEFAULT_QUEUE_CAPACITY);
        assert_eq!(queue.total.load(Ordering::Relaxed), DEFAULT_QUEUE_CAPACITY);
    }

    #[test]
    fn destination_queue_is_fifo() {
        let queue = destination(10);
        for i in 0..5 {
            queue.push(alert(&format!("rule_{i}"))).unwrap();
        }
        assert_eq!(
            drain_names(&queue),
            vec!["rule_0", "rule_1", "rule_2", "rule_3", "rule_4"]
        );
        assert!(queue.pop().is_none());
    }

    #[test]
    fn destination_queue_reports_drops_once() {
        let queue = destination(2);
        for i in 0..5 {
            queue.push(alert(&format!("rule_{i}"))).unwrap();
        }
        assert_eq!(queue.pop().map(|(_, d)| d), Some(3));
        assert_eq!(queue.pop().map(|(_, d)| d), Some(0));
    }

    #[test]
    fn destination_queue_refuses_push_after_close() {
        let queue = destination(10);
        queue.push(alert("before")).unwrap();
        queue.close();

        assert_eq!(queue.push(alert("after")), Err(QueueError::Closed));
        assert_eq!(drain_names(&queue), vec!["before"]);
    }

    #[test]
    fn destination_queues_share_the_total() {
        let total = Arc::new(AtomicUsize::new(0));
        let a = DestinationQueue::new("a".into(), "t".into(), 2, Arc::clone(&total));
        let b = DestinationQueue::new("b".into(), "t".into(), 2, Arc::clone(&total));
        for _ in 0..3 {
            a.push(alert("x")).unwrap();
        }
        b.push(alert("y")).unwrap();
        assert_eq!(total.load(Ordering::Relaxed), 3);
        a.pop();
        assert_eq!(total.load(Ordering::Relaxed), 2);
    }
}
