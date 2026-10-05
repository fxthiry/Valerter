//! Recording notifier and delivery harness.
//!
//! Engine tests observe the alerts they produce through the real delivery
//! path: a registry of [`RecordingNotifier`]s, the notification queue built
//! from it and a running `NotificationWorker`. Each delivered payload is
//! forwarded to an `mpsc` channel the test drains.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use valerter::error::NotifyError;
use valerter::notify::{
    AlertPayload, DEFAULT_QUEUE_CAPACITY, NotificationQueue, NotificationWorker, Notifier,
    NotifierRegistry,
};

/// Notifier that forwards every alert it receives to a channel.
pub struct RecordingNotifier {
    name: String,
    tx: mpsc::UnboundedSender<AlertPayload>,
}

impl RecordingNotifier {
    pub fn new(name: &str, tx: mpsc::UnboundedSender<AlertPayload>) -> Self {
        Self {
            name: name.to_string(),
            tx,
        }
    }
}

#[async_trait]
impl Notifier for RecordingNotifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn notifier_type(&self) -> &str {
        "recording"
    }

    async fn send(&self, alert: &AlertPayload) -> Result<(), NotifyError> {
        // The receiver may be gone once the test stopped draining.
        let _ = self.tx.send(alert.clone());
        Ok(())
    }
}

/// Registry + queue + running worker delivering to recording notifiers.
pub struct RecordingDelivery {
    /// Queue to hand to the `RuleEngine`.
    pub queue: NotificationQueue,
    rx: mpsc::UnboundedReceiver<AlertPayload>,
    cancel: CancellationToken,
    worker: JoinHandle<()>,
}

impl RecordingDelivery {
    /// Register one recording notifier per destination name and start the
    /// notification worker. Must be called inside a Tokio runtime.
    pub fn start(destinations: &[&str]) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut registry = NotifierRegistry::new();
        for name in destinations {
            registry
                .register(Arc::new(RecordingNotifier::new(name, tx.clone())))
                .expect("destination names must be unique");
        }
        let registry = Arc::new(registry);
        let queue = NotificationQueue::new(DEFAULT_QUEUE_CAPACITY, &registry);
        let mut worker = NotificationWorker::new(&queue, registry);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let worker = tokio::spawn(async move { worker.run(worker_cancel).await });
        Self {
            queue,
            rx,
            cancel,
            worker,
        }
    }

    /// Collect up to `max` delivered alerts within `deadline`, returning
    /// whatever arrived.
    pub async fn drain(&mut self, max: usize, deadline: Duration) -> Vec<AlertPayload> {
        let mut out = Vec::new();
        let _ = tokio::time::timeout(deadline, async {
            while out.len() < max {
                match self.rx.recv().await {
                    Some(p) => out.push(p),
                    None => break,
                }
            }
        })
        .await;
        out
    }

    /// Stop the worker.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), self.worker).await;
    }
}
