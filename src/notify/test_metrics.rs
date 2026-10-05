//! Local metrics recorder for notifier unit tests.

use std::future::Future;

/// Run `f` on a current-thread runtime with a local Prometheus recorder, so
/// every metric it emits lands in that recorder. Returns the output of `f`
/// and the Prometheus rendering.
pub(crate) fn run_with_recorder<F: Future>(f: impl FnOnce() -> F) -> (F::Output, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let output = metrics::with_local_recorder(&recorder, || rt.block_on(f()));
    (output, handle.render())
}

/// Sum of every series of the counter `name` in a Prometheus rendering
/// (0 when the counter was never emitted).
pub(crate) fn counter_total(rendered: &str, name: &str) -> u64 {
    rendered
        .lines()
        .filter(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .filter_map(|l| l.rsplit_once(' ')?.1.parse::<u64>().ok())
        .sum()
}
