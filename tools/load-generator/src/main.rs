//! High-performance log load generator for VictoriaLogs.
//!
//! Generates JSON logs at a specified rate and sends them to VictoriaLogs
//! insert endpoint using async HTTP requests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use rand::Rng;
use reqwest::Client;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::time::{interval, MissedTickBehavior};

/// High-performance log load generator for VictoriaLogs
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Target rate in logs per second
    #[arg(short, long, default_value = "100")]
    rate: u64,

    /// Duration in seconds
    #[arg(short, long, default_value = "60")]
    duration: u64,

    /// VictoriaLogs URL
    #[arg(short, long, default_value = "http://localhost:9428")]
    url: String,

    /// Stream/app name for logs
    #[arg(short, long, default_value = "perf-test")]
    stream: String,

    /// Log level to generate
    #[arg(short, long, default_value = "error")]
    level: String,

    /// Number of concurrent workers
    #[arg(short, long, default_value = "10")]
    workers: usize,

    /// Batch size (logs per HTTP request)
    #[arg(short, long, default_value = "100")]
    batch_size: usize,

    /// Verbose output (show progress every second)
    #[arg(short = 'V', long)]
    verbose: bool,
}

/// Log entry matching valerter test format
#[derive(Serialize)]
struct LogEntry {
    app: String,
    host: String,
    level: String,
    timestamp: String,
    message: String,
    cpu: u32,
    seq: u64,
}

/// Statistics tracker
struct Stats {
    logs_sent: AtomicU64,
    errors: AtomicU64,
    batches_sent: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            logs_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
        }
    }
}

const HOSTS: &[&str] = &["server-01", "server-02", "server-03", "server-04", "server-05"];

fn generate_batch(args: &Args, start_seq: u64, batch_size: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut lines = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        let host = HOSTS[rng.gen_range(0..HOSTS.len())];
        let cpu = rng.gen_range(50..100);
        let entry = LogEntry {
            app: args.stream.clone(),
            host: host.to_string(),
            level: args.level.clone(),
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            message: format!("cpu usage high: {}%", cpu),
            cpu,
            seq: start_seq + i as u64,
        };
        lines.push(serde_json::to_string(&entry).unwrap());
    }

    lines.join("\n") + "\n"
}

async fn send_batch(
    client: &Client,
    endpoint: &str,
    batch: String,
    stats: &Stats,
    batch_size: usize,
) {
    match client
        .post(endpoint)
        .header("Content-Type", "application/x-ndjson")
        .body(batch)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            stats.logs_sent.fetch_add(batch_size as u64, Ordering::Relaxed);
            stats.batches_sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(resp) => {
            stats.errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("HTTP error: {}", resp.status());
        }
        Err(e) => {
            stats.errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("Request error: {}", e);
        }
    }
}

async fn check_health(client: &Client, url: &str) -> Result<()> {
    let health_url = format!("{}/health", url);
    client
        .get(&health_url)
        .send()
        .await
        .context("Failed to connect to VictoriaLogs")?
        .error_for_status()
        .context("VictoriaLogs health check failed")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let total_logs = args.rate * args.duration;
    let endpoint = format!(
        "{}/insert/jsonline?_stream_fields=app,host&_msg_field=message",
        args.url
    );

    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!(" Load Generator for VictoriaLogs (Rust)");
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!();
    println!(" Target:      {}", args.url);
    println!(" Rate:        {} logs/sec", args.rate);
    println!(" Duration:    {} seconds", args.duration);
    println!(" Total logs:  {}", total_logs);
    println!(" Stream:      {}", args.stream);
    println!(" Log level:   {}", args.level);
    println!(" Workers:     {}", args.workers);
    println!(" Batch size:  {}", args.batch_size);
    println!();

    // Create HTTP client with connection pooling
    let client = Client::builder()
        .pool_max_idle_per_host(args.workers)
        .timeout(Duration::from_secs(30))
        .build()?;

    // Health check
    print!("Checking VictoriaLogs connectivity... ");
    check_health(&client, &args.url).await?;
    println!("OK");
    println!();

    // Calculate batches per second to achieve target rate
    let batches_per_sec = (args.rate as f64 / args.batch_size as f64).ceil() as u64;
    let batch_interval = Duration::from_secs_f64(1.0 / batches_per_sec as f64);

    println!("Starting load generation...");
    println!(" Batches/sec: {} (interval: {:?})", batches_per_sec, batch_interval);
    println!();

    let stats = Arc::new(Stats::new());
    let semaphore = Arc::new(Semaphore::new(args.workers));
    let start_time = Instant::now();
    let seq_counter = Arc::new(AtomicU64::new(0));

    // Spawn progress reporter if verbose
    let stats_clone = stats.clone();
    let verbose = args.verbose;
    let progress_handle = tokio::spawn(async move {
        if !verbose {
            return;
        }
        let mut interval = interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_sent = 0u64;

        loop {
            interval.tick().await;
            let sent = stats_clone.logs_sent.load(Ordering::Relaxed);
            let errors = stats_clone.errors.load(Ordering::Relaxed);
            let rate = sent - last_sent;
            last_sent = sent;
            print!(
                "\r  Sent: {}/{} logs ({} logs/sec, {} errors)    ",
                sent, total_logs, rate, errors
            );
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
    });

    // Main send loop
    let mut tick_interval = interval(batch_interval);
    tick_interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

    let duration = Duration::from_secs(args.duration);

    while start_time.elapsed() < duration {
        tick_interval.tick().await;

        let current_seq = seq_counter.fetch_add(args.batch_size as u64, Ordering::Relaxed);
        if current_seq >= total_logs {
            break;
        }

        // Acquire semaphore permit
        let permit = semaphore.clone().acquire_owned().await?;
        let client = client.clone();
        let endpoint = endpoint.clone();
        let stats = stats.clone();
        let batch_size = args.batch_size;

        // Generate batch (could be optimized further with pre-generation)
        let batch = generate_batch(&args, current_seq, batch_size);

        // Spawn task to send batch
        tokio::spawn(async move {
            send_batch(&client, &endpoint, batch, &stats, batch_size).await;
            drop(permit);
        });
    }

    // Wait for all pending requests to complete
    let _ = semaphore.acquire_many(args.workers as u32).await;

    // Cancel progress reporter
    progress_handle.abort();

    if args.verbose {
        println!();
    }

    // Final stats
    let elapsed = start_time.elapsed();
    let logs_sent = stats.logs_sent.load(Ordering::Relaxed);
    let errors = stats.errors.load(Ordering::Relaxed);
    let actual_rate = logs_sent as f64 / elapsed.as_secs_f64();

    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!(" Results");
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!();
    println!(" Logs sent:     {} / {}", logs_sent, total_logs);
    println!(" Errors:        {}", errors);
    println!(" Duration:      {:.2}s", elapsed.as_secs_f64());
    println!(" Actual rate:   {:.1} logs/sec", actual_rate);
    println!(" Target rate:   {} logs/sec", args.rate);
    println!();

    if errors > 0 {
        std::process::exit(1);
    }

    Ok(())
}
