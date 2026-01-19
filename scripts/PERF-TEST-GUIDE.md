# Performance Testing Guide - WP2

This guide describes the complete procedure for running valerter performance tests.

## Prerequisites

- Docker and Docker Compose
- Python 3 (for mock servers)
- Rust toolchain (for load generator)
- valerter compiled (`cargo build --release`)

## Test Architecture

```
┌─────────────────┐    logs/sec    ┌──────────────────┐
│ load-generator  │ ────────────►  │  VictoriaLogs    │
│  (Rust tool)    │                │  :9428           │
└─────────────────┘                └────────┬─────────┘
                                            │ tail stream
                                            ▼
                                   ┌──────────────────┐
                                   │    valerter      │
                                   │  (under test)    │
                                   └────────┬─────────┘
                                            │ notifications
                           ┌────────────────┼────────────────┐
                           ▼                ▼                ▼
                   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
                   │mock-mattermost│ │ mock-webhook │ │   mailhog    │
                   │    :8065      │ │    :8080     │ │    :1025     │
                   └──────────────┘ └──────────────┘ └──────────────┘
```

## Steps

### 1. Build Load Generator

```bash
cd tools/load-generator
cargo build --release
cd ../..
```

### 2. Start Infrastructure

```bash
# VictoriaLogs + Mailhog
docker compose -f scripts/docker-compose-perf.yaml up -d

# Verify VL is ready
curl -s http://localhost:9428/health
```

### 3. Start Mock Servers

```bash
# Terminal 2: Mock Mattermost
python3 scripts/mock-mattermost.py --port 8065

# Terminal 3: Mock Webhook
python3 scripts/mock-webhook.py --port 8080
```

### 4. Compile and Start Valerter

```bash
cargo build --release

# With DEBUG logs to observe behavior
RUST_LOG=valerter=debug ./target/release/valerter --config scripts/perf-test-config.yaml
```

### 5. Run Load Tests

```bash
# Load generator location
LOAD_GEN=./tools/load-generator/target/release/load-generator

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Without Throttle (find limits)
# ═══════════════════════════════════════════════════════════════════════════════

# T1: Baseline - 100 logs/sec for 30 seconds
$LOAD_GEN --rate 100 --duration 30 --verbose

# T2: Moderate load - 1000 logs/sec
$LOAD_GEN --rate 1000 --duration 30 --verbose

# T3: Stress - 5000 logs/sec
$LOAD_GEN --rate 5000 --duration 20 --verbose --workers 20

# T4: Extreme - 10000 logs/sec
$LOAD_GEN --rate 10000 --duration 15 --verbose --workers 50 --batch-size 500
```

### 6. Collect Metrics

During each test, observe:

```bash
# Valerter RSS memory
ps -o rss= -p $(pgrep valerter) | awk '{print $1/1024 " MB"}'

# Prometheus metrics
curl -s http://localhost:9090/metrics | grep valerter_
```

---

## Load Generator Options

```
load-generator [OPTIONS]

Options:
  -r, --rate <RATE>          Target rate in logs/sec [default: 100]
  -d, --duration <SECS>      Duration in seconds [default: 60]
  -u, --url <URL>            VictoriaLogs URL [default: http://localhost:9428]
  -s, --stream <NAME>        Stream/app name [default: perf-test]
  -l, --level <LEVEL>        Log level [default: error]
  -w, --workers <N>          Concurrent workers [default: 10]
  -b, --batch-size <N>       Logs per HTTP request [default: 100]
  -V, --verbose              Show progress every second
  -h, --help                 Print help
```

---

## Phase 2: With Throttle

Edit `scripts/perf-test-config.yaml`:

```yaml
rules:
  - name: perf_test_rule
    throttle:
      key: "{{ host }}"
      count: 5          # 5 notifications per host
      window: 60s       # per minute
```

Restart valerter and repeat T3/T4.

---

## Phase 3: VictoriaLogs Resilience

```bash
# During an ongoing test:
docker stop valerter-perf-vl

# Observe valerter logs: should see connection errors + backoff

# After 30 seconds:
docker start valerter-perf-vl

# Observe: valerter should reconnect automatically
```

---

## Expected Results

| Test | Rate | Expected Behavior |
|------|------|-------------------|
| T1 | 100/s | 100% delivery, no drops |
| T2 | 1,000/s | Queue backpressure, some drops |
| T3 | 5,000/s | Heavy backpressure, stable memory |
| T4 | 10,000/s | Extreme load, no crash |
| Throttle | any | Limited notifications, 0 drops |
| VL Resilience | - | Auto-reconnect <60s |

---

## Cleanup

```bash
# Stop infrastructure
docker compose -f scripts/docker-compose-perf.yaml down -v
```
