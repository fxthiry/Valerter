# Performance Testing Guide - WP2

This guide describes the complete procedure for running valerter performance tests.

## Prerequisites

- Docker and Docker Compose
- Python 3 (for mock servers)
- `curl` (for load generator)
- valerter compiled (`cargo build --release`)

## Test Architecture

```
┌─────────────────┐    logs/sec    ┌──────────────────┐
│ load-generator  │ ────────────►  │  VictoriaLogs    │
│  (bash script)  │                │  :9428           │
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

### 1. Start Infrastructure

```bash
# Terminal 1: VictoriaLogs + Mailhog
docker compose -f scripts/docker-compose-perf.yaml up -d

# Verify VL is ready
curl -s http://localhost:9428/health
```

### 2. Start Mock Servers

```bash
# Terminal 2: Mock Mattermost
python3 scripts/mock-mattermost.py --port 8065

# Terminal 3: Mock Webhook
python3 scripts/mock-webhook.py --port 8080
```

### 3. Compile and Start Valerter

```bash
# Terminal 4: Valerter
cargo build --release

# With DEBUG logs to observe behavior
RUST_LOG=valerter=debug ./target/release/valerter --config scripts/perf-test-config.yaml
```

### 4. Run Load Tests

```bash
# Terminal 5: Load Generator

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Without Throttle (find limits)
# ═══════════════════════════════════════════════════════════════════════════════

# T1: Baseline - 10 logs/sec for 1 minute
./scripts/load-generator.sh --rate 10 --duration 60 --verbose

# T2: Moderate load - 100 logs/sec
./scripts/load-generator.sh --rate 100 --duration 60 --verbose

# T3: Stress - 500 logs/sec
./scripts/load-generator.sh --rate 500 --duration 60 --verbose

# T4: High limit - 1000 logs/sec
./scripts/load-generator.sh --rate 1000 --duration 60 --verbose
```

### 5. Collect Metrics

During each test, observe:

```bash
# Valerter RSS memory
ps -o rss= -p $(pgrep valerter) | awk '{print $1/1024 " MB"}'

# CPU (over 5 seconds)
top -b -n 5 -p $(pgrep valerter) | grep valerter

# Prometheus metrics
curl -s http://localhost:9090/metrics | grep valerter_
```

---

## Phase 2: With Throttle

Edit `scripts/perf-test-config.yaml`:

```yaml
rules:
  - name: perf_test_rule
    # ...
    throttle:
      key: "{{ host }}"
      count: 5          # Changed from 1000 to 5
      window: 60s       # Changed from 1s to 60s
```

Restart valerter and repeat T3/T4.

Verify:
- Notifications are limited (~5 per host per minute)
- No OOM
- No panic
- `throttled` logs present

---

## Phase 3: VictoriaLogs Resilience

### Test 3.1: VL down

```bash
# During an ongoing test:
docker stop valerter-perf-vl

# Observe valerter logs: should see connection errors + backoff

# After 30 seconds:
docker start valerter-perf-vl

# Observe: valerter should reconnect automatically
```

### Test 3.2: VL full restart

```bash
docker restart valerter-perf-vl

# Valerter should:
# 1. Detect disconnection
# 2. Retry with exponential backoff
# 3. Reconnect once VL is available
# 4. Resume streaming
```

---

## Metrics to Collect

| Tier | Logs/sec | Duration | RSS (MB) | CPU (%) | Latency (ms) | Errors | Notes |
|------|----------|----------|----------|---------|--------------|--------|-------|
| T1   | 10       | 60s      |          |         |              |        |       |
| T2   | 100      | 60s      |          |         |              |        |       |
| T3   | 500      | 60s      |          |         |              |        |       |
| T4   | 1000     | 60s      |          |         |              |        |       |
| T3-throttle | 500 | 60s   |          |         |              |        |       |
| T4-throttle | 1000| 60s   |          |         |              |        |       |

### Key Prometheus Metrics

```
valerter_alerts_sent_total
valerter_alerts_dropped_total
valerter_alerts_throttled_total
valerter_queue_size
valerter_connection_errors_total
valerter_reconnections_total
```

---

## Pass/Fail Criteria

| Criterion | Pass | Fail |
|-----------|------|------|
| T1 baseline | 0 errors, all notifications received | Errors or losses |
| T2 100/s | Stable, <100MB RSS | OOM or panic |
| T3 500/s | Works (degradation OK) | Crash |
| T4 1000/s | Document the limit | Immediate crash |
| Throttle | Notifications correctly limited | Throttle not applied |
| VL reconnect | Auto reconnect <60s | No reconnection |

---

## Cleanup

```bash
# Stop infrastructure
docker compose -f scripts/docker-compose-perf.yaml down -v

# Remove data
docker volume rm valerter_victorialogs-data
```
