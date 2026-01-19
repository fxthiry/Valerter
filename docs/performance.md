# Performance Test Report

**Date:** 2026-01-19
**Version tested:** valerter 1.0.0-rc.5
**Load generator:** Rust (`tools/load-generator`)

## Test Environment

| Component | Specification |
|-----------|---------------|
| **CPU** | Intel Core i7-14700 (20 cores) |
| **RAM** | 32 GB |
| **Storage** | Samsung 990 PRO NVMe 1TB |
| **OS** | Linux (CachyOS 6.18) |
| **VictoriaLogs** | Docker container (local) |

---

## Understanding the Tests

### Why Two Types of Tests?

Valerter is an **alerting system**, not a log forwarder. The goal is to send **actionable notifications** to humans, not to forward every single log line. This distinction is crucial for understanding the test results.

| Test Type | Purpose | Realistic? |
|-----------|---------|------------|
| **With Throttle** | Simulates production use | **YES** - This is how you should run valerter |
| **Without Throttle** | Stress test / robustness check | NO - Only to verify no crash under extreme load |

**The throttle tests are the most important.** They prove that valerter can handle massive log volumes while sending only the notifications you actually need.

---

## Executive Summary

### Production-Realistic Tests (With Throttle)

| Test | Log Rate | Logs Processed | Notifications | Dropped | Status |
|------|----------|----------------|---------------|---------|--------|
| Throttle 10k/s | 10,000/s | 150,000 | **25** | **0** | **PASS** |
| Throttle 50k/s | 50,000/s | 500,000 | **25** | **0** | **PASS** |
| Throttle 100k/s | 100,000/s | 500,000 | **25** | **0** | **PASS** |

**Key insight:** With throttle enabled, valerter handles **100,000 logs/sec** while sending only **25 actionable notifications** (5 per host). Zero drops, stable memory.

### Robustness Tests (Without Throttle)

| Test | Log Rate | Notifications | Dropped | Crash? | Status |
|------|----------|---------------|---------|--------|--------|
| T1 Baseline | 100/s | 3,000 (100%) | 0 | No | **PASS** |
| T2 Moderate | 1,000/s | 7,843 (26%) | 25,157 | No | **PASS** |
| T3 Stress | 5,000/s | 13,098 (13%) | ~87k | No | **PASS** |
| T4 Extreme | 10,000/s | 18,957 (13%) | ~131k | No | **PASS** |

**Key insight:** Even without throttle, valerter doesn't crash. It gracefully drops excess notifications to protect memory.

---

## Part 1: Production-Realistic Tests (With Throttle)

These tests simulate real-world usage where you want **actionable alerts**, not notification spam.

### Configuration

```yaml
throttle:
  key: "{{ host }}"    # Group by host
  count: 5             # Max 5 notifications per host
  window: 60s          # Per minute
```

With 5 unique hosts in the test data, maximum expected notifications = 5 hosts × 5 = **25 per minute**.

### Test: 10,000 logs/sec with Throttle

| Metric | Value |
|--------|-------|
| Log rate | 10,000/sec |
| Duration | 15s |
| Total logs | 150,000 |
| **Notifications sent** | **25** |
| Throttled | 149,975 |
| **Dropped** | **0** |
| RSS Memory | 18.49 MB |
| Panics | 0 |

**Result:** Exactly 25 notifications as configured. Zero drops. System stable.

### Test: 50,000 logs/sec with Throttle

| Metric | Value |
|--------|-------|
| Log rate | 50,000/sec |
| Duration | 10s |
| Total logs | 500,000 |
| **Notifications sent** | **25** |
| Throttled | 499,975 |
| **Dropped** | **0** |
| RSS Memory | 18.64 MB |
| Panics | 0 |

**Result:** Half a million logs processed, only 25 notifications. Zero drops.

### Test: 100,000 logs/sec with Throttle

| Metric | Value |
|--------|-------|
| Log rate | 100,000/sec |
| Duration | 5s |
| Total logs | 500,000 |
| **Notifications sent** | **25** |
| Throttled | 499,975 |
| **Dropped** | **0** |
| RSS Memory | 20.11 MB |
| Panics | 0 |

**Result:** 100k logs/sec ingested, only 25 actionable notifications sent. Perfect throttle behavior.

### Why This Matters

In production, you don't want 100,000 Mattermost messages per second. You want:
- "server-01 has high CPU" → 1 notification
- "server-02 has high CPU" → 1 notification
- etc.

The throttle ensures your team gets **actionable alerts** without notification fatigue.

---

## Part 2: Robustness Tests (Without Throttle)

These tests verify that valerter **doesn't crash** under extreme load, even in misconfigured scenarios.

> **Note:** These tests are NOT realistic. In production, you should ALWAYS enable throttle.

### Why Run These Tests?

To ensure that if someone misconfigures valerter (no throttle, or throttle too high), the system:
- Doesn't crash
- Doesn't run out of memory
- Gracefully degrades (drops old notifications)

### T1: Baseline (100 logs/sec, no throttle)

| Metric | Value |
|--------|-------|
| Log rate | 100/sec |
| Notifications sent | 3,000 (100%) |
| Dropped | 0 |
| RSS Memory | 16.65 MB |

**Result:** At low rates, 100% delivery is possible even without throttle.

### T2: Moderate (1,000 logs/sec, no throttle)

| Metric | Value |
|--------|-------|
| Log rate | 1,000/sec |
| Notifications sent | 7,843 (26%) |
| Dropped | 25,157 |
| RSS Memory | 18.38 MB |

**Result:** HTTP notifiers can't keep up. Valerter drops oldest alerts to prevent memory growth. No crash.

### T3: Stress (5,000 logs/sec, no throttle)

| Metric | Value |
|--------|-------|
| Log rate | 5,000/sec |
| Notifications sent | 13,098 (13%) |
| Dropped | ~87,000 |
| RSS Memory | 21.18 MB |

**Result:** Heavy backpressure. Queue drops working as designed. No crash.

### T4: Extreme (10,000 logs/sec, no throttle)

| Metric | Value |
|--------|-------|
| Log rate | 10,000/sec |
| Notifications sent | 18,957 (13%) |
| Dropped | ~131,000 |
| RSS Memory | 21.83 MB |

**Result:** Extreme load. Memory bounded, no crash, no panic.

### What These Tests Prove

Even without throttle:
- **No crash** under any load tested
- **Memory bounded** at ~22 MB (queue has fixed size)
- **Graceful degradation** (FIFO drops, not OOM)

---

## Part 3: VictoriaLogs Resilience

Tests that valerter recovers from VictoriaLogs outages.

### Reconnection Test

**Procedure:**
1. Valerter connected to VictoriaLogs
2. `docker stop valerter-perf-vl`
3. Observed exponential backoff (1s, 2s, 4s...)
4. `docker start valerter-perf-vl`
5. Valerter auto-reconnected

**Results:**
- Reconnection attempts: 5 (with exponential backoff)
- Final state: `valerter_victorialogs_up = 1`
- Auto-reconnect successful

**Verdict:** PASS

---

## Performance Characteristics

### Throughput Summary

| Component | Measured Throughput |
|-----------|---------------------|
| Log ingestion | **100,000+ logs/sec** |
| JSON parsing | **100,000+ logs/sec** |
| Throttle evaluation | **100,000+ logs/sec** |
| HTTP notification | ~50-100/sec per notifier |

**Bottleneck:** HTTP notification delivery (network latency). This is expected and mitigated by throttle.

### Memory Usage

| Scenario | RSS Memory |
|----------|------------|
| Idle | ~15 MB |
| With throttle (any load) | ~18-20 MB |
| Without throttle (extreme) | ~22 MB |

Memory is **always bounded** regardless of load.

---

## Key Prometheus Metrics

```prometheus
# The metrics that matter in production
valerter_alerts_sent_total          # Notifications actually delivered
valerter_alerts_throttled_total     # Logs matched but throttled (expected)
valerter_alerts_dropped_total       # Queue overflow (should be 0 with throttle)
valerter_victorialogs_up            # Connection health
```

---

## Recommendations

### 1. Always Enable Throttle

```yaml
throttle:
  key: "{{ host }}"     # Or "{{ service }}", "{{ pod }}", etc.
  count: 10             # Max notifications per key
  window: 60s           # Per minute
```

### 2. Monitor These Metrics

| Metric | Expected | Action if abnormal |
|--------|----------|-------------------|
| `valerter_alerts_dropped_total` | 0 | Enable/tighten throttle |
| `valerter_alerts_throttled_total` | > 0 | Normal, throttle working |
| `valerter_victorialogs_up` | 1 | Check VL connection |

### 3. Choose Appropriate Throttle Keys

- `{{ host }}` - Alert per machine
- `{{ service }}` - Alert per service
- `{{ host }}-{{ level }}` - Alert per machine+severity

---

## Test Files

| File | Description |
|------|-------------|
| `tools/load-generator/` | Rust load generator (100k+ logs/sec) |
| `scripts/perf-test-config.yaml` | Test configuration |
| `scripts/mock-mattermost.py` | Mock Mattermost webhook |
| `scripts/mock-webhook.py` | Mock generic webhook |
| `scripts/docker-compose-perf.yaml` | Infrastructure (VL + Mailhog) |
| `scripts/PERF-TEST-GUIDE.md` | Test execution guide |

---

## Conclusion

### Production Use (With Throttle)

Valerter handles **100,000 logs/sec** while sending only the notifications you configure:
- ✅ Exact throttle behavior (25 notifications from 500k logs)
- ✅ Zero drops
- ✅ Stable memory (~20 MB)
- ✅ No crashes

### Robustness (Without Throttle)

Even misconfigured, valerter doesn't crash:
- ✅ Graceful backpressure
- ✅ Bounded memory
- ✅ No panics

### Resilience

- ✅ Auto-reconnects to VictoriaLogs after outage

---

**Overall status: PASS**

The throttle feature is the key to production use. With proper throttle configuration, valerter transforms massive log volumes into actionable, human-friendly notifications.
