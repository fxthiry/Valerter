#!/usr/bin/env bash
#
# load-generator.sh - Generate log load for VictoriaLogs performance testing
#
# Usage:
#   ./scripts/load-generator.sh --rate 100 --duration 60
#   ./scripts/load-generator.sh --rate 500 --duration 60 --url http://localhost:9428
#
# This script sends JSON logs to VictoriaLogs at a specified rate.
# Logs contain fields that match valerter rule queries for testing.

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# DEFAULTS
# ═══════════════════════════════════════════════════════════════════════════════

VICTORIA_LOGS_URL="${VICTORIA_LOGS_URL:-http://localhost:9428}"
RATE=10          # logs per second
DURATION=60      # seconds
STREAM="perf-test"
LOG_LEVEL="error"
VERBOSE=false

# ═══════════════════════════════════════════════════════════════════════════════
# USAGE
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Generate log load for VictoriaLogs performance testing.

OPTIONS:
    --rate RATE         Logs per second (default: $RATE)
    --duration SECS     Duration in seconds (default: $DURATION)
    --url URL           VictoriaLogs URL (default: $VICTORIA_LOGS_URL)
    --stream NAME       Stream name (default: $STREAM)
    --level LEVEL       Log level: error, warn, info (default: $LOG_LEVEL)
    --verbose           Show progress every second
    -h, --help          Show this help

EXAMPLES:
    # Baseline test: 10 logs/sec for 1 minute
    $(basename "$0") --rate 10 --duration 60

    # Stress test: 500 logs/sec for 1 minute
    $(basename "$0") --rate 500 --duration 60 --verbose

    # Custom VictoriaLogs instance
    $(basename "$0") --rate 100 --url http://vl.example.com:9428

ENVIRONMENT VARIABLES:
    VICTORIA_LOGS_URL   VictoriaLogs URL (default: http://localhost:9428)

EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rate)
            RATE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --url)
            VICTORIA_LOGS_URL="$2"
            shift 2
            ;;
        --stream)
            STREAM="$2"
            shift 2
            ;;
        --level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed." >&2
    exit 1
fi

if ! [[ "$RATE" =~ ^[0-9]+$ ]] || [[ "$RATE" -lt 1 ]]; then
    echo "Error: --rate must be a positive integer" >&2
    exit 1
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [[ "$DURATION" -lt 1 ]]; then
    echo "Error: --duration must be a positive integer" >&2
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

TOTAL_LOGS=$((RATE * DURATION))
ENDPOINT="${VICTORIA_LOGS_URL}/insert/jsonline?_stream_fields=app,host&_msg_field=message"

echo "═══════════════════════════════════════════════════════════════════════════════"
echo " Load Generator for VictoriaLogs"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
echo " Target:      $VICTORIA_LOGS_URL"
echo " Rate:        $RATE logs/sec"
echo " Duration:    $DURATION seconds"
echo " Total logs:  $TOTAL_LOGS"
echo " Stream:      $STREAM"
echo " Log level:   $LOG_LEVEL"
echo ""

# Check VictoriaLogs is reachable
echo -n "Checking VictoriaLogs connectivity... "
if ! curl -sf "${VICTORIA_LOGS_URL}/health" > /dev/null 2>&1; then
    echo "FAILED"
    echo ""
    echo "Error: Cannot reach VictoriaLogs at $VICTORIA_LOGS_URL" >&2
    echo "Make sure VictoriaLogs is running:" >&2
    echo "  docker run -d -p 9428:9428 victoriametrics/victoria-logs:latest" >&2
    exit 1
fi
echo "OK"
echo ""

# Calculate batch size and interval for target rate
# Higher rates need larger batches to overcome curl overhead
if [[ "$RATE" -ge 500 ]]; then
    BATCH_SIZE=50
    BATCHES_PER_SEC=$(awk "BEGIN {printf \"%.0f\", $RATE / $BATCH_SIZE}")
    BATCH_INTERVAL=$(awk "BEGIN {printf \"%.6f\", 1 / $BATCHES_PER_SEC}")
elif [[ "$RATE" -ge 100 ]]; then
    BATCH_SIZE=10
    BATCHES_PER_SEC=$(awk "BEGIN {printf \"%.0f\", $RATE / $BATCH_SIZE}")
    BATCH_INTERVAL=$(awk "BEGIN {printf \"%.6f\", 1 / $BATCHES_PER_SEC}")
else
    BATCH_SIZE=1
    BATCH_INTERVAL=$(awk "BEGIN {printf \"%.6f\", 1 / $RATE}")
fi

echo "Starting load generation..."
echo ""

START_TIME=$(date +%s.%N)
LOGS_SENT=0
ERRORS=0
LAST_REPORT_TIME=$START_TIME
LAST_REPORT_LOGS=0

# Generate unique hosts for variety
HOSTS=("server-01" "server-02" "server-03" "server-04" "server-05")

generate_log_batch() {
    local batch=""
    for ((i=0; i<BATCH_SIZE; i++)); do
        local timestamp
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
        local host="${HOSTS[$((RANDOM % ${#HOSTS[@]}))]}"
        local cpu=$((50 + RANDOM % 50))  # CPU between 50-99 to trigger alerts
        local seq=$((LOGS_SENT + i))

        # JSON log line matching the example rule in config.example.yaml
        batch+='{"app":"'$STREAM'","host":"'$host'","level":"'$LOG_LEVEL'","timestamp":"'$timestamp'","message":"cpu usage high: '$cpu'%","cpu":'$cpu',"seq":'$seq'}'
        batch+=$'\n'
    done
    echo -n "$batch"
}

# Trap to show final stats on interrupt
trap 'echo ""; echo "Interrupted."; show_stats; exit 130' INT TERM

show_stats() {
    local end_time
    end_time=$(date +%s.%N)
    local actual_duration
    actual_duration=$(awk "BEGIN {printf \"%.2f\", $end_time - $START_TIME}")
    local actual_rate
    actual_rate=$(awk "BEGIN {printf \"%.1f\", $LOGS_SENT / $actual_duration}")

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo " Results"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo " Logs sent:     $LOGS_SENT / $TOTAL_LOGS"
    echo " Errors:        $ERRORS"
    echo " Duration:      ${actual_duration}s"
    echo " Actual rate:   ${actual_rate} logs/sec"
    echo " Target rate:   $RATE logs/sec"
    echo ""
}

# Main loop
while [[ "$LOGS_SENT" -lt "$TOTAL_LOGS" ]]; do
    # Generate and send batch
    batch=$(generate_log_batch)

    if ! curl -sf -X POST "$ENDPOINT" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary "$batch" > /dev/null 2>&1; then
        ((ERRORS++))
    fi

    LOGS_SENT=$((LOGS_SENT + BATCH_SIZE))

    # Progress report every second if verbose
    if $VERBOSE; then
        current_time=$(date +%s.%N)
        elapsed_since_report=$(awk "BEGIN {printf \"%.0f\", ($current_time - $LAST_REPORT_TIME)}")
        if [[ "$elapsed_since_report" -ge 1 ]]; then
            logs_this_second=$((LOGS_SENT - LAST_REPORT_LOGS))
            printf "\r  Sent: %d/%d logs (%.1f logs/sec, %d errors)    " \
                "$LOGS_SENT" "$TOTAL_LOGS" "$logs_this_second" "$ERRORS"
            LAST_REPORT_TIME=$current_time
            LAST_REPORT_LOGS=$LOGS_SENT
        fi
    fi

    # Sleep to maintain rate (skip if we're behind)
    if [[ "$BATCH_INTERVAL" != "0.000000" ]]; then
        sleep "$BATCH_INTERVAL" 2>/dev/null || true
    fi
done

if $VERBOSE; then
    echo ""  # Clear progress line
fi

show_stats

# Exit with error if there were failures
if [[ "$ERRORS" -gt 0 ]]; then
    exit 1
fi
