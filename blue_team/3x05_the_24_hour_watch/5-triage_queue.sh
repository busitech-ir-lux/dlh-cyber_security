#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[triage] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE TRIAGE_BIN ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
BRIEFING="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
BASELINE="$SHIFT_WORKSPACE/enriched/baseline.json"
ASSETS="$ASSETS_DIR/assets.json"

TRIAGE_LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
RUN_LOG="$SHIFT_WORKSPACE/runtime/triage_run.log"


# --------------------------------------------------
# 1. Check required input files
# --------------------------------------------------

for file in \
    "$ALERT_QUEUE" \
    "$BRIEFING" \
    "$BASELINE" \
    "$ASSETS"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# Validate JSON inputs.

for file in \
    "$ALERT_QUEUE" \
    "$BRIEFING" \
    "$BASELINE" \
    "$ASSETS"
do
    if ! jq empty "$file" >/dev/null 2>&1; then
        fail "invalid JSON: $file"
    fi
done


# --------------------------------------------------
# Count alerts
# --------------------------------------------------

ALERT_COUNT=$(
    jq '
        if type == "array" then
            length
        elif (.alerts | type?) == "array" then
            .alerts | length
        else
            0
        end
    ' "$ALERT_QUEUE"
)


if [[ "$ALERT_COUNT" -eq 0 ]]; then
    fail "alert queue contains zero alerts"
fi


echo "[triage] alert_queue: $ALERT_COUNT alerts"


# --------------------------------------------------
# Briefing summary
# --------------------------------------------------

IOC_COUNT=$(jq '.ioc_count // 0' "$BRIEFING")

CHANGE_COUNT=$(
    jq '.active_change_tickets // [] | length' "$BRIEFING"
)


echo "[triage] briefing loaded ($IOC_COUNT IOCs, $CHANGE_COUNT change tickets)"


# --------------------------------------------------
# 2. Check triage runner
# --------------------------------------------------

if [[ ! -x "$TRIAGE_BIN" ]]; then
    fail "TRIAGE_BIN missing or not executable: $TRIAGE_BIN"
fi


mkdir -p "$SHIFT_WORKSPACE/alerts"
mkdir -p "$SHIFT_WORKSPACE/runtime"


# Remove old results so reruns are clean.

: > "$TRIAGE_LOG"
: > "$RUN_LOG"


echo "[triage] invoking $TRIAGE_BIN"
echo "[triage] classifying $ALERT_COUNT alerts"


# --------------------------------------------------
# Run previous 3x03 triage logic
# --------------------------------------------------
#
# Arguments:
#   1 alert queue
#   2 briefing
#   3 baseline
#   4 asset inventory
#   5 output triage log
#
# Environment variables are also provided in case
# your previous script reads them that way.
# --------------------------------------------------

set +e

TRIAGE_ALERT_QUEUE="$ALERT_QUEUE" \
TRIAGE_BRIEFING="$BRIEFING" \
TRIAGE_BASELINE="$BASELINE" \
TRIAGE_ASSETS="$ASSETS" \
TRIAGE_OUTPUT="$TRIAGE_LOG" \
"$TRIAGE_BIN" \
    "$ALERT_QUEUE" \
    "$BRIEFING" \
    "$BASELINE" \
    "$ASSETS" \
    "$TRIAGE_LOG" \
    >"$RUN_LOG" 2>&1

TRIAGE_STATUS=$?

set -e


if [[ "$TRIAGE_STATUS" -ne 0 ]]; then
    cat "$RUN_LOG"
    fail "triage runner exited with status $TRIAGE_STATUS"
fi


# --------------------------------------------------
# 3. Verify triage_log.jsonl
# --------------------------------------------------

if [[ ! -s "$TRIAGE_LOG" ]]; then
    fail "triage_log.jsonl is missing or empty"
fi


# Check every line is valid JSON.

if ! jq -e . "$TRIAGE_LOG" >/dev/null 2>&1; then
    fail "triage_log.jsonl contains invalid JSON"
fi


# --------------------------------------------------
# Validate required classification values
# --------------------------------------------------

INVALID_CLASSIFICATIONS=$(
    jq -s '
        [
            .[]
            | select(
                (.classification // "")
                | IN("TP", "FP", "NOISE")
                | not
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)


if [[ "$INVALID_CLASSIFICATIONS" -ne 0 ]]; then
    fail "$INVALID_CLASSIFICATIONS records have invalid or missing classification"
fi


# --------------------------------------------------
# Validate severity
# --------------------------------------------------

INVALID_SEVERITY=$(
    jq -s '
        [
            .[]
            | select(
                (
                    .severity //
                    ""
                    | ascii_downcase
                )
                | IN("critical", "high", "medium", "low")
                | not
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)


if [[ "$INVALID_SEVERITY" -ne 0 ]]; then
    fail "$INVALID_SEVERITY records have invalid severity"
fi


# --------------------------------------------------
# Check hostnames are lowercase
# --------------------------------------------------

BAD_HOSTS=$(
    jq -s '
        [
            .[]
            | select(
                (.host // "") !=
                ((.host // "") | ascii_downcase)
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)


if [[ "$BAD_HOSTS" -ne 0 ]]; then
    fail "$BAD_HOSTS records contain non-lowercase hostnames"
fi


# --------------------------------------------------
# Check analyst_note maximum length
# --------------------------------------------------

LONG_NOTES=$(
    jq -s '
        [
            .[]
            | select(
                (.analyst_note // "" | length) > 200
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)


if [[ "$LONG_NOTES" -ne 0 ]]; then
    fail "$LONG_NOTES analyst notes exceed 200 characters"
fi


# --------------------------------------------------
# 4. Count classifications
# --------------------------------------------------

TP_COUNT=$(
    jq -s '[.[] | select(.classification == "TP")] | length' \
        "$TRIAGE_LOG"
)

FP_COUNT=$(
    jq -s '[.[] | select(.classification == "FP")] | length' \
        "$TRIAGE_LOG"
)

NOISE_COUNT=$(
    jq -s '[.[] | select(.classification == "NOISE")] | length' \
        "$TRIAGE_LOG"
)


TRIAGED_COUNT=$(
    jq -s 'length' "$TRIAGE_LOG"
)


# --------------------------------------------------
# Check that every alert ID was classified
# --------------------------------------------------

QUEUE_IDS=$(mktemp)
TRIAGE_IDS=$(mktemp)

trap 'rm -f "$QUEUE_IDS" "$TRIAGE_IDS"' EXIT


jq -r '
    if type == "array" then
        .[]
    else
        .alerts[]
    end

    |
    (
        .alert_id //
        .id //
        empty
    )
    | tostring
' "$ALERT_QUEUE" |
sort -u > "$QUEUE_IDS"


jq -r '
    .alert_id //
    empty
    | tostring
' "$TRIAGE_LOG" |
sort -u > "$TRIAGE_IDS"


UNCLASSIFIED=$(
    comm -23 "$QUEUE_IDS" "$TRIAGE_IDS" |
    grep -c . || true
)


# --------------------------------------------------
# Check for missing alert_id values
# --------------------------------------------------

MISSING_IDS=$(
    jq -s '
        [
            .[]
            | select(
                (.alert_id // "") == ""
            )
        ]
        | length
    ' "$TRIAGE_LOG"
)


if [[ "$MISSING_IDS" -ne 0 ]]; then
    fail "$MISSING_IDS triage records are missing alert_id"
fi


# --------------------------------------------------
# Ensure no alerts were skipped
# --------------------------------------------------

if [[ "$UNCLASSIFIED" -ne 0 ]]; then

    echo "[triage] missing alert IDs:" >&2

    comm -23 "$QUEUE_IDS" "$TRIAGE_IDS" >&2

    fail "$UNCLASSIFIED alerts remain unclassified"

fi


# --------------------------------------------------
# Basic count comparison
# --------------------------------------------------

if [[ "$TRIAGED_COUNT" -lt "$ALERT_COUNT" ]]; then
    fail "triage log has $TRIAGED_COUNT records but alert queue has $ALERT_COUNT alerts"
fi


# --------------------------------------------------
# 5. Final summary
# --------------------------------------------------

echo "[triage] TP=$TP_COUNT FP=$FP_COUNT NOISE=$NOISE_COUNT unclassified=$UNCLASSIFIED"

echo "[triage] triage_log.jsonl written"
