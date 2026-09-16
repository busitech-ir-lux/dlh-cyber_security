#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[detect] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE CATALOG_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
CATALOG_RUN="$SHIFT_WORKSPACE/runtime/catalog_run.json"
DETECT_LOG="$SHIFT_WORKSPACE/runtime/catalog_run.log"


# --------------------------------------------------
# 1. Check Task 1 pipeline result
# --------------------------------------------------

if [[ ! -s "$PIPELINE_RUN" ]]; then
    fail "pipeline_run.json is missing or empty"
fi

if ! jq empty "$PIPELINE_RUN" >/dev/null 2>&1; then
    fail "pipeline_run.json is not valid JSON"
fi

PIPELINE_STATUS=$(jq -r '.exit_status // -1' "$PIPELINE_RUN")

if [[ "$PIPELINE_STATUS" != "0" ]]; then
    fail "pipeline did not complete successfully"
fi

echo "[detect] pipeline check: OK"


# --------------------------------------------------
# Find enriched events file
# --------------------------------------------------

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"

elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then

    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.json"

else

    fail "enriched events file is missing"

fi


# --------------------------------------------------
# 2. Find Sigma rule directory
# --------------------------------------------------

if [[ -d "$CATALOG_DIR/rules/sigma" ]]; then
    RULE_DIR="$CATALOG_DIR/rules/sigma"
else
    RULE_DIR="$CATALOG_DIR"
fi


RULE_COUNT=$(find "$RULE_DIR" -type f -name '*.yml' | wc -l)


if [[ "$RULE_COUNT" -eq 0 ]]; then
    fail "no .yml Sigma rules found in $RULE_DIR"
fi


echo "[detect] catalog loaded: $RULE_COUNT rules"


# --------------------------------------------------
# 3. Find previous 3x02 detection runner
# --------------------------------------------------
#
# If DETECTION_BIN is already exported, use it.
# Otherwise try common names inside the catalog.
# --------------------------------------------------

if [[ -n "${DETECTION_BIN:-}" ]]; then

    DETECT_RUNNER="$DETECTION_BIN"

elif [[ -x "$CATALOG_DIR/run_detections.sh" ]]; then

    DETECT_RUNNER="$CATALOG_DIR/run_detections.sh"

elif [[ -x "$CATALOG_DIR/run_catalog.sh" ]]; then

    DETECT_RUNNER="$CATALOG_DIR/run_catalog.sh"

elif [[ -x "$CATALOG_DIR/detect.sh" ]]; then

    DETECT_RUNNER="$CATALOG_DIR/detect.sh"

else

    fail "3x02 detection runner not found; set DETECTION_BIN to your previous detection runner"

fi


if [[ ! -x "$DETECT_RUNNER" ]]; then
    fail "detection runner is not executable: $DETECT_RUNNER"
fi


mkdir -p "$SHIFT_WORKSPACE/alerts"
mkdir -p "$SHIFT_WORKSPACE/runtime"


# --------------------------------------------------
# Run detection catalog
# --------------------------------------------------

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


echo "[detect] invoking detection runner"
echo "[detect] input: $EVENTS_FILE"
echo "[detect] rules: $RULE_DIR"
echo "[detect] output: $ALERT_QUEUE"


set +e

"$DETECT_RUNNER" \
    "$EVENTS_FILE" \
    "$RULE_DIR" \
    "$ALERT_QUEUE" \
    >"$DETECT_LOG" 2>&1

DETECT_STATUS=$?

set -e


if [[ "$DETECT_STATUS" -ne 0 ]]; then
    cat "$DETECT_LOG"
    fail "detection runner exited with status $DETECT_STATUS"
fi


ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------
# 4. Verify alert_queue.json
# --------------------------------------------------

if [[ ! -s "$ALERT_QUEUE" ]]; then
    fail "alert_queue.json is missing or empty"
fi


if ! jq empty "$ALERT_QUEUE" >/dev/null 2>&1; then
    fail "alert_queue.json is not valid JSON"
fi


# --------------------------------------------------
# Normalize alert array
# --------------------------------------------------
#
# Supports either:
#
# [
#   {...},
#   {...}
# ]
#
# or:
#
# {
#   "alerts": [...]
# }
# --------------------------------------------------

ALERTS_JSON=$(
    jq '
        if type == "array" then
            .
        elif (.alerts | type?) == "array" then
            .alerts
        else
            []
        end
    ' "$ALERT_QUEUE"
)


# --------------------------------------------------
# 5. Total alerts
# --------------------------------------------------

ALERTS_TOTAL=$(jq 'length' <<< "$ALERTS_JSON")


if [[ "$ALERTS_TOTAL" -eq 0 ]]; then
    fail "zero alerts fired"
fi


# --------------------------------------------------
# Count alerts by severity
# --------------------------------------------------

CRITICAL=$(
    jq '
        [
            .[]
            | select(
                (
                    .severity //
                    .level //
                    .rule.severity //
                    .rule.level //
                    ""
                )
                | tostring
                | ascii_downcase
                == "critical"
            )
        ]
        | length
    ' <<< "$ALERTS_JSON"
)


HIGH=$(
    jq '
        [
            .[]
            | select(
                (
                    .severity //
                    .level //
                    .rule.severity //
                    .rule.level //
                    ""
                )
                | tostring
                | ascii_downcase
                == "high"
            )
        ]
        | length
    ' <<< "$ALERTS_JSON"
)


MEDIUM=$(
    jq '
        [
            .[]
            | select(
                (
                    .severity //
                    .level //
                    .rule.severity //
                    .rule.level //
                    ""
                )
                | tostring
                | ascii_downcase
                == "medium"
            )
        ]
        | length
    ' <<< "$ALERTS_JSON"
)


LOW=$(
    jq '
        [
            .[]
            | select(
                (
                    .severity //
                    .level //
                    .rule.severity //
                    .rule.level //
                    ""
                )
                | tostring
                | ascii_downcase
                == "low"
            )
        ]
        | length
    ' <<< "$ALERTS_JSON"
)


# --------------------------------------------------
# Count alerts by rule ID
# --------------------------------------------------

ALERTS_BY_RULE=$(
    jq '
        [
            .[]
            |
            (
                .rule_id //
                .rule.id //
                .id //
                .detection_id //
                "unknown"
            )
            | tostring
        ]

        | group_by(.)

        | map({
            key: .[0],
            value: length
        })

        | sort_by(-.value)

        | from_entries
    ' <<< "$ALERTS_JSON"
)


# --------------------------------------------------
# Count unique rules that fired
# --------------------------------------------------

RULES_FIRED=$(jq 'keys | length' <<< "$ALERTS_BY_RULE")


# --------------------------------------------------
# Print summary
# --------------------------------------------------

echo "[detect] matched: $RULES_FIRED rules / $ALERTS_TOTAL alerts"

echo "[detect] severity critical=$CRITICAL high=$HIGH medium=$MEDIUM low=$LOW"

echo "[detect] top rules:"


jq -r '
    to_entries
    | sort_by(-.value)
    | .[]
    | "  \(.key) : \(.value) alerts"
' <<< "$ALERTS_BY_RULE"


# --------------------------------------------------
# Build severity object
# --------------------------------------------------

ALERTS_BY_SEVERITY=$(
    jq -n \
        --argjson critical "$CRITICAL" \
        --argjson high "$HIGH" \
        --argjson medium "$MEDIUM" \
        --argjson low "$LOW" \
        '
        {
            critical: $critical,
            high: $high,
            medium: $medium,
            low: $low
        }
        '
)


# --------------------------------------------------
# 6. Write catalog_run.json
# --------------------------------------------------

jq -n \
    --argjson catalog_rules_total "$RULE_COUNT" \
    --argjson catalog_rules_fired "$RULES_FIRED" \
    --argjson alerts_total "$ALERTS_TOTAL" \
    --argjson alerts_by_severity "$ALERTS_BY_SEVERITY" \
    --argjson alerts_by_rule "$ALERTS_BY_RULE" \
    --arg started_at "$STARTED_AT" \
    --arg ended_at "$ENDED_AT" \
    '
    {
        catalog_rules_total: $catalog_rules_total,

        catalog_rules_fired: $catalog_rules_fired,

        alerts_total: $alerts_total,

        alerts_by_severity: $alerts_by_severity,

        alerts_by_rule: $alerts_by_rule,

        started_at: $started_at,

        ended_at: $ended_at,

        exit_status: 0
    }
    ' > "$CATALOG_RUN"


echo "[detect] alert_queue.json written"
echo "[detect] catalog_run.json written"
