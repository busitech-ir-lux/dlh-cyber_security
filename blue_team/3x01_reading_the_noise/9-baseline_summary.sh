#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 9 - CROSS-SOURCE BASELINE SUMMARY
#
# Combines:
#   baseline_auth.json
#   baseline_process.json
#   baseline_network.json
#   baseline_file.json
#   temporal_profile.json
#
# Produces:
#   baseline_summary.json
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-.}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

AUTH_FILE="$BASELINE_PKG/baseline_auth.json"
PROCESS_FILE="$BASELINE_PKG/baseline_process.json"
NETWORK_FILE="$BASELINE_PKG/baseline_network.json"
FILE_FILE="$BASELINE_PKG/baseline_file.json"
TEMPORAL_FILE="$BASELINE_PKG/temporal_profile.json"

OUTPUT_FILE="$BASELINE_PKG/baseline_summary.json"


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

if ! [[ "$BASELINE_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: BASELINE_DAYS must be a positive integer." >&2
    exit 1
fi


# Check the main dataset.
if [ ! -f "$DATA_FILE" ]; then
    echo "Error: dataset not found: $DATA_FILE" >&2
    exit 1
fi


# Check every required baseline file.
for file in \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$FILE_FILE" \
    "$TEMPORAL_FILE"
do
    if [ ! -f "$file" ]; then
        echo "Error: required file not found: $file" >&2
        exit 1
    fi

    if ! jq -e . "$file" >/dev/null 2>&1; then
        echo "Error: invalid JSON: $file" >&2
        exit 1
    fi
done


# ============================================================
# TEMPORARY FILES
# ============================================================

TMP_HOSTS=$(mktemp)
TMP_OUTPUT=$(mktemp)

cleanup()
{
    rm -f "$TMP_HOSTS" "$TMP_OUTPUT"
}

trap cleanup EXIT


# ============================================================
# FIND DATASET TIME RANGE
#
# Window boundaries must be derived from the dataset.
# ============================================================

FIRST_TIMESTAMP=$(
    jq -r '
        select(
            .timestamp != null
            and
            .timestamp != ""
        )
        | .timestamp
    ' "$DATA_FILE" |
        sort |
        head -n 1
)


LAST_TIMESTAMP=$(
    jq -r '
        select(
            .timestamp != null
            and
            .timestamp != ""
        )
        | .timestamp
    ' "$DATA_FILE" |
        sort |
        tail -n 1
)


if [ -z "$FIRST_TIMESTAMP" ] || [ -z "$LAST_TIMESTAMP" ]; then
    echo "Error: dataset does not contain usable timestamps." >&2
    exit 1
fi


# ============================================================
# CALCULATE BASELINE AND EVALUATION WINDOWS
#
# Example with BASELINE_DAYS=7:
#
#   baseline:
#       day 1 00:00:00
#       through day 7 23:59:59
#
#   evaluation:
#       day 8 00:00:00
#       through day 8 23:59:59
# ============================================================

FIRST_DATE="${FIRST_TIMESTAMP%%T*}"

BASELINE_START="${FIRST_DATE}T00:00:00Z"


EVALUATION_START=$(
    date -u \
        -d "$FIRST_DATE + $BASELINE_DAYS days" \
        '+%Y-%m-%dT00:00:00Z'
)


BASELINE_END=$(
    date -u \
        -d "$EVALUATION_START - 1 second" \
        '+%Y-%m-%dT%H:%M:%SZ'
)


EVALUATION_END=$(
    date -u \
        -d "$EVALUATION_START + 24 hours - 1 second" \
        '+%Y-%m-%dT%H:%M:%SZ'
)


# ============================================================
# GENERATED_AT
#
# The project requires idempotent scripts: identical input
# should produce identical output.
#
# Using "date now" would make the JSON different every run.
#
# Therefore use the newest dataset timestamp as a deterministic
# ISO-8601 generation marker.
# ============================================================

GENERATED_AT="$LAST_TIMESTAMP"


# ============================================================
# BUILD HOST INVENTORY
#
# Use the complete enriched dataset rather than one particular
# baseline type. This includes any host that was present during
# the clean baseline window.
# ============================================================

jq -s \
    --arg start "$BASELINE_START" \
    --arg evaluation_start "$EVALUATION_START" '

    [
        .[]

        | select(
            .timestamp >= $start
            and
            .timestamp < $evaluation_start
        )

        | .hostname

        | select(
            . != null
            and
            . != ""
        )

        | tostring
    ]

    | unique
    | sort

' "$DATA_FILE" > "$TMP_HOSTS"


# ============================================================
# BUILD THE SUMMARY
#
# The five previous files are included without changing their
# contents. Downstream anomaly scripts can therefore use:
#
#   .auth
#   .process
#   .network
#   .file
#   .temporal
#
# without opening separate files.
# ============================================================

jq -n \
    --slurpfile auth "$AUTH_FILE" \
    --slurpfile process "$PROCESS_FILE" \
    --slurpfile network "$NETWORK_FILE" \
    --slurpfile filebaseline "$FILE_FILE" \
    --slurpfile temporal "$TEMPORAL_FILE" \
    --slurpfile hosts "$TMP_HOSTS" \
    --arg version "1.0" \
    --arg generated_at "$GENERATED_AT" \
    --arg baseline_start "$BASELINE_START" \
    --arg baseline_end "$BASELINE_END" \
    --arg evaluation_start "$EVALUATION_START" \
    --arg evaluation_end "$EVALUATION_END" \
    --argjson baseline_days "$BASELINE_DAYS" '

    {
        version: $version,

        generated_at: $generated_at,


        # ====================================================
        # TIME WINDOWS
        # ====================================================

        baseline_window: {
            start: $baseline_start,
            end: $baseline_end,
            duration_days: $baseline_days
        },


        evaluation_window: {
            start: $evaluation_start,
            end: $evaluation_end,
            duration_hours: 24
        },


        # ====================================================
        # HOST INVENTORY
        # ====================================================

        host_inventory: $hosts[0],


        # ====================================================
        # PREVIOUS BASELINES
        # ====================================================

        auth: $auth[0],

        process: $process[0],

        network: $network[0],

        file: $filebaseline[0],

        temporal: $temporal[0],


        # ====================================================
        # ANOMALY THRESHOLDS
        #
        # Later anomaly scripts should read these values from
        # baseline_summary.json instead of defining their own
        # numeric thresholds.
        # ====================================================

        thresholds: {

            # ------------------------------------------------
            # Authentication failure multiplier
            #
            # Three times the normal hourly failure rate is
            # used as the comparison multiplier.
            # ------------------------------------------------

            failure_rate_multiplier: 3,

            failure_rate_multiplier_comment:
                "Evaluation failure rates are compared against three times the observed baseline hourly failure rate.",


            # ------------------------------------------------
            # Baseline-derived business-hours threshold
            # ------------------------------------------------

            business_failure_rate_threshold:
                (
                    (
                        $auth[0]
                        .business_hours_avg
                        .failure_per_hour
                        // 0
                    )
                    * 3
                ),

            business_failure_rate_threshold_comment:
                "Derived from baseline business-hours failures per hour multiplied by failure_rate_multiplier.",


            # ------------------------------------------------
            # Baseline-derived off-hours threshold
            # ------------------------------------------------

            offhours_failure_rate_threshold:
                (
                    (
                        $auth[0]
                        .offhours_avg
                        .failure_per_hour
                        // 0
                    )
                    * 3
                ),

            offhours_failure_rate_threshold_comment:
                "Derived from baseline off-hours failures per hour multiplied by failure_rate_multiplier.",


            # ------------------------------------------------
            # Failure burst threshold
            #
            # This is taken directly from Task 4.
            # ------------------------------------------------

            max_failures_1h_window:
                (
                    $auth[0]
                    .max_failures_1h_window
                    // 0
                ),

            max_failures_1h_window_comment:
                "Directly derived from the largest one-hour login-failure burst observed from one src_ip during the clean baseline.",


            # ------------------------------------------------
            # Unknown process scoring weight
            #
            # A process absent from the per-host baseline is a
            # strong investigation trigger in this project.
            # ------------------------------------------------

            unknown_process_penalty: 5,

            unknown_process_penalty_comment:
                "Project scoring weight for a process absent from that host's expected process baseline.",


            # ------------------------------------------------
            # Unknown network port scoring weight
            # ------------------------------------------------

            unknown_port_penalty: 4,

            unknown_port_penalty_comment:
                "Project scoring weight for a network port absent from the expected network baseline."
        }
    }

' > "$TMP_OUTPUT"


# ============================================================
# WRITE FINAL OUTPUT
#
# Replace the old file rather than append.
# ============================================================

mv "$TMP_OUTPUT" "$OUTPUT_FILE"

TMP_OUTPUT=""


# ============================================================
# SUMMARY INFORMATION
# ============================================================

HOST_COUNT=$(
    jq '.host_inventory | length' "$OUTPUT_FILE"
)


VERSION=$(
    jq -r '.version' "$OUTPUT_FILE"
)


# ============================================================
# PRINT EXPECTED OUTPUT
# ============================================================

printf "version           : %s\n" "$VERSION"

printf "baseline window   : %s -> %s  (%s days)\n" \
    "$BASELINE_START" \
    "$BASELINE_END" \
    "$BASELINE_DAYS"

printf "evaluation window : %s -> %s  (24h)\n" \
    "$EVALUATION_START" \
    "$EVALUATION_END"

printf "hosts             : %s\n" "$HOST_COUNT"

printf "sections included : auth, process, network, file, temporal, thresholds\n"

printf "baseline_summary.json written\n"
