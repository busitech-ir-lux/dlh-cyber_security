#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 15 - BASELINE VALIDATION
#
# Runs T10, T11 and T12 twice:
#
#   1. Self-check:
#      Evaluation window = clean baseline window
#
#   2. Live-check:
#      Evaluation window = normal day-8 evaluation window
#
# Outputs:
#   self_check_auth.json
#   self_check_process.json
#   self_check_network.json
#
#   live_check_auth.json
#   live_check_process.json
#   live_check_network.json
#
#   baseline_validation.json
# ============================================================


# ============================================================
# VALIDATION RUBRIC
#
# PASS when:
#
#   self_check_total < 5
#
# AND
#
#   signal_to_noise_ratio >= 3.0
#
# The self-check threshold may be changed for testing.
# ============================================================

SELF_CHECK_THRESHOLD="${SELF_CHECK_THRESHOLD:-5}"
MIN_SIGNAL_TO_NOISE="3.0"


# ============================================================
# PATHS
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-.}"

PROJECT_DIR="$(pwd -P)"

SUMMARY_FILE="$BASELINE_PKG/baseline_summary.json"
LABELED_FILE="$PROJECT_DIR/labeled_events.json"

AUTH_SCRIPT="$PROJECT_DIR/10-anomalies_auth.sh"
PROCESS_SCRIPT="$PROJECT_DIR/11-anomalies_process.sh"
NETWORK_SCRIPT="$PROJECT_DIR/12-anomalies_network.sh"

OUTPUT_FILE="$PROJECT_DIR/baseline_validation.json"


# ============================================================
# VALIDATION OUTPUT FILES
# ============================================================

SELF_AUTH="$PROJECT_DIR/self_check_auth.json"
SELF_PROCESS="$PROJECT_DIR/self_check_process.json"
SELF_NETWORK="$PROJECT_DIR/self_check_network.json"

LIVE_AUTH="$PROJECT_DIR/live_check_auth.json"
LIVE_PROCESS="$PROJECT_DIR/live_check_process.json"
LIVE_NETWORK="$PROJECT_DIR/live_check_network.json"


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi


if ! [[ "$SELF_CHECK_THRESHOLD" =~ ^[0-9]+$ ]]; then
    echo "Error: SELF_CHECK_THRESHOLD must be an integer." >&2
    exit 1
fi


if [ ! -f "$SUMMARY_FILE" ]; then
    echo "Error: baseline summary not found: $SUMMARY_FILE" >&2
    exit 1
fi


if [ ! -f "$LABELED_FILE" ]; then
    echo "Error: labeled_events.json not found." >&2
    exit 1
fi


# Check the three anomaly scripts.
for script in \
    "$AUTH_SCRIPT" \
    "$PROCESS_SCRIPT" \
    "$NETWORK_SCRIPT"
do
    if [ ! -f "$script" ]; then
        echo "Error: required script not found: $script" >&2
        exit 1
    fi
done


# Validate JSON inputs.
if ! jq -e . "$SUMMARY_FILE" >/dev/null 2>&1; then
    echo "Error: invalid JSON in $SUMMARY_FILE" >&2
    exit 1
fi


if ! jq -e . "$LABELED_FILE" >/dev/null 2>&1; then
    echo "Error: invalid JSON in $LABELED_FILE" >&2
    exit 1
fi


# ============================================================
# TEMPORARY VALIDATION ENVIRONMENT
#
# This prevents T10-T12 from overwriting the normal anomaly
# files in the project directory.
# ============================================================

TMP_ROOT=$(mktemp -d)

SELF_RUN="$TMP_ROOT/self_run"
LIVE_RUN="$TMP_ROOT/live_run"

SELF_PKG="$TMP_ROOT/self_pkg"
LIVE_PKG="$TMP_ROOT/live_pkg"

mkdir -p \
    "$SELF_RUN" \
    "$LIVE_RUN" \
    "$SELF_PKG" \
    "$LIVE_PKG"


cleanup()
{
    rm -rf "$TMP_ROOT"
}

trap cleanup EXIT


# ============================================================
# CREATE SELF-CHECK SUMMARY
#
# Keep the real baseline unchanged.
#
# Only change evaluation_window so that T10-T12 inspect the
# clean baseline period instead of day 8.
# ============================================================

jq '
    .evaluation_window.start =
        .baseline_window.start

    |

    .evaluation_window.end =
        .baseline_window.end

    |

    .evaluation_window.duration_hours =
        (.baseline_window.duration_days * 24)
' "$SUMMARY_FILE" > "$SELF_PKG/baseline_summary.json"


# ============================================================
# CREATE LIVE-CHECK SUMMARY
#
# The normal summary already contains the real evaluation
# window, so simply copy it.
# ============================================================

cp "$SUMMARY_FILE" \
    "$LIVE_PKG/baseline_summary.json"


# ============================================================
# PREPARE ISOLATED RUN DIRECTORIES
#
# Some anomaly scripts read:
#
#   $BASELINE_PKG/baseline_summary.json
#
# while others may expect:
#
#   ./baseline_summary.json
#
# We support both forms.
# ============================================================

ln -s \
    "$SELF_PKG/baseline_summary.json" \
    "$SELF_RUN/baseline_summary.json"

ln -s \
    "$LIVE_PKG/baseline_summary.json" \
    "$LIVE_RUN/baseline_summary.json"


# T10-T12 all need the same labeled dataset.
ln -s \
    "$LABELED_FILE" \
    "$SELF_RUN/labeled_events.json"

ln -s \
    "$LABELED_FILE" \
    "$LIVE_RUN/labeled_events.json"


# ============================================================
# RUN ONE ANOMALY SCRIPT
#
# Arguments:
#
#   $1 = run directory
#   $2 = temporary BASELINE_PKG
#   $3 = anomaly script
#   $4 = expected generated filename
#   $5 = final validation filename
# ============================================================

run_detector()
{
    local run_dir="$1"
    local package_dir="$2"
    local script="$3"
    local generated_file="$4"
    local destination="$5"
    local log_file

    log_file="$TMP_ROOT/$(basename "$script").log"


    # --------------------------------------------------------
    # Execute in an isolated directory.
    # --------------------------------------------------------

    if ! (
        cd "$run_dir"

        HANDOFF_DIR="$HANDOFF_DIR" \
        BASELINE_PKG="$package_dir" \
        bash "$script"
    ) >"$log_file" 2>&1
    then
        echo "Error: validation run failed: $(basename "$script")" >&2
        cat "$log_file" >&2
        exit 1
    fi


    # --------------------------------------------------------
    # Most anomaly scripts write into their working directory.
    #
    # Also accept output in BASELINE_PKG for compatibility.
    # --------------------------------------------------------

    if [ -f "$run_dir/$generated_file" ]; then

        cp "$run_dir/$generated_file" "$destination"

    elif [ -f "$package_dir/$generated_file" ]; then

        cp "$package_dir/$generated_file" "$destination"

    else

        echo \
            "Error: $generated_file was not created by $(basename "$script")" \
            >&2

        exit 1
    fi
}


# ============================================================
# 1. SELF-CHECK
#
# Run the real anomaly scripts against the clean baseline.
# ============================================================

run_detector \
    "$SELF_RUN" \
    "$SELF_PKG" \
    "$AUTH_SCRIPT" \
    "anomalies_auth.json" \
    "$SELF_AUTH"


run_detector \
    "$SELF_RUN" \
    "$SELF_PKG" \
    "$PROCESS_SCRIPT" \
    "anomalies_process.json" \
    "$SELF_PROCESS"


run_detector \
    "$SELF_RUN" \
    "$SELF_PKG" \
    "$NETWORK_SCRIPT" \
    "anomalies_network.json" \
    "$SELF_NETWORK"


# ============================================================
# 2. LIVE-CHECK
#
# Run the same scripts against the normal day-8 window.
# ============================================================

run_detector \
    "$LIVE_RUN" \
    "$LIVE_PKG" \
    "$AUTH_SCRIPT" \
    "anomalies_auth.json" \
    "$LIVE_AUTH"


run_detector \
    "$LIVE_RUN" \
    "$LIVE_PKG" \
    "$PROCESS_SCRIPT" \
    "anomalies_process.json" \
    "$LIVE_PROCESS"


run_detector \
    "$LIVE_RUN" \
    "$LIVE_PKG" \
    "$NETWORK_SCRIPT" \
    "anomalies_network.json" \
    "$LIVE_NETWORK"


# ============================================================
# COUNT TOTAL FINDINGS
#
# jq -s works correctly for NDJSON and empty files.
# ============================================================

SELF_TOTAL=$(
    jq -s 'length' \
        "$SELF_AUTH" \
        "$SELF_PROCESS" \
        "$SELF_NETWORK"
)


LIVE_TOTAL=$(
    jq -s 'length' \
        "$LIVE_AUTH" \
        "$LIVE_PROCESS" \
        "$LIVE_NETWORK"
)


# ============================================================
# PER-TYPE BREAKDOWN
#
# Example:
#
# {
#   "unknown_account": 2,
#   "offhours_login": 1,
#   "high_risk_process": 3
# }
# ============================================================

SELF_BREAKDOWN=$(
    jq -s '
        map(
            select(
                .anomaly_type != null
            )
        )

        | sort_by(.anomaly_type)

        | group_by(.anomaly_type)

        | map(
            {
                key: .[0].anomaly_type,
                value: length
            }
        )

        | from_entries
    ' \
        "$SELF_AUTH" \
        "$SELF_PROCESS" \
        "$SELF_NETWORK"
)


LIVE_BREAKDOWN=$(
    jq -s '
        map(
            select(
                .anomaly_type != null
            )
        )

        | sort_by(.anomaly_type)

        | group_by(.anomaly_type)

        | map(
            {
                key: .[0].anomaly_type,
                value: length
            }
        )

        | from_entries
    ' \
        "$LIVE_AUTH" \
        "$LIVE_PROCESS" \
        "$LIVE_NETWORK"
)


# ============================================================
# SIGNAL-TO-NOISE RATIO
#
# Required formula:
#
#   live_check_total / max(self_check_total, 1)
# ============================================================

SIGNAL_TO_NOISE=$(
    jq -n \
        --argjson live "$LIVE_TOTAL" \
        --argjson self "$SELF_TOTAL" '

        $live
        /
        (
            if $self > 1
            then $self
            else 1
            end
        )
    '
)


# ============================================================
# VERDICT
#
# PASS when:
#
#   self-check is UNDER the threshold
#
# AND
#
#   ratio is AT LEAST 3.0
# ============================================================

RATIO_OK=$(
    jq -n \
        --argjson ratio "$SIGNAL_TO_NOISE" \
        --argjson minimum "$MIN_SIGNAL_TO_NOISE" '

        $ratio >= $minimum
    '
)


if [ "$SELF_TOTAL" -lt "$SELF_CHECK_THRESHOLD" ] &&
   [ "$RATIO_OK" = "true" ]
then

    VERDICT="pass"

else

    VERDICT="fail"

fi


# ============================================================
# WINDOWS USED FOR VALIDATION
# ============================================================

BASELINE_START=$(
    jq -r '.baseline_window.start' "$SUMMARY_FILE"
)

BASELINE_END=$(
    jq -r '.baseline_window.end' "$SUMMARY_FILE"
)

EVAL_START=$(
    jq -r '.evaluation_window.start' "$SUMMARY_FILE"
)

EVAL_END=$(
    jq -r '.evaluation_window.end' "$SUMMARY_FILE"
)


# ============================================================
# BUILD baseline_validation.json
# ============================================================

TMP_VALIDATION="$TMP_ROOT/baseline_validation.json"


jq -n \
    --arg baseline_start "$BASELINE_START" \
    --arg baseline_end "$BASELINE_END" \
    --arg evaluation_start "$EVAL_START" \
    --arg evaluation_end "$EVAL_END" \
    --argjson self_total "$SELF_TOTAL" \
    --argjson live_total "$LIVE_TOTAL" \
    --argjson ratio "$SIGNAL_TO_NOISE" \
    --argjson self_breakdown "$SELF_BREAKDOWN" \
    --argjson live_breakdown "$LIVE_BREAKDOWN" \
    --argjson self_threshold "$SELF_CHECK_THRESHOLD" \
    --argjson minimum_ratio "$MIN_SIGNAL_TO_NOISE" \
    --arg verdict "$VERDICT" '

    {
        baseline_window: {
            start: $baseline_start,
            end: $baseline_end
        },

        evaluation_window: {
            start: $evaluation_start,
            end: $evaluation_end
        },

        self_check_total: $self_total,

        live_check_total: $live_total,

        signal_to_noise_ratio: $ratio,

        self_check_breakdown: $self_breakdown,

        live_check_breakdown: $live_breakdown,

        acceptance_criteria: {
            self_check_threshold: $self_threshold,
            self_check_rule: "self_check_total < self_check_threshold",
            minimum_signal_to_noise_ratio: $minimum_ratio
        },

        verdict: $verdict
    }

' > "$TMP_VALIDATION"


# Replace rather than append.
mv "$TMP_VALIDATION" "$OUTPUT_FILE"


# ============================================================
# TERMINAL OUTPUT
# ============================================================

printf "self-check anomalies (baseline window): %s\n" \
    "$SELF_TOTAL"

printf "live-check anomalies (evaluation win ): %s\n" \
    "$LIVE_TOTAL"

printf "signal-to-noise ratio                : %.2f\n" \
    "$SIGNAL_TO_NOISE"

printf "verdict                              : %s\n" \
    "$VERDICT"

printf "baseline_validation.json written\n"


# ============================================================
# REQUIRED EXIT STATUS
# ============================================================

if [ "$VERDICT" = "pass" ]; then
    exit 0
else
    exit 1
fi
