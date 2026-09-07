#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# 10-fp_baseline.sh
#
# Run every Sigma rule against the confirmed-clean 3x01
# baseline window.
#
# Any match during this window is counted as a false positive.
#
# Output:
#   fp_baseline.json
# ------------------------------------------------------------


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RULE_DIR="$SCRIPT_DIR/rules/sigma"
RUNNER="$SCRIPT_DIR/3-sigma_runner.sh"

BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

OUTPUT="$SCRIPT_DIR/fp_baseline.json"


# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required" >&2
    exit 1
}


# ------------------------------------------------------------
# Input checks
# ------------------------------------------------------------

if [[ ! -d "$RULE_DIR" ]]; then
    echo "ERROR: rule directory not found: $RULE_DIR" >&2
    exit 1
fi

if [[ ! -x "$RUNNER" ]]; then
    echo "ERROR: runner not found or not executable: $RUNNER" >&2
    exit 1
fi

if [[ ! -f "$BASELINE_SUMMARY" ]]; then
    echo "ERROR: baseline summary not found: $BASELINE_SUMMARY" >&2
    exit 1
fi

jq empty "$BASELINE_SUMMARY" >/dev/null


# ------------------------------------------------------------
# Read baseline window
#
# Support a few reasonable baseline_summary.json layouts.
# The dates are always taken from the file, never hardcoded.
# ------------------------------------------------------------

BASELINE_START="$(
    jq -r '
        [
            .baseline_window_start?,
            .baseline_start?,
            .baseline_window?.start?,
            .baseline?.window_start?,
            .baseline?.start?
        ]
        | map(select(type == "string" and length > 0))
        | .[0] // empty
    ' "$BASELINE_SUMMARY"
)"

BASELINE_END="$(
    jq -r '
        [
            .baseline_window_end?,
            .baseline_end?,
            .baseline_window?.end?,
            .baseline?.window_end?,
            .baseline?.end?
        ]
        | map(select(type == "string" and length > 0))
        | .[0] // empty
    ' "$BASELINE_SUMMARY"
)"


if [[ -z "$BASELINE_START" || -z "$BASELINE_END" ]]; then
    echo "ERROR: could not determine baseline window from:" >&2
    echo "       $BASELINE_SUMMARY" >&2
    exit 1
fi


# ------------------------------------------------------------
# Normalize date-only boundaries
#
# If the summary contains only:
#
#   2026-03-18
#   2026-03-24
#
# the runner needs the final day to include the whole day.
# ------------------------------------------------------------

RUNNER_START="$BASELINE_START"
RUNNER_END="$BASELINE_END"

if [[ "$RUNNER_START" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    RUNNER_START="${RUNNER_START}T00:00:00Z"
fi

if [[ "$RUNNER_END" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    RUNNER_END="${RUNNER_END}T23:59:59Z"
fi


# ------------------------------------------------------------
# Calculate number of days in the baseline window.
#
# We derive this instead of assuming seven days so the script
# remains reusable if the input dataset changes.
# ------------------------------------------------------------

BASELINE_DAYS="$(
    python3 -W error - "$RUNNER_START" "$RUNNER_END" <<'PY'
import math
import sys
from datetime import datetime, timezone


def parse_iso(value):
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


start = parse_iso(sys.argv[1])
end = parse_iso(sys.argv[2])

seconds = (end - start).total_seconds()

if seconds < 0:
    raise SystemExit("baseline end is before baseline start")

days = max(1, math.ceil(seconds / 86400))

print(days)
PY
)"


# ------------------------------------------------------------
# Find all Sigma rules
# ------------------------------------------------------------

mapfile -t RULES < <(
    find "$RULE_DIR" \
        -maxdepth 1 \
        -type f \
        \( -name '*.yml' -o -name '*.yaml' \) \
        -print |
    sort
)

RULE_COUNT="${#RULES[@]}"

if [[ "$RULE_COUNT" -eq 0 ]]; then
    echo "ERROR: no Sigma rules found in $RULE_DIR" >&2
    exit 1
fi


# ------------------------------------------------------------
# Temporary files
# ------------------------------------------------------------

TMP_DIR="$(mktemp -d)"
RESULTS_JSONL="$TMP_DIR/fp_results.jsonl"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT


# ------------------------------------------------------------
# Initial summary
# ------------------------------------------------------------

DISPLAY_START="${BASELINE_START:0:10}"
DISPLAY_END="${BASELINE_END:0:10}"

echo "evaluating $RULE_COUNT rules against baseline window $DISPLAY_START -> $DISPLAY_END"


# ------------------------------------------------------------
# Evaluate every rule
# ------------------------------------------------------------

for rule in "${RULES[@]}"; do

    # Run the Sigma rule against only the clean baseline window.
    RESULT="$(
        "$RUNNER" \
            "$rule" \
            --window "$RUNNER_START,$RUNNER_END"
    )"

    # Make sure the runner returned valid JSON.
    if ! jq empty <<<"$RESULT" >/dev/null 2>&1; then
        echo "ERROR: runner returned invalid JSON for $rule" >&2
        exit 1
    fi

    RULE_ID="$(jq -r '.rule_id' <<<"$RESULT")"
    RULE_TITLE="$(jq -r '.rule_title' <<<"$RESULT")"
    LEVEL="$(jq -r '.level' <<<"$RESULT")"
    FP_COUNT="$(jq -r '.match_count' <<<"$RESULT")"

    # Validate the count before using it in arithmetic.
    if [[ ! "$FP_COUNT" =~ ^[0-9]+$ ]]; then
        echo "ERROR: invalid match_count for $rule: $FP_COUNT" >&2
        exit 1
    fi

    # Store one deterministic record.
    jq -n \
        --arg rule_id "$RULE_ID" \
        --arg rule_title "$RULE_TITLE" \
        --arg level "$LEVEL" \
        --argjson fp_count "$FP_COUNT" \
        --arg baseline_start "$BASELINE_START" \
        --arg baseline_end "$BASELINE_END" \
        --argjson baseline_days "$BASELINE_DAYS" \
        '
        {
            rule_id: $rule_id,
            rule_title: $rule_title,
            level: $level,
            fp_count: $fp_count,
            baseline_window_start: $baseline_start,
            baseline_window_end: $baseline_end,
            fp_rate_per_day:
                (
                    ($fp_count / $baseline_days)
                    * 1000000
                    | round
                    | . / 1000000
                )
        }
        ' >> "$RESULTS_JSONL"

done


# ------------------------------------------------------------
# Write final JSON array
#
# Keep the file itself in rule order for deterministic output.
# ------------------------------------------------------------

jq -s '.' "$RESULTS_JSONL" > "$OUTPUT"


# ------------------------------------------------------------
# Print summary sorted by false positives descending
# ------------------------------------------------------------

jq -r '
    sort_by(.fp_count)
    | reverse
    | .[]
    | [
        .rule_id,
        .rule_title,
        (.fp_count | tostring)
      ]
    | @tsv
' "$OUTPUT" |
while IFS=$'\t' read -r rule_id rule_title fp_count; do

    # Find the filename corresponding to this rule UUID.
    RULE_FILE=""

    for candidate in "${RULES[@]}"; do
        candidate_id="$(
            python3 -W error - "$candidate" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    rule = yaml.safe_load(handle)

print(rule.get("id", ""))
PY
        )"

        if [[ "$candidate_id" == "$rule_id" ]]; then
            RULE_FILE="$(basename "$candidate")"
            break
        fi
    done

    # Extract:
    #   001_ssh_brute_force.yml
    #
    # into:
    #   001
    #   ssh_brute_force
    NUMBER="${RULE_FILE%%_*}"
    SHORT_NAME="${RULE_FILE#*_}"
    SHORT_NAME="${SHORT_NAME%.yml}"
    SHORT_NAME="${SHORT_NAME%.yaml}"

    MARK=""

    if (( fp_count > 10 )); then
        MARK="   [TUNE]"
    fi

    printf "  %-3s %-32s fp=%3d%s\n" \
        "$NUMBER" \
        "$SHORT_NAME" \
        "$fp_count" \
        "$MARK"

done


echo "fp_baseline.json written"
