#!/bin/bash

#----------------------------------------------------------
set -euo pipefail

# ---------------------------------------------------------
# Main file locations
# ---------------------------------------------------------

# Directory containing this orchestrator and the other scripts
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Temporary file used to store one JSON result per step
RESULTS_FILE=$(mktemp)

# Final JSON reports
RUN_REPORT="$SCRIPT_DIR/hardening_run.json"
IMPROVEMENT_REPORT="$SCRIPT_DIR/hardening_improvement.json"

# Lynis report location
LYNIS_REPORT="/var/log/lynis-report.dat"

# Counters
COMPLETED=0
FAILED=0

# Lynis scores
BEFORE_SCORE=0
AFTER_SCORE=0


# ---------------------------------------------------------
# List scripts in the required execution order
# ---------------------------------------------------------

STEPS=(
    "Baseline snapshot|0-baseline_snapshot.sh"
    "Lynis report parser|2-lynis_parse.sh"
    "SSH hardening|4-ssh_hardening.sh"
    "Kernel hardening|5-sysctl_hardening.sh"
    "Filesystem hardening|6-filesystem_hardening.sh"
    "Service minimization|7-service_minimization.sh"
    "PAM hardening|8-pam_hardening.sh"
    "AppArmor configuration|9-apparmor_config.sh"
    "Auditd configuration|10-auditd_config.sh"
    "Audit coverage test|11-audit_coverage_test.sh"
    "Logging configuration|12-log_config.sh"
    "Firewall baseline|13-firewall_baseline.sh"
    "Final validation|15-validation.sh"
)


# ---------------------------------------------------------
# Remove the temporary file when the script finishes
# ---------------------------------------------------------

cleanup() {
    rm -f "$RESULTS_FILE"
}

trap cleanup EXIT


# ---------------------------------------------------------
# Function that creates the final JSON reports
# ---------------------------------------------------------

create_reports() {

    # Combine all step results into one JSON array
    jq -s \
        --arg started_at "$RUN_START" \
        --arg finished_at "$(date --iso-8601=seconds)" \
        --argjson scheduled "${#STEPS[@]}" \
        --argjson completed "$COMPLETED" \
        --argjson failed "$FAILED" \
        '{
            started_at: $started_at,
            finished_at: $finished_at,
            steps_scheduled: $scheduled,
            steps_completed: $completed,
            steps_failed: $failed,
            steps: .
        }' "$RESULTS_FILE" > "$RUN_REPORT"

    # Calculate the difference between Lynis scores
    DELTA=$((AFTER_SCORE - BEFORE_SCORE))

    jq -n \
        --argjson before_score "$BEFORE_SCORE" \
        --argjson after_score "$AFTER_SCORE" \
        --argjson delta "$DELTA" \
        '{
            before_lynis_score: $before_score,
            after_lynis_score: $after_score,
            improvement: $delta
        }' > "$IMPROVEMENT_REPORT"
}


# ---------------------------------------------------------
# Function that runs one hardening script
# ---------------------------------------------------------

run_step() {

    # Information passed to the function
    STEP_NUMBER="$1"
    STEP_NAME="$2"
    SCRIPT_NAME="$3"

    SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
    STEP_LOG="$SCRIPT_DIR/${SCRIPT_NAME%.sh}.log"

    echo "[$STEP_NUMBER/${#STEPS[@]}] Running $SCRIPT_NAME..."

    # Record the start time
    START_TIME=$(date --iso-8601=seconds)
    START_SECONDS=$(date +%s)

    # Task 2 needs the Lynis report path as its first argument
    if [[ "$SCRIPT_NAME" == "2-lynis_parse.sh" ]]; then

        if bash "$SCRIPT_PATH" "$LYNIS_REPORT" \
            > "$SCRIPT_DIR/lynis_findings.json" \
            2> "$STEP_LOG"; then

            EXIT_CODE=0
        else
            EXIT_CODE=$?
        fi

    else

        # Run other scripts normally and save their output
        if bash "$SCRIPT_PATH" > "$STEP_LOG" 2>&1; then
            EXIT_CODE=0
        else
            EXIT_CODE=$?
        fi
    fi

    # Record the finish time and calculate duration
    END_TIME=$(date --iso-8601=seconds)
    END_SECONDS=$(date +%s)
    DURATION=$((END_SECONDS - START_SECONDS))

    if [[ "$EXIT_CODE" -eq 0 ]]; then
        STATUS="completed"
        ((COMPLETED+=1))

        echo "    $STEP_NAME: PASS (${DURATION}s)"
    else
        STATUS="failed"
        ((FAILED+=1))

        echo "    $STEP_NAME: FAIL (exit code $EXIT_CODE)"
    fi

    # Store the step result as one JSON object
    jq -n \
        --arg name "$STEP_NAME" \
        --arg script "$SCRIPT_NAME" \
        --arg status "$STATUS" \
        --arg started_at "$START_TIME" \
        --arg finished_at "$END_TIME" \
        --arg log_file "$STEP_LOG" \
        --argjson duration_seconds "$DURATION" \
        --argjson exit_code "$EXIT_CODE" \
        '{
            name: $name,
            script: $script,
            status: $status,
            started_at: $started_at,
            finished_at: $finished_at,
            duration_seconds: $duration_seconds,
            exit_code: $exit_code,
            log_file: $log_file
        }' >> "$RESULTS_FILE"

    # Stop the workflow immediately when a script fails
    if [[ "$EXIT_CODE" -ne 0 ]]; then
        create_reports

        echo
        echo "Hardening stopped because $SCRIPT_NAME failed."
        echo "Check log: $STEP_LOG"
        echo "Run log saved to: hardening_run.json"

        exit "$EXIT_CODE"
    fi
}


# ---------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------

RUN_START=$(date --iso-8601=seconds)

# The orchestrator must run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi

# Check the commands required by the orchestrator
for command in jq lynis grep cut; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing required command: $command"
        exit 1
    fi
done

# Check that every required script exists
for step in "${STEPS[@]}"; do

    # Extract the script name after the | character
    SCRIPT_NAME="${step#*|}"

    if [[ ! -f "$SCRIPT_DIR/$SCRIPT_NAME" ]]; then
        echo "Missing required script: $SCRIPT_NAME"
        exit 1
    fi
done

echo "Pre-checks: PASS"
echo "Steps scheduled: ${#STEPS[@]}"


# ---------------------------------------------------------
# Capture the Lynis score before hardening
# ---------------------------------------------------------

echo "[*] Running pre-hardening Lynis audit..."

lynis audit system --quick >/dev/null 2>&1

BEFORE_SCORE=$(
    grep "^hardening_index=" "$LYNIS_REPORT" |
    head -1 |
    cut -d= -f2
)

# Save a copy of the original Lynis report
cp "$LYNIS_REPORT" "$SCRIPT_DIR/lynis-report-before.dat"

echo "    Before Lynis score: $BEFORE_SCORE"


# ---------------------------------------------------------
# Run all hardening scripts in order
# ---------------------------------------------------------

STEP_NUMBER=1

for step in "${STEPS[@]}"; do

    # Text before | is the readable step name
    STEP_NAME="${step%%|*}"

    # Text after | is the script filename
    SCRIPT_NAME="${step#*|}"

    run_step "$STEP_NUMBER" "$STEP_NAME" "$SCRIPT_NAME"

    ((STEP_NUMBER+=1))
done


# ---------------------------------------------------------
# Capture the Lynis score after hardening
# ---------------------------------------------------------

echo "[*] Running post-hardening Lynis audit..."

lynis audit system --quick >/dev/null 2>&1

AFTER_SCORE=$(
    grep "^hardening_index=" "$LYNIS_REPORT" |
    head -1 |
    cut -d= -f2
)

# Save the final Lynis report
cp "$LYNIS_REPORT" "$SCRIPT_DIR/lynis-report-after.dat"

# Generate a JSON version of the final Lynis findings
bash "$SCRIPT_DIR/2-lynis_parse.sh" "$LYNIS_REPORT" \
    > "$SCRIPT_DIR/lynis_findings_after.json"

echo "    After Lynis score: $AFTER_SCORE"


# ---------------------------------------------------------
# Create the final JSON reports
# ---------------------------------------------------------

create_reports

DELTA=$((AFTER_SCORE - BEFORE_SCORE))

echo
echo "Steps completed: $COMPLETED"
echo "Steps failed: $FAILED"
echo "Before Lynis score: $BEFORE_SCORE"
echo "After Lynis score: $AFTER_SCORE"

# Add a plus sign when the improvement is positive
if [[ "$DELTA" -ge 0 ]]; then
    echo "Delta: +$DELTA"
else
    echo "Delta: $DELTA"
fi

echo "Run log saved to: hardening_run.json"
echo "Improvement saved to: hardening_improvement.json"
