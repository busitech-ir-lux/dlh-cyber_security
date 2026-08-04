#!/bin/bash

# 14-hardening_orchestrator.sh — Production Hardening Workflow Orchestrator
#                                  Executes hardening scripts in dependency order,
#                                  records timing/exit codes, captures Lynis delta.
#
# ---------------------------------------------------------
# Production Hardening Orchestrator
# Runs all hardening scripts in dependency order
# ---------------------------------------------------------

set -euo pipefail

# Directory containing this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Temporary file containing one JSON object per completed step
RESULTS_FILE=$(mktemp)

# Final report files
RUN_REPORT="$SCRIPT_DIR/hardening_run.json"
IMPROVEMENT_REPORT="$SCRIPT_DIR/hardening_improvement.json"

# Default Lynis report location
LYNIS_REPORT="/var/log/lynis-report.dat"

# Counters
COMPLETED=0
FAILED=0

# Lynis scores
BEFORE_SCORE=0
AFTER_SCORE=0

# Overall start time
RUN_START=$(date --iso-8601=seconds)


# ---------------------------------------------------------
# Hardening scripts in required order
# ---------------------------------------------------------

STEPS=(
    "Baseline snapshot|0-baseline_snapshot.sh"
    "Lynis baseline parser|2-lynis_parse.sh"
    "SSH hardening|4-ssh_hardening.sh"
    "Sysctl hardening|5-sysctl_hardening.sh"
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
# Remove temporary files when the script exits
# ---------------------------------------------------------

cleanup() {
    rm -f "$RESULTS_FILE"
}

trap cleanup EXIT


# ---------------------------------------------------------
# Read the Lynis hardening score
# ---------------------------------------------------------

get_lynis_score() {
    local score

    # Return 0 if the report or score is unavailable
    if [[ ! -f "$LYNIS_REPORT" ]]; then
        echo "0"
        return
    fi

    score=$(
        grep "^hardening_index=" "$LYNIS_REPORT" 2>/dev/null |
        head -1 |
        cut -d= -f2 || true
    )

    if [[ "$score" =~ ^[0-9]+$ ]]; then
        echo "$score"
    else
        echo "0"
    fi
}


# ---------------------------------------------------------
# Create the final JSON reports
# ---------------------------------------------------------

create_reports() {
    local finished_at
    local delta

    finished_at=$(date --iso-8601=seconds)
    delta=$((AFTER_SCORE - BEFORE_SCORE))

    # Convert all individual JSON objects into one JSON array
    if [[ -s "$RESULTS_FILE" ]]; then
        jq -s \
            --arg started_at "$RUN_START" \
            --arg finished_at "$finished_at" \
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
    else
        jq -n \
            --arg started_at "$RUN_START" \
            --arg finished_at "$finished_at" \
            --argjson scheduled "${#STEPS[@]}" \
            --argjson completed "$COMPLETED" \
            --argjson failed "$FAILED" \
            '{
                started_at: $started_at,
                finished_at: $finished_at,
                steps_scheduled: $scheduled,
                steps_completed: $completed,
                steps_failed: $failed,
                steps: []
            }' > "$RUN_REPORT"
    fi

    # Create the before-and-after improvement report
    jq -n \
        --argjson before_score "$BEFORE_SCORE" \
        --argjson after_score "$AFTER_SCORE" \
        --argjson delta "$delta" \
        '{
            before_lynis_score: $before_score,
            after_lynis_score: $after_score,
            improvement: $delta
        }' > "$IMPROVEMENT_REPORT"
}


# ---------------------------------------------------------
# Run one hardening step
# ---------------------------------------------------------

run_step() {
    local step_number="$1"
    local step_name="$2"
    local script_name="$3"

    local script_path="$SCRIPT_DIR/$script_name"
    local step_log="$SCRIPT_DIR/${script_name%.sh}.log"

    local start_time
    local end_time
    local start_seconds
    local end_seconds
    local duration
    local exit_code
    local status

    echo "[$step_number/${#STEPS[@]}] Running $script_name..."

    start_time=$(date --iso-8601=seconds)
    start_seconds=$(date +%s)

    # Task 2 receives the Lynis report as an argument
    if [[ "$script_name" == "2-lynis_parse.sh" ]]; then
        if bash "$script_path" "$LYNIS_REPORT" \
            > "$SCRIPT_DIR/lynis_findings.json" \
            2> "$step_log"; then

            exit_code=0
        else
            exit_code=$?
        fi
    else
        # Run all other scripts and save their output to a log file
        if bash "$script_path" > "$step_log" 2>&1; then
            exit_code=0
        else
            exit_code=$?
        fi
    fi

    end_time=$(date --iso-8601=seconds)
    end_seconds=$(date +%s)
    duration=$((end_seconds - start_seconds))

    if [[ "$exit_code" -eq 0 ]]; then
        status="completed"
        COMPLETED=$((COMPLETED + 1))

        echo "    $step_name: PASS (${duration}s)"
    else
        status="failed"
        FAILED=$((FAILED + 1))

        echo "    $step_name: FAIL (exit code $exit_code)"
    fi

    # Add this step result to the temporary JSON file
    jq -n \
        --arg name "$step_name" \
        --arg script "$script_name" \
        --arg status "$status" \
        --arg started_at "$start_time" \
        --arg finished_at "$end_time" \
        --arg log_file "$step_log" \
        --argjson duration_seconds "$duration" \
        --argjson exit_code "$exit_code" \
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

    # Stop immediately when a step fails
    if [[ "$exit_code" -ne 0 ]]; then
        AFTER_SCORE="$BEFORE_SCORE"

        create_reports

        echo
        echo "Hardening stopped because $script_name failed."
        echo "Check log: $step_log"
        echo "Run log saved to: hardening_run.json"
        echo "Improvement saved to: hardening_improvement.json"

        exit "$exit_code"
    fi
}


# ---------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------

# The orchestrator must run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi

# Check required commands
for command_name in bash jq grep cut lynis; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Missing required command: $command_name"
        exit 1
    fi
done

# Check that every required script exists
for step in "${STEPS[@]}"; do
    script_name="${step#*|}"

    if [[ ! -f "$SCRIPT_DIR/$script_name" ]]; then
        echo "Missing required script: $script_name"
        exit 1
    fi
done

echo "Pre-checks: PASS"
echo "Steps scheduled: ${#STEPS[@]}"


# ---------------------------------------------------------
# Capture the pre-hardening Lynis score
# ---------------------------------------------------------

echo "[*] Running pre-hardening Lynis audit..."

lynis audit system --quick > "$SCRIPT_DIR/lynis-before.log" 2>&1

BEFORE_SCORE=$(get_lynis_score)

# Save the pre-hardening Lynis report
if [[ -f "$LYNIS_REPORT" ]]; then
    cp "$LYNIS_REPORT" "$SCRIPT_DIR/lynis-report-before.dat"
fi

echo "    Before Lynis score: $BEFORE_SCORE"


# ---------------------------------------------------------
# Run all hardening scripts
# ---------------------------------------------------------

STEP_NUMBER=1

for step in "${STEPS[@]}"; do
    # Text before | is the readable step name
    STEP_NAME="${step%%|*}"

    # Text after | is the script filename
    SCRIPT_NAME="${step#*|}"

    run_step "$STEP_NUMBER" "$STEP_NAME" "$SCRIPT_NAME"

    STEP_NUMBER=$((STEP_NUMBER + 1))
done


# ---------------------------------------------------------
# Capture the post-hardening Lynis score
# ---------------------------------------------------------

echo "[*] Running post-hardening Lynis audit..."

lynis audit system --quick > "$SCRIPT_DIR/lynis-after.log" 2>&1

AFTER_SCORE=$(get_lynis_score)

# Save the post-hardening Lynis report
if [[ -f "$LYNIS_REPORT" ]]; then
    cp "$LYNIS_REPORT" "$SCRIPT_DIR/lynis-report-after.dat"

    bash "$SCRIPT_DIR/2-lynis_parse.sh" "$LYNIS_REPORT" \
        > "$SCRIPT_DIR/lynis_findings_after.json"
fi

echo "    After Lynis score: $AFTER_SCORE"


# ---------------------------------------------------------
# Generate final reports
# ---------------------------------------------------------

create_reports

DELTA=$((AFTER_SCORE - BEFORE_SCORE))


# ---------------------------------------------------------
# Display final summary
# ---------------------------------------------------------

echo
echo "Steps completed: $COMPLETED"
echo "Steps failed: $FAILED"
echo "Before Lynis score: $BEFORE_SCORE"
echo "After Lynis score: $AFTER_SCORE"

if [[ "$DELTA" -ge 0 ]]; then
    echo "Delta: +$DELTA"
else
    echo "Delta: $DELTA"
fi

echo "Run log saved to: hardening_run.json"
echo "Improvement saved to: hardening_improvement.json"
