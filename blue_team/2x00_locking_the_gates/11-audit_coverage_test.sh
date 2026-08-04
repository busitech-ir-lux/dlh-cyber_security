#!/bin/bash
set -euo pipefail

# JSON report produced by this script
REPORT="audit_validation.json"

# Temporary file that stores one JSON object per test
TEMP_RESULTS=$(mktemp)

# Temporary files used during testing
TEST_FILE="/var/log/meddefense-audit-test/coverage-test.txt"
CRON_FILE="/etc/cron.d/meddefense-audit-test"

CAPTURED=0
MISSED=0


# ---------------------------------------------------------
# Cleanup
# ---------------------------------------------------------

# This function removes temporary test files.
# It runs when the script finishes, even if an error occurs.
cleanup() {
    rm -f "$TEST_FILE"
    rm -f "$CRON_FILE"
    rm -f "$TEMP_RESULTS"
}

trap cleanup EXIT


# ---------------------------------------------------------
# Test helper
# ---------------------------------------------------------

# This function runs one test and checks the audit log.
#
# $1 = test number
# $2 = test name
# $3 = expected audit key
# $4 = command to execute
run_test() {
    NUMBER="$1"
    NAME="$2"
    KEY="$3"
    COMMAND="$4"

    # Record the time immediately before the test.
    # ausearch will search for events created after this time.
    START_TIME=$(date '+%H:%M:%S')
    TIMESTAMP=$(date --iso-8601=seconds)

    # Run the controlled test command.
    # bash -c allows the command stored in the variable to run.
    bash -c "$COMMAND" >/dev/null 2>&1 || true

    # Give auditd time to write the event.
    sleep 1

    # Count recent audit events containing the expected key.
    EVENT_COUNT=$(ausearch \
        -ts "$START_TIME" \
        -k "$KEY" \
        --success yes 2>/dev/null |
        grep -c '^type=SYSCALL' || true)

    # Store a short matching event excerpt.
    EXCERPT=$(ausearch \
        -ts "$START_TIME" \
        -k "$KEY" \
        --success yes 2>/dev/null |
        grep '^type=SYSCALL' |
        head -1 || true)

    if [[ "$EVENT_COUNT" -gt 0 ]]; then
        STATUS="captured"
        DISPLAY="[CAPTURED]"
        ((CAPTURED+=1))
    else
        STATUS="missed"
        DISPLAY="[MISSED]"
        ((MISSED+=1))
    fi

    printf "[%s/6] %-35s %s\n" "$NUMBER" "$NAME" "$DISPLAY"

    # Create one JSON object for this test.
    jq -n \
        --arg test_name "$NAME" \
        --arg expected_key "$KEY" \
        --arg command "$COMMAND" \
        --arg timestamp "$TIMESTAMP" \
        --arg capture_status "$STATUS" \
        --arg excerpt "$EXCERPT" \
        --argjson matching_event_count "$EVENT_COUNT" \
        '{
            test_name: $test_name,
            expected_audit_key: $expected_key,
            command_executed: $command,
            timestamp: $timestamp,
            capture_status: $capture_status,
            matching_event_count: $matching_event_count,
            matching_excerpt: $excerpt
        }' >> "$TEMP_RESULTS"
}


# ---------------------------------------------------------
# Check that auditd is running
# ---------------------------------------------------------

if ! systemctl is-active --quiet auditd; then
    echo "auditd is not running."
    exit 1
fi


echo "[*] Running audit telemetry coverage tests..."


# ---------------------------------------------------------
# Test 1: privileged command through sudo
# ---------------------------------------------------------

# sudo -n true executes a harmless privileged command.
# The audit rule watches execution of /usr/bin/sudo.
run_test \
    "1" \
    "sudo execution" \
    "priv_esc" \
    "sudo -n true"


# ---------------------------------------------------------
# Test 2: access to /etc/shadow
# ---------------------------------------------------------

# head reads one line from the shadow file.
# No content is displayed because output is redirected.
run_test \
    "2" \
    "shadow access" \
    "identity" \
    "head -1 /etc/shadow"


# ---------------------------------------------------------
# Test 3: execution of curl or wget
# ---------------------------------------------------------

# Running --version is harmless but still executes curl.
run_test \
    "3" \
    "suspicious download tool" \
    "suspicious_download" \
    "curl --version"


# ---------------------------------------------------------
# Test 4: read SSH server configuration
# ---------------------------------------------------------

# head reads one line without changing the file.
run_test \
    "4" \
    "sshd config read" \
    "sshd_config" \
    "head -1 /etc/ssh/sshd_config"


# ---------------------------------------------------------
# Test 5: controlled write to monitored test directory
# ---------------------------------------------------------

# This creates a harmless temporary text file.
run_test \
    "5" \
    "monitored test file write" \
    "test_write" \
    "echo audit-test > '$TEST_FILE'"


# ---------------------------------------------------------
# Test 6: controlled cron file action
# ---------------------------------------------------------

# This creates an empty cron file.
# It contains no cron command and is removed during cleanup.
run_test \
    "6" \
    "cron configuration check" \
    "cron_config" \
    "touch '$CRON_FILE'"


# ---------------------------------------------------------
# Build the final JSON report
# ---------------------------------------------------------

# jq -s combines all individual JSON objects into one array.
jq -s \
    --arg generated_at "$(date --iso-8601=seconds)" \
    --argjson tests_executed 6 \
    --argjson captured "$CAPTURED" \
    --argjson missed "$MISSED" \
    '{
        generated_at: $generated_at,
        tests_executed: $tests_executed,
        captured: $captured,
        missed: $missed,
        tests: .
    }' "$TEMP_RESULTS" > "$REPORT"


# ---------------------------------------------------------
# Print summary
# ---------------------------------------------------------

echo "[*] Cleaning test artifacts..."

rm -f "$TEST_FILE"
rm -f "$CRON_FILE"

echo "Tests executed: 6"
echo "Captured: $CAPTURED"
echo "Missed: $MISSED"
echo "Report saved to: $REPORT"
