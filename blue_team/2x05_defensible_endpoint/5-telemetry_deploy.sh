#!/bin/bash
set -Eeuo pipefail

RULES_FILE="/etc/audit/rules.d/meddefense.rules"
OUT_DIR="${OUT_DIR:-capstone/telemetry}"
EVENTS_JSON="${OUT_DIR}/linux_events.json"
COVERAGE_JSON="${OUT_DIR}/linux_coverage.json"

mkdir -p "$OUT_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi

command -v auditctl >/dev/null || { echo "ERROR: auditctl not found" >&2; exit 1; }
command -v ausearch >/dev/null || { echo "ERROR: ausearch not found" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "ERROR: systemctl not found" >&2; exit 1; }

[[ -f "$RULES_FILE" ]] || {
    echo "ERROR: missing project audit rules: $RULES_FILE" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Deploy/activate auditd rules
# ---------------------------------------------------------------------------

systemctl enable --now auditd

# Load the project rules. augenrules is preferred when available because
# /etc/audit/rules.d is the canonical rules.d location.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$RULES_FILE"
fi

systemctl is-active --quiet auditd || {
    echo "ERROR: auditd is not active" >&2
    exit 1
}

# Give auditd a moment to commit the rules.
sleep 1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

declare -a COVERAGE=()
OVERALL_RC=0

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

add_result() {
    local action="$1"
    local key="$2"
    local rc="$3"
    local evidence="$4"

    local status="pass"
    [[ "$rc" -eq 0 ]] || status="fail"

    [[ "$rc" -eq 0 ]] || OVERALL_RC=1

    COVERAGE+=(
        "$(python3 - "$action" "$key" "$status" "$evidence" <<'PY'
import json, sys
action, key, status, evidence = sys.argv[1:]
print(json.dumps({
    "action": action,
    "expected_key": key,
    "status": status,
    "verified": status == "pass",
    "evidence": evidence
}, separators=(",", ":")))
PY
)"
    )
}

verify_key() {
    local action="$1"
    local key="$2"

    local output rc
    set +e
    output="$(ausearch -k "$key" -ts today 2>/dev/null)"
    rc=$?
    set -e

    # ausearch returns 0 when matching records exist.
    if [[ $rc -eq 0 && -n "$output" ]]; then
        add_result "$action" "$key" 0 "$output"
        return 0
    fi

    add_result "$action" "$key" 1 "${output:-No matching audit record}"
    return 1
}

# ---------------------------------------------------------------------------
# 2. Controlled Linux test sequence
# ---------------------------------------------------------------------------

TEST_USER="mdtelemetry_$$"
CRON_FILE="/etc/cron.d/meddefense-telemetry-$$"

cleanup() {
    userdel "$TEST_USER" >/dev/null 2>&1 || true
    rm -f "$CRON_FILE"
}
trap cleanup EXIT

# User creation/removal
useradd --no-create-home --shell /usr/sbin/nologin "$TEST_USER"
verify_key "create_user" "meddefense-user-mgmt" || true

userdel "$TEST_USER"
verify_key "remove_user" "meddefense-user-mgmt" || true

# Service management.
# cron is expected on the project Linux endpoint. Starting/stopping it is a
# reversible service-management action.
systemctl start cron 2>/dev/null || systemctl start crond
systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond
verify_key "service_management" "meddefense-service-mgmt" || true

# Controlled cron creation.
cat > "$CRON_FILE" <<EOF
# MedDefense telemetry coverage test
* * * * * root /usr/bin/true
EOF

chmod 0644 "$CRON_FILE"

# Give auditd time to ingest the filesystem/process events.
sleep 1
verify_key "cron_create" "meddefense-cron" || true

rm -f "$CRON_FILE"
sleep 1
verify_key "cron_remove" "meddefense-cron" || true

# Short authorized find as root.
find /etc -maxdepth 1 -type f -name '*.conf' -print >/dev/null
verify_key "authorized_find" "meddefense-file-search" || true

# ---------------------------------------------------------------------------
# 3. Export last 30 minutes of auditd + syslog records as structured JSON
# ---------------------------------------------------------------------------

SINCE="$(date -d '30 minutes ago' '+%m/%d/%Y %H:%M:%S')"

AUDIT_TMP="$(mktemp)"
SYSLOG_TMP="$(mktemp)"
trap 'rm -f "$AUDIT_TMP" "$SYSLOG_TMP"; cleanup' EXIT

ausearch -ts "$SINCE" -i 2>/dev/null > "$AUDIT_TMP" || true

# Support the common syslog locations.
if [[ -f /var/log/syslog ]]; then
    tail -n 10000 /var/log/syslog > "$SYSLOG_TMP"
elif [[ -f /var/log/messages ]]; then
    tail -n 10000 /var/log/messages > "$SYSLOG_TMP"
else
    : > "$SYSLOG_TMP"
fi

python3 - "$AUDIT_TMP" "$SYSLOG_TMP" "$EVENTS_JSON" "$SINCE" <<'PY'
import json
import os
import sys
from datetime import datetime, timedelta

audit_file, syslog_file, output_file, since_text = sys.argv[1:]

since = datetime.strptime(since_text, "%m/%d/%Y %H:%M:%S")

events = []

def add_lines(path, source):
    if not os.path.exists(path):
        return

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            events.append({
                "source": source,
                "timestamp": None,
                "message": line
            })

add_lines(audit_file, "auditd")
add_lines(syslog_file, "syslog")

# The raw audit/syslog formats vary by distribution and configuration.
# Preserve the original record while providing a stable structured envelope.
payload = {
    "schema_version": "1.0",
    "host": os.uname().nodename,
    "generated_at": datetime.now().astimezone().isoformat(),
    "window": {
        "start": since.astimezone().isoformat(),
        "duration_minutes": 30
    },
    "events": events
}

with open(output_file, "w") as f:
    json.dump(payload, f, indent=2)

PY

# ---------------------------------------------------------------------------
# 4. Persist coverage evidence
# ---------------------------------------------------------------------------

python3 - "$COVERAGE_JSON" "${COVERAGE[@]}" <<'PY'
import json
import socket
import sys
from datetime import datetime

output = sys.argv[1]
records = [json.loads(x) for x in sys.argv[2:]]

payload = {
    "schema_version": "1.0",
    "platform": "linux",
    "host": socket.gethostname(),
    "generated_at": datetime.now().astimezone().isoformat(),
    "all_actions_verified": all(x["verified"] for x in records),
    "actions": records
}

with open(output, "w") as f:
    json.dump(payload, f, indent=2)

PY

# Configuration/deployment failure
if [[ ! -f "$RULES_FILE" ]]; then
    echo "ERROR: missing audit rules: $RULES_FILE" >&2
    exit 2
fi

# Deplpoyment

if [[ "$OVERALL_RC" -ne 0 ]]; then
    echo "ERROR: telemetry coverage verification failed"
    cat "$COVERAGE_JSON"
    exit 1
fi

echo "Linux telemetry deployment and coverage verification: PASS"
echo "Events:   $EVENTS_JSON"
echo "Coverage: $COVERAGE_JSON"
exit 0

