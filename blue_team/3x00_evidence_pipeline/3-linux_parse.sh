#!/bin/bash

# ============================================================
# TASK 3 - LINUX LOG PARSING
#
# Parse:
#   auth.log
#   audit.log
#   syslog
#
# Append:
#   student_telemetry/linux_events.json
#
# Output:
#   linux_events.json (NDJSON)
# ============================================================

set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
LINUX_DIR="$EVIDENCE_PACK/linux"
STUDENT_FILE="$EVIDENCE_PACK/student_telemetry/linux_events.json"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/linux_events.json}"

if [[ ! -d "$LINUX_DIR" ]]; then
    echo "ERROR: Linux directory not found: $LINUX_DIR" >&2
    exit 1
fi


# ============================================================
# PYTHON PARSER
#
# Python is used because the three Linux log formats are easier
# to parse clearly with regular expressions and dictionaries.
# ============================================================

python3 - "$LINUX_DIR" "$STUDENT_FILE" "$OUTPUT_FILE" <<'PYTHON_EOF'

import json
import os
import re
import shlex
import sys


linux_dir = sys.argv[1]
student_file = sys.argv[2]
output_file = sys.argv[3]


# ============================================================
# SYSLOG / AUTH.LOG PARSER
#
# Typical format:
#
# Mar 18 00:00:38 srv-web-01 sshd[1234]: message
# ============================================================

SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'([^\s:\[]+)'
    r'(?:\[(\d+)\])?:\s*'
    r'(.*)$'
)


def parse_syslog_line(line):
    """Parse one auth.log or syslog line."""

    match = SYSLOG_RE.match(line)

    if match:
        timestamp, hostname, program, pid, message = match.groups()
    else:
        # Preserve an unrecognized line instead of dropping it.
        timestamp = None
        hostname = None
        program = None
        pid = None
        message = line

    parsed_fields = {}

    # --------------------------------------------------------
    # Extract simple key=value fields from the message.
    # --------------------------------------------------------

    for key, value in re.findall(r'(\w+)=("[^"]*"|\S+)', message):
        parsed_fields[key] = value.strip('"')

    # Try to identify a username from common auth messages.
    user = None

    user_match = re.search(
        r'(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9._-]+)',
        message,
        re.IGNORECASE
    )

    if user_match:
        user = user_match.group(1)

    return {
        "timestamp_raw": timestamp,
        "hostname": hostname,
        "program": program,
        "pid": int(pid) if pid else None,
        "user": user,
        "raw_message": line,
        "parsed_fields": parsed_fields,
        "source_origin": "evidence_pack"
    }


# ============================================================
# AUDIT.LOG PARSER
#
# Typical format:
#
# type=SYSCALL msg=audit(1773792000.123:456): ...
#
# We emit one record per line.
#
# Records sharing the same audit ID can still be correlated
# later using:
#
#   parsed_fields.audit_group_id
# ============================================================

def parse_audit_line(line):
    """Parse one Linux auditd line."""

    fields = {}

    # shlex helps preserve quoted values.
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()

    for part in parts:

        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value.strip('"')

    audit_type = fields.get("type")

    # --------------------------------------------------------
    # Extract timestamp and group ID from:
    #
    # msg=audit(1773792000.123:456)
    # --------------------------------------------------------

    timestamp_raw = None
    audit_group_id = None

    match = re.search(
        r'audit\(([\d.]+):(\d+)\)',
        line
    )

    if match:
        timestamp_raw = match.group(1)
        audit_group_id = match.group(2)
        fields["audit_group_id"] = audit_group_id

    # --------------------------------------------------------
    # Hostname may be available as node=hostname.
    # --------------------------------------------------------

    hostname = fields.get("node")

    # --------------------------------------------------------
    # Try common audit user fields.
    # Prefer account name when available.
    # --------------------------------------------------------

    user = (
        fields.get("acct")
        or fields.get("user")
        or fields.get("auid")
        or fields.get("uid")
    )

    pid = fields.get("pid")

    try:
        pid = int(pid) if pid is not None else None
    except ValueError:
        pass

    return {
        "timestamp_raw": timestamp_raw,
        "hostname": hostname,
        "audit_type": audit_type,
        "pid": pid,
        "user": user,
        "raw_message": line,
        "parsed_fields": fields,
        "source_origin": "evidence_pack"
    }


# ============================================================
# PROCESS ONE TEXT LOG
# ============================================================

def process_file(filepath, parser, output):
    """Parse every non-empty line from one Linux source."""

    line_count = 0
    record_count = 0

    with open(filepath, "r", errors="replace") as handle:

        for raw_line in handle:

            line_count += 1
            line = raw_line.rstrip("\n")

            if not line:
                continue

            record = parser(line)

            output.write(
                json.dumps(record, separators=(",", ":")) + "\n"
            )

            record_count += 1

    return line_count, record_count


# ============================================================
# APPEND STUDENT TELEMETRY
#
# Preserve the student's original fields.
#
# Only add:
#   source_origin
#   timestamp_raw
#
# when they are missing.
# ============================================================

def append_student_telemetry(filepath, output):

    if not os.path.isfile(filepath):
        return 0

    count = 0

    with open(filepath, "r", errors="replace") as handle:

        for line in handle:

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                sys.stderr.write(
                    "WARNING: malformed student telemetry line skipped\n"
                )
                continue

            if not isinstance(record, dict):
                continue

            # Preserve existing source_origin if already present.
            if not record.get("source_origin"):
                record["source_origin"] = "student_telemetry"

            # Compatibility with the intermediate schema.
            if "timestamp_raw" not in record and "timestamp" in record:
                record["timestamp_raw"] = record["timestamp"]

            output.write(
                json.dumps(record, separators=(",", ":")) + "\n"
            )

            count += 1

    return count


# ============================================================
# MAIN
# ============================================================

auth_file = os.path.join(linux_dir, "auth.log")
audit_file = os.path.join(linux_dir, "audit.log")
syslog_file = os.path.join(linux_dir, "syslog")


with open(output_file, "w") as output:

    auth_lines, auth_records = process_file(
        auth_file,
        parse_syslog_line,
        output
    )

    audit_lines, audit_records = process_file(
        audit_file,
        parse_audit_line,
        output
    )

    syslog_lines, syslog_records = process_file(
        syslog_file,
        parse_syslog_line,
        output
    )

    student_records = append_student_telemetry(
        student_file,
        output
    )


# ============================================================
# SUMMARY
# ============================================================

print(
    f"parsing auth.log      ... "
    f"{auth_lines} lines  -> {auth_records} records"
)

print(
    f"parsing audit.log     ... "
    f"{audit_lines} lines  -> {audit_records} records"
)

print(
    f"parsing syslog        ... "
    f"{syslog_lines} lines  -> {syslog_records} records"
)

print(
    f"appending student telemetry ... "
    f"{student_records} records"
)

print("linux_events.json: written")

PYTHON_EOF
