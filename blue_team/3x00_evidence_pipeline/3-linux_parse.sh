#!/bin/bash
set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
LINUX_DIR="$EVIDENCE_PACK/linux"
STUDENT_FILE="$EVIDENCE_PACK/student_telemetry/linux_events.json"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/linux_events.json}"

python3 - "$LINUX_DIR" "$STUDENT_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import os
import re
import sys

linux_dir = sys.argv[1]
student_file = sys.argv[2]
output_file = sys.argv[3]


# ------------------------------------------------------------
# Parse normal syslog-style lines:
# Mar 18 10:22:11 host sshd[1234]: message
# ------------------------------------------------------------

SYSLOG_RE = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'([^\s:\[]+)'
    r'(?:\[(\d+)\])?:\s*(.*)$'
)


def extract_key_values(text):
    fields = {}

    for match in re.finditer(
        r'([A-Za-z0-9_.-]+)=("[^"]*"|\S+)',
        text
    ):
        key = match.group(1)
        value = match.group(2).strip('"')
        fields[key] = value

    return fields


def extract_user(message):
    patterns = [
        r'for invalid user\s+([A-Za-z0-9_.-]+)',
        r'for user\s+([A-Za-z0-9_.-]+)',
        r'for\s+([A-Za-z0-9_.-]+)',
        r'user[ =]([A-Za-z0-9_.-]+)'
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)

        if match:
            return match.group(1)

    return None


def parse_syslog_line(line):
    match = SYSLOG_RE.match(line)

    if not match:
        return {
            "timestamp_raw": None,
            "hostname": None,
            "program": None,
            "pid": None,
            "user": None,
            "raw_message": line,
            "parsed_fields": {},
            "source_origin": "evidence_pack"
        }

    timestamp, hostname, program, pid, message = match.groups()

    return {
        "timestamp_raw": timestamp,
        "hostname": hostname,
        "program": program,
        "pid": int(pid) if pid else None,
        "user": extract_user(message),
        "raw_message": line,
        "parsed_fields": extract_key_values(message),
        "source_origin": "evidence_pack"
    }


# ------------------------------------------------------------
# Parse auditd line.
#
# Example:
# type=SYSCALL msg=audit(1773792000.123:456): ...
#
# Task explicitly allows one output record per audit line.
# audit_group_id preserves the relationship between lines.
# ------------------------------------------------------------

def parse_audit_line(line):
    fields = extract_key_values(line)

    audit_type_match = re.search(r'\btype=([A-Za-z0-9_]+)', line)

    audit_match = re.search(
        r'msg=audit\(([\d.]+):(\d+)\)',
        line
    )

    timestamp_raw = None
    audit_group_id = None

    if audit_match:
        timestamp_raw = audit_match.group(1)
        audit_group_id = audit_match.group(2)
        fields["audit_group_id"] = audit_group_id

    audit_type = (
        audit_type_match.group(1)
        if audit_type_match
        else None
    )

    hostname = fields.get("node")

    pid = fields.get("pid")

    if pid is not None:
        try:
            pid = int(pid)
        except ValueError:
            pass

    user = (
        fields.get("acct")
        or fields.get("user")
        or fields.get("auid")
        or fields.get("uid")
    )

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


# ------------------------------------------------------------
# Process a Linux text file.
# ------------------------------------------------------------

def process_text_file(filepath, parser, output):
    lines = 0
    records = 0

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for raw_line in f:
            lines += 1

            line = raw_line.rstrip("\n")

            if not line:
                continue

            record = parser(line)

            output.write(
                json.dumps(
                    record,
                    separators=(",", ":")
                )
                + "\n"
            )

            records += 1

    return lines, records


# ------------------------------------------------------------
# Student telemetry may be JSON array, object, or NDJSON.
# ------------------------------------------------------------

def parse_json_file(filepath):
    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:
        content = f.read()

    try:
        data = json.loads(content)

        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    records = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)

            if isinstance(record, dict):
                records.append(record)

        except json.JSONDecodeError:
            sys.stderr.write(
                f"WARNING: malformed telemetry line skipped in {filepath}\n"
            )

    return records


# ------------------------------------------------------------
# Preserve student fields and only add compatibility fields.
# ------------------------------------------------------------

def append_student_telemetry(filepath, output):
    if not os.path.isfile(filepath):
        return 0

    records = parse_json_file(filepath)

    for record in records:
        record["source_origin"] = "student_telemetry"

        if "timestamp_raw" not in record:
            record["timestamp_raw"] = record.get("timestamp")

        if "hostname" not in record:
            record["hostname"] = None

        # Linux intermediate requires program OR audit_type.
        if (
            "program" not in record
            and "audit_type" not in record
        ):
            record["program"] = record.get("source_type")

        if "pid" not in record:
            record["pid"] = None

        if "user" not in record:
            record["user"] = None

        if "raw_message" not in record:
            record["raw_message"] = json.dumps(
                record,
                separators=(",", ":")
            )

        if "parsed_fields" not in record:
            record["parsed_fields"] = {}

        output.write(
            json.dumps(
                record,
                separators=(",", ":")
            )
            + "\n"
        )

    return len(records)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

auth_file = os.path.join(linux_dir, "auth.log")
audit_file = os.path.join(linux_dir, "audit.log")
syslog_file = os.path.join(linux_dir, "syslog")

for filepath in (auth_file, audit_file, syslog_file):
    if not os.path.isfile(filepath):
        sys.stderr.write(f"ERROR: missing file: {filepath}\n")
        sys.exit(1)


with open(
    output_file,
    "w",
    encoding="utf-8"
) as output:

    auth_lines, auth_records = process_text_file(
        auth_file,
        parse_syslog_line,
        output
    )

    audit_lines, audit_records = process_text_file(
        audit_file,
        parse_audit_line,
        output
    )

    syslog_lines, syslog_records = process_text_file(
        syslog_file,
        parse_syslog_line,
        output
    )

    student_records = append_student_telemetry(
        student_file,
        output
    )


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

PYTHON
