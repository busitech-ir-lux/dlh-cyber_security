#!/bin/bash

# ============================================================
# TASK 5 - NORMALIZATION
#
# Reads:
#   windows_events.json
#   linux_events.json
#   event_schema.json
#
# Writes:
#   normalized_events.json
#   quarantine.json
#
# Records that cannot produce required fields or a valid
# timestamp are sent to quarantine.
# ============================================================

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

WINDOWS_FILE="$WORKDIR/windows_events.json"
LINUX_FILE="$WORKDIR/linux_events.json"
SCHEMA_FILE="$WORKDIR/event_schema.json"

NORMALIZED_FILE="$WORKDIR/normalized_events.json"
QUARANTINE_FILE="$WORKDIR/quarantine.json"


# ============================================================
# CHECK REQUIRED INPUTS
# ============================================================

for file in "$WINDOWS_FILE" "$LINUX_FILE" "$SCHEMA_FILE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file: $file" >&2
        exit 1
    fi
done


# ============================================================
# NORMALIZE WITH PYTHON
# ============================================================

python3 - \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$SCHEMA_FILE" \
    "$NORMALIZED_FILE" \
    "$QUARANTINE_FILE" <<'PYTHON_EOF'

import json
import os
import sys
from datetime import datetime, timezone


windows_file = sys.argv[1]
linux_file = sys.argv[2]
schema_file = sys.argv[3]
normalized_file = sys.argv[4]
quarantine_file = sys.argv[5]


# ============================================================
# LOAD THE UNIFIED SCHEMA
#
# Every field defined in event_schema.json will appear in
# every normalized record.
# ============================================================

with open(schema_file, "r", encoding="utf-8") as f:
    schema = json.load(f)

schema_fields = schema["fields"]

field_names = [
    field["name"]
    for field in schema_fields
]

required_fields = [
    field["name"]
    for field in schema_fields
    if field["required"]
]


# ============================================================
# TIMESTAMP NORMALIZATION
#
# Converts timestamps into:
#
#   2026-03-18T00:00:13Z
#
# Supported inputs:
#
#   ISO 8601
#   Unix epoch
#   Linux syslog timestamps
#
# Traditional syslog has no year, so the current UTC year is
# used unless NORMALIZE_YEAR is provided.
# ============================================================

DEFAULT_YEAR = int(
    os.environ.get(
        "NORMALIZE_YEAR",
        datetime.now(timezone.utc).year
    )
)


def normalize_timestamp(value):

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None


    # --------------------------------------------------------
    # Unix epoch
    # --------------------------------------------------------

    try:
        if value.replace(".", "", 1).isdigit():

            timestamp = float(value)

            dt = datetime.fromtimestamp(
                timestamp,
                timezone.utc
            )

            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except (ValueError, OverflowError):
        pass


    # --------------------------------------------------------
    # ISO 8601
    # --------------------------------------------------------

    try:

        iso_value = value

        if iso_value.endswith("Z"):
            iso_value = iso_value[:-1] + "+00:00"

        dt = datetime.fromisoformat(iso_value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        dt = dt.astimezone(timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        pass


    # --------------------------------------------------------
    # Linux syslog
    #
    # Example:
    #   Mar 18 00:00:38
    # --------------------------------------------------------

    try:

        dt = datetime.strptime(
            f"{DEFAULT_YEAR} {value}",
            "%Y %b %d %H:%M:%S"
        )

        dt = dt.replace(tzinfo=timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        return None


# ============================================================
# WINDOWS EVENT CATEGORY
#
# Keep an existing category when present.
#
# Otherwise use a small deterministic mapping for common
# Windows events used in this project.
# ============================================================

def windows_category(record):

    if record.get("event_category"):
        return record["event_category"]

    event_id = str(record.get("event_id", ""))
    channel = str(record.get("channel", "")).lower()
    provider = str(record.get("provider", "")).lower()

    if event_id in {"4624", "4625", "4648"}:
        return "authentication"

    if event_id in {"4720", "4726", "4732"}:
        return "account"

    if event_id == "4688":
        return "process"

    if "sysmon" in provider:

        if event_id == "1":
            return "process"

        if event_id == "3":
            return "network"

        return "sysmon"

    if "powershell" in channel or "powershell" in provider:
        return "powershell"

    return "windows_event"


# ============================================================
# LINUX EVENT CATEGORY
# ============================================================

def linux_category(record):

    if record.get("event_category"):
        return record["event_category"]

    if record.get("audit_type"):
        return "audit"

    program = str(
        record.get("program") or ""
    ).lower()

    if program in {"sshd", "sudo", "su"}:
        return "authentication"

    return "linux_event"


# ============================================================
# BUILD NORMALIZED WINDOWS EVENT
# ============================================================

def normalize_windows(record):

    event_data = record.get("event_data") or {}

    values = {
        "timestamp": normalize_timestamp(
            record.get("timestamp_raw")
        ),

        "hostname": record.get("hostname"),

        "source_type": "windows_json",

        "source_origin": record.get(
            "source_origin"
        ),

        "event_category": windows_category(
            record
        ),

        "event_id": record.get("event_id"),

        "severity": record.get("severity"),

        "user": (
            record.get("user")
            or event_data.get("TargetUserName")
            or event_data.get("User")
        ),

        "process_name": (
            record.get("process_name")
            or event_data.get("Image")
            or event_data.get("NewProcessName")
        ),

        "process_id": (
            record.get("process_id")
            or event_data.get("ProcessId")
            or event_data.get("NewProcessId")
        ),

        "src_ip": (
            record.get("src_ip")
            or event_data.get("IpAddress")
            or event_data.get("SourceIp")
        ),

        "src_port": (
            record.get("src_port")
            or event_data.get("IpPort")
            or event_data.get("SourcePort")
        ),

        "dst_ip": (
            record.get("dst_ip")
            or event_data.get("DestinationIp")
        ),

        "dst_port": (
            record.get("dst_port")
            or event_data.get("DestinationPort")
        ),

        "protocol": (
            record.get("protocol")
            or event_data.get("Protocol")
        ),

        "raw_message": record.get(
            "raw_message"
        ),

        "source_fields": event_data
    }

    return build_schema_record(values)


# ============================================================
# BUILD NORMALIZED LINUX EVENT
# ============================================================

def normalize_linux(record):

    parsed = record.get("parsed_fields") or {}

    values = {
        "timestamp": normalize_timestamp(
            record.get("timestamp_raw")
        ),

        "hostname": record.get("hostname"),

        "source_type": "linux_text",

        "source_origin": record.get(
            "source_origin"
        ),

        "event_category": linux_category(
            record
        ),

        "event_id": record.get(
            "audit_type"
        ),

        "severity": record.get("severity"),

        "user": record.get("user"),

        "process_name": record.get(
            "program"
        ),

        "process_id": record.get("pid"),

        "src_ip": (
            parsed.get("src_ip")
            or parsed.get("src")
        ),

        "src_port": (
            parsed.get("src_port")
            or parsed.get("sport")
        ),

        "dst_ip": (
            parsed.get("dst_ip")
            or parsed.get("dst")
        ),

        "dst_port": (
            parsed.get("dst_port")
            or parsed.get("dport")
        ),

        "protocol": (
            parsed.get("proto")
            or parsed.get("protocol")
        ),

        "raw_message": record.get(
            "raw_message"
        ),

        "source_fields": parsed
    }

    return build_schema_record(values)


# ============================================================
# APPLY THE EVENT SCHEMA
#
# Start every field as null.
#
# Then fill values we were able to derive.
#
# This guarantees that optional missing fields are explicitly
# null instead of absent.
# ============================================================

def build_schema_record(values):

    normalized = {
        name: None
        for name in field_names
    }

    for key, value in values.items():

        if key in normalized:
            normalized[key] = value

    return normalized


# ============================================================
# REQUIRED FIELD CHECK
# ============================================================

def quarantine_reason(record):

    if record.get("timestamp") is None:
        return "unparseable timestamp"

    for field in required_fields:

        if record.get(field) is None:
            return f"missing required field: {field}"

    return None


# ============================================================
# PROCESS ONE NDJSON SOURCE
# ============================================================

def process_file(
    filepath,
    source_type,
    normalizer,
    normalized_output,
    quarantine_output
):

    normalized_count = 0
    quarantine_count = 0

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1
        ):

            line = line.strip()

            if not line:
                continue


            # ------------------------------------------------
            # Parse the NDJSON line.
            # ------------------------------------------------

            try:
                original = json.loads(line)

            except json.JSONDecodeError:

                bad = {
                    "source_type": source_type,
                    "raw_message": line,
                    "quarantine_reason":
                        f"invalid JSON at line {line_number}"
                }

                quarantine_output.write(
                    json.dumps(
                        bad,
                        separators=(",", ":")
                    ) + "\n"
                )

                quarantine_count += 1
                continue


            # ------------------------------------------------
            # Normalize the record.
            # ------------------------------------------------

            normalized = normalizer(original)

            reason = quarantine_reason(
                normalized
            )


            # ------------------------------------------------
            # Quarantine failed records.
            # ------------------------------------------------

            if reason:

                bad = dict(original)

                bad["quarantine_reason"] = reason

                quarantine_output.write(
                    json.dumps(
                        bad,
                        separators=(",", ":")
                    ) + "\n"
                )

                quarantine_count += 1


            # ------------------------------------------------
            # Write successful normalized records.
            # ------------------------------------------------

            else:

                normalized_output.write(
                    json.dumps(
                        normalized,
                        separators=(",", ":")
                    ) + "\n"
                )

                normalized_count += 1


    return normalized_count, quarantine_count


# ============================================================
# MAIN
#
# Opening with "w" makes the script idempotent.
# ============================================================

with open(
    normalized_file,
    "w",
    encoding="utf-8"
) as normalized_output, open(
    quarantine_file,
    "w",
    encoding="utf-8"
) as quarantine_output:


    windows_normalized, windows_quarantined = process_file(
        windows_file,
        "windows_json",
        normalize_windows,
        normalized_output,
        quarantine_output
    )


    linux_normalized, linux_quarantined = process_file(
        linux_file,
        "linux_text",
        normalize_linux,
        normalized_output,
        quarantine_output
    )


# ============================================================
# SUMMARY
# ============================================================

total_normalized = (
    windows_normalized
    + linux_normalized
)

total_quarantined = (
    windows_quarantined
    + linux_quarantined
)


print(
    f"windows_json     : normalized "
    f"{windows_normalized:6d} "
    f"quarantined {windows_quarantined}"
)

print(
    f"linux_text       : normalized "
    f"{linux_normalized:6d} "
    f"quarantined {linux_quarantined}"
)

print(
    f"total            : normalized "
    f"{total_normalized:6d} "
    f"quarantined {total_quarantined}"
)

print("normalized_events.json written")
print("quarantine.json  written")

PYTHON_EOF
