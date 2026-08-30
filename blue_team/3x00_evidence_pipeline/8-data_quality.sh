#!/bin/bash

# ============================================================
# TASK 8 - DIRTY DATA HANDLING
#
# Input:
#   normalized_events.json
#
# Output:
#   cleaned_events.json
#   cleaning_log.json
# ============================================================

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

INPUT="$WORKDIR/normalized_events.json"
CLEANED="$WORKDIR/cleaned_events.json"
LOG="$WORKDIR/cleaning_log.json"

if [[ ! -f "$INPUT" ]]; then
    echo "ERROR: Missing file: $INPUT" >&2
    exit 1
fi


# ============================================================
# RUN DATA QUALITY PROCESSOR
# ============================================================

python3 - "$INPUT" "$CLEANED" "$LOG" <<'PYTHON_EOF'

import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone, timedelta


input_file = sys.argv[1]
cleaned_file = sys.argv[2]
log_file = sys.argv[3]


# ============================================================
# COUNTERS
# ============================================================

stats = {
    "malformed_detected": 0,
    "malformed_repaired": 0,
    "malformed_dropped": 0,
    "duplicates": 0,
    "hostname_case": 0,
    "encoding_detected": 0,
    "encoding_repaired": 0,
    "wrong_tz": 0,
}

corrections = []
unrepairable = []


# ============================================================
# RECORD ID
#
# Produce a deterministic ID from the original record.
# ============================================================

def make_record_id(record):
    data = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        data.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


# ============================================================
# WRITE CLEANING LOG ENTRY
# ============================================================

def log_change(
    defect_type,
    original,
    corrected,
    record_id,
    reason
):
    corrections.append({
        "defect_type": defect_type,
        "original_value": original,
        "corrected_value": corrected,
        "record_id": record_id,
        "reason": reason
    })


# ============================================================
# TIMESTAMP PARSER
#
# Normal expected form:
#
#   2026-03-18T12:30:00Z
#
# Fallback formats are attempted for malformed timestamps.
# ============================================================

def parse_timestamp(value):

    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None


    # --------------------------------------------------------
    # ISO 8601
    # --------------------------------------------------------

    try:
        iso = text

        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"

        dt = datetime.fromisoformat(iso)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except ValueError:
        pass


    # --------------------------------------------------------
    # Common fallback formats
    # --------------------------------------------------------

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]

    for fmt in formats:

        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)

        except ValueError:
            continue


    # --------------------------------------------------------
    # Unix epoch fallback
    # --------------------------------------------------------

    try:
        if text.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(
                float(text),
                timezone.utc
            )

    except (ValueError, OverflowError):
        pass

    return None


def timestamp_to_string(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================
# ENCODING REPAIR
#
# Common mojibake examples:
#
#   cafÃ©  -> café
#   FranÃ§ois -> François
#
# Attempt latin-1 -> UTF-8 repair.
# ============================================================

def repair_encoding(value):

    if not isinstance(value, str):
        return value, False

    suspicious = (
        "\ufffd" in value
        or "Ã" in value
        or "Â" in value
        or "â€" in value
    )

    if not suspicious:
        return value, False

    try:
        repaired = value.encode(
            "latin-1"
        ).decode(
            "utf-8"
        )

        return repaired, repaired != value

    except (UnicodeEncodeError, UnicodeDecodeError):
        return value, False


# ============================================================
# READ INPUT
# ============================================================

records = []

with open(
    input_file,
    "r",
    encoding="utf-8",
    errors="replace"
) as f:

    for line_number, line in enumerate(f, start=1):

        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)

        except json.JSONDecodeError:
            continue

        if not isinstance(record, dict):
            continue

        records.append(record)


# ============================================================
# STEP 1 - REPAIR TIMESTAMPS
# STEP 2 - HOSTNAME CASE
# STEP 3 - ENCODING
# ============================================================

repaired_records = []

for record in records:

    record_id = make_record_id(record)


    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    original_timestamp = record.get("timestamp")

    parsed_time = parse_timestamp(original_timestamp)

    if parsed_time is None:

        stats["malformed_detected"] += 1
        stats["malformed_dropped"] += 1

        unrepairable.append({
            "defect_type": "malformed_timestamp",
            "original_value": original_timestamp,
            "corrected_value": None,
            "record_id": record_id,
            "reason": "Timestamp could not be parsed using fallback formats"
        })

        continue


    corrected_timestamp = timestamp_to_string(parsed_time)

    if corrected_timestamp != original_timestamp:

        stats["malformed_detected"] += 1
        stats["malformed_repaired"] += 1

        log_change(
            "malformed_timestamp",
            original_timestamp,
            corrected_timestamp,
            record_id,
            "Timestamp converted to ISO 8601 UTC"
        )

        record["timestamp"] = corrected_timestamp


    # --------------------------------------------------------
    # HOSTNAME CASE
    # --------------------------------------------------------

    hostname = record.get("hostname")

    if isinstance(hostname, str):

        corrected_hostname = hostname.lower()

        if hostname != corrected_hostname:

            stats["hostname_case"] += 1

            log_change(
                "hostname_case",
                hostname,
                corrected_hostname,
                record_id,
                "Hostname normalized to lowercase"
            )

            record["hostname"] = corrected_hostname


    # --------------------------------------------------------
    # ENCODING
    # --------------------------------------------------------

    raw_message = record.get("raw_message")

    repaired_message, repaired = repair_encoding(
        raw_message
    )

    if (
        isinstance(raw_message, str)
        and (
            "\ufffd" in raw_message
            or "Ã" in raw_message
            or "Â" in raw_message
            or "â€" in raw_message
        )
    ):
        stats["encoding_detected"] += 1

    if repaired:

        stats["encoding_repaired"] += 1

        log_change(
            "encoding_error",
            raw_message,
            repaired_message,
            record_id,
            "Re-decoded suspected latin-1 mojibake as UTF-8"
        )

        record["raw_message"] = repaired_message


    repaired_records.append(record)


# ============================================================
# DETERMINE EXPECTED DATE RANGE
#
# Find the busiest normal date range automatically instead of
# hardcoding March 2026.
#
# Sparse outlier dates are ignored.
# ============================================================

date_counts = Counter()

for record in repaired_records:

    dt = parse_timestamp(record.get("timestamp"))

    if dt:
        date_counts[dt.date()] += 1


expected_start = None
expected_end = None

if date_counts:

    busiest_day_count = max(date_counts.values())

    # A normal evidence day should contain at least 1% of the
    # events seen on the busiest day.
    threshold = max(10, int(busiest_day_count * 0.01))

    normal_dates = [
        date
        for date, count in date_counts.items()
        if count >= threshold
    ]

    if normal_dates:

        first_date = min(normal_dates)
        last_date = max(normal_dates)

        expected_start = datetime.combine(
            first_date,
            datetime.min.time(),
            tzinfo=timezone.utc
        )

        expected_end = datetime.combine(
            last_date,
            datetime.max.time(),
            tzinfo=timezone.utc
        )


# ============================================================
# STEP 4 - TIMEZONE OUTLIERS
#
# Flag timestamps more than 12 hours outside the expected
# evidence range.
#
# We flag them but do NOT modify them.
# ============================================================

if expected_start and expected_end:

    lower_limit = expected_start - timedelta(hours=12)
    upper_limit = expected_end + timedelta(hours=12)

    for record in repaired_records:

        dt = parse_timestamp(record.get("timestamp"))

        if dt and (
            dt < lower_limit
            or dt > upper_limit
        ):

            stats["wrong_tz"] += 1

            record_id = make_record_id(record)

            log_change(
                "suspected_wrong_tz",
                record.get("timestamp"),
                record.get("timestamp"),
                record_id,
                "Timestamp falls more than 12 hours outside the expected evidence date range"
            )


# ============================================================
# STEP 5 - REMOVE DUPLICATES
#
# Duplicate key:
#
#   timestamp
#   hostname
#   source_type
#   raw_message
#
# Keep only the first occurrence.
# ============================================================

cleaned_records = []
seen = set()

for record in repaired_records:

    duplicate_key = (
        record.get("timestamp"),
        record.get("hostname"),
        record.get("source_type"),
        record.get("raw_message"),
    )

    if duplicate_key in seen:

        stats["duplicates"] += 1

        record_id = make_record_id(record)

        log_change(
            "duplicate",
            duplicate_key,
            None,
            record_id,
            "Duplicate event removed; first occurrence was retained"
        )

        continue

    seen.add(duplicate_key)
    cleaned_records.append(record)


# ============================================================
# WRITE CLEANED NDJSON
# ============================================================

with open(
    cleaned_file,
    "w",
    encoding="utf-8"
) as f:

    for record in cleaned_records:

        json.dump(
            record,
            f,
            separators=(",", ":"),
            ensure_ascii=False
        )

        f.write("\n")


# ============================================================
# WRITE CLEANING LOG
#
# The log contains:
#
#   corrections
#   unrepairable
# ============================================================

cleaning_log = {
    "corrections": corrections,
    "unrepairable": unrepairable
}

with open(
    log_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        cleaning_log,
        f,
        indent=2,
        ensure_ascii=False
    )

    f.write("\n")


# ============================================================
# SUMMARY
# ============================================================

print(
    "malformed timestamps   : "
    f"{stats['malformed_detected']} detected  "
    f"{stats['malformed_repaired']} repaired  "
    f"{stats['malformed_dropped']} dropped"
)

print(
    "duplicates             : "
    f"{stats['duplicates']} detected  "
    f"{stats['duplicates']} removed"
)

print(
    "hostname case          : "
    f"{stats['hostname_case']} normalized"
)

print(
    "encoding errors        : "
    f"{stats['encoding_detected']} detected  "
    f"{stats['encoding_repaired']} repaired"
)

print(
    "suspected wrong tz     : "
    f"{stats['wrong_tz']} flagged"
)

print("cleaned_events.json    written")
print("cleaning_log.json      written")

PYTHON_EOF
