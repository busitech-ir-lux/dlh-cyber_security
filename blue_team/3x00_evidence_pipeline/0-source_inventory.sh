#!/bin/bash

# ============================================================
# TASK 0 - EVIDENCE PACK INVENTORY
#
# Purpose:
# Inventory every evidence source file under:
#
#   windows/
#   linux/
#   network/
#
# The script creates:
#
#   source_inventory.json
#
# For every source file it records:
#
#   - relative path
#   - source type
#   - size in bytes
#   - SHA256 hash
#   - line count or record count
#   - first event time
#   - last event time
#
# Python is used for parsing because it handles JSON arrays,
# NDJSON, CSV and timestamp conversion more clearly than a
# large Bash-only solution.
# ============================================================

set -euo pipefail


# ============================================================
# CONFIGURATION
#
# Usage:
#
#   ./0-source_inventory.sh
#
# Or with another evidence pack:
#
#   ./0-source_inventory.sh ~/evidence_pack_secondary
#
# The output directory can also be controlled through WORKDIR.
# ============================================================

WORKDIR="${WORKDIR:-$(pwd)}"

EVIDENCE_PACK="${1:-${EVIDENCE_PACK:-$HOME/evidence_pack_primary}}"

OUTPUT_FILE="${2:-${WORKDIR}/source_inventory.json}"


# ============================================================
# INPUT VALIDATION
# ============================================================

if [[ ! -d "$EVIDENCE_PACK" ]]; then
    echo "ERROR: Evidence pack not found: $EVIDENCE_PACK" >&2
    exit 1
fi


# ============================================================
# RUN THE INVENTORY
#
# Bash passes the evidence-pack path and output path to Python.
#
# All parsing and manifest creation happens inside this single
# Python process.
# ============================================================

python3 - "$EVIDENCE_PACK" "$OUTPUT_FILE" <<'PYTHON_EOF'

import csv
import hashlib
import json
import os
import re
import sys

from datetime import datetime, timezone


# ============================================================
# COMMAND-LINE VALUES
# ============================================================

evidence_pack = sys.argv[1]
output_file = sys.argv[2]


# ============================================================
# REQUIRED SOURCE DIRECTORIES
#
# Task 0 only inventories these three source categories.
#
# context/ and student_telemetry/ are not included here.
# ============================================================

SOURCE_DIRS = [
    "windows",
    "linux",
    "network",
]


# ============================================================
# COMMON TIMESTAMP FIELD NAMES
#
# Different security products use different timestamp names.
#
# Examples in this project include:
#
#   timestamp_raw
#   timestamp
#   time
# ============================================================

TIMESTAMP_KEYS = [
    "timestamp_raw",
    "timestamp",
    "@timestamp",
    "event_time",
    "eventtime",
    "systemtime",
    "timecreated",
    "utc_time",
    "utctime",
    "datetime",
    "time",
]


# ============================================================
# CALCULATE SHA256
#
# Read the file in blocks instead of loading the whole file
# into memory only for hashing.
# ============================================================

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as handle:

        while True:
            block = handle.read(65536)

            if not block:
                break

            sha256.update(block)

    return sha256.hexdigest()


# ============================================================
# NORMALIZE TIMESTAMP
#
# Convert different timestamp formats into:
#
#   YYYY-MM-DDTHH:MM:SSZ
#
# Supported examples include:
#
#   1773792002
#   2026-03-18T00:00:13Z
#   2026-03-18T00:00:31.026524+0000
#   03/20/2026 11:16:56 PM
#   Mar 18 00:00:38
#
# If a value cannot be understood, return None.
# ============================================================

def normalize_timestamp(value, default_year=None):

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None


    # --------------------------------------------------------
    # UNIX EPOCH
    #
    # Example:
    #   1773792002
    #
    # Millisecond epochs are also supported.
    # --------------------------------------------------------

    if re.fullmatch(r"\d+(?:\.\d+)?", value):

        try:
            epoch = float(value)

            # Large epoch values are probably milliseconds.
            if epoch > 100000000000:
                epoch = epoch / 1000

            dt = datetime.fromtimestamp(epoch, timezone.utc)

            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        except (ValueError, OverflowError):
            return None


    # --------------------------------------------------------
    # ISO 8601
    #
    # Convert trailing Z into an explicit UTC offset so
    # datetime.fromisoformat() can parse it consistently.
    # --------------------------------------------------------

    iso_value = value

    if iso_value.endswith("Z"):
        iso_value = iso_value[:-1] + "+00:00"

    # Convert timezone such as +0000 into +00:00.
    iso_value = re.sub(
        r"([+-]\d{2})(\d{2})$",
        r"\1:\2",
        iso_value,
    )

    try:
        dt = datetime.fromisoformat(iso_value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        dt = dt.astimezone(timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        pass


    # --------------------------------------------------------
    # US DATE FORMAT
    #
    # Example:
    #   03/20/2026 11:16:56 PM
    # --------------------------------------------------------

    try:
        dt = datetime.strptime(
            value,
            "%m/%d/%Y %I:%M:%S %p",
        )

        dt = dt.replace(tzinfo=timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    except ValueError:
        pass


    # --------------------------------------------------------
    # TRADITIONAL LINUX SYSLOG
    #
    # Example:
    #   Mar 18 00:00:38
    #
    # Traditional syslog does not include a year, so use the
    # year provided by the caller.
    # --------------------------------------------------------

    if default_year is not None:

        try:
            dt = datetime.strptime(
                f"{default_year} {value}",
                "%Y %b %d %H:%M:%S",
            )

            dt = dt.replace(tzinfo=timezone.utc)

            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        except ValueError:
            pass


    return None


# ============================================================
# FIND A TIMESTAMP INSIDE A JSON OBJECT
#
# First check common fields at the top level.
#
# If none exist, search nested dictionaries.
#
# We return the first useful timestamp field found.
# ============================================================

def find_json_timestamp(record):

    if not isinstance(record, dict):
        return None


    # --------------------------------------------------------
    # Check common top-level fields first.
    # --------------------------------------------------------

    for key in TIMESTAMP_KEYS:

        if key in record:
            return record[key]


    # --------------------------------------------------------
    # Check keys case-insensitively.
    # --------------------------------------------------------

    for key, value in record.items():

        if str(key).lower() in TIMESTAMP_KEYS:
            return value


    # --------------------------------------------------------
    # Search nested dictionaries if needed.
    # --------------------------------------------------------

    for value in record.values():

        if isinstance(value, dict):

            result = find_json_timestamp(value)

            if result is not None:
                return result


    return None


# ============================================================
# PARSE JSON OR NDJSON
#
# The evidence may be:
#
# 1. JSON array
#
#    [
#      {...},
#      {...}
#    ]
#
# 2. Single JSON object
#
#    {...}
#
# 3. NDJSON
#
#    {...}
#    {...}
#
# First try to parse the complete file.
#
# If that fails, parse it line by line as NDJSON.
# ============================================================

def parse_json_file(filepath):

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        content = handle.read()


    # --------------------------------------------------------
    # Try normal JSON first.
    # --------------------------------------------------------

    try:
        data = json.loads(content)

        if isinstance(data, list):
            return [
                record
                for record in data
                if isinstance(record, dict)
            ]

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass


    # --------------------------------------------------------
    # Fall back to NDJSON.
    # --------------------------------------------------------

    records = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):

        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)

            if isinstance(record, dict):
                records.append(record)

        except json.JSONDecodeError:

            sys.stderr.write(
                f"WARNING: malformed JSON line skipped: "
                f"{filepath}:{line_number}\n"
            )


    return records


# ============================================================
# GET FIRST AND LAST JSON EVENT TIME
#
# Extract every recognizable timestamp, normalize it, then
# report the earliest and latest event times.
#
# This also works when records are not perfectly ordered.
# ============================================================

def json_time_range(records):

    timestamps = []

    for record in records:

        raw_timestamp = find_json_timestamp(record)

        timestamp = normalize_timestamp(raw_timestamp)

        if timestamp is not None:
            timestamps.append(timestamp)


    if not timestamps:
        return None, None


    return min(timestamps), max(timestamps)


# ============================================================
# PARSE LINUX TEXT LOG
#
# Linux files use line_count rather than record_count.
#
# Supported timestamps include:
#
#   audit(1773792000.123:123)
#   2026-03-18T00:00:20Z
#   Mar 18 00:00:38
# ============================================================

def parse_linux_file(filepath):

    line_count = 0
    timestamps = []


    # --------------------------------------------------------
    # Traditional syslog does not contain a year.
    #
    # Use the file modification year as a reasonable
    # best-effort value.
    # --------------------------------------------------------

    file_year = datetime.fromtimestamp(
        os.path.getmtime(filepath),
        timezone.utc,
    ).year


    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line in handle:

            line_count += 1

            line = line.rstrip("\n")


            # ------------------------------------------------
            # Linux audit timestamp.
            # ------------------------------------------------

            audit_match = re.search(
                r"audit\((\d+(?:\.\d+)?)",
                line,
            )

            if audit_match:

                timestamp = normalize_timestamp(
                    audit_match.group(1)
                )

                if timestamp:
                    timestamps.append(timestamp)

                continue


            # ------------------------------------------------
            # ISO timestamp at the beginning of a line.
            # ------------------------------------------------

            iso_match = re.match(
                r"^(\d{4}-\d{2}-\d{2}T\S+)",
                line,
            )

            if iso_match:

                timestamp = normalize_timestamp(
                    iso_match.group(1)
                )

                if timestamp:
                    timestamps.append(timestamp)

                continue


            # ------------------------------------------------
            # Traditional syslog:
            #
            #   Mar 18 00:00:38
            # ------------------------------------------------

            if len(line) >= 15:

                possible_time = line[:15]

                timestamp = normalize_timestamp(
                    possible_time,
                    default_year=file_year,
                )

                if timestamp:
                    timestamps.append(timestamp)


    if timestamps:

        first_time = min(timestamps)
        last_time = max(timestamps)

    else:

        first_time = None
        last_time = None


    return line_count, first_time, last_time


# ============================================================
# FIND TIMESTAMP COLUMN IN CSV
#
# First look for common timestamp column names.
#
# If no obvious header exists, inspect the first data row for
# something that looks like a timestamp.
# ============================================================

def find_csv_time_column(header, rows):

    # --------------------------------------------------------
    # Search by header name.
    # --------------------------------------------------------

    for index, name in enumerate(header):

        clean_name = name.strip().strip('"').lower()

        if clean_name in TIMESTAMP_KEYS:
            return index


    # --------------------------------------------------------
    # Best-effort fallback:
    # inspect values in the first row.
    # --------------------------------------------------------

    if rows:

        for index, value in enumerate(rows[0]):

            if normalize_timestamp(value) is not None:
                return index


    return None


# ============================================================
# PARSE CSV FILE
#
# The first row is treated as the CSV header.
#
# record_count contains data rows only.
# ============================================================

def parse_csv_file(filepath):

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as handle:

        reader = csv.reader(handle)

        rows = list(reader)


    if not rows:
        return 0, None, None


    header = rows[0]
    data_rows = rows[1:]

    record_count = len(data_rows)

    column = find_csv_time_column(
        header,
        data_rows,
    )


    timestamps = []


    # --------------------------------------------------------
    # Extract timestamps from the selected column.
    # --------------------------------------------------------

    if column is not None:

        for row in data_rows:

            if column >= len(row):
                continue

            timestamp = normalize_timestamp(
                row[column]
            )

            if timestamp:
                timestamps.append(timestamp)


    if timestamps:

        first_time = min(timestamps)
        last_time = max(timestamps)

    else:

        first_time = None
        last_time = None


    return record_count, first_time, last_time


# ============================================================
# DETERMINE SOURCE TYPE
#
# Source types allowed by the task:
#
#   windows_json
#   linux_text
#   network_csv
#   network_json
#
# Every file in the three source directories is inventoried.
# ============================================================

def get_source_type(category, filepath):

    if category == "windows":
        return "windows_json"

    if category == "linux":
        return "linux_text"

    if category == "network":

        if filepath.lower().endswith(".csv"):
            return "network_csv"

        return "network_json"

    raise ValueError(f"Unsupported category: {category}")


# ============================================================
# COLLECT ALL SOURCE FILES
#
# Walk every file recursively inside:
#
#   windows/
#   linux/
#   network/
#
# Sorting makes the output deterministic.
# ============================================================

source_files = []


for category in SOURCE_DIRS:

    directory = os.path.join(
        evidence_pack,
        category,
    )


    if not os.path.isdir(directory):

        sys.stderr.write(
            f"WARNING: source directory missing: "
            f"{directory}\n"
        )

        continue


    for root, _, filenames in os.walk(directory):

        for filename in filenames:

            filepath = os.path.join(
                root,
                filename,
            )

            source_files.append(
                (
                    category,
                    filepath,
                )
            )


source_files.sort(
    key=lambda item: item[1]
)


# ============================================================
# BUILD MANIFEST
# ============================================================

manifest = []


# Summary values for stdout.
summary = {
    "windows": {
        "files": 0,
        "bytes": 0,
    },
    "linux": {
        "files": 0,
        "bytes": 0,
    },
    "network": {
        "files": 0,
        "bytes": 0,
    },
}


for category, filepath in source_files:

    relative_path = os.path.relpath(
        filepath,
        evidence_pack,
    )

    size_bytes = os.path.getsize(filepath)

    source_type = get_source_type(
        category,
        filepath,
    )


    # --------------------------------------------------------
    # Common manifest fields.
    #
    # line_count and record_count both exist so the manifest
    # structure stays consistent.
    #
    # Only the relevant field receives a numeric value.
    # --------------------------------------------------------

    entry = {
        "path": relative_path,
        "source_type": source_type,
        "size_bytes": size_bytes,
        "sha256": calculate_sha256(filepath),
        "first_event_time": None,
        "last_event_time": None,
    }


    # --------------------------------------------------------
    # WINDOWS JSON / NDJSON
    # --------------------------------------------------------

    if source_type == "windows_json":

        records = parse_json_file(filepath)

        first_time, last_time = json_time_range(
            records
        )

        entry["record_count"] = len(records)

        entry["first_event_time"] = first_time
        entry["last_event_time"] = last_time


    # --------------------------------------------------------
    # LINUX TEXT
    # --------------------------------------------------------

    elif source_type == "linux_text":

        (
            line_count,
            first_time,
            last_time,
        ) = parse_linux_file(filepath)

        entry["line_count"] = line_count

        entry["first_event_time"] = first_time
        entry["last_event_time"] = last_time


    # --------------------------------------------------------
    # NETWORK CSV
    # --------------------------------------------------------

    elif source_type == "network_csv":

        (
            record_count,
            first_time,
            last_time,
        ) = parse_csv_file(filepath)

        entry["record_count"] = record_count

        entry["first_event_time"] = first_time
        entry["last_event_time"] = last_time


    # --------------------------------------------------------
    # NETWORK JSON / NDJSON
    # --------------------------------------------------------

    elif source_type == "network_json":

        records = parse_json_file(filepath)

        first_time, last_time = json_time_range(
            records
        )

        entry["record_count"] = len(records)

        entry["first_event_time"] = first_time
        entry["last_event_time"] = last_time


    manifest.append(entry)


    # --------------------------------------------------------
    # Update human-readable summary values.
    # --------------------------------------------------------

    summary[category]["files"] += 1
    summary[category]["bytes"] += size_bytes


# ============================================================
# WRITE JSON MANIFEST
#
# indent=2 keeps the output readable.
#
# sort_keys=False preserves the field order above.
# ============================================================

output_dir = os.path.dirname(output_file) or "."

os.makedirs(
    output_dir,
    exist_ok=True,
)


with open(
    output_file,
    "w",
    encoding="utf-8",
) as handle:

    json.dump(
        manifest,
        handle,
        indent=2,
    )

    # Project requirement:
    # every file should end with a newline.
    handle.write("\n")


# ============================================================
# PRINT HUMAN-READABLE SUMMARY
# ============================================================

total_files = 0
total_bytes = 0


for category in SOURCE_DIRS:

    file_count = summary[category]["files"]

    byte_count = summary[category]["bytes"]

    size_mb = byte_count / (1024 * 1024)

    total_files += file_count
    total_bytes += byte_count


    print(
        f"{category:<8}: "
        f"{file_count} files  |  "
        f"{size_mb:6.1f} MB"
    )


total_mb = total_bytes / (1024 * 1024)


print(
    f"{'total':<8}: "
    f"{total_files} files  |  "
    f"{total_mb:6.1f} MB"
)

print(
    f"manifest written to "
    f"{os.path.basename(output_file)}"
)

PYTHON_EOF
