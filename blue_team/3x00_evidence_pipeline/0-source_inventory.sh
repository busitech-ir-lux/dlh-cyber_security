#!/bin/bash
set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/source_inventory.json}"
EVIDENCE_YEAR="${EVIDENCE_YEAR:-2026}"

python3 - "$EVIDENCE_PACK" "$OUTPUT_FILE" "$EVIDENCE_YEAR" <<'PYTHON'
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone


root = sys.argv[1]
output_file = sys.argv[2]
evidence_year = int(sys.argv[3])

categories = ["windows", "linux", "network"]


# ------------------------------------------------------------
# SHA256
# ------------------------------------------------------------

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)

    return digest.hexdigest()


# ------------------------------------------------------------
# Timestamp conversion
# ------------------------------------------------------------

def iso_utc(dt):
    return dt.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_timestamp(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    # Unix epoch
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", value):
            return iso_utc(
                datetime.fromtimestamp(
                    float(value),
                    tz=timezone.utc
                )
            )
    except (ValueError, OverflowError):
        pass

    # ISO 8601
    try:
        text = value

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        # +0000 -> +00:00
        text = re.sub(
            r"([+-]\d{2})(\d{2})$",
            r"\1:\2",
            text
        )

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return iso_utc(dt)

    except ValueError:
        pass

    # PCAP timestamp
    try:
        dt = datetime.strptime(
            value,
            "%m/%d/%Y %I:%M:%S %p"
        )

        return iso_utc(
            dt.replace(tzinfo=timezone.utc)
        )

    except ValueError:
        pass

    # Linux syslog timestamp
    try:
        dt = datetime.strptime(
            f"{evidence_year} {value}",
            "%Y %b %d %H:%M:%S"
        )

        return iso_utc(
            dt.replace(tzinfo=timezone.utc)
        )

    except ValueError:
        return None


# ------------------------------------------------------------
# Read JSON array, single object, or NDJSON
# ------------------------------------------------------------

def read_json_records(path):
    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:
        content = f.read()

    try:
        data = json.loads(content)

        if isinstance(data, list):
            return data

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
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records


# ------------------------------------------------------------
# Windows JSON
# ------------------------------------------------------------

def inspect_windows(path):
    records = read_json_records(path)
    times = []

    for record in records:
        if not isinstance(record, dict):
            continue

        timestamp = parse_timestamp(
            record.get("timestamp_raw")
        )

        if timestamp:
            times.append(timestamp)

    return {
        "record_count": len(records),
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }


# ------------------------------------------------------------
# Linux text logs
# ------------------------------------------------------------

def inspect_linux(path):
    line_count = 0
    times = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

        for line in f:
            line_count += 1
            line = line.rstrip("\n")

            # audit.log
            audit_match = re.search(
                r'msg=audit\(([\d.]+):\d+\)',
                line
            )

            if audit_match:
                timestamp = parse_timestamp(
                    audit_match.group(1)
                )

                if timestamp:
                    times.append(timestamp)

                continue

            # auth.log / syslog
            syslog_match = re.match(
                r'^([A-Z][a-z]{2}\s+\d{1,2}\s+'
                r'\d{2}:\d{2}:\d{2})',
                line
            )

            if syslog_match:
                timestamp = parse_timestamp(
                    syslog_match.group(1)
                )

                if timestamp:
                    times.append(timestamp)

    return {
        "line_count": line_count,
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }


# ------------------------------------------------------------
# Firewall CSV
# ------------------------------------------------------------

def inspect_csv(path):
    record_count = 0
    times = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            record_count += 1

            timestamp = parse_timestamp(
                row.get("timestamp")
            )

            if timestamp:
                times.append(timestamp)

    return {
        "record_count": record_count,
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }


# ------------------------------------------------------------
# Network JSON
# ------------------------------------------------------------

def inspect_network_json(path):
    records = read_json_records(path)

    first_times = []
    last_times = []

    for record in records:
        if not isinstance(record, dict):
            continue

        # Suricata
        if "timestamp" in record:
            timestamp = parse_timestamp(
                record.get("timestamp")
            )

            if timestamp:
                first_times.append(timestamp)
                last_times.append(timestamp)

        # PCAP summary
        elif "start_time" in record:
            start = parse_timestamp(
                record.get("start_time")
            )

            end = parse_timestamp(
                record.get("end_time")
            )

            if start:
                first_times.append(start)

            if end:
                last_times.append(end)
            elif start:
                last_times.append(start)

    return {
        "record_count": len(records),
        "first_event_time": (
            min(first_times)
            if first_times else None
        ),
        "last_event_time": (
            max(last_times)
            if last_times else None
        )
    }


# ------------------------------------------------------------
# Build manifest
# ------------------------------------------------------------

manifest = []

summary = {
    "windows": {"files": 0, "bytes": 0},
    "linux": {"files": 0, "bytes": 0},
    "network": {"files": 0, "bytes": 0}
}


for category in categories:
    directory = os.path.join(root, category)

    if not os.path.isdir(directory):
        continue

    for current, _, filenames in os.walk(directory):

        for filename in sorted(filenames):
            path = os.path.join(current, filename)

            relative_path = os.path.relpath(
                path,
                root
            )

            size = os.path.getsize(path)

            if category == "windows":
                source_type = "windows_json"
                details = inspect_windows(path)

            elif category == "linux":
                source_type = "linux_text"
                details = inspect_linux(path)

            elif filename.lower().endswith(".csv"):
                source_type = "network_csv"
                details = inspect_csv(path)

            else:
                source_type = "network_json"
                details = inspect_network_json(path)

            entry = {
                "path": relative_path,
                "source_type": source_type,
                "size_bytes": size,
                "sha256": sha256_file(path)
            }

            # Add only line_count OR record_count.
            entry.update(details)

            manifest.append(entry)

            summary[category]["files"] += 1
            summary[category]["bytes"] += size


# Keep manifest order deterministic.
manifest.sort(key=lambda x: x["path"])


# ------------------------------------------------------------
# Write source_inventory.json
# ------------------------------------------------------------

with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        manifest,
        f,
        indent=2
    )

    f.write("\n")


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

total_files = 0
total_bytes = 0

for category in categories:
    files = summary[category]["files"]
    size = summary[category]["bytes"]

    total_files += files
    total_bytes += size

    print(
        f"{category:<8}: "
        f"{files} files  |  "
        f"{size / (1024 * 1024):5.1f} MB"
    )

print(
    f"{'total':<8}: "
    f"{total_files} files  |  "
    f"{total_bytes / (1024 * 1024):5.1f} MB"
)

print("manifest written to source_inventory.json")

PYTHON
