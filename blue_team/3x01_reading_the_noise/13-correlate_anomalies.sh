#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 13 - CROSS-SOURCE CORRELATION
#
# Inputs:
#   anomalies_auth.json
#   anomalies_process.json
#   anomalies_network.json
#
# Auxiliary context:
#   $HANDOFF_DIR/context/asset_inventory.json
#
# Output:
#   correlated_anomalies.json
#
# Correlation rule:
#   - same host
#   - at least 2 anomalies
#   - at least 2 different source categories
#   - all timestamps inside CORRELATION_WINDOW seconds
#
# Default correlation window:
#   300 seconds
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

CORRELATION_WINDOW="${CORRELATION_WINDOW:-300}"

AUTH_FILE="anomalies_auth.json"
PROCESS_FILE="anomalies_process.json"
NETWORK_FILE="anomalies_network.json"

ASSET_FILE="$HANDOFF_DIR/context/asset_inventory.json"

OUTPUT_FILE="correlated_anomalies.json"


# ============================================================
# SCORE RUBRIC
#
# Score =
#
#   1 point for each involved source
# + 1 point for each distinct anomaly type
# + asset criticality value
#
# Asset criticality:
#
#   critical/high = 3
#   medium        = 2
#   low/unknown   = 1
#
# Example:
#
#   auth + process + network = 3
#   3 anomaly types          = 3
#   critical asset           = 3
#
#   score = 9
# ============================================================


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

if ! [[ "$CORRELATION_WINDOW" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: CORRELATION_WINDOW must be a positive integer." >&2
    exit 1
fi


# Make sure all three anomaly files exist.
for file in \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE"
do
    if [ ! -f "$file" ]; then
        echo "Error: required file not found: $file" >&2
        exit 1
    fi

    # Empty anomaly files are valid.
    if [ -s "$file" ]; then
        if ! jq -e . "$file" >/dev/null 2>&1; then
            echo "Error: invalid JSON in $file" >&2
            exit 1
        fi
    fi
done


# ============================================================
# TEMPORARY OUTPUT
# ============================================================

TMP_OUTPUT=$(mktemp)

cleanup()
{
    rm -f "$TMP_OUTPUT"
}

trap cleanup EXIT


# ============================================================
# CORRELATE ANOMALIES
# ============================================================

python3 -W error - \
    "$AUTH_FILE" \
    "$PROCESS_FILE" \
    "$NETWORK_FILE" \
    "$ASSET_FILE" \
    "$TMP_OUTPUT" \
    "$CORRELATION_WINDOW" <<'PY'

import hashlib
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


auth_file = sys.argv[1]
process_file = sys.argv[2]
network_file = sys.argv[3]
asset_file = sys.argv[4]
output_file = sys.argv[5]
correlation_window = int(sys.argv[6])


# ============================================================
# HELPER: PARSE ISO TIMESTAMP
# ============================================================

def parse_time(value):
    """Convert ISO-8601 text to a timezone-aware datetime."""

    if not value:
        return None

    try:
        value = value.replace("Z", "+00:00")
        result = datetime.fromisoformat(value)

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result

    except ValueError:
        return None


# ============================================================
# HELPER: READ JSON OR NDJSON
#
# Previous anomaly tasks produce NDJSON, but this also accepts
# a normal JSON array for easier reuse.
# ============================================================

def read_records(filename):
    """Read anomaly records from JSON or NDJSON."""

    with open(filename, "r", encoding="utf-8") as file:
        text = file.read().strip()

    if not text:
        return []

    # First try normal JSON.
    try:
        data = json.loads(text)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    # Otherwise treat the file as NDJSON.
    records = []

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        records.append(json.loads(line))

    return records


# ============================================================
# HELPER: ASSET INVENTORY
#
# Asset inventories can sometimes be:
#
#   [ {...}, {...} ]
#
# or:
#
#   { "assets": [ {...}, {...} ] }
#
# This helper accepts both.
# ============================================================

def asset_records(data):

    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    for key in ("assets", "hosts", "inventory"):

        value = data.get(key)

        if isinstance(value, list):
            return value

    # Also support an object keyed by hostname.
    records = []

    for key, value in data.items():

        if not isinstance(value, dict):
            continue

        record = dict(value)

        if "hostname" not in record:
            record["hostname"] = key

        records.append(record)

    return records


# ============================================================
# HELPER: CRITICALITY MULTIPLIER
# ============================================================

def criticality_value(value):
    """Map asset criticality into a small integer."""

    if value is None:
        return 1

    # Numeric inventory value.
    if isinstance(value, (int, float)):

        if value >= 3:
            return 3

        if value >= 2:
            return 2

        return 1

    value = str(value).strip().lower()

    if value in {
        "critical",
        "very high",
        "high",
        "mission critical",
        "mission-critical"
    }:
        return 3

    if value in {
        "medium",
        "moderate"
    }:
        return 2

    return 1


# ============================================================
# LOAD ASSET CRITICALITY
#
# If the inventory is unavailable or the host is absent from
# it, the safe/default multiplier is 1.
# ============================================================

asset_criticality = {}


if os.path.isfile(asset_file):

    try:

        with open(asset_file, "r", encoding="utf-8") as file:
            asset_data = json.load(file)

        for asset in asset_records(asset_data):

            if not isinstance(asset, dict):
                continue

            host = (
                asset.get("hostname")
                or asset.get("host")
                or asset.get("name")
                or asset.get("asset_name")
            )

            criticality = (
                asset.get("criticality")
                or asset.get("asset_criticality")
                or asset.get("priority")
            )

            if host:
                asset_criticality[str(host).lower()] = {
                    "name": str(criticality or "unknown"),
                    "multiplier": criticality_value(criticality)
                }

    except (json.JSONDecodeError, OSError):

        # Asset criticality is useful scoring context,
        # but correlation can still work without it.
        asset_criticality = {}


# ============================================================
# LOAD THE THREE ANOMALY SOURCES
# ============================================================

source_files = [
    ("auth", auth_file),
    ("process", process_file),
    ("network", network_file)
]


all_anomalies = []


for source_category, filename in source_files:

    records = read_records(filename)

    for entry_number, anomaly in enumerate(records, start=1):

        if not isinstance(anomaly, dict):
            continue

        timestamp = parse_time(
            anomaly.get("timestamp")
        )

        host = anomaly.get("host")

        anomaly_type = anomaly.get("anomaly_type")

        # Correlation requires host and timestamp.
        if timestamp is None:
            continue

        if host is None or str(host).strip() == "":
            continue

        if not anomaly_type:
            continue

        all_anomalies.append(
            {
                "source": source_category,
                "file": filename,
                "entry": entry_number,
                "timestamp": timestamp,
                "timestamp_text": anomaly.get("timestamp"),
                "host": str(host),
                "anomaly_type": str(anomaly_type)
            }
        )


single_source_count = len(all_anomalies)


# ============================================================
# GROUP ANOMALIES BY HOST
# ============================================================

by_host = defaultdict(list)


for anomaly in all_anomalies:

    by_host[anomaly["host"]].append(anomaly)


# ============================================================
# FIND CANDIDATE CORRELATION WINDOWS
#
# We use a sliding window.
#
# Every member inside a finding must fall within:
#
#     newest timestamp - oldest timestamp
#     <= CORRELATION_WINDOW
#
# This is stricter and clearer than simply checking whether
# adjacent events are close together.
# ============================================================

candidates = {}


for host, records in by_host.items():

    records.sort(
        key=lambda item: (
            item["timestamp"],
            item["source"],
            item["entry"]
        )
    )

    left = 0

    for right in range(len(records)):

        # Shrink the window until every member fits inside
        # CORRELATION_WINDOW seconds.
        while (
            records[right]["timestamp"]
            - records[left]["timestamp"]
        ).total_seconds() > correlation_window:

            left += 1

        members = records[left:right + 1]

        if len(members) < 2:
            continue

        sources = {
            member["source"]
            for member in members
        }

        # Cross-source means at least two source categories.
        if len(sources) < 2:
            continue

        # Deterministic identity of the candidate group.
        member_key = tuple(
            sorted(
                (
                    member["source"],
                    member["entry"]
                )
                for member in members
            )
        )

        candidates[
            (
                host,
                member_key
            )
        ] = list(members)


# ============================================================
# REMOVE SUBSET FINDINGS
#
# Example:
#
#   auth + process
#   auth + process + network
#
# If all three occurred inside the same valid window, keep the
# larger correlation instead of reporting both.
# ============================================================

candidate_items = list(candidates.items())

keep = []


for current_key, current_members in candidate_items:

    current_host = current_key[0]

    current_refs = {
        (
            item["source"],
            item["entry"]
        )
        for item in current_members
    }

    is_subset = False

    for other_key, other_members in candidate_items:

        if current_key == other_key:
            continue

        if other_key[0] != current_host:
            continue

        other_refs = {
            (
                item["source"],
                item["entry"]
            )
            for item in other_members
        }

        if current_refs < other_refs:
            is_subset = True
            break

    if not is_subset:
        keep.append(current_members)


# ============================================================
# BUILD CORRELATED FINDINGS
# ============================================================

findings = []


for members in keep:

    members.sort(
        key=lambda item: (
            item["timestamp"],
            item["source"],
            item["entry"]
        )
    )

    host = members[0]["host"]

    sources = sorted(
        {
            item["source"]
            for item in members
        }
    )

    anomaly_types = sorted(
        {
            item["anomaly_type"]
            for item in members
        }
    )

    window_start = members[0]["timestamp"]
    window_end = members[-1]["timestamp"]


    # --------------------------------------------------------
    # ASSET CRITICALITY
    # --------------------------------------------------------

    asset_info = asset_criticality.get(
        host.lower(),
        {
            "name": "unknown",
            "multiplier": 1
        }
    )

    asset_multiplier = asset_info["multiplier"]


    # --------------------------------------------------------
    # COMPOSITE SCORE
    #
    # 1 per source
    # +1 per distinct anomaly type
    # +asset criticality value
    # --------------------------------------------------------

    score = (
        len(sources)
        + len(anomaly_types)
        + asset_multiplier
    )


    # --------------------------------------------------------
    # MEMBER REFERENCES
    # --------------------------------------------------------

    member_refs = [
        {
            "source": item["source"],
            "file": item["file"],
            "entry": item["entry"],
            "timestamp": item["timestamp_text"],
            "anomaly_type": item["anomaly_type"]
        }
        for item in members
    ]


    # --------------------------------------------------------
    # DETERMINISTIC CORRELATION ID
    #
    # No random value and no current timestamp are used.
    # Identical input produces the same identifier.
    # --------------------------------------------------------

    id_material = "|".join(
        [
            host,
            window_start.isoformat(),
            window_end.isoformat()
        ]
        + [
            f"{ref['source']}:{ref['entry']}"
            for ref in member_refs
        ]
    )

    correlation_id = (
        "COR-"
        + hashlib.sha256(
            id_material.encode("utf-8")
        ).hexdigest()[:10]
    )


    findings.append(
        {
            "correlation_id": correlation_id,
            "host": host,

            "window_start":
                window_start.isoformat().replace(
                    "+00:00",
                    "Z"
                ),

            "window_end":
                window_end.isoformat().replace(
                    "+00:00",
                    "Z"
                ),

            "sources_involved": sources,

            "anomaly_types": anomaly_types,

            "member_refs": member_refs,

            "asset_criticality":
                asset_info["name"],

            "asset_criticality_multiplier":
                asset_multiplier,

            "score": score
        }
    )


# ============================================================
# SORT HIGHEST SCORE FIRST
#
# The project wants the most dangerous/high-confidence item at
# the top instead of buried below lower-value findings.
# ============================================================

findings.sort(
    key=lambda item: (
        -item["score"],
        item["window_start"],
        item["host"],
        item["correlation_id"]
    )
)


# ============================================================
# WRITE NDJSON
# ============================================================

with open(output_file, "w", encoding="utf-8") as file:

    for finding in findings:

        json.dump(
            finding,
            file,
            sort_keys=True
        )

        file.write("\n")


# Print internal counters for Bash.
print(single_source_count)
print(len(findings))

if findings:
    print(max(item["score"] for item in findings))
else:
    print(0)

PY
