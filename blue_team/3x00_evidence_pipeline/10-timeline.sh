#!/bin/bash
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

INPUT_FILE="$WORKDIR/enriched_events.json"
OUTPUT_FILE="$WORKDIR/timeline_index.json"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "ERROR: Missing file: $INPUT_FILE" >&2
    exit 1
fi


python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PYTHON'

import json
import sys
from datetime import datetime


input_file = sys.argv[1]
output_file = sys.argv[2]


# ------------------------------------------------------------
# Parse ISO timestamp for sorting and one-second comparison.
# ------------------------------------------------------------

def parse_time(value):
    text = str(value)

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    return datetime.fromisoformat(text)


# ------------------------------------------------------------
# Build analyst-friendly summary based on event_category.
# ------------------------------------------------------------

def build_summary(event):
    category = event.get("event_category")
    user = event.get("user") or "unknown"
    process = event.get("process_name") or "unknown"
    src_ip = event.get("src_ip") or "unknown"
    dst_ip = event.get("dst_ip") or "unknown"
    src_port = event.get("src_port")
    dst_port = event.get("dst_port")

    source_fields = event.get("source_fields") or {}
    event_data = event.get("event_data") or {}

    if category == "authentication":
        result = (
            event.get("action")
            or source_fields.get("result")
            or source_fields.get("res")
            or event_data.get("Status")
            or event_data.get("FailureReason")
            or "unknown"
        )

        return f"Authentication user={user} result={result}"

    if category == "process":
        return f"Process {process}"

    if category == "network":
        source = (
            f"{src_ip}:{src_port}"
            if src_port is not None
            else src_ip
        )

        destination = (
            f"{dst_ip}:{dst_port}"
            if dst_port is not None
            else dst_ip
        )

        return f"Network {source} -> {destination}"

    if category == "network_alert":
        signature = event.get("signature") or "unknown alert"
        return f"Network alert {src_ip} -> {dst_ip}: {signature}"

    if category == "network_flow":
        return f"Network flow {src_ip} -> {dst_ip}"

    # Simple fallback for other categories.
    raw = event.get("raw_message") or category or "event"

    # Keep summary on one line.
    return str(raw).replace("\n", " ")[:200]


# ------------------------------------------------------------
# Read enriched events and create compact timeline entries.
# ------------------------------------------------------------

events = []

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
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        timestamp = event.get("timestamp")

        if not timestamp:
            continue

        try:
            sort_time = parse_time(timestamp)
        except (ValueError, TypeError):
            continue

        entry = {
            "timestamp": timestamp,
            "hostname": event.get("hostname"),
            "source_type": event.get("source_type"),
            "event_category": event.get("event_category"),
            "severity": event.get("severity"),
            "summary": build_summary(event),
            "event_ref": f"enriched:{line_number}"
        }

        events.append((sort_time, line_number, entry))


total_read = len(events)


# ------------------------------------------------------------
# Sort chronologically.
#
# Original line number gives deterministic ordering when two
# events have the same timestamp.
# ------------------------------------------------------------

events.sort(
    key=lambda item: (
        item[0],
        item[1]
    )
)


# ------------------------------------------------------------
# Deduplicate consecutive identical entries occurring within
# one second.
#
# event_ref and timestamp are not used when deciding whether
# two events describe the same activity.
# ------------------------------------------------------------

timeline = []
collapsed = 0

for sort_time, _, entry in events:

    if timeline:
        previous_time, previous_entry = timeline[-1]

        same_event = (
            previous_entry.get("hostname")
            == entry.get("hostname")
            and previous_entry.get("source_type")
            == entry.get("source_type")
            and previous_entry.get("event_category")
            == entry.get("event_category")
            and previous_entry.get("severity")
            == entry.get("severity")
            and previous_entry.get("summary")
            == entry.get("summary")
        )

        within_one_second = (
            abs(
                (sort_time - previous_time).total_seconds()
            ) <= 1
        )

        if same_event and within_one_second:
            previous_entry["count"] = (
                previous_entry.get("count", 1) + 1
            )

            collapsed += 1
            continue

    timeline.append(
        (sort_time, entry)
    )


# ------------------------------------------------------------
# Write timeline NDJSON.
# ------------------------------------------------------------

with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    for _, entry in timeline:
        json.dump(
            entry,
            f,
            separators=(",", ":")
        )
        f.write("\n")


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

print(f"enriched events read : {total_read}")
print(f"collapsed duplicates : {collapsed}")
print(f"timeline entries     : {len(timeline)}")

if timeline:
    print(
        f"first entry          : "
        f"{timeline[0][1]['timestamp']}"
    )

    print(
        f"last entry           : "
        f"{timeline[-1][1]['timestamp']}"
    )
else:
    print("first entry          : none")
    print("last entry           : none")

print("timeline_index.json written")

PYTHON
