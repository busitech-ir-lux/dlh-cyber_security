#!/bin/bash

# ============================================================
# Task 1 - Critical Field Extraction and Indexing
#
# Reads:
#   $HANDOFF_DIR/data/enriched_events.json
#
# Produces:
#   field_index.json
#
# Builds a reverse index for these critical fields:
#   hostname
#   user
#   process_name
#   src_ip
#   dst_ip
#   event_category
#   source_type
#
# For values occurring 50 times or fewer:
#   - store count
#   - store event_refs
#
# For values occurring more than 50 times:
#   - store only count
#   - store capped: true
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

INPUT_FILE="$HANDOFF_DIR/data/enriched_events.json"
OUTPUT_FILE="field_index.json"


# ============================================================
# 2. Validate input
# ============================================================

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: input file not found:"
    echo "$INPUT_FILE"
    exit 1
fi


# ============================================================
# 3. Build the reverse index
# ============================================================

python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PYTHON'

import json
import os
import sys
from collections import defaultdict


input_file = sys.argv[1]
output_file = sys.argv[2]


# ============================================================
# Critical fields required by the task
# ============================================================

CRITICAL_FIELDS = [
    "hostname",
    "user",
    "process_name",
    "src_ip",
    "dst_ip",
    "event_category",
    "source_type",
]

MAX_REFS = 50


# ============================================================
# Helper: load JSON array or NDJSON
# ============================================================

def load_events(path):
    """
    Support both:
      1. a normal JSON array
      2. newline-delimited JSON (NDJSON)

    This makes the script less dependent on one physical
    representation of enriched_events.json.
    """

    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        return []

    # First try normal JSON.
    try:
        data = json.loads(content)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    # Otherwise try NDJSON.
    events = []

    for line_number, line in enumerate(content.splitlines(), start=1):

        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)

        except json.JSONDecodeError as exc:
            print(
                f"Warning: skipping invalid JSON on line "
                f"{line_number}: {exc}",
                file=sys.stderr
            )
            continue

        if isinstance(event, dict):
            events.append(event)

    return events


# ============================================================
# Helper: decide whether a field value should be indexed
# ============================================================

def is_present(value):
    """
    Null and empty strings are not useful index values.

    Values such as 0 and False are still legitimate values.
    """

    if value is None:
        return False

    if isinstance(value, str) and value.strip() == "":
        return False

    return True


# ============================================================
# Helper: turn a field value into a JSON object key
# ============================================================

def value_to_key(value):
    """
    JSON object keys must be strings.

    Normal string values are preserved as-is.

    If an unexpected list/object appears, convert it to a stable
    JSON representation instead of crashing.
    """

    if isinstance(value, str):
        return value

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        )

    return str(value)


# ============================================================
# Helper: obtain a stable pointer to an event
# ============================================================

def get_event_ref(event, record_number):
    """
    Prefer an event_ref already produced by the evidence pipeline.

    If the dataset does not contain one, create a deterministic
    pointer based on the record position.
    """

    event_ref = event.get("event_ref")

    if is_present(event_ref):
        return event_ref

    return f"record:{record_number}"


# ============================================================
# Load the dataset
# ============================================================

events = load_events(input_file)

if not events:
    print(
        "Error: no valid events found in enriched_events.json",
        file=sys.stderr
    )
    sys.exit(1)


print(
    f"indexing {len(CRITICAL_FIELDS)} critical fields "
    f"over {len(events)} records"
)


# ============================================================
# Internal index
#
# Structure while building:
#
# index[field][value] = {
#     "count":  ...,
#     "event_refs": [...]
# }
#
# We stop collecting event_refs after 50, but continue counting.
# ============================================================

index = {}

for field in CRITICAL_FIELDS:
    index[field] = {}


# ============================================================
# Process each event only once
# ============================================================

for record_number, event in enumerate(events):

    if not isinstance(event, dict):
        continue

    event_ref = get_event_ref(event, record_number)

    for field in CRITICAL_FIELDS:

        value = event.get(field)

        if not is_present(value):
            continue

        key = value_to_key(value)


        # ----------------------------------------------------
        # First time we see this value
        # ----------------------------------------------------

        if key not in index[field]:

            index[field][key] = {
                "count": 0,
                "event_refs": []
            }


        entry = index[field][key]

        entry["count"] += 1


        # ----------------------------------------------------
        # Keep only the first 50 references.
        #
        # We still continue increasing count after reaching 50.
        # ----------------------------------------------------

        if len(entry["event_refs"]) < MAX_REFS:
            entry["event_refs"].append(event_ref)


# ============================================================
# Convert entries into final bounded output
# ============================================================

final_index = {}

for field in CRITICAL_FIELDS:

    final_index[field] = {}

    # Sort values so repeated runs produce deterministic JSON.
    for value in sorted(index[field]):

        entry = index[field][value]
        count = entry["count"]

        if count > MAX_REFS:

            # Task requirement:
            # values occurring more than 50 times only store
            # their total count and a capped marker.
            final_index[field][value] = {
                "count": count,
                "capped": True
            }

        else:

            final_index[field][value] = {
                "count": count,
                "event_refs": entry["event_refs"]
            }


# ============================================================
# Write field_index.json
# ============================================================

with open(output_file, "w", encoding="utf-8") as f:

    json.dump(
        final_index,
        f,
        indent=2,
        ensure_ascii=False,
        sort_keys=True
    )


# ============================================================
# Print summary
# ============================================================

total_unique_values = 0

for field in CRITICAL_FIELDS:

    unique_count = len(final_index[field])
    total_unique_values += unique_count

    print(
        f"  {field:<15} "
        f"unique values : {unique_count:>6}"
    )


# ------------------------------------------------------------
# File size
# ------------------------------------------------------------

size_bytes = os.path.getsize(output_file)
size_mb = size_bytes / (1024 * 1024)


print(
    f"{len(CRITICAL_FIELDS)} fields indexed, "
    f"{total_unique_values} total unique values"
)

print(
    f"{output_file} written ({size_mb:.2f} MB)"
)

PYTHON
