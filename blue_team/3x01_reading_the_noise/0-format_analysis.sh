#!/usr/bin/env bash

# ============================================================
# Task 0 - Format Analysis Across All Sources
#
# Reads:
#   $HANDOFF_DIR/data/enriched_events.json
#
# Produces:
#   format_analysis.json
#
# The script profiles every source_type and reports:
#   - record_count
#   - first_event
#   - last_event
#   - unique_hosts
#   - field_profile
#   - top_event_categories
#
# HANDOFF_DIR defaults to:
#   ~/3x00_handoff/evidence_handoff
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

INPUT_FILE="$HANDOFF_DIR/data/enriched_events.json"
OUTPUT_FILE="format_analysis.json"


# ============================================================
# 2. Check that the input file exists
# ============================================================

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: input file not found:"
    echo "$INPUT_FILE"
    exit 1
fi


# ============================================================
# 3. Run the format analysis
#
# Python is used here because profiling every field, calculating
# cardinality, determining types, and collecting examples is much
# easier to keep readable than a large jq expression.
# ============================================================

python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime


input_file = sys.argv[1]
output_file = sys.argv[2]


# ------------------------------------------------------------
# Helper: load the event file
#
# The 3x00 pipeline may produce either:
#   - one JSON array
#   - newline-delimited JSON (NDJSON)
#
# Supporting both makes the script more reusable.
# ------------------------------------------------------------

def load_events(path):
    events = []

    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        return events

    # First try a normal JSON document.
    try:
        data = json.loads(content)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    except json.JSONDecodeError:
        pass

    # Otherwise treat the file as NDJSON.
    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)

            if isinstance(record, dict):
                events.append(record)

        except json.JSONDecodeError as exc:
            print(
                f"Warning: skipping invalid JSON on line {line_number}: {exc}",
                file=sys.stderr
            )

    return events


# ------------------------------------------------------------
# Helper: infer a simple JSON-friendly field type
# ------------------------------------------------------------

def value_type(value):
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "boolean"

    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"

    if isinstance(value, float):
        return "number"

    if isinstance(value, str):
        return "string"

    if isinstance(value, list):
        return "array"

    if isinstance(value, dict):
        return "object"

    return "unknown"


# ------------------------------------------------------------
# Helper: make values safe for comparison and examples
#
# Lists and dictionaries cannot directly be added to a Python set,
# so they are converted to deterministic JSON strings.
# ------------------------------------------------------------

def comparable_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False
        )

    if value is None:
        return None

    return value


# ------------------------------------------------------------
# Helper: decide whether a value counts as "present"
#
# A field is considered present when:
#   - the key exists
#   - the value is not null
#   - strings are not empty
#
# Values such as 0 and False are still valid values.
# ------------------------------------------------------------

def is_present(value):
    if value is None:
        return False

    if isinstance(value, str) and value.strip() == "":
        return False

    return True


# ------------------------------------------------------------
# Helper: timestamp sorting
#
# ISO 8601 strings normally sort correctly when they have been
# normalized by the evidence pipeline. We therefore keep the
# original value instead of rewriting the evidence.
# ------------------------------------------------------------

def timestamp_value(event):
    return event.get("timestamp")


# ============================================================
# 4. Load events
# ============================================================

events = load_events(input_file)

if not events:
    print("Error: no valid events found in input file.", file=sys.stderr)
    sys.exit(1)


# ============================================================
# 5. Group records by source_type
# ============================================================

by_source = defaultdict(list)

for event in events:
    source_type = event.get("source_type")

    if source_type is None or str(source_type).strip() == "":
        source_type = "unknown"

    by_source[str(source_type)].append(event)


# ============================================================
# 6. Build the profile for each source type
# ============================================================

analysis = {}


for source_type in sorted(by_source):
    records = by_source[source_type]
    record_count = len(records)

    # --------------------------------------------------------
    # Timestamp range
    # --------------------------------------------------------

    timestamps = []

    for record in records:
        ts = timestamp_value(record)

        if is_present(ts):
            timestamps.append(str(ts))

    timestamps.sort()

    first_event = timestamps[0] if timestamps else None
    last_event = timestamps[-1] if timestamps else None


    # --------------------------------------------------------
    # Unique host count
    # --------------------------------------------------------

    hosts = set()

    for record in records:
        hostname = record.get("hostname")

        if is_present(hostname):
            hosts.add(str(hostname))

    unique_hosts = len(hosts)


    # --------------------------------------------------------
    # Discover every field seen in this source
    # --------------------------------------------------------

    all_fields = set()

    for record in records:
        all_fields.update(record.keys())


    # --------------------------------------------------------
    # Profile every discovered field
    # --------------------------------------------------------

    field_profile = {}

    for field in sorted(all_fields):

        present_values = []
        seen_types = Counter()

        for record in records:

            if field not in record:
                continue

            value = record[field]

            if not is_present(value):
                continue

            present_values.append(value)
            seen_types[value_type(value)] += 1


        presence_count = len(present_values)

        if record_count > 0:
            presence_pct = round(
                (presence_count / record_count) * 100,
                2
            )
        else:
            presence_pct = 0.0


        # ----------------------------------------------------
        # Infer the dominant observed type.
        #
        # If different real types occur, report "mixed".
        # ----------------------------------------------------

        if len(seen_types) == 0:
            inferred_type = "null"

        elif len(seen_types) == 1:
            inferred_type = next(iter(seen_types))

        else:
            inferred_type = "mixed"


        # ----------------------------------------------------
        # Cardinality = number of distinct non-empty values
        # ----------------------------------------------------

        unique_values = set()

        for value in present_values:
            unique_values.add(comparable_value(value))

        cardinality = len(unique_values)


        # ----------------------------------------------------
        # Collect up to three example values.
        #
        # Preserve their original JSON data type where possible.
        # ----------------------------------------------------

        example_values = []
        seen_examples = set()

        for value in present_values:

            comparable = comparable_value(value)

            # Convert to a stable marker so even nested values can
            # safely be checked for duplicates.
            marker = json.dumps(
                comparable,
                sort_keys=True,
                ensure_ascii=False
            )

            if marker in seen_examples:
                continue

            seen_examples.add(marker)
            example_values.append(value)

            if len(example_values) == 3:
                break


        field_profile[field] = {
            "presence_pct": presence_pct,
            "inferred_type": inferred_type,
            "cardinality": cardinality,
            "example_values": example_values
        }


    # --------------------------------------------------------
    # Top event categories
    # --------------------------------------------------------

    category_counts = Counter()

    for record in records:
        category = record.get("event_category")

        if is_present(category):
            category_counts[str(category)] += 1


    top_event_categories = [
        {
            "event_category": category,
            "count": count
        }
        for category, count in category_counts.most_common(10)
    ]


    # --------------------------------------------------------
    # Store this source profile
    # --------------------------------------------------------

    analysis[source_type] = {
        "record_count": record_count,
        "first_event": first_event,
        "last_event": last_event,
        "unique_hosts": unique_hosts,
        "field_profile": field_profile,
        "top_event_categories": top_event_categories
    }


# ============================================================
# 7. Write format_analysis.json
# ============================================================

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(
        analysis,
        f,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# 8. Human-readable stdout summary
# ============================================================

for source_type in sorted(analysis):

    profile = analysis[source_type]

    print(
        f"{source_type:<18} "
        f"{profile['record_count']} records   "
        f"{profile['unique_hosts']} hosts   "
        f"{len(profile['field_profile'])} fields"
    )


print(f"{len(analysis)} source types profiled")
print(f"{output_file} written")

PYTHON
