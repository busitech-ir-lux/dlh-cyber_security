#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 11 - PROCESS ANOMALIES
#
# Inputs:
#   baseline_summary.json
#   labeled_events.json
#
# Output:
#   anomalies_process.json
#
# Output format:
#   NDJSON - one anomaly per line
# ============================================================


# ============================================================
# SEVERITY RUBRIC
#
# The task requires severity to come from a declared rubric.
#
# LOW:
#   New process or new parent-child relationship.
#
# MEDIUM:
#   Repeated rare process or high-risk tool/interpreter.
# ============================================================

SEV_UNKNOWN_PROCESS="low"
SEV_UNKNOWN_PARENT_CHILD="low"
SEV_RARE_SPIKE="medium"
SEV_HIGH_RISK="medium"


# ============================================================
# PATHS
# ============================================================

BASELINE_PKG="${BASELINE_PKG:-.}"

SUMMARY_FILE="$BASELINE_PKG/baseline_summary.json"
LABELED_FILE="labeled_events.json"
OUTPUT_FILE="anomalies_process.json"


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

if [ ! -f "$SUMMARY_FILE" ]; then
    echo "Error: $SUMMARY_FILE not found." >&2
    exit 1
fi

if [ ! -f "$LABELED_FILE" ]; then
    echo "Error: $LABELED_FILE not found." >&2
    exit 1
fi

if ! jq -e . "$SUMMARY_FILE" >/dev/null 2>&1; then
    echo "Error: invalid JSON in $SUMMARY_FILE" >&2
    exit 1
fi

if ! jq -e . "$LABELED_FILE" >/dev/null 2>&1; then
    echo "Error: invalid JSON in $LABELED_FILE" >&2
    exit 1
fi


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
# PROCESS ANOMALY DETECTION
# ============================================================

python3 -W error - \
    "$SUMMARY_FILE" \
    "$LABELED_FILE" \
    "$TMP_OUTPUT" \
    "$SEV_UNKNOWN_PROCESS" \
    "$SEV_UNKNOWN_PARENT_CHILD" \
    "$SEV_RARE_SPIKE" \
    "$SEV_HIGH_RISK" <<'PY'

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone


summary_file = sys.argv[1]
events_file = sys.argv[2]
output_file = sys.argv[3]

severity_unknown_process = sys.argv[4]
severity_unknown_parent = sys.argv[5]
severity_rare_spike = sys.argv[6]
severity_high_risk = sys.argv[7]


# ============================================================
# HIGH-RISK PROCESS WATCHLIST
#
# This list comes directly from the task requirements.
# ============================================================

HIGH_RISK_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
    "nc",
    "nmap",
    "wget",
    "curl",
    "python3",
    "bash"
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def parse_time(value):
    """Convert an ISO-8601 timestamp to datetime."""

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


def process_basename(value):
    """
    Return a simple process name.

    Examples:
        C:\Windows\System32\cmd.exe -> cmd.exe
        /usr/bin/python3            -> python3
    """

    if value is None:
        return None

    value = str(value).replace("\\", "/")
    return value.split("/")[-1]


def normalize_process(value):
    """Normalize process names for reliable comparison."""

    name = process_basename(value)

    if not name:
        return None

    return name.lower()


def get_parent_process(event):
    """
    Sysmon Event 1 parent information is preserved
    inside event_data.ParentImage.
    """

    event_data = event.get("event_data")

    if not isinstance(event_data, dict):
        return None

    parent = event_data.get("ParentImage")

    if not parent:
        return None

    return process_basename(parent)


def make_event_ref(event, line_number):
    """Create a stable reference to labeled_events.json."""

    return {
        "file": "labeled_events.json",
        "line": line_number,
        "event_id": event.get("event_id"),
        "source_type": event.get("source_type")
    }


def make_anomaly(
    record,
    anomaly_type,
    severity,
    parent_process=None
):
    """Create the common anomaly structure."""

    event = record["event"]

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("hostname"),
        "user": event.get("user"),
        "process_name": process_basename(
            event.get("process_name")
        ),
        "parent_process_name": parent_process,
        "anomaly_type": anomaly_type,
        "severity": severity,
        "event_refs": [
            make_event_ref(
                event,
                record["line"]
            )
        ]
    }


# ============================================================
# LOAD BASELINE SUMMARY
# ============================================================

with open(summary_file, "r", encoding="utf-8") as file:
    summary = json.load(file)


process_baseline = summary.get("process", {})
evaluation_window = summary.get("evaluation_window", {})


# ============================================================
# READ EVALUATION WINDOW
# ============================================================

evaluation_start = parse_time(
    evaluation_window.get("start")
)

evaluation_hours = evaluation_window.get(
    "duration_hours"
)


if evaluation_start is None:
    raise SystemExit(
        "Error: evaluation_window.start is missing or invalid."
    )

if not isinstance(evaluation_hours, (int, float)):
    raise SystemExit(
        "Error: evaluation_window.duration_hours is missing."
    )


evaluation_end = (
    evaluation_start
    + timedelta(hours=evaluation_hours)
)


# ============================================================
# BUILD EXPECTED PROCESS SET PER HOST
#
# baseline_summary.json contains Task 5 under:
#
#   .process.per_host
#
# We normalize names so paths and capitalization do not create
# false differences.
# ============================================================

expected_by_host = defaultdict(set)

per_host = process_baseline.get("per_host", {})


for host, processes in per_host.items():

    if not isinstance(processes, list):
        continue

    for process in processes:

        name = normalize_process(
            process.get("process_name")
        )

        if name:
            expected_by_host[str(host)].add(name)


# ============================================================
# BUILD KNOWN PARENT -> CHILD PAIRS PER HOST
# ============================================================

known_pairs = defaultdict(set)

parent_child_pairs = process_baseline.get(
    "parent_child_pairs",
    {}
)


for host, pairs in parent_child_pairs.items():

    if not isinstance(pairs, list):
        continue

    for pair in pairs:

        parent = normalize_process(
            pair.get("parent")
        )

        child = normalize_process(
            pair.get("child")
        )

        if parent and child:
            known_pairs[str(host)].add(
                (parent, child)
            )


# ============================================================
# FIND PROCESSES WITH FEWER THAN FIVE BASELINE EXECUTIONS
#
# Task 5 rare_processes can also contain processes that were
# rare because they appeared on only one host.
#
# For THIS detector we specifically need:
#
#     baseline execution_count < 5
# ============================================================

rare_baseline_counts = {}

for process in process_baseline.get(
    "rare_processes",
    []
):

    name = normalize_process(
        process.get("process_name")
    )

    count = process.get("execution_count")

    if (
        name
        and
        isinstance(count, int)
        and
        count < 5
    ):
        rare_baseline_counts[name] = count


# ============================================================
# LOAD EVALUATION PROCESS EVENTS
#
# Both labels represent process execution in our taxonomy:
#
#   process_start
#   child_process_spawn
# ============================================================

evaluation_events = []


with open(events_file, "r", encoding="utf-8") as file:

    for line_number, line in enumerate(file, start=1):

        event = json.loads(line)

        if event.get("canonical_label") not in {
            "process_start",
            "child_process_spawn"
        }:
            continue

        process_name = event.get("process_name")

        if not process_name:
            continue

        timestamp = parse_time(
            event.get("timestamp")
        )

        if timestamp is None:
            continue

        if not (
            evaluation_start
            <= timestamp
            < evaluation_end
        ):
            continue

        evaluation_events.append(
            {
                "event": event,
                "timestamp": timestamp,
                "line": line_number
            }
        )


# ============================================================
# RESULT LIST
# ============================================================

anomalies = []


# ============================================================
# 1. UNKNOWN PROCESS FOR HOST
#
# Every evaluation execution is compared with that host's
# expected process list.
# ============================================================

for record in evaluation_events:

    event = record["event"]

    host = str(
        event.get("hostname") or ""
    )

    process_name = normalize_process(
        event.get("process_name")
    )

    if not host or not process_name:
        continue

    if process_name not in expected_by_host[host]:

        parent = get_parent_process(event)

        anomalies.append(
            make_anomaly(
                record,
                "unknown_process_for_host",
                severity_unknown_process,
                parent
            )
        )


# ============================================================
# 2. UNKNOWN PARENT-CHILD PAIR
#
# Only events containing parent information can be checked.
# ============================================================

for record in evaluation_events:

    event = record["event"]

    host = str(
        event.get("hostname") or ""
    )

    child = normalize_process(
        event.get("process_name")
    )

    parent_display = get_parent_process(event)

    parent = normalize_process(
        parent_display
    )

    if not host or not parent or not child:
        continue

    pair = (parent, child)

    if pair not in known_pairs[host]:

        anomalies.append(
            make_anomaly(
                record,
                "unknown_parent_child",
                severity_unknown_parent,
                parent_display
            )
        )


# ============================================================
# 3. RARE PROCESS SPIKE
#
# Requirement:
#
#   baseline total < 5
#
# AND
#
#   evaluation count > 10
#   on one host
#
# This finding is aggregated per host/process rather than
# producing one finding for every execution.
# ============================================================

evaluation_counts = defaultdict(list)


for record in evaluation_events:

    event = record["event"]

    host = str(
        event.get("hostname") or ""
    )

    process_name = normalize_process(
        event.get("process_name")
    )

    if not host or not process_name:
        continue

    evaluation_counts[
        (host, process_name)
    ].append(record)


for key, records in evaluation_counts.items():

    host, process_name = key

    if process_name not in rare_baseline_counts:
        continue

    observed_count = len(records)

    # Task requirement: MORE THAN ten.
    if observed_count <= 10:
        continue

    first_record = records[0]
    first_event = first_record["event"]

    anomaly = {
        "timestamp": first_event.get("timestamp"),
        "host": host,
        "user": first_event.get("user"),
        "process_name": process_basename(
            first_event.get("process_name")
        ),
        "parent_process_name": get_parent_process(
            first_event
        ),
        "anomaly_type": "rare_process_spike",
        "severity": severity_rare_spike,

        # Helpful extra context for the analyst.
        "baseline_count":
            rare_baseline_counts[process_name],

        "observed_count":
            observed_count,

        "event_refs": [
            make_event_ref(
                item["event"],
                item["line"]
            )
            for item in records
        ]
    }

    anomalies.append(anomaly)


# ============================================================
# 4. HIGH-RISK PROCESS
#
# The process must:
#
#   - be on the task watchlist
#   - NOT have run on that host in the baseline
# ============================================================

for record in evaluation_events:

    event = record["event"]

    host = str(
        event.get("hostname") or ""
    )

    process_name = normalize_process(
        event.get("process_name")
    )

    if not host or not process_name:
        continue

    if process_name not in HIGH_RISK_PROCESSES:
        continue

    if process_name in expected_by_host[host]:
        continue

    parent = get_parent_process(event)

    anomalies.append(
        make_anomaly(
            record,
            "high_risk_process",
            severity_high_risk,
            parent
        )
    )


# ============================================================
# DETERMINISTIC SORTING
#
# Identical input should produce identical output order.
# ============================================================

anomalies.sort(
    key=lambda item: (
        item.get("timestamp") or "",
        item.get("anomaly_type") or "",
        item.get("host") or "",
        item.get("process_name") or ""
    )
)


# ============================================================
# WRITE NDJSON
# ============================================================

with open(output_file, "w", encoding="utf-8") as file:

    for anomaly in anomalies:

        json.dump(
            anomaly,
            file,
            sort_keys=True
        )

        file.write("\n")

PY


# ============================================================
# WRITE FINAL OUTPUT
#
# Replace the file instead of appending to it.
# ============================================================

mv "$TMP_OUTPUT" "$OUTPUT_FILE"
TMP_OUTPUT=""


# ============================================================
# DISPLAY EVALUATION WINDOW
# ============================================================

EVAL_START=$(
    jq -r \
        '.evaluation_window.start' \
        "$SUMMARY_FILE"
)

EVAL_END=$(
    jq -r \
        '.evaluation_window.end' \
        "$SUMMARY_FILE"
)


# ============================================================
# COUNT EACH ANOMALY TYPE
# ============================================================

UNKNOWN_PROCESS_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "unknown_process_for_host"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


UNKNOWN_PAIR_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "unknown_parent_child"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


RARE_SPIKE_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "rare_process_spike"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


HIGH_RISK_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "high_risk_process"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


TOTAL_COUNT=$(
    wc -l < "$OUTPUT_FILE" |
        tr -d ' '
)


# ============================================================
# EXPECTED TERMINAL OUTPUT
# ============================================================

printf "evaluation window : %s -> %s\n" \
    "$EVAL_START" "$EVAL_END"

printf "unknown_process_for_host : %s\n" \
    "$UNKNOWN_PROCESS_COUNT"

printf "unknown_parent_child     : %s\n" \
    "$UNKNOWN_PAIR_COUNT"

printf "rare_process_spike       : %s\n" \
    "$RARE_SPIKE_COUNT"

printf "high_risk_process        : %s\n" \
    "$HIGH_RISK_COUNT"

printf "total anomalies          : %s\n" \
    "$TOTAL_COUNT"

printf "anomalies_process.json written\n"
