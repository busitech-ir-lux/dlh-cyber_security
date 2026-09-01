#!/bin/bash

# ============================================================
# Task 7 - File Access Baseline
#
# Reads:
#   labeled_events.json
#
# Produces:
#   baseline_file.json
#
# Only these canonical labels are considered:
#   - file_read_sensitive
#   - file_write_sensitive
#   - file_permission_change
#
# The baseline window is derived from the dataset.
# BASELINE_DAYS defaults to 7.
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff/}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

INPUT_FILE="labeled_events.json"
OUTPUT_FILE="baseline_file.json"


# ============================================================
# 2. Configurable sensitive path prefixes
#
# Add additional MedDefense application paths here if the
# project environment defines more of them later.
# ============================================================

SENSITIVE_PREFIXES=(
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/"
    "/var/log/audit/"
    'C:\Windows\System32\config\'
    'C:\MedDefense\'
)


# ============================================================
# 3. Locate the input
# ============================================================

# Normally labeled_events.json is produced by an earlier task
# in the current project directory.
#
# This fallback also allows it to be read from the handoff data
# directory if it is placed there.

if [ ! -f "$INPUT_FILE" ] && \
   [ -f "${HANDOFF_DIR%/}/data/labeled_events.json" ]; then
    INPUT_FILE="${HANDOFF_DIR%/}/data/labeled_events.json"
fi


if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: labeled_events.json not found" >&2
    exit 1
fi


# ============================================================
# 4. Validate BASELINE_DAYS
# ============================================================

case "$BASELINE_DAYS" in
    ''|*[!0-9]*)
        echo "Error: BASELINE_DAYS must be a positive integer" >&2
        exit 1
        ;;
esac

if [ "$BASELINE_DAYS" -lt 1 ]; then
    echo "Error: BASELINE_DAYS must be at least 1" >&2
    exit 1
fi


# ============================================================
# 5. Build the file-access baseline
# ============================================================

python3 -W error - \
    "$INPUT_FILE" \
    "$OUTPUT_FILE" \
    "$BASELINE_DAYS" \
    "${SENSITIVE_PREFIXES[@]}" <<'PYTHON'

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


input_file = sys.argv[1]
output_file = sys.argv[2]
baseline_days = int(sys.argv[3])
sensitive_prefixes = sys.argv[4:]


ALLOWED_LABELS = {
    "file_read_sensitive",
    "file_write_sensitive",
    "file_permission_change",
}


# ============================================================
# Helper: load JSON array or NDJSON
# ============================================================

def load_events(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    if not text:
        return []

    # First try a normal JSON document.
    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        # Otherwise read it as NDJSON.
        events = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {line_number}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"record on line {line_number} "
                    "is not a JSON object"
                )

            events.append(event)

        return events

    if isinstance(data, list):
        if not all(isinstance(event, dict) for event in data):
            raise ValueError(
                "JSON array contains a non-object record"
            )

        return data

    if isinstance(data, dict):
        return [data]

    raise ValueError(
        "input must be a JSON array, object, or NDJSON"
    )


# ============================================================
# Helper: test whether a value is present
# ============================================================

def present(value):
    if value is None:
        return False

    if isinstance(value, str) and not value.strip():
        return False

    return True


# ============================================================
# Helper: parse normalized timestamps
# ============================================================

def parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "event contains a missing timestamp"
        )

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)

    except ValueError as exc:
        raise ValueError(
            f"invalid timestamp: {value}"
        ) from exc

    # Normalized data should contain timezone information.
    # Treat a missing timezone as UTC so test datasets remain usable.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def iso_utc(value):
    return (
        value
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# Helper: get canonical label
#
# canonical_label is preferred.
# label is accepted for compatibility with earlier taxonomy
# implementations.
# ============================================================

def get_label(event):
    label = event.get("canonical_label")

    if not present(label):
        label = event.get("label")

    if not present(label):
        return None

    return str(label).strip()


# ============================================================
# Helper: get file path
#
# file_path is the preferred normalized name.
# The small fallbacks make the script tolerant of earlier
# pipeline versions without changing the analysis logic.
# ============================================================

def get_file_path(event):
    for field in (
        "file_path",
        "path",
        "target_path",
    ):
        value = event.get(field)

        if present(value):
            return str(value).strip()

    return None


# ============================================================
# Helper: determine whether path is sensitive
# ============================================================

def is_sensitive_path(path):
    """
    Linux paths are case-sensitive.

    Windows paths are compared case-insensitively because Windows
    filesystem paths normally are not case-sensitive.
    """

    for prefix in sensitive_prefixes:

        # Windows-style path.
        if "\\" in prefix:
            if path.lower().startswith(prefix.lower()):
                return True

        # Linux/Unix-style path.
        else:
            if path.startswith(prefix):
                return True

    return False


# ============================================================
# 6. Load all labeled events
# ============================================================

events = load_events(input_file)

if not events:
    raise ValueError(
        "labeled_events.json contains no events"
    )


# ============================================================
# 7. Derive baseline window from the complete dataset
# ============================================================

parsed_events = []

for event in events:
    timestamp = parse_timestamp(
        event.get("timestamp")
    )

    parsed_events.append(
        (timestamp, event)
    )


dataset_start = min(
    timestamp
    for timestamp, _ in parsed_events
)

baseline_end = (
    dataset_start
    + timedelta(days=baseline_days)
)


# Baseline end is exclusive:
#
#     start <= event < end
#
# Therefore the first event of the evaluation window is not
# accidentally included in the baseline.
baseline_events = [
    event
    for timestamp, event in parsed_events
    if dataset_start <= timestamp < baseline_end
]


# ============================================================
# 8. Keep only sensitive file events
# ============================================================

file_events = []

for event in baseline_events:

    label = get_label(event)

    if label not in ALLOWED_LABELS:
        continue

    path = get_file_path(event)

    if path is None:
        continue

    if not is_sensitive_path(path):
        continue

    file_events.append(
        (path, event)
    )


# ============================================================
# 9. Baseline counters
# ============================================================

# Exact sensitive paths observed.
sensitive_paths = set()

# path -> total access count
path_counts = Counter()

# path -> process -> count
path_processes = defaultdict(Counter)

# path -> user -> count
path_users = defaultdict(Counter)

# host -> paths
host_paths = defaultdict(set)


# ============================================================
# 10. Process sensitive file events
# ============================================================

for path, event in file_events:

    sensitive_paths.add(path)
    path_counts[path] += 1

    process_name = event.get("process_name")
    user = event.get("user")
    hostname = event.get("hostname")


    # --------------------------------------------------------
    # Process access
    # --------------------------------------------------------

    if present(process_name):
        process_name = str(process_name).strip()

        path_processes[
            path
        ][process_name] += 1


    # --------------------------------------------------------
    # User access
    # --------------------------------------------------------

    if present(user):
        user = str(user).strip()

        path_users[
            path
        ][user] += 1


    # --------------------------------------------------------
    # Host coverage
    # --------------------------------------------------------

    if present(hostname):
        hostname = str(hostname).strip()

        host_paths[
            hostname
        ].add(path)


# ============================================================
# 11. Build per_path_access
# ============================================================

per_path_access = {}


for path in sorted(sensitive_paths):

    processes = {
        process: path_processes[path][process]
        for process in sorted(
            path_processes[path]
        )
    }

    users = {
        user: path_users[path][user]
        for user in sorted(
            path_users[path]
        )
    }

    per_path_access[path] = {
        "access_count": path_counts[path],
        "processes": processes,
        "users": users,
    }


# ============================================================
# 12. Build per_host_paths
# ============================================================

per_host_paths = {
    hostname: sorted(host_paths[hostname])
    for hostname in sorted(host_paths)
}


# ============================================================
# 13. Find rare accesses
#
# The task explicitly defines rare here as a path touched
# fewer than three times during the entire baseline.
# ============================================================

rare_accesses = [
    {
        "path": path,
        "count": path_counts[path],
    }
    for path in sorted(sensitive_paths)
    if path_counts[path] < 3
]


# ============================================================
# 14. Final baseline
# ============================================================

result = {
    "baseline_window": {
        "start": iso_utc(dataset_start),
        "end_exclusive": iso_utc(baseline_end),
        "baseline_days": baseline_days,
    },

    "sensitive_path_prefixes": sensitive_prefixes,

    "sensitive_paths": sorted(sensitive_paths),

    "per_path_access": per_path_access,

    "per_host_paths": per_host_paths,

    "rare_accesses": rare_accesses,
}


# ============================================================
# 15. Write deterministic JSON
#
# Temporary file + os.replace prevents partial output and
# guarantees that a second run replaces the previous result.
# ============================================================

temporary_file = output_file + ".tmp"


with open(
    temporary_file,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        result,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Every project file must end with a newline.
    handle.write("\n")


os.replace(
    temporary_file,
    output_file
)


# ============================================================
# 16. Human-readable summary
# ============================================================

print(
    "baseline window   : "
    f"{iso_utc(dataset_start)} "
    "-> "
    f"{iso_utc(baseline_end)}"
)

print(
    "sensitive paths   : "
    f"{len(sensitive_paths)}"
)

print(
    "total accesses    : "
    f"{len(file_events)}"
)

print(
    "per host coverage : "
    f"{len(host_paths)} hosts"
)

print(
    "rare accesses     : "
    f"{len(rare_accesses)}"
)

print(
    f"{output_file} written"
)

PYTHON
