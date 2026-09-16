#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[group] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variable
# --------------------------------------------------

if [[ -z "${SHIFT_WORKSPACE:-}" ]]; then
    fail "SHIFT_WORKSPACE is not set"
fi


TRIAGE_LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
OUTPUT="$SHIFT_WORKSPACE/alerts/incidents.json"


# --------------------------------------------------
# Check required files
# --------------------------------------------------

for file in \
    "$TRIAGE_LOG" \
    "$ALERT_QUEUE" \
    "$SHIFT_START"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# --------------------------------------------------
# Count TP alerts
# --------------------------------------------------

TP_COUNT=$(
    jq -s '
        [.[] | select(.classification == "TP")]
        | length
    ' "$TRIAGE_LOG"
)


echo "[group] TP alerts: $TP_COUNT"


if [[ "$TP_COUNT" -lt 3 ]]; then
    fail "fewer than 3 TP alerts; review Task 5 triage"
fi


echo "[group] grouping by temporal proximity, shared user, IOC match"


# --------------------------------------------------
# Run deterministic grouping
# --------------------------------------------------

python3 - \
    "$TRIAGE_LOG" \
    "$ALERT_QUEUE" \
    "$SHIFT_START" \
    "$OUTPUT" <<'PY'

import json
import sys
from datetime import datetime, timezone


triage_file = sys.argv[1]
alerts_file = sys.argv[2]
shift_start_file = sys.argv[3]
output_file = sys.argv[4]


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def parse_time(value):
    """Convert ISO-8601 timestamp to datetime."""

    if not value:
        return None

    value = str(value).strip()

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except ValueError:
        return None


def iso_time(dt):
    if dt is None:
        return ""

    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def alert_id(alert):
    return str(
        alert.get("alert_id")
        or alert.get("id")
        or alert.get("event_id")
        or ""
    )


def alert_timestamp(alert):
    """
    Accept common timestamp field names from
    the normalized detection output.
    """

    return (
        alert.get("timestamp")
        or alert.get("event_time")
        or alert.get("@timestamp")
        or alert.get("time")
        or alert.get("ts")
    )


# --------------------------------------------------
# Read TP triage records
# --------------------------------------------------

tp_records = []

with open(triage_file, "r", encoding="utf-8") as f:
    for line in f:

        line = line.strip()

        if not line:
            continue

        record = json.loads(line)

        if record.get("classification") == "TP":
            tp_records.append(record)


# --------------------------------------------------
# Read alert queue
# --------------------------------------------------

with open(alerts_file, "r", encoding="utf-8") as f:
    alert_data = json.load(f)


if isinstance(alert_data, list):
    alerts = alert_data

elif isinstance(alert_data, dict):
    alerts = alert_data.get("alerts", [])

else:
    alerts = []


# Build fast alert lookup.

alerts_by_id = {}

for alert in alerts:

    aid = alert_id(alert)

    if aid:
        alerts_by_id[aid] = alert


# --------------------------------------------------
# Enrich TP records with timestamps
# --------------------------------------------------

records = []

for position, tp in enumerate(tp_records):

    aid = str(tp.get("alert_id", ""))

    original_alert = alerts_by_id.get(aid, {})

    timestamp_value = (
        tp.get("timestamp")
        or tp.get("event_time")
        or alert_timestamp(original_alert)
        or tp.get("classified_at")
    )

    timestamp = parse_time(timestamp_value)

    host = str(tp.get("host") or "").lower()

    user = tp.get("user")

    if user in ("", "null"):
        user = None

    matches_ioc = tp.get("matches_ioc") or []

    if not isinstance(matches_ioc, list):
        matches_ioc = [str(matches_ioc)]


    records.append(
        {
            "position": position,
            "alert_id": aid,
            "host": host,
            "user": user,
            "matches_ioc": [str(x) for x in matches_ioc if x],
            "timestamp": timestamp,

            # Preserve optional context if your earlier
            # detection/triage scripts already produced it.
            "category": (
                tp.get("tentative_category")
                or original_alert.get("tentative_category")
                or original_alert.get("category")
            ),

            "confidence": (
                tp.get("confidence")
                or original_alert.get("confidence")
            ),
        }
    )


# --------------------------------------------------
# Union-Find structure
#
# This lets grouping remain transitive:
#
# A groups with B
# B groups with C
# therefore A, B, C become one incident.
# --------------------------------------------------

count = len(records)

parent = list(range(count))

group_reasons = [set() for _ in range(count)]


def find(x):

    while parent[x] != x:

        parent[x] = parent[parent[x]]
        x = parent[x]

    return x


def union(a, b, reason):

    root_a = find(a)
    root_b = find(b)

    if root_a == root_b:
        group_reasons[root_a].add(reason)
        return

    # Keep the earlier record as the root.
    if records[root_a]["position"] <= records[root_b]["position"]:
        parent[root_b] = root_a
        group_reasons[root_a].update(group_reasons[root_b])
        group_reasons[root_a].add(reason)

    else:
        parent[root_a] = root_b
        group_reasons[root_b].update(group_reasons[root_a])
        group_reasons[root_b].add(reason)


# --------------------------------------------------
# Rule 1: Same host within 15 minutes
# --------------------------------------------------

for i in range(count):

    for j in range(i + 1, count):

        a = records[i]
        b = records[j]

        if not a["host"] or not b["host"]:
            continue

        if a["host"] != b["host"]:
            continue

        if a["timestamp"] is None or b["timestamp"] is None:
            continue

        difference = abs(
            (a["timestamp"] - b["timestamp"]).total_seconds()
        )

        if difference <= 15 * 60:
            union(i, j, "temporal")


# --------------------------------------------------
# Rule 2: Shared user
# --------------------------------------------------

for i in range(count):

    for j in range(i + 1, count):

        a = records[i]
        b = records[j]

        if not a["user"] or not b["user"]:
            continue

        if str(a["user"]).lower() == str(b["user"]).lower():
            union(i, j, "shared_user")


# --------------------------------------------------
# Rule 3: Shared IOC
# --------------------------------------------------

for i in range(count):

    for j in range(i + 1, count):

        a = records[i]
        b = records[j]

        shared = (
            set(a["matches_ioc"])
            & set(b["matches_ioc"])
        )

        if shared:
            union(i, j, "ioc_match")


# --------------------------------------------------
# Build final groups
# --------------------------------------------------

groups = {}

for index in range(count):

    root = find(index)

    groups.setdefault(root, []).append(index)


# Sort candidates by when their first TP surfaced.

ordered_groups = sorted(
    groups.values(),
    key=lambda members: min(
        records[i]["position"]
        for i in members
    )
)


# --------------------------------------------------
# Shift ID
# --------------------------------------------------

with open(shift_start_file, "r", encoding="utf-8") as f:
    shift_start = json.load(f)


shift_id = str(shift_start.get("shift_id", ""))


# Use current UTC date.

today = datetime.now(timezone.utc).strftime("%Y%m%d")


# --------------------------------------------------
# Allowed category/confidence values
# --------------------------------------------------

allowed_categories = {
    "credential_abuse",
    "persistence",
    "c2",
    "staging",
    "lateral_movement",
    "unknown",
}

allowed_confidence = {
    "low",
    "medium",
    "high",
}


# Priority required by the task.

reason_priority = [
    "temporal",
    "shared_user",
    "ioc_match",
]


incident_list = []


for number, members in enumerate(ordered_groups):

    letter = chr(ord("A") + number)

    incident_id = f"INC-{today}-{letter}"


    # ----------------------------------------------
    # Collect hosts
    # ----------------------------------------------

    hosts = sorted(
        {
            records[i]["host"]
            for i in members
            if records[i]["host"]
        }
    )


    # ----------------------------------------------
    # Collect users
    # ----------------------------------------------

    users = sorted(
        {
            str(records[i]["user"])
            for i in members
            if records[i]["user"]
        }
    )


    # ----------------------------------------------
    # Collect IOCs
    # ----------------------------------------------

    iocs = sorted(
        {
            ioc
            for i in members
            for ioc in records[i]["matches_ioc"]
        }
    )


    # ----------------------------------------------
    # Alert IDs
    # ----------------------------------------------

    alert_ids = [
        records[i]["alert_id"]
        for i in members
        if records[i]["alert_id"]
    ]


    # ----------------------------------------------
    # First / last seen
    # ----------------------------------------------

    timestamps = [
        records[i]["timestamp"]
        for i in members
        if records[i]["timestamp"] is not None
    ]


    if timestamps:

        first_seen = iso_time(min(timestamps))
        last_seen = iso_time(max(timestamps))

    else:

        first_seen = ""
        last_seen = ""


    # ----------------------------------------------
    # Determine grouping rule
    #
    # The first matching rule in task order wins.
    # ----------------------------------------------

    root = find(members[0])

    reasons = group_reasons[root]


    grouping_rule = "residual"

    for reason in reason_priority:

        if reason in reasons:
            grouping_rule = reason
            break


    # ----------------------------------------------
    # Tentative category
    #
    # Only use a category already provided by an
    # earlier artifact. Otherwise remain unknown.
    # ----------------------------------------------

    tentative_category = "unknown"

    for i in members:

        category = records[i]["category"]

        if category:

            category = str(category).lower()

            if category in allowed_categories:
                tentative_category = category
                break


    # ----------------------------------------------
    # Confidence
    #
    # Do not invent confidence.
    # Use existing value if available.
    # ----------------------------------------------

    confidence = "low"

    for level in ("high", "medium", "low"):

        if any(
            str(records[i]["confidence"]).lower() == level
            for i in members
            if records[i]["confidence"]
        ):

            confidence = level
            break


    incident_list.append(
        {
            "incident_id": incident_id,
            "host_list": hosts,
            "user_list": users,
            "ioc_list": iocs,
            "alert_ids": alert_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "grouping_rule": grouping_rule,
            "tentative_category": tentative_category,
            "confidence": confidence,
        }
    )


# --------------------------------------------------
# Every TP is assigned because residual alerts form
# their own incident.
# --------------------------------------------------

assigned_alerts = sum(
    len(incident["alert_ids"])
    for incident in incident_list
)

unmatched_tp_count = max(
    0,
    len(records) - assigned_alerts
)


# --------------------------------------------------
# Final JSON
# --------------------------------------------------

result = {
    "shift_id": shift_id,
    "generated_at": datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ"),

    "incidents": incident_list,

    "incident_count": len(incident_list),

    "unmatched_tp_count": unmatched_tp_count,
}


with open(output_file, "w", encoding="utf-8") as f:

    json.dump(
        result,
        f,
        indent=2
    )

    f.write("\n")

PY


# --------------------------------------------------
# Check output
# --------------------------------------------------

if [[ ! -s "$OUTPUT" ]]; then
    fail "incidents.json was not created"
fi


if ! jq empty "$OUTPUT" >/dev/null 2>&1; then
    fail "incidents.json is invalid JSON"
fi


INCIDENT_COUNT=$(jq '.incident_count' "$OUTPUT")


# --------------------------------------------------
# Print one-line summary per incident
# --------------------------------------------------

jq -r '
    .incidents[]
    |
    "[group] \(.incident_id): \(.alert_ids | length) alerts  host=\(.host_list | join(","))  rule=\(.grouping_rule)"
' "$OUTPUT"


echo "[group] incident_count=$INCIDENT_COUNT"
echo "[group] incidents.json written"


# --------------------------------------------------
# Minimum incident requirement
# --------------------------------------------------

if [[ "$INCIDENT_COUNT" -lt 3 ]]; then
    fail "incident_count is below 3; review Task 5 classifications"
fi
