#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 10 - AUTHENTICATION ANOMALIES
#
# Inputs:
#   baseline_summary.json
#   labeled_events.json
#
# Output:
#   anomalies_auth.json
#
# The output is NDJSON:
#   one JSON object per anomaly.
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

BASELINE_PKG="${BASELINE_PKG:-.}"

SUMMARY_FILE="$BASELINE_PKG/baseline_summary.json"
LABELED_FILE="labeled_events.json"

OUTPUT_FILE="anomalies_auth.json"


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
    echo "Error: baseline summary not found: $SUMMARY_FILE" >&2
    exit 1
fi

if [ ! -f "$LABELED_FILE" ]; then
    echo "Error: labeled dataset not found: $LABELED_FILE" >&2
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
#
# Write to a temporary file first.
# This prevents a failed run from leaving a partial result.
# ============================================================

TMP_OUTPUT=$(mktemp)

cleanup()
{
    rm -f "$TMP_OUTPUT"
}

trap cleanup EXIT


# ============================================================
# FIND AUTHENTICATION ANOMALIES
#
# Python is used here because rolling one-hour windows are much
# easier to read and maintain than a large jq expression.
# ============================================================

python3 -W error - \
    "$SUMMARY_FILE" \
    "$LABELED_FILE" \
    "$TMP_OUTPUT" <<'PY'

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone


summary_file = sys.argv[1]
events_file = sys.argv[2]
output_file = sys.argv[3]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def parse_time(value):
    """
    Convert an ISO-8601 timestamp into a timezone-aware datetime.
    """

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


def event_ref(event, line_number):
    """
    Create a stable reference back to the original labeled event.
    """

    return {
        "file": "labeled_events.json",
        "line": line_number,
        "event_id": event.get("event_id"),
        "source_type": event.get("source_type")
    }


def auth_event(event):
    """
    Return True only for authentication-related canonical events.
    """

    return event.get("canonical_label") in {
        "login_success",
        "login_failure",
        "logout",
        "account_lockout",
        "privilege_escalation"
    }


# ============================================================
# LOAD BASELINE SUMMARY
# ============================================================

with open(summary_file, "r", encoding="utf-8") as file:
    summary = json.load(file)


baseline_window = summary.get("baseline_window", {})
evaluation_window = summary.get("evaluation_window", {})
auth_baseline = summary.get("auth", {})
thresholds = summary.get("thresholds", {})


# ============================================================
# READ REQUIRED WINDOW VALUES
# ============================================================

baseline_start = parse_time(baseline_window.get("start"))
evaluation_start = parse_time(evaluation_window.get("start"))

baseline_days = baseline_window.get("duration_days")
evaluation_hours = evaluation_window.get("duration_hours")


if baseline_start is None:
    raise SystemExit("Error: baseline_window.start missing or invalid.")

if evaluation_start is None:
    raise SystemExit("Error: evaluation_window.start missing or invalid.")

if not isinstance(baseline_days, (int, float)):
    raise SystemExit("Error: baseline_window.duration_days missing.")

if not isinstance(evaluation_hours, (int, float)):
    raise SystemExit("Error: evaluation_window.duration_hours missing.")


# Use duration values from the summary instead of hardcoding dates.
baseline_end_exclusive = (
    baseline_start + timedelta(days=baseline_days)
)

evaluation_end_exclusive = (
    evaluation_start + timedelta(hours=evaluation_hours)
)


# ============================================================
# READ BASELINE-DERIVED THRESHOLDS
# ============================================================

failure_multiplier = thresholds.get("failure_rate_multiplier")

# Task 9 may expose max failures in thresholds directly.
# It is also present inside the nested auth baseline.
baseline_max_failures = thresholds.get(
    "max_failures_1h_window",
    auth_baseline.get("max_failures_1h_window")
)


if not isinstance(failure_multiplier, (int, float)):
    raise SystemExit(
        "Error: failure_rate_multiplier missing from baseline summary."
    )

if not isinstance(baseline_max_failures, (int, float)):
    raise SystemExit(
        "Error: max_failures_1h_window missing from baseline summary."
    )


failure_burst_threshold = (
    baseline_max_failures * failure_multiplier
)


# ============================================================
# KNOWN BASELINE DATA
# ============================================================

known_accounts = {
    str(user)
    for user in auth_baseline.get("known_accounts", [])
}

baseline_per_host = auth_baseline.get("per_host", {})

baseline_hosts = {
    str(host)
    for host in summary.get("host_inventory", [])
}


# ============================================================
# LOAD LABELED EVENTS
#
# Keep the original line number so event_refs can point back to
# the exact record.
# ============================================================

baseline_events = []
evaluation_events = []


with open(events_file, "r", encoding="utf-8") as file:

    for line_number, line in enumerate(file, start=1):

        event = json.loads(line)

        timestamp = parse_time(event.get("timestamp"))

        if timestamp is None:
            continue

        record = {
            "event": event,
            "timestamp": timestamp,
            "line": line_number
        }

        if (
            baseline_start
            <= timestamp
            < baseline_end_exclusive
        ):
            baseline_events.append(record)

        elif (
            evaluation_start
            <= timestamp
            < evaluation_end_exclusive
        ):
            evaluation_events.append(record)


# ============================================================
# FIND USERS WHO ONLY LOGGED IN DURING BUSINESS HOURS
#
# Task 4 defines business hours as:
#
#   06:00 through 17:59
#
# A user qualifies only when:
#
#   - at least one successful baseline login exists
#   - every successful baseline login is during business hours
# ============================================================

baseline_success_hours = defaultdict(list)


for record in baseline_events:

    event = record["event"]

    if event.get("canonical_label") != "login_success":
        continue

    user = event.get("user")

    if user is None or str(user) == "":
        continue

    hour = record["timestamp"].hour

    baseline_success_hours[str(user)].append(hour)


business_only_users = set()


for user, hours in baseline_success_hours.items():

    if hours and all(6 <= hour <= 17 for hour in hours):
        business_only_users.add(user)


# ============================================================
# COLLECT ANOMALIES
# ============================================================

anomalies = []


# ============================================================
# 1. UNKNOWN ACCOUNT
#
# An authentication event using a user not seen anywhere in the
# baseline known_accounts list.
# ============================================================

for record in evaluation_events:

    event = record["event"]

    if not auth_event(event):
        continue

    user = event.get("user")

    if user is None or str(user) == "":
        continue

    user = str(user)

    if user in known_accounts:
        continue

    anomalies.append(
        {
            "timestamp": event.get("timestamp"),
            "host": event.get("hostname"),
            "user": user,
            "src_ip": event.get("src_ip"),
            "anomaly_type": "unknown_account",
            "baseline_value": "not present in known_accounts",
            "observed_value": user,
            "severity": "high",
            "event_refs": [
                event_ref(
                    event,
                    record["line"]
                )
            ]
        }
    )


# ============================================================
# 2. OFF-HOURS LOGIN
#
# Trigger only when:
#
#   - evaluation event is login_success
#   - login occurs outside 06:00-17:59
#   - the same user had successful logins during the baseline
#   - ALL baseline successful logins were during business hours
# ============================================================

for record in evaluation_events:

    event = record["event"]

    if event.get("canonical_label") != "login_success":
        continue

    user = event.get("user")

    if user is None or str(user) == "":
        continue

    user = str(user)

    if user not in business_only_users:
        continue

    hour = record["timestamp"].hour

    if 6 <= hour <= 17:
        continue

    anomalies.append(
        {
            "timestamp": event.get("timestamp"),
            "host": event.get("hostname"),
            "user": user,
            "src_ip": event.get("src_ip"),
            "anomaly_type": "offhours_login",
            "baseline_value": "business-hours-only login history",
            "observed_value": event.get("timestamp"),
            "severity": "medium",
            "event_refs": [
                event_ref(
                    event,
                    record["line"]
                )
            ]
        }
    )


# ============================================================
# 3. FAILURE RATE BURST
#
# Group evaluation login failures by src_ip.
#
# For each source:
#
#   - sort timestamps
#   - calculate the largest rolling 60-minute window
#   - compare it with:
#
#       baseline max failures
#       x failure_rate_multiplier
#
# Emit one anomaly for the maximum violating window per src_ip.
# ============================================================

failures_by_ip = defaultdict(list)


for record in evaluation_events:

    event = record["event"]

    if event.get("canonical_label") != "login_failure":
        continue

    src_ip = event.get("src_ip")

    if src_ip is None or str(src_ip) == "":
        continue

    failures_by_ip[str(src_ip)].append(record)


for src_ip, records in failures_by_ip.items():

    records.sort(
        key=lambda item: item["timestamp"]
    )

    left = 0

    best_left = 0
    best_right = -1
    best_count = 0


    # --------------------------------------------------------
    # Sliding one-hour window
    # --------------------------------------------------------

    for right in range(len(records)):

        while (
            records[right]["timestamp"]
            - records[left]["timestamp"]
            >= timedelta(hours=1)
        ):
            left += 1

        count = right - left + 1

        if count > best_count:
            best_count = count
            best_left = left
            best_right = right


    # Only values GREATER than the baseline-derived threshold
    # are anomalies.
    if best_count <= failure_burst_threshold:
        continue


    burst_records = records[
        best_left:best_right + 1
    ]

    first_event = burst_records[0]["event"]


    anomalies.append(
        {
            "timestamp": first_event.get("timestamp"),
            "host": first_event.get("hostname"),
            "user": first_event.get("user"),
            "src_ip": src_ip,
            "anomaly_type": "failure_rate_burst",
            "baseline_value": failure_burst_threshold,
            "observed_value": best_count,
            "severity": "high",
            "event_refs": [
                event_ref(
                    item["event"],
                    item["line"]
                )
                for item in burst_records
            ],
            "details": {
                "baseline_max_failures_1h":
                    baseline_max_failures,

                "failure_rate_multiplier":
                    failure_multiplier
            }
        }
    )


# ============================================================
# 4. PRIVILEGE ESCALATION SURGE
#
# Count evaluation privilege_escalation events by host.
#
# The requirement applies to hosts where the baseline contains
# zero privilege-escalation events.
#
# Therefore N is the host's baseline value:
#
#   N = 0
#
# and an observed value greater than that baseline is anomalous.
# ============================================================

privilege_by_host = defaultdict(list)


for record in evaluation_events:

    event = record["event"]

    if event.get("canonical_label") != "privilege_escalation":
        continue

    host = event.get("hostname")

    if host is None or str(host) == "":
        continue

    privilege_by_host[str(host)].append(record)


for host, records in privilege_by_host.items():

    # Only compare known baseline hosts.
    if host not in baseline_hosts:
        continue

    host_baseline = baseline_per_host.get(
        host,
        {}
    )

    baseline_count = host_baseline.get(
        "privilege_escalation",
        0
    )


    # This anomaly specifically requires a zero baseline.
    if baseline_count != 0:
        continue


    observed_count = len(records)

    # N is the baseline count, which is zero here.
    if observed_count <= baseline_count:
        continue


    first_event = records[0]["event"]


    anomalies.append(
        {
            "timestamp": first_event.get("timestamp"),
            "host": host,
            "user": first_event.get("user"),
            "src_ip": first_event.get("src_ip"),
            "anomaly_type": "privilege_escalation_surge",
            "baseline_value": baseline_count,
            "observed_value": observed_count,
            "severity": "high",
            "event_refs": [
                event_ref(
                    item["event"],
                    item["line"]
                )
                for item in records
            ]
        }
    )


# ============================================================
# DETERMINISTIC ORDER
#
# Sort the results so repeated runs produce the same order.
# ============================================================

anomalies.sort(
    key=lambda item: (
        item.get("timestamp") or "",
        item.get("anomaly_type") or "",
        item.get("host") or "",
        item.get("user") or ""
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
# REPLACE FINAL OUTPUT
#
# Do not append. Replacing the file keeps the script idempotent.
# ============================================================

mv "$TMP_OUTPUT" "$OUTPUT_FILE"
TMP_OUTPUT=""


# ============================================================
# READ EVALUATION WINDOW FOR DISPLAY
# ============================================================

EVAL_START=$(
    jq -r '.evaluation_window.start' \
        "$SUMMARY_FILE"
)

EVAL_END=$(
    jq -r '.evaluation_window.end' \
        "$SUMMARY_FILE"
)


# ============================================================
# COUNT ANOMALIES
# ============================================================

UNKNOWN_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "unknown_account"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


BURST_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "failure_rate_burst"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


OFFHOURS_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "offhours_login"
        )
        | 1
    ' "$OUTPUT_FILE" |
        wc -l |
        tr -d ' '
)


PRIV_COUNT=$(
    jq -r '
        select(
            .anomaly_type == "privilege_escalation_surge"
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

printf "evaluation window  : %s -> %s\n" \
    "$EVAL_START" "$EVAL_END"

printf "unknown_account           : %s\n" \
    "$UNKNOWN_COUNT"

printf "failure_rate_burst        : %s\n" \
    "$BURST_COUNT"

printf "offhours_login            : %s\n" \
    "$OFFHOURS_COUNT"

printf "privilege_escalation_surge: %s\n" \
    "$PRIV_COUNT"

printf "total anomalies           : %s\n" \
    "$TOTAL_COUNT"

printf "anomalies_auth.json written\n"
