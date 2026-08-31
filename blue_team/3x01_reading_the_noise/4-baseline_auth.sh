#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 4 - AUTHENTICATION BASELINE
#
# Input:
#   labeled_events.json
#
# Output:
#   baseline_auth.json
#
# The baseline covers the first 7 days by default.
# BASELINE_DAYS can override this value.
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

LABELED_FILE="labeled_events.json"
OUTPUT_FILE="baseline_auth.json"

BASELINE_DAYS="${BASELINE_DAYS:-7}"


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

if [ ! -f "$LABELED_FILE" ]; then
    echo "Error: $LABELED_FILE not found." >&2
    exit 1
fi

# BASELINE_DAYS must be a positive integer.
if ! [[ "$BASELINE_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: BASELINE_DAYS must be a positive integer." >&2
    exit 1
fi

# Check that every line contains valid JSON.
if ! jq -e . "$LABELED_FILE" >/dev/null 2>&1; then
    echo "Error: $LABELED_FILE contains invalid JSON." >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILES
# ============================================================

TMP_BASELINE=$(mktemp)
TMP_AUTH=$(mktemp)
TMP_OUTPUT=$(mktemp)

cleanup()
{
    rm -f "$TMP_BASELINE" "$TMP_AUTH" "$TMP_OUTPUT"
}

trap cleanup EXIT


# ============================================================
# FIND THE FIRST DATE IN THE DATASET
#
# The project says the window must be derived from the data.
# We find the earliest timestamp and use its calendar day as
# day 1 of the baseline.
# ============================================================

FIRST_TIMESTAMP=$(
    jq -r '
        select(
            .timestamp != null
            and
            (.timestamp | type) == "string"
            and
            .timestamp != ""
        )
        | .timestamp
    ' "$LABELED_FILE" |
        sort |
        sed -n '1p'
)


if [ -z "$FIRST_TIMESTAMP" ]; then
    echo "Error: no timestamps found in dataset." >&2
    exit 1
fi


# Get only the YYYY-MM-DD part.
FIRST_DATE="${FIRST_TIMESTAMP%%T*}"


# Baseline begins at midnight on the first dataset day.
BASELINE_START="${FIRST_DATE}T00:00:00Z"


# Calculate the beginning of the evaluation window.
# This is an exclusive boundary.
BASELINE_CUTOFF=$(
    date -u \
        -d "$FIRST_DATE + $BASELINE_DAYS days" \
        '+%Y-%m-%dT00:00:00Z'
)


# ============================================================
# EXTRACT THE BASELINE WINDOW
#
# Start is inclusive.
# Cutoff is exclusive.
#
# Example:
#
#   timestamp >= day 1 00:00
#   timestamp <  day 8 00:00
# ============================================================

jq -c \
    --arg start "$BASELINE_START" \
    --arg cutoff "$BASELINE_CUTOFF" '
        select(
            .timestamp >= $start
            and
            .timestamp < $cutoff
        )
    ' "$LABELED_FILE" > "$TMP_BASELINE"


if [ ! -s "$TMP_BASELINE" ]; then
    echo "Error: no events found in baseline window." >&2
    exit 1
fi


# ============================================================
# FIND THE LAST ACTUAL EVENT IN THE BASELINE
#
# This value is stored as window.end in baseline_auth.json.
# ============================================================

BASELINE_END=$(
    jq -r '.timestamp' "$TMP_BASELINE" |
        sort |
        tail -n 1
)


# ============================================================
# KEEP ONLY AUTHENTICATION-RELATED EVENTS
# ============================================================

jq -c '
    select(
        .canonical_label == "login_success"
        or
        .canonical_label == "login_failure"
        or
        .canonical_label == "logout"
        or
        .canonical_label == "account_lockout"
        or
        .canonical_label == "privilege_escalation"
    )
' "$TMP_BASELINE" > "$TMP_AUTH"


# ============================================================
# MAXIMUM FAILURES IN ANY ROLLING 1-HOUR WINDOW
#
# We use a small Python section because a sliding time window
# is much easier and clearer to calculate this way.
#
# For each src_ip:
#
#   1. collect failure timestamps
#   2. sort them
#   3. move a 60-minute window through them
#   4. keep the largest count
# ============================================================

MAX_FAILURES=$(
    python3 - "$TMP_AUTH" <<'PY'
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


filename = sys.argv[1]

failures = defaultdict(list)


# ------------------------------------------------------------
# Read login failures
# ------------------------------------------------------------

with open(filename, "r", encoding="utf-8") as file:
    for line in file:
        event = json.loads(line)

        if event.get("canonical_label") != "login_failure":
            continue

        src_ip = event.get("src_ip")
        timestamp = event.get("timestamp")

        if not src_ip or not timestamp:
            continue

        # Convert Z into a format datetime understands.
        timestamp = timestamp.replace("Z", "+00:00")

        try:
            dt = datetime.fromisoformat(timestamp)
        except ValueError:
            continue

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        failures[src_ip].append(dt.timestamp())


# ------------------------------------------------------------
# Find the largest rolling 1-hour failure count
# ------------------------------------------------------------

maximum = 0

for timestamps in failures.values():

    timestamps.sort()

    left = 0

    for right in range(len(timestamps)):

        # Keep only events less than 3600 seconds apart.
        while timestamps[right] - timestamps[left] >= 3600:
            left += 1

        count = right - left + 1

        if count > maximum:
            maximum = count


print(maximum)
PY
)


# ============================================================
# BUILD baseline_auth.json
# ============================================================
#
# Business hours:
#   06:00 through 17:59
#
# Off hours:
#   18:00 through 05:59
#
# There are 12 business hours and 12 off-hours per day.
#
# We divide by ALL possible hours in the baseline, including
# hours where zero authentication events happened.
# ============================================================

jq -s \
    --arg start "$BASELINE_START" \
    --arg end "$BASELINE_END" \
    --argjson baseline_days "$BASELINE_DAYS" \
    --argjson max_failures "$MAX_FAILURES" '

    # --------------------------------------------------------
    # Helper: count one canonical label inside an event list.
    # --------------------------------------------------------

    def count_label($events; $label):
        [
            $events[]
            | select(.canonical_label == $label)
        ]
        | length;


    # --------------------------------------------------------
    # Store all authentication events in $events.
    # --------------------------------------------------------

    . as $events


    | {


        # ====================================================
        # BASELINE WINDOW
        # ====================================================

        window: {
            start: $start,
            end: $end
        },


        # ====================================================
        # PER HOST
        # ====================================================

        per_host: (

            [
                $events[]
                | select(
                    .hostname != null
                    and
                    .hostname != ""
                )
            ]

            | sort_by(.hostname)

            | group_by(.hostname)

            | map(

                . as $host_events

                | {
                    key: $host_events[0].hostname,

                    value: {

                        login_success:
                            count_label(
                                $host_events;
                                "login_success"
                            ),

                        login_failure:
                            count_label(
                                $host_events;
                                "login_failure"
                            ),

                        logout:
                            count_label(
                                $host_events;
                                "logout"
                            ),

                        account_lockout:
                            count_label(
                                $host_events;
                                "account_lockout"
                            ),

                        privilege_escalation:
                            count_label(
                                $host_events;
                                "privilege_escalation"
                            )
                    }
                }
            )

            | from_entries
        ),


        # ====================================================
        # PER USER
        #
        # Requirement:
        # success and failure counts for each observed account.
        # ====================================================

        per_user: (

            [
                $events[]
                | select(
                    .user != null
                    and
                    (.user | tostring) != ""
                )
            ]

            | sort_by(.user)

            | group_by(.user)

            | map(

                . as $user_events

                | {

                    user: ($user_events[0].user | tostring),

                    login_success:
                        count_label(
                            $user_events;
                            "login_success"
                        ),

                    login_failure:
                        count_label(
                            $user_events;
                            "login_failure"
                        )
                }
            )
        ),


        # ====================================================
        # KNOWN ACCOUNTS
        # ====================================================

        known_accounts: (

            [
                $events[]

                | select(
                    .user != null
                    and
                    (.user | tostring) != ""
                )

                | (.user | tostring)
            ]

            | unique
            | sort
        ),


        # ====================================================
        # BUSINESS HOURS AVERAGE
        #
        # Business hours = 06:00 - 17:59
        #
        # Divide by:
        #     baseline days * 12 hours
        # ====================================================

        business_hours_avg: {

            success_per_hour: (

                (
                    [
                        $events[]

                        | select(
                            .canonical_label == "login_success"
                        )

                        | (.timestamp[11:13] | tonumber) as $hour

                        | select(
                            $hour >= 6
                            and
                            $hour <= 17
                        )
                    ]

                    | length
                )

                /

                ($baseline_days * 12)
            ),


            failure_per_hour: (

                (
                    [
                        $events[]

                        | select(
                            .canonical_label == "login_failure"
                        )

                        | (.timestamp[11:13] | tonumber) as $hour

                        | select(
                            $hour >= 6
                            and
                            $hour <= 17
                        )
                    ]

                    | length
                )

                /

                ($baseline_days * 12)
            )
        },


        # ====================================================
        # OFF-HOURS AVERAGE
        #
        # Off hours = 18:00 - 05:59
        # ====================================================

        offhours_avg: {

            success_per_hour: (

                (
                    [
                        $events[]

                        | select(
                            .canonical_label == "login_success"
                        )

                        | (.timestamp[11:13] | tonumber) as $hour

                        | select(
                            $hour >= 18
                            or
                            $hour <= 5
                        )
                    ]

                    | length
                )

                /

                ($baseline_days * 12)
            ),


            failure_per_hour: (

                (
                    [
                        $events[]

                        | select(
                            .canonical_label == "login_failure"
                        )

                        | (.timestamp[11:13] | tonumber) as $hour

                        | select(
                            $hour >= 18
                            or
                            $hour <= 5
                        )
                    ]

                    | length
                )

                /

                ($baseline_days * 12)
            )
        },


        # ====================================================
        # FAILURE BURST BASELINE
        # ====================================================

        max_failures_1h_window: $max_failures
    }

' "$TMP_AUTH" > "$TMP_OUTPUT"


# ============================================================
# WRITE FINAL OUTPUT
#
# Replace instead of append so repeated runs are idempotent.
# ============================================================

mv "$TMP_OUTPUT" "$OUTPUT_FILE"

TMP_OUTPUT=""


# ============================================================
# PRINT EXPECTED SUMMARY
# ============================================================

HOST_COUNT=$(
    jq '.per_host | length' "$OUTPUT_FILE"
)

ACCOUNT_COUNT=$(
    jq '.known_accounts | length' "$OUTPUT_FILE"
)

BUSINESS_SUCCESS=$(
    jq -r '.business_hours_avg.success_per_hour' "$OUTPUT_FILE"
)

BUSINESS_FAILURE=$(
    jq -r '.business_hours_avg.failure_per_hour' "$OUTPUT_FILE"
)

OFFHOURS_SUCCESS=$(
    jq -r '.offhours_avg.success_per_hour' "$OUTPUT_FILE"
)

OFFHOURS_FAILURE=$(
    jq -r '.offhours_avg.failure_per_hour' "$OUTPUT_FILE"
)


printf "baseline window : %s -> %s\n" \
    "$BASELINE_START" "$BASELINE_END"

printf "hosts           : %s\n" "$HOST_COUNT"

printf "known accounts  : %s\n" "$ACCOUNT_COUNT"

printf "business hours  : %.2f success/h  |  %.2f failure/h\n" \
    "$BUSINESS_SUCCESS" "$BUSINESS_FAILURE"

printf "off hours       : %.2f success/h  |  %.2f failure/h\n" \
    "$OFFHOURS_SUCCESS" "$OFFHOURS_FAILURE"

printf "max 1h src_ip failures : %s\n" "$MAX_FAILURES"

printf "baseline_auth.json written\n"
