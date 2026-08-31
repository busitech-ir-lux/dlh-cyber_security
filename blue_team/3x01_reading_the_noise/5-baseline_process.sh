#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 5 - PROCESS EXECUTION BASELINE
#
# Input:
#   labeled_events.json
#
# Output:
#   baseline_process.json
#
# Builds:
#   - expected processes per host
#   - global top processes
#   - rare processes
#   - observed parent -> child pairs
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

LABELED_FILE="labeled_events.json"
OUTPUT_FILE="baseline_process.json"

BASELINE_DAYS="${BASELINE_DAYS:-7}"


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

if [ ! -f "$LABELED_FILE" ]; then
    echo "Error: $LABELED_FILE not found." >&2
    exit 1
fi

if ! [[ "$BASELINE_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: BASELINE_DAYS must be a positive integer." >&2
    exit 1
fi

# Validate the NDJSON input.
if ! jq -e . "$LABELED_FILE" >/dev/null 2>&1; then
    echo "Error: $LABELED_FILE contains invalid JSON." >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILES
# ============================================================

TMP_BASELINE=$(mktemp)
TMP_PROCESS=$(mktemp)
TMP_OUTPUT=$(mktemp)

cleanup()
{
    rm -f "$TMP_BASELINE" "$TMP_PROCESS" "$TMP_OUTPUT"
}

trap cleanup EXIT


# ============================================================
# FIND BASELINE WINDOW
#
# The dates are derived from the dataset.
# Nothing is hardcoded.
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
        head -n 1
)

if [ -z "$FIRST_TIMESTAMP" ]; then
    echo "Error: no timestamps found." >&2
    exit 1
fi


# Get the first calendar day.
FIRST_DATE="${FIRST_TIMESTAMP%%T*}"

BASELINE_START="${FIRST_DATE}T00:00:00Z"


# The cutoff is exclusive.
# Example with 7 days:
#
#   start  = day 1 00:00
#   cutoff = day 8 00:00
#
BASELINE_CUTOFF=$(
    date -u \
        -d "$FIRST_DATE + $BASELINE_DAYS days" \
        '+%Y-%m-%dT00:00:00Z'
)


# ============================================================
# EXTRACT BASELINE EVENTS
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


# Last actual event observed inside the baseline.
BASELINE_END=$(
    jq -r '.timestamp' "$TMP_BASELINE" |
        sort |
        tail -n 1
)


# ============================================================
# EXTRACT PROCESS EXECUTIONS
#
# process_start:
#   normal process-start event
#
# child_process_spawn:
#   process-start event where Task 3 found parent information
#
# Both represent process execution.
# ============================================================

jq -c '
    select(
        (
            .canonical_label == "process_start"
            or
            .canonical_label == "child_process_spawn"
        )
        and
        .hostname != null
        and
        .hostname != ""
        and
        .process_name != null
        and
        .process_name != ""
    )
' "$TMP_BASELINE" > "$TMP_PROCESS"


# ============================================================
# BUILD baseline_process.json
# ============================================================

jq -s \
    --arg start "$BASELINE_START" \
    --arg end "$BASELINE_END" '

    # --------------------------------------------------------
    # Helper function:
    #
    # Turn a full path into only the process filename.
    #
    # Examples:
    #
    # C:\Windows\System32\cmd.exe -> cmd.exe
    # /usr/bin/python3            -> python3
    # --------------------------------------------------------

    def basename:

        tostring

        | gsub("\\\\"; "/")

        | split("/")

        | last;


    # All process executions.
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
        # PER-HOST PROCESS BASELINE
        #
        # Each host contains its own expected process list.
        # ====================================================

        per_host: (

            $events

            | sort_by(.hostname)

            | group_by(.hostname)

            | map(

                . as $host_events

                | {

                    key: $host_events[0].hostname,

                    value: (

                        $host_events

                        | sort_by(.process_name)

                        | group_by(.process_name)

                        | map(

                            . as $process_events

                            | {

                                process_name:
                                    $process_events[0].process_name,


                                execution_count:
                                    ($process_events | length),


                                first_seen:
                                    (
                                        $process_events
                                        | map(.timestamp)
                                        | min
                                    ),


                                last_seen:
                                    (
                                        $process_events
                                        | map(.timestamp)
                                        | max
                                    ),


                                users: (

                                    [
                                        $process_events[].user

                                        | select(
                                            . != null
                                            and
                                            . != ""
                                        )

                                        | tostring
                                    ]

                                    | unique
                                    | sort
                                )
                            }
                        )

                        | sort_by(.process_name)
                    )
                }
            )

            | from_entries
        ),


        # ====================================================
        # GLOBAL TOP 50
        #
        # This is global only for reference.
        # Per-host remains the authoritative baseline.
        # ====================================================

        global_top: (

            $events

            | sort_by(.process_name)

            | group_by(.process_name)

            | map(

                {
                    process_name: .[0].process_name,
                    execution_count: length
                }
            )

            # Highest execution count first.
            # Process name breaks ties deterministically.
            | sort_by(
                [
                    -(.execution_count),
                    .process_name
                ]
            )

            | .[:50]
        ),


        # ====================================================
        # RARE PROCESSES
        #
        # Rare means either:
        #
        #   - observed on only one host
        #
        # OR
        #
        #   - fewer than 5 executions globally
        # ====================================================

        rare_processes: (

            $events

            | sort_by(.process_name)

            | group_by(.process_name)

            | map(

                . as $process_events

                | {

                    process_name:
                        $process_events[0].process_name,


                    execution_count:
                        ($process_events | length),


                    hosts: (

                        [
                            $process_events[].hostname
                        ]

                        | unique
                        | sort
                    )
                }

                | .host_count = (.hosts | length)
            )

            | map(

                select(
                    .host_count == 1
                    or
                    .execution_count < 5
                )
            )

            | sort_by(
                [
                    .execution_count,
                    .process_name
                ]
            )
        ),


        # ====================================================
        # PARENT -> CHILD PAIRS
        #
        # Task 3 preserved vendor-specific information in
        # event_data.
        #
        # Sysmon Event 1 provides ParentImage.
        #
        # Example:
        #
        # explorer.exe -> cmd.exe
        # cmd.exe      -> powershell.exe
        #
        # Duplicate pairs are removed.
        # ====================================================

        parent_child_pairs: (

            [
                $events[]

                | select(
                    .event_data != null
                    and
                    .event_data.ParentImage != null
                    and
                    .event_data.ParentImage != ""
                )

                | {

                    hostname: .hostname,

                    parent:
                        (
                            .event_data.ParentImage
                            | basename
                        ),

                    child:
                        .process_name
                }
            ]

            | sort_by(.hostname)

            | group_by(.hostname)

            | map(

                . as $host_pairs

                | {

                    key: $host_pairs[0].hostname,

                    value: (

                        $host_pairs

                        | map(
                            {
                                parent: .parent,
                                child: .child
                            }
                        )

                        | unique_by(
                            [
                                .parent,
                                .child
                            ]
                        )

                        | sort_by(
                            [
                                .parent,
                                .child
                            ]
                        )
                    )
                }
            )

            | from_entries
        )
    }

' "$TMP_PROCESS" > "$TMP_OUTPUT"


# ============================================================
# WRITE FINAL OUTPUT
#
# mv replaces the previous file.
# No data is appended, so repeated runs are idempotent.
# ============================================================

mv "$TMP_OUTPUT" "$OUTPUT_FILE"


# ============================================================
# SUMMARY VALUES
# ============================================================

HOST_COUNT=$(
    jq '.per_host | length' "$OUTPUT_FILE"
)


TOP_PROCESS=$(
    jq -r '
        .global_top[0].process_name // "none"
    ' "$OUTPUT_FILE"
)


TOP_COUNT=$(
    jq -r '
        .global_top[0].execution_count // 0
    ' "$OUTPUT_FILE"
)


RARE_COUNT=$(
    jq '.rare_processes | length' "$OUTPUT_FILE"
)


PAIR_COUNT=$(
    jq '
        (
            [
                .parent_child_pairs[]
                | length
            ]
            | add
        )
        // 0
    ' "$OUTPUT_FILE"
)


# ============================================================
# PRINT EXPECTED OUTPUT
# ============================================================

printf "baseline window : %s -> %s\n" \
    "$BASELINE_START" "$BASELINE_END"

printf "processes indexed by host: %s hosts\n" \
    "$HOST_COUNT"

printf "global top process    : %s (%s executions)\n" \
    "$TOP_PROCESS" "$TOP_COUNT"

printf "rare processes        : %s\n" \
    "$RARE_COUNT"

printf "parent->child pairs   : %s\n" \
    "$PAIR_COUNT"

printf "baseline_process.json written\n"
