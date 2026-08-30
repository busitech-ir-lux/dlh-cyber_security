#!/bin/bash

# ============================================================
# TASK 2 - WINDOWS EVENT PARSING
#
# Purpose:
# Merge the three Windows NDJSON evidence files:
#
#   security.json
#   sysmon.json
#   powershell.json
#
# Then append:
#
#   student_telemetry/windows_events.json
#
# The final output is:
#
#   windows_events.json
#
# Each line in the output is one JSON object.
# ============================================================


# ============================================================
# CONFIGURATION
#
# The evidence pack can be supplied as the first argument.
#
# Example:
#
#   ./2-windows_parse.sh ~/evidence_pack_secondary
#
# If no argument is supplied, use the primary evidence pack.
#
# The second argument can optionally change the output file.
# ============================================================

PACK_DIR="${1:-$HOME/evidence_pack_primary}"
OUTPUT="${2:-windows_events.json}"

WINDOWS_DIR="$PACK_DIR/windows"
STUDENT_FILE="$PACK_DIR/student_telemetry/windows_events.json"


# ============================================================
# TEMPORARY OUTPUT
#
# We build the combined file in a temporary file first.
#
# Only after all processing succeeds do we replace the final
# windows_events.json.
#
# This also makes the script idempotent: running it twice does
# not append duplicate records to the old output.
# ============================================================

TMP_FILE=$(mktemp)

trap 'rm -f "$TMP_FILE"' EXIT

: > "$TMP_FILE"


# ============================================================
# CHECK REQUIRED DIRECTORIES AND FILES
# ============================================================

if [ ! -d "$PACK_DIR" ]; then
    echo "Error: evidence pack not found: $PACK_DIR" >&2
    exit 1
fi


if [ ! -d "$WINDOWS_DIR" ]; then
    echo "Error: Windows directory not found: $WINDOWS_DIR" >&2
    exit 1
fi




# ============================================================
# PROCESS ONE EVIDENCE-PACK WINDOWS FILE
#
# The three normal Windows files should have:
#
#   source_origin: "evidence_pack"
#
# We explicitly set that value while producing the intermediate
# output.
#
# jq -c makes sure every output event is written on exactly
# one line, which gives us NDJSON.
# ============================================================

process_windows_file()
{
    local file="$1"
    local filename
    local count

    filename=$(basename "$file")


    # --------------------------------------------------------
    # Make sure the source file exists.
    # --------------------------------------------------------

    if [ ! -f "$file" ]; then
        echo "Error: required file not found: $file" >&2
        exit 1
    fi


    # --------------------------------------------------------
    # Validate every event in the Windows NDJSON source.
    #
    # One jq process reads the whole file.
    # If even one record is missing a required field, jq stops
    # with an error.
    # --------------------------------------------------------

    if ! jq '
        if (
            has("timestamp_raw") and
            has("hostname") and
            has("event_id") and
            has("channel") and
            has("provider") and
            has("raw_message") and
            has("event_data")
        )
        then
            empty
        else
            error("missing required Windows field")
        end
    ' "$file" >/dev/null 2>&1
    then

        echo "Error: missing required field in $filename" >&2
        exit 1

    fi


    # --------------------------------------------------------
    # Convert each record to compact JSON and ensure that its
    # source origin is evidence_pack.
    #
    # Because the input is NDJSON, jq processes every record
    # independently.
    # --------------------------------------------------------

    jq -c '
        .source_origin = "evidence_pack"
    ' "$file" >> "$TMP_FILE"


    # --------------------------------------------------------
    # Count the number of records in this source file.
    #
    # The files are NDJSON, so one non-empty line represents
    # one Windows event.
    # --------------------------------------------------------

    count=$(
        awk '
            NF > 0 {
                count++
            }

            END {
                print count + 0
            }
        ' "$file"
    )


    printf "reading %-18s ... %6d records\n" \
        "$filename" \
        "$count"
}


# ============================================================
# PROCESS STUDENT TELEMETRY
#
# Student telemetry uses a slightly different schema from the
# main Windows evidence files.
#
# Example student fields:
#
#   timestamp
#   hostname
#   source_type
#   event_category
#   event_id
#   user
#   command_line
#   raw_message
#
# We map these fields into the minimum Windows intermediate
# schema without losing the useful student-specific data.
# ============================================================

process_student_telemetry()
{
    local count


    # --------------------------------------------------------
    # Make sure the student telemetry file exists.
    # --------------------------------------------------------

    if [ ! -f "$STUDENT_FILE" ]; then
        echo "Error: student telemetry not found: $STUDENT_FILE" >&2
        exit 1
    fi


    # --------------------------------------------------------
    # Validate the fields expected in the original student
    # telemetry schema.
    # --------------------------------------------------------

    if ! jq '
        if (
            has("timestamp") and
            has("hostname") and
            has("source_type") and
            has("event_id") and
            has("raw_message")
        )
        then
            empty
        else
            error("missing required student telemetry field")
        end
    ' "$STUDENT_FILE" >/dev/null 2>&1
    then

        echo "Error: student telemetry is missing required source fields" >&2
        exit 1

    fi


    # --------------------------------------------------------
    # Convert student telemetry into the common Windows
    # intermediate structure.
    #
    # Important mappings:
    #
    #   timestamp   -> timestamp_raw
    #   source_type -> channel
    #
    # Student-specific information is preserved inside
    # event_data instead of being discarded.
    # --------------------------------------------------------

    jq -c '
        {
            timestamp_raw: .timestamp,

            hostname: .hostname,

            event_id: .event_id,

            channel: .source_type,

            provider:
                (
                    if (
                        has("provider") and
                        .provider != null and
                        .provider != ""
                    )
                    then
                        .provider
                    else
                        "student_telemetry"
                    end
                ),

            raw_message: .raw_message,

            event_data: {
                event_category: (.event_category // null),
                user: (.user // null),
                command_line: (.command_line // null)
            },

            source_origin:
                (
                    if (
                        has("source_origin") and
                        .source_origin != null and
                        .source_origin != ""
                    )
                    then
                        .source_origin
                    else
                        "student_telemetry"
                    end
                )
        }
    ' "$STUDENT_FILE" >> "$TMP_FILE"


    # --------------------------------------------------------
    # Count student telemetry records.
    #
    # The source is NDJSON, so each non-empty line is one
    # event.
    # --------------------------------------------------------

    count=$(
        awk '
            NF > 0 {
                count++
            }

            END {
                print count + 0
            }
        ' "$STUDENT_FILE"
    )


    printf "appending student telemetry ... %6d records\n" \
        "$count"
}


# ============================================================
# PROCESS THE THREE WINDOWS SOURCES
#
# The order here also determines the order in the intermediate
# output file.
# ============================================================

process_windows_file "$WINDOWS_DIR/security.json"

process_windows_file "$WINDOWS_DIR/sysmon.json"

process_windows_file "$WINDOWS_DIR/powershell.json"


# ============================================================
# APPEND STUDENT TELEMETRY
# ============================================================

process_student_telemetry


# ============================================================
# FINAL VALIDATION
#
# Validate the COMPLETE NDJSON output using one jq process.
#
# This is much faster than starting jq once for every record.
#
# Each record must contain all fields required by the task.
#
# If any record is missing a required field, jq raises an
# error and the script stops before writing the final file.
# ============================================================

if ! jq '
    if (
        has("timestamp_raw") and
        has("hostname") and
        has("event_id") and
        has("channel") and
        has("provider") and
        has("raw_message") and
        has("event_data") and
        has("source_origin")
    )
    then
        empty
    else
        error("record is missing a required field")
    end
' "$TMP_FILE" >/dev/null 2>&1
then

    echo "Error: invalid record found in combined output" >&2
    exit 1

fi

# ============================================================
# WRITE FINAL OUTPUT
#
# mv replaces an old output instead of appending to it.
#
# This is important for idempotency.
# ============================================================

mv "$TMP_FILE" "$OUTPUT"

# TMP_FILE no longer exists after mv, so disable the old trap.
trap - EXIT


# ============================================================
# PRINT TOTAL RECORD COUNT
# ============================================================

total_count=$(
    awk '
        NF > 0 {
            count++
        }

        END {
            print count + 0
        }
    ' "$OUTPUT"
)


printf "%s: %d records\n" \
    "$OUTPUT" \
    "$total_count"
