#!/bin/bash

# ============================================================
# TASK 0 - EVIDENCE PACK INVENTORY
#
# This script inventories every file under:
#
#   windows/
#   linux/
#   network/
#
# It creates source_inventory.json containing:
#
#   - path
#   - source_type
#   - size_bytes
#   - sha256
#   - line_count
#   - record_count
#   - first_event_time
#   - last_event_time
#
# The script accepts another evidence pack as argument, so it
# can later work with the secondary pack without modification.
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

PACK_DIR="${1:-$HOME/evidence_pack_primary}"
OUTPUT="${2:-source_inventory.json}"


# ============================================================
# INPUT VALIDATION
#
# Stop if the evidence pack itself does not exist.
# ============================================================

if [ ! -d "$PACK_DIR" ]; then
    echo "Error: evidence pack not found: $PACK_DIR" >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILE
#
# Each source is first written as one JSON object.
# At the end, jq combines all objects into one JSON array.
# ============================================================

TMP_FILE=$(mktemp)

trap 'rm -f "$TMP_FILE"' EXIT

: > "$TMP_FILE"


# ============================================================
# CHECK EXPECTED DIRECTORIES
#
# Do not stop if one source directory is missing.
#
# A missing directory may itself indicate an incomplete
# evidence pack, so print a warning instead.
# ============================================================

for directory in windows linux network
do
    if [ ! -d "$PACK_DIR/$directory" ]; then
        echo "Warning: missing directory: $directory/" >&2
    fi
done


# ============================================================
# DETECT JSON INPUT TYPE
#
# We explicitly distinguish JSON arrays from JSON streams.
#
# ARRAY example:
#
# [
#   {"id": 1},
#   {"id": 2}
# ]
#
# STREAM / NDJSON example:
#
# {"id": 1}
# {"id": 2}
#
# A normal single JSON object is also treated as a stream with
# one record.
#
# Returning explicit modes makes the handling clear:
#
#   array
#   stream
#   invalid
# ============================================================

json_input_type()
{
    local file="$1"

    # --------------------------------------------------------
    # First test specifically for a valid JSON array.
    #
    # This creates an explicit code path for arrays instead of
    # treating all JSON formats the same.
    # --------------------------------------------------------

    if jq -e 'type == "array"' "$file" >/dev/null 2>&1; then

        printf '%s\n' "array"
        return

    fi


    # --------------------------------------------------------
    # If it is not an array, test whether jq can parse the file
    # as one or more top-level JSON values.
    #
    # This supports:
    #
    #   single JSON object
    #   NDJSON / JSON stream
    # --------------------------------------------------------

    if jq -c '.' "$file" >/dev/null 2>&1; then

        printf '%s\n' "stream"
        return

    fi


    # --------------------------------------------------------
    # If neither parser succeeds, mark the source as invalid
    # JSON rather than silently guessing that parsing worked.
    # --------------------------------------------------------

    printf '%s\n' "invalid"
}


# ============================================================
# COUNT JSON RECORDS
#
# Array and stream formats are intentionally counted using
# different methods.
#
# JSON array:
#   use the array length
#
# NDJSON / JSON stream:
#   count top-level JSON values
#
# Single JSON object:
#   count is 1
# ============================================================

json_record_count()
{
    local file="$1"
    local mode="$2"

    case "$mode" in

        array)

            # Count elements inside the JSON array.
            jq 'length' "$file" 2>/dev/null
            ;;


        stream)

            # jq prints one compact line for each top-level
            # JSON value.
            #
            # Therefore:
            #
            # single object = 1
            # NDJSON with 100 objects = 100
            jq -c '.' "$file" 2>/dev/null |
                awk 'END {print NR + 0}'
            ;;


        *)

            # Should only happen for invalid JSON.
            printf '%s\n' "0"
            ;;

    esac
}


# ============================================================
# FIND TIMESTAMP PATH IN JSON
#
# Security sources use different names for timestamps.
#
# Examples from this evidence pack include:
#
#   timestamp_raw
#   timestamp
#   time
#
# We inspect only the FIRST event to discover the timestamp
# field. We do not recursively search every event because that
# would be very slow for large Windows logs.
# ============================================================

json_time_path()
{
    local file="$1"

    jq -c '

        # ----------------------------------------------------
        # If this source is an array, inspect only the first
        # element.
        #
        # If it is NDJSON, jq processes the first top-level
        # event and head below stops after the first result.
        # ----------------------------------------------------

        if type == "array" then
            .[0]
        else
            .
        end

        |

        # ----------------------------------------------------
        # Find scalar fields whose key looks like an event
        # timestamp.
        # ----------------------------------------------------

        [
            paths(scalars) as $path

            |

            ($path[-1] | tostring | ascii_downcase) as $key

            |

            select(
                $key == "timestamp_raw" or
                $key == "timestamp" or
                $key == "@timestamp" or
                $key == "systemtime" or
                $key == "@systemtime" or
                $key == "timecreated" or
                $key == "event_time" or
                $key == "eventtime" or
                $key == "datetime" or
                $key == "utctime" or
                $key == "utc_time" or
                $key == "start_time" or
                $key == "end_time" or
                $key == "first_time" or
                $key == "last_time" or
                $key == "time"
            )

            |

            $path
        ]

        |

        # Use the first matching timestamp path.
        .[0] // empty

    ' "$file" 2>/dev/null |
        head -n 1
}


# ============================================================
# EXTRACT JSON EVENT TIMES
#
# First discover the timestamp path.
#
# Then use that same path against every event in the file.
#
# This works with both:
#
#   JSON arrays
#   NDJSON / JSON streams
# ============================================================

json_event_times()
{
    local file="$1"
    local time_path

    time_path=$(json_time_path "$file")


    # If no timestamp field could be identified, return no
    # value. The manifest will use null.
    if [ -z "$time_path" ]; then
        return
    fi


    jq -r \
        --argjson time_path "$time_path" \
        '

        # Expand an array into individual records.
        #
        # For NDJSON, each input is already processed as an
        # individual record by jq.
        if type == "array" then
            .[]
        else
            .
        end

        |

        getpath($time_path)?

        |

        select(. != null and . != "")

        |

        tostring

        ' "$file" 2>/dev/null
}


# ============================================================
# NORMALIZE TIMESTAMP
#
# All timestamps written to the manifest should use:
#
#   YYYY-MM-DDTHH:MM:SSZ
#
# Examples accepted here:
#
#   1773792002
#   03/20/2026 11:16:56 PM
#   2026-03-18T00:00:31.026524+0000
#   2026-03-18T00:00:13Z
# ============================================================

normalize_time_value()
{
    local value="$1"
    local seconds

    if [ -z "$value" ]; then
        return
    fi


    # --------------------------------------------------------
    # Unix epoch timestamp.
    # --------------------------------------------------------

    if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then

        seconds=${value%%.*}

        date -u -d "@$seconds" \
            '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null

        return
    fi


    # --------------------------------------------------------
    # Other date formats.
    #
    # TZ=UTC gives timestamps without an explicit timezone a
    # predictable UTC interpretation for this evidence pack.
    # --------------------------------------------------------

    TZ=UTC date -u -d "$value" \
        '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
}


# ============================================================
# FIRST JSON EVENT TIME
# ============================================================

json_first_time()
{
    local raw_time

    raw_time=$(json_event_times "$1" | head -n 1)

    normalize_time_value "$raw_time"
}


# ============================================================
# LAST JSON EVENT TIME
# ============================================================

json_last_time()
{
    local raw_time

    raw_time=$(json_event_times "$1" | tail -n 1)

    normalize_time_value "$raw_time"
}


# ============================================================
# FIRST LINUX EVENT TIME
#
# audit.log commonly stores an epoch timestamp inside:
#
#   audit(1773792000.123:123)
#
# auth.log and syslog usually begin with:
#
#   Mar 18 00:00:38
# ============================================================

linux_first_time()
{
    local file="$1"
    local audit_time
    local raw_time


    # --------------------------------------------------------
    # AUDIT LOG
    #
    # Audit records are not guaranteed to be in perfect
    # chronological order.
    #
    # Extract all audit timestamps, sort them numerically and
    # use the earliest one.
    # --------------------------------------------------------

    audit_time=$(
        grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
            sed 's/audit(//' |
            sort -n |
            head -n 1
    )


    if [ -n "$audit_time" ]; then

        normalize_time_value "$audit_time"
        return

    fi


    # --------------------------------------------------------
    # NORMAL LINUX TEXT LOG
    #
    # Read the first non-empty event line.
    # --------------------------------------------------------

    raw_time=$(
        awk '

            NF > 0 {

                if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) {
                    print $1
                } else {
                    print $1 " " $2 " " $3
                }

                exit
            }

        ' "$file"
    )


    normalize_time_value "$raw_time"
}


# ============================================================
# LAST LINUX EVENT TIME
# ============================================================

linux_last_time()
{
    local file="$1"
    local audit_time
    local raw_time


    # --------------------------------------------------------
    # AUDIT LOG
    #
    # Sort all audit timestamps and use the newest one.
    # --------------------------------------------------------

    audit_time=$(
        grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
            sed 's/audit(//' |
            sort -n |
            tail -n 1
    )


    if [ -n "$audit_time" ]; then

        normalize_time_value "$audit_time"
        return

    fi


    # --------------------------------------------------------
    # NORMAL LINUX TEXT LOG
    #
    # Remember the timestamp from the last non-empty line.
    # --------------------------------------------------------

    raw_time=$(
        awk '

            NF > 0 {

                if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) {
                    last = $1
                } else {
                    last = $1 " " $2 " " $3
                }
            }

            END {
                print last
            }

        ' "$file"
    )


    normalize_time_value "$raw_time"
}


# ============================================================
# FIND TIMESTAMP COLUMN IN CSV
#
# First inspect the header.
#
# If the header does not clearly identify the timestamp, check
# the first data row for either:
#
#   YYYY-MM-DD...
#
# or a Unix epoch-like number.
# ============================================================

csv_time_column()
{
    local file="$1"

    awk -F',' '

        # ----------------------------------------------------
        # Check the header.
        # ----------------------------------------------------

        NR == 1 {

            for (i = 1; i <= NF; i++) {

                field = $i

                gsub(/"/, "", field)

                field = tolower(field)


                if (field == "timestamp" || field == "time" || field == "event_time" || field == "datetime" || field == "date") {
                    print i
                    exit
                }
            }
        }


        # ----------------------------------------------------
        # If the header did not help, inspect the first record.
        # ----------------------------------------------------

        NR == 2 {

            for (i = 1; i <= NF; i++) {

                value = $i

                gsub(/"/, "", value)


                # ISO-style timestamp.
                if (value ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) {
                    print i
                    exit
                }


                # Unix epoch-like timestamp.
                if (value ~ /^[0-9]+$/ && length(value) >= 10 && length(value) <= 13) {
                    print i
                    exit
                }
            }
        }

    ' "$file"
}


# ============================================================
# FIRST CSV EVENT TIME
# ============================================================

csv_first_time()
{
    local file="$1"
    local column="$2"
    local raw_time

    raw_time=$(
        awk -F',' -v col="$column" '

            NR == 2 {

                value = $col

                gsub(/^"|"$/, "", value)

                print value
                exit
            }

        ' "$file"
    )


    normalize_time_value "$raw_time"
}


# ============================================================
# LAST CSV EVENT TIME
# ============================================================

csv_last_time()
{
    local file="$1"
    local column="$2"
    local raw_time

    raw_time=$(
        awk -F',' -v col="$column" '

            NR > 1 && $col != "" {

                value = $col

                gsub(/^"|"$/, "", value)

                last = value
            }

            END {
                print last
            }

        ' "$file"
    )


    normalize_time_value "$raw_time"
}


# ============================================================
# DETECT NETWORK SOURCE TYPE
#
# The task allows two network types:
#
#   network_csv
#   network_json
#
# Do not depend only on the file extension.
#
# First test the actual content as JSON.
#
# If it is not JSON, check whether the first line looks like
# CSV.
#
# This means a valid JSON file with an unexpected filename is
# still inventoried correctly.
# ============================================================

network_source_type()
{
    local file="$1"
    local json_mode

    json_mode=$(json_input_type "$file")


    # --------------------------------------------------------
    # Valid JSON array, object or NDJSON.
    # --------------------------------------------------------

    if [ "$json_mode" != "invalid" ]; then

        printf '%s\n' "network_json"
        return

    fi


    # --------------------------------------------------------
    # If the content contains comma-separated fields, treat it
    # as network CSV.
    # --------------------------------------------------------

    if head -n 1 "$file" | grep -q ','; then

        printf '%s\n' "network_csv"
        return

    fi


    # --------------------------------------------------------
    # Fallback based on filename.
    #
    # IMPORTANT:
    # We still inventory the file. We do NOT skip it.
    # --------------------------------------------------------

    case "$file" in

        *.csv|*.CSV)
            printf '%s\n' "network_csv"
            ;;

        *)
            printf '%s\n' "network_json"
            ;;

    esac
}


# ============================================================
# INVENTORY EVERY FILE
#
# This find command does NOT restrict filenames or extensions.
#
# Every file anywhere under:
#
#   windows/
#   linux/
#   network/
#
# is passed into the inventory loop.
#
# This directly addresses the requirement to inventory every
# source file rather than only *.json or *.csv filenames.
# ============================================================

find "$PACK_DIR" -type f \
    \( \
        -path "$PACK_DIR/windows/*" \
        -o -path "$PACK_DIR/linux/*" \
        -o -path "$PACK_DIR/network/*" \
    \) \
    -print 2>/dev/null |
sort |
while IFS= read -r file
do

    # ========================================================
    # COMMON METADATA
    # ========================================================

    relative_path="${file#"$PACK_DIR"/}"

    size_bytes=$(stat -c '%s' "$file")

    sha256=$(sha256sum "$file" | awk '{print $1}')


    # ========================================================
    # DEFAULT VALUES
    #
    # Both count fields exist in every manifest object.
    #
    # The unused count type is stored as null.
    # ========================================================

    line_count="null"
    record_count="null"

    first_time=""
    last_time=""

    source_type=""


    # ========================================================
    # WINDOWS
    #
    # All Windows evidence sources in this task are exported
    # JSON/NDJSON and therefore use windows_json.
    #
    # Notice that we do NOT require a .json extension here.
    # Every file under windows/ is inventoried.
    # ========================================================

    case "$relative_path" in

        windows/*)

            source_type="windows_json"

            json_mode=$(json_input_type "$file")


            if [ "$json_mode" = "array" ] || [ "$json_mode" = "stream" ]; then

                record_count=$(json_record_count "$file" "$json_mode")

                first_time=$(json_first_time "$file")

                last_time=$(json_last_time "$file")

            else

                echo "Warning: Windows source is not valid JSON: $relative_path" >&2

            fi
            ;;


        # ====================================================
        # LINUX
        #
        # Every file under linux/ is treated as Linux text,
        # independent of the filename or extension.
        # ====================================================

        linux/*)

            source_type="linux_text"

            line_count=$(awk 'END {print NR + 0}' "$file")

            first_time=$(linux_first_time "$file")

            last_time=$(linux_last_time "$file")
            ;;


        # ====================================================
        # NETWORK
        #
        # Determine JSON vs CSV using the file contents.
        #
        # Every network file is still inventoried even if its
        # filename is unexpected.
        # ====================================================

        network/*)

            source_type=$(network_source_type "$file")


            # ------------------------------------------------
            # NETWORK JSON
            # ------------------------------------------------

            if [ "$source_type" = "network_json" ]; then

                json_mode=$(json_input_type "$file")


                if [ "$json_mode" = "array" ] || [ "$json_mode" = "stream" ]; then

                    record_count=$(json_record_count "$file" "$json_mode")

                    first_time=$(json_first_time "$file")

                    last_time=$(json_last_time "$file")

                else

                    echo "Warning: network source is not valid JSON: $relative_path" >&2

                fi


            # ------------------------------------------------
            # NETWORK CSV
            # ------------------------------------------------

            else

                # Count all data rows except the header.
                record_count=$(
                    awk '

                        NR > 1 {
                            count++
                        }

                        END {
                            print count + 0
                        }

                    ' "$file"
                )


                column=$(csv_time_column "$file")


                if [ -n "$column" ]; then

                    first_time=$(csv_first_time "$file" "$column")

                    last_time=$(csv_last_time "$file" "$column")

                else

                    echo "Warning: no timestamp column detected: $relative_path" >&2

                fi

            fi
            ;;

    esac


    # ========================================================
    # REPORT TIMESTAMP EXTRACTION PROBLEMS
    #
    # Best-effort extraction means a missing timestamp should
    # be visible, not silently hidden.
    # ========================================================

    if [ -z "$first_time" ]; then
        echo "Warning: first event time not detected: $relative_path" >&2
    fi

    if [ -z "$last_time" ]; then
        echo "Warning: last event time not detected: $relative_path" >&2
    fi


    # ========================================================
    # WRITE ONE MANIFEST ENTRY
    #
    # Every entry has exactly the same field structure.
    # ========================================================

    jq -n \
        --arg path "$relative_path" \
        --arg source_type "$source_type" \
        --argjson size_bytes "$size_bytes" \
        --arg sha256 "$sha256" \
        --argjson line_count "$line_count" \
        --argjson record_count "$record_count" \
        --arg first_event_time "$first_time" \
        --arg last_event_time "$last_time" \
        '{
            path: $path,
            source_type: $source_type,
            size_bytes: $size_bytes,
            sha256: $sha256,
            line_count: $line_count,
            record_count: $record_count,

            first_event_time:
                (
                    if $first_event_time == ""
                    then null
                    else $first_event_time
                    end
                ),

            last_event_time:
                (
                    if $last_event_time == ""
                    then null
                    else $last_event_time
                    end
                )
        }' >> "$TMP_FILE"

done


# ============================================================
# CREATE FINAL JSON MANIFEST
#
# Convert the temporary stream of JSON objects into one normal
# JSON array.
# ============================================================

jq -s '.' "$TMP_FILE" > "$OUTPUT"


# ============================================================
# VALIDATE FINAL DELIVERABLE
#
# The project explicitly requires all JSON deliverables to
# pass:
#
#   jq empty
#
# source_inventory.json is a normal JSON document.
# ============================================================

if ! jq empty "$OUTPUT" 2>/dev/null; then

    echo "Error: source_inventory.json is invalid JSON" >&2
    exit 1

fi


# ============================================================
# HUMAN-READABLE SUMMARY
# ============================================================

print_summary()
{
    local category="$1"
    local file_count
    local byte_count
    local size_mb


    # Count files in this category.
    file_count=$(
        jq \
            --arg prefix "$category/" \
            '[
                .[]
                | select(.path | startswith($prefix))
            ]
            | length' \
            "$OUTPUT"
    )


    # Add the file sizes.
    byte_count=$(
        jq \
            --arg prefix "$category/" \
            '[
                .[]
                | select(.path | startswith($prefix))
                | .size_bytes
            ]
            | add // 0' \
            "$OUTPUT"
    )


    # Convert bytes to MiB.
    size_mb=$(
        awk -v bytes="$byte_count" '

            BEGIN {
                printf "%.1f", bytes / 1048576
            }

        '
    )


    printf "%-8s: %d files  |  %6s MB\n" \
        "$category" \
        "$file_count" \
        "$size_mb"
}


# ============================================================
# PRINT CATEGORY SUMMARY
# ============================================================

print_summary "windows"
print_summary "linux"
print_summary "network"


# ============================================================
# PRINT TOTAL SUMMARY
# ============================================================

total_files=$(jq 'length' "$OUTPUT")

total_bytes=$(
    jq '
        [
            .[].size_bytes
        ]
        | add // 0
    ' "$OUTPUT"
)

total_mb=$(
    awk -v bytes="$total_bytes" '

        BEGIN {
            printf "%.1f", bytes / 1048576
        }

    '
)


printf "%-8s: %d files  |  %6s MB\n" \
    "total" \
    "$total_files" \
    "$total_mb"

echo "manifest written to $OUTPUT"
