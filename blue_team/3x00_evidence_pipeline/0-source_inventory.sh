#!/bin/bash

# ============================================================
# TASK 0 - EVIDENCE PACK INVENTORY
#
# This script inventories the Windows, Linux and network
# evidence files before any parsing or normalization happens.
#
# For each file it records:
#   - relative path
#   - source type
#   - file size
#   - SHA256 hash
#   - record count or line count
#   - first event time
#   - last event time
#
# The final manifest is written as valid JSON.
# ============================================================


# ============================================================
# CONFIGURATION
#
# The evidence pack can be supplied as the first argument.
#
# Example:
#   ./0-source_inventory.sh ~/evidence_pack_primary
#
# If no argument is provided, use the default primary pack.
# ============================================================

PACK_DIR="${1:-$HOME/evidence_pack_primary}"
OUTPUT="${2:-source_inventory.json}"


# ============================================================
# INPUT VALIDATION
#
# Stop early if the evidence pack does not exist.
# This prevents us from creating an empty or misleading
# inventory from a wrong path.
# ============================================================

if [ ! -d "$PACK_DIR" ]; then
    echo "Error: evidence pack not found: $PACK_DIR" >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILE
#
# Each file inventory entry is first written as one JSON object
# into a temporary file.
#
# At the end, jq combines all objects into one JSON array.
# ============================================================

TMP_FILE=$(mktemp)

# Make sure the temporary file is deleted when the script ends.
trap 'rm -f "$TMP_FILE"' EXIT

# Start with an empty temporary file.
: > "$TMP_FILE"


# ============================================================
# CHECK EXPECTED DIRECTORIES
#
# Missing directories should be visible to the analyst.
# We do not stop the entire script because an incomplete
# evidence pack is something the inventory should report.
# ============================================================

for directory in windows linux network
do
    if [ ! -d "$PACK_DIR/$directory" ]; then
        echo "Warning: missing directory: $directory/" >&2
    fi
done


# ============================================================
# JSON RECORD COUNT FUNCTION
#
# JSON evidence can arrive in different formats.
#
# Format 1:
# [
#   {...},
#   {...}
# ]
#
# This is a JSON array. The number of records is the array
# length.
#
# Format 2:
# {...}
# {...}
# {...}
#
# This is NDJSON. Each top-level JSON object is one record.
#
# Format 3:
# {...}
#
# This is a normal single JSON object and counts as one record.
#
# Detecting these cases separately avoids confusing a JSON
# array with NDJSON.
# ============================================================

json_record_count()
{
    file="$1"

    # Read the type of the first top-level JSON value.
    first_type=$(jq -r 'type' "$file" 2>/dev/null | head -n 1)

    if [ "$first_type" = "array" ]; then

        # A normal JSON array.
        jq 'length' "$file" 2>/dev/null | head -n 1

    else

        # For NDJSON, jq outputs one compact line per
        # top-level JSON record.
        #
        # A normal single JSON object therefore gives 1.
        # NDJSON gives the actual number of records.
        jq -c '.' "$file" 2>/dev/null |
            wc -l |
            awk '{print $1}'
    fi
}


# ============================================================
# JSON TIMESTAMP EXTRACTION
#
# Different sources use different names for their timestamp.
#
# We check several common timestamp field names.
# The goal here is only "best effort" inventory, not full
# normalization. Full timestamp normalization happens later
# in the pipeline.
# ============================================================

json_event_times()
{
    file="$1"

    jq -r '
        # If the file contains a JSON array, inspect every
        # object inside the array.
        #
        # For NDJSON, jq already processes each top-level
        # object separately.
        if type == "array" then
            .[]
        else
            .
        end

        |

        # Ignore values that are not JSON objects.
        objects

        |

        # Try common timestamp fields used by Windows,
        # Suricata and other JSON security sources.
        (
            .timestamp //
            ."@timestamp" //
            .event_time //
            .time //
            .TimeCreated //
            .time_created //
            .System.TimeCreated.SystemTime //
            .Event.System.TimeCreated.SystemTime //
            .system.time_created //
            .event.created //
            .event.start //
            .start_time //
            .end_time //
            empty
        )

        |

        # Only return useful timestamp values.
        select(. != null and . != "")

        |

        tostring
    ' "$file" 2>/dev/null
}


# ============================================================
# FIRST JSON EVENT TIME
# ============================================================

json_first_time()
{
    json_event_times "$1" | head -n 1
}


# ============================================================
# LAST JSON EVENT TIME
# ============================================================

json_last_time()
{
    json_event_times "$1" | tail -n 1
}


# ============================================================
# TIME VALUE NORMALIZATION FOR TEXT LOGS
#
# Linux logs may contain:
#
#   Aug 30 12:30:20
#
# or an epoch timestamp such as:
#
#   1788093020
#
# This function makes a best-effort attempt to turn the value
# into an ISO 8601 UTC timestamp.
#
# If date cannot understand the value, we keep the original
# value instead of silently deleting it.
# ============================================================

normalize_time_value()
{
    value="$1"

    if [ -z "$value" ]; then
        return
    fi

    # Check for an epoch timestamp.
    if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then

        # Remove any decimal part.
        seconds=${value%%.*}

        date -u -d "@$seconds" \
            '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
            printf '%s\n' "$value"

    else

        # Try to parse normal date text.
        date -u -d "$value" \
            '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
            printf '%s\n' "$value"
    fi
}


# ============================================================
# FIRST LINUX EVENT TIME
#
# Linux audit.log often contains timestamps like:
#
#   msg=audit(1788093020.123:100)
#
# auth.log and syslog often use:
#
#   Aug 30 12:30:20
# ============================================================

linux_first_time()
{
    file="$1"

    # First check whether this is an audit-style log.
    audit_time=$(
        grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
            head -n 1 |
            sed 's/audit(//'
    )

    if [ -n "$audit_time" ]; then
        normalize_time_value "$audit_time"
        return
    fi

    # Otherwise read the timestamp from the first non-empty
    # normal Linux log line.
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
#
# Same idea as linux_first_time(), but use the final event.
# ============================================================

linux_last_time()
{
    file="$1"

    # Check for Linux audit timestamps first.
    audit_time=$(
        grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
            tail -n 1 |
            sed 's/audit(//'
    )

    if [ -n "$audit_time" ]; then
        normalize_time_value "$audit_time"
        return
    fi

    # Save the timestamp from each non-empty line.
    # At END, print the last one found.
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
# First, look for a timestamp-like column name.
#
# Examples:
#   timestamp
#   time
#   event_time
#   datetime
#   date
#
# If the header does not help, inspect the first data row and
# look for a value that looks like an ISO date.
#
# This provides a better fallback than simply returning no
# timestamp without explanation.
# ============================================================

csv_time_column()
{
    file="$1"

    awk -F',' '
        NR == 1 {
            found = 0

            for (i = 1; i <= NF; i++) {
                field = $i

                # Remove quotes around the CSV header.
                gsub(/"/, "", field)

                # Convert header to lowercase.
                field = tolower(field)

                if (
                    field == "timestamp" ||
                    field == "time" ||
                    field == "event_time" ||
                    field == "datetime" ||
                    field == "date"
                ) {
                    print i
                    found = 1
                    exit
                }
            }
        }

        # If no useful header was found, inspect the first
        # actual data row.
        NR == 2 && found == 0 {
            for (i = 1; i <= NF; i++) {
                value = $i
                gsub(/"/, "", value)

                # Basic ISO-style date detection.
                if (value ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) {
                    print i
                    exit
                }
            }
        }
    ' "$file"
}


# ============================================================
# CSV FIRST EVENT TIME
#
# Read the first data record from the timestamp column.
# ============================================================

csv_first_time()
{
    file="$1"
    column="$2"

    awk -F',' -v col="$column" '
        NR == 2 {
            value = $col

            # Remove surrounding quotes.
            gsub(/^"|"$/, "", value)

            print value
            exit
        }
    ' "$file"
}


# ============================================================
# CSV LAST EVENT TIME
#
# Read through the file and remember the last non-empty value
# in the timestamp column.
# ============================================================

csv_last_time()
{
    file="$1"
    column="$2"

    awk -F',' -v col="$column" '
        NR > 1 && $col != "" {
            value = $col

            # Remove surrounding quotes.
            gsub(/^"|"$/, "", value)

            last = value
        }

        END {
            print last
        }
    ' "$file"
}


# ============================================================
# FILE INVENTORY
#
# Walk only the required evidence categories:
#
#   windows/
#   linux/
#   network/
#
# context/ and student_telemetry/ are intentionally not part
# of Task 0 because the instructions specifically request
# Windows, Linux and network source files.
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
    # COMMON FILE INFORMATION
    #
    # These fields exist for every inventory record.
    # ========================================================

    relative_path="${file#"$PACK_DIR"/}"

    size_bytes=$(stat -c '%s' "$file")

    sha256=$(sha256sum "$file" | awk '{print $1}')


    # Always initialize timestamp variables.
    #
    # This makes their state explicit even when a source does
    # not contain a timestamp we can identify.
    first_time=""
    last_time=""


    # ========================================================
    # WINDOWS JSON
    # ========================================================

    case "$relative_path" in

        windows/*)

            source_type="windows_json"

            # Verify that the source is valid JSON/NDJSON
            # before trying to count its records.
            if jq empty "$file" 2>/dev/null; then

                record_count=$(json_record_count "$file")

                first_time=$(json_first_time "$file")
                last_time=$(json_last_time "$file")

            else

                # The inventory should make corrupt evidence
                # visible instead of silently ignoring it.
                echo "Warning: invalid JSON: $relative_path" >&2

                # Fall back to physical line count because the
                # JSON parser cannot safely count records.
                record_count=$(awk 'END {print NR}' "$file")
            fi


            # Write one Windows inventory object.
            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$record_count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
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
            ;;


        # ====================================================
        # LINUX TEXT LOGS
        # ====================================================

        linux/*)

            source_type="linux_text"

            # For plain text logs, one physical line is treated
            # as one log record for inventory purposes.
            line_count=$(awk 'END {print NR}' "$file")

            first_time=$(linux_first_time "$file")
            last_time=$(linux_last_time "$file")


            # Tell the analyst if timestamps could not be found.
            if [ -z "$first_time" ] || [ -z "$last_time" ]; then
                echo "Warning: timestamp not fully detected: $relative_path" >&2
            fi


            # Write one Linux inventory object.
            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson line_count "$line_count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
                    line_count: $line_count,

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
            ;;


        # ====================================================
        # NETWORK CSV
        # ====================================================

        network/*.csv)

            source_type="network_csv"


            # Count data records but not the CSV header.
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


            # Try to locate the column containing event time.
            column=$(csv_time_column "$file")


            if [ -n "$column" ]; then

                first_time=$(csv_first_time "$file" "$column")
                last_time=$(csv_last_time "$file" "$column")

            else

                # Do not silently hide missing temporal
                # information.
                echo "Warning: no timestamp column detected: $relative_path" >&2

                first_time=""
                last_time=""
            fi


            # Write one network CSV inventory object.
            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$record_count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
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
            ;;


        # ====================================================
        # NETWORK JSON / NDJSON
        # ====================================================

        network/*.json)

            source_type="network_json"


            if jq empty "$file" 2>/dev/null; then

                # This correctly distinguishes JSON arrays from
                # NDJSON before counting records.
                record_count=$(json_record_count "$file")

                first_time=$(json_first_time "$file")
                last_time=$(json_last_time "$file")

            else

                echo "Warning: invalid JSON: $relative_path" >&2

                record_count=$(awk 'END {print NR}' "$file")
            fi


            # If the JSON is valid but contains no timestamp
            # field we recognize, report that fact.
            if [ -z "$first_time" ] || [ -z "$last_time" ]; then
                echo "Warning: timestamp not fully detected: $relative_path" >&2
            fi


            # Write one network JSON inventory object.
            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$record_count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
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
            ;;
    esac

done


# ============================================================
# BUILD FINAL JSON MANIFEST
#
# The temporary file currently contains one JSON object per
# evidence source.
#
# jq -s combines these separate objects into one JSON array.
# ============================================================

jq -s '.' "$TMP_FILE" > "$OUTPUT"


# ============================================================
# VALIDATE FINAL JSON
#
# A project requirement says every JSON deliverable must be
# parseable with:
#
#   jq empty
#
# Stop if our generated manifest is somehow invalid.
# ============================================================

if ! jq empty "$OUTPUT" 2>/dev/null; then
    echo "Error: generated manifest is not valid JSON" >&2
    exit 1
fi


# ============================================================
# HUMAN-READABLE SUMMARY FUNCTION
#
# Count files and bytes for one top-level evidence category.
# ============================================================

print_summary()
{
    category="$1"


    # Count inventory records whose path starts with:
    #
    # windows/
    # linux/
    # network/
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


    # Add file sizes for the same category.
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


    # Convert bytes to MiB for readable output.
    size_mb=$(
        awk -v bytes="$byte_count" \
            'BEGIN {
                printf "%.1f", bytes / 1048576
            }'
    )


    printf "%-8s: %d files  |  %6s MB\n" \
        "$category" \
        "$file_count" \
        "$size_mb"
}


# ============================================================
# PRINT CATEGORY SUMMARIES
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
    awk -v bytes="$total_bytes" \
        'BEGIN {
            printf "%.1f", bytes / 1048576
        }'
)


printf "%-8s: %d files  |  %6s MB\n" \
    "total" \
    "$total_files" \
    "$total_mb"


echo "manifest written to $OUTPUT"
