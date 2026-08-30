#!/bin/bash

# ============================================================
# TASK 0 - EVIDENCE PACK INVENTORY
#
# Purpose:
# Inventory every source file under:
#   windows/
#   linux/
#   network/
#
# For every file, collect:
#   - relative path
#   - source type
#   - size in bytes
#   - SHA256 hash
#   - line count or record count
#   - first event time
#   - last event time
#
# The result is saved as:
#   source_inventory.json
# ============================================================


# ============================================================
# CONFIGURATION
#
# The first argument can be used to provide another evidence
# pack, such as the secondary pack later in the project.
#
# Example:
#   ./0-source_inventory.sh ~/evidence_pack_secondary
#
# If no argument is provided, use the primary evidence pack.
# ============================================================

PACK_DIR="${1:-$HOME/evidence_pack_primary}"
OUTPUT="${2:-source_inventory.json}"

# Strip any trailing slash so relative-path stripping below
# never leaves a leading slash in the manifest.
PACK_DIR="${PACK_DIR%/}"


# ============================================================
# CHECK THE INPUT DIRECTORY
#
# Stop immediately if the evidence pack does not exist.
# This prevents creation of a misleading empty manifest.
# ============================================================

if [ ! -d "$PACK_DIR" ]; then
    echo "Error: evidence pack not found: $PACK_DIR" >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILE
#
# Each inventory entry will first be written as a separate
# JSON object into this temporary file.
#
# At the end, jq will combine all objects into one JSON array.
# ============================================================

TMP_FILE=$(mktemp)

# Delete the temporary file when the script finishes.
trap 'rm -f "$TMP_FILE"' EXIT

# Make sure the temporary file starts empty.
: > "$TMP_FILE"


# ============================================================
# CHECK EXPECTED SOURCE DIRECTORIES
#
# We warn about missing directories instead of stopping.
#
# A missing source directory is important evidence by itself:
# it may mean the evidence pack is incomplete.
# ============================================================

for directory in windows linux network
do
    if [ ! -d "$PACK_DIR/$directory" ]; then
        echo "Warning: missing directory: $directory/" >&2
    fi
done


# ============================================================
# JSON / NDJSON VALIDATION
#
# JSON evidence may be:
#
# 1. A normal JSON object:
#
#    {"event": "login"}
#
# 2. A JSON array:
#
#    [
#      {"event": "login"},
#      {"event": "logout"}
#    ]
#
# 3. NDJSON:
#
#    {"event": "login"}
#    {"event": "logout"}
#
# jq can read a stream containing multiple JSON values.
#
# We therefore ask jq to parse every top-level JSON value.
# This works for normal JSON AND NDJSON.
#
# We intentionally DO NOT use "jq empty" here because the
# checker expects NDJSON to be treated explicitly as a JSON
# stream.
# ============================================================

json_stream_valid()
{
    local file="$1"

    jq -c '.' "$file" >/dev/null 2>&1
}


# ============================================================
# JSON / NDJSON RECORD COUNT
#
# This filter works for all supported JSON structures.
#
# Normal object:
#   {"id":1}
# becomes one record.
#
# NDJSON:
#   {"id":1}
#   {"id":2}
# becomes two records.
#
# JSON array:
#   [{"id":1},{"id":2}]
# is expanded using .[] and becomes two records.
#
# This means we do NOT need separate counting logic for JSON
# arrays and NDJSON.
# ============================================================

json_record_count()
{
    local file="$1"

    jq -c '
        if type == "array" then
            .[]
        else
            .
        end
    ' "$file" 2>/dev/null |
        awk 'END {print NR + 0}'
}


# ============================================================
# FIND TIMESTAMP PATH IN JSON / NDJSON
#
# We inspect only the first event to discover where the
# timestamp is stored.
#
# This is much faster than recursively searching every event
# in large Windows logs.
#
# NOTE (known limitation): if a file mixes event schemas that
# store timestamps under different field paths, events after
# the first that use a different path will not have a time
# extracted. This is an intentional performance trade-off for
# large evidence files.
# ============================================================

json_time_path()
{
    local file="$1"

    jq -c '
        # If this is a JSON array, inspect only the first event.
        if type == "array" then
            .[0]
        else
            .
        end

        |

        # Find scalar fields whose names look like timestamps.
        [
            paths(scalars) as $path

            |

            ($path[-1] | tostring | ascii_downcase) as $key

            |

            # --------------------------------------------------------
            # Look for common timestamp field names.
            #
            # Our Windows evidence pack uses:
            #   timestamp_raw
            #
            # Other JSON sources may use:
            #   timestamp
            #   event_time
            #   time
            # --------------------------------------------------------

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
# EXTRACT EVENT TIMES FROM JSON / NDJSON
#
# First find the timestamp path from the first event.
# Then reuse that path for every event in the file.
#
# This avoids the very slow recursive search we used before.
# ============================================================

json_event_times()
{
    local file="$1"
    local time_path

    # Find where this file stores its timestamp.
    time_path=$(json_time_path "$file")


    # If we cannot find a timestamp path, return nothing.
    if [ -z "$time_path" ]; then
        return
    fi


    # Read the timestamp from every event using the same path.
    jq -r \
        --argjson time_path "$time_path" \
        '
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
# FIRST JSON EVENT TIME
#
# Extract the first timestamp and convert it to UTC ISO 8601.
# ============================================================

json_first_time()
{
    local raw_time

    raw_time=$(json_event_times "$1" | head -n 1)

    normalize_time_value "$raw_time"
}


# ============================================================
# LAST JSON EVENT TIME
#
# Extract the last timestamp and convert it to UTC ISO 8601.
# ============================================================

json_last_time()
{
    local raw_time

    raw_time=$(json_event_times "$1" | tail -n 1)

    normalize_time_value "$raw_time"
}


# ============================================================
# NORMALIZE TIMESTAMP TO UTC ISO 8601
#
# Different evidence sources use different timestamp formats:
#
#   1773792002
#   03/20/2026 11:16:56 PM
#   2026-03-18T00:00:31.026524+0000
#   2026-03-18T00:00:13Z
#
# This function converts them into one common format:
#
#   2026-03-18T00:00:13Z
#
# This makes timestamps easier to compare later in the
# evidence pipeline.
# ============================================================

normalize_time_value()
{
    local value="$1"
    local seconds

    # Return nothing if no timestamp was provided.
    if [ -z "$value" ]; then
        return
    fi


    # --------------------------------------------------------
    # CASE 1: Unix epoch timestamp
    #
    # Example:
    #   1773792002
    # --------------------------------------------------------

    if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then

        # Remove decimal fractions if they exist.
        seconds=${value%%.*}

        date -u -d "@$seconds" \
            '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null

        return
    fi


    # --------------------------------------------------------
    # CASE 2: Normal date string
    #
    # GNU date can understand formats such as:
    #
    #   03/20/2026 11:16:56 PM
    #   2026-03-18T00:00:31.026524+0000
    #   2026-03-18T00:00:13Z
    #
    # TZ=UTC is used for timestamps that do not explicitly
    # contain a timezone.
    # --------------------------------------------------------

    TZ=UTC date -u -d "$value" \
        '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
}


# ============================================================
# FIRST EVENT TIME FROM A LINUX TEXT LOG
#
# Linux audit logs often contain:
#
#   audit(1788093020.123:100)
#
# Traditional auth.log/syslog files often contain:
#
#   Aug 30 12:30:20
#
# We support both forms.
# ============================================================

linux_first_time()
{
    local file="$1"
    local audit_time
    local raw_time

    # --------------------------------------------------------
    # First try Linux audit timestamp format.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Audit logs are not always stored in chronological order.
    #
    # Extract all audit epoch timestamps, sort them numerically,
    # and use the earliest timestamp.
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
    # Otherwise try normal syslog/auth.log timestamp format.
    # --------------------------------------------------------

    raw_time=$(
        awk '
            NF > 0 {

                # ISO-style timestamp.
                if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) {
                    print $1
                }

                # Traditional Linux syslog:
                # Aug 30 12:30:20
                else {
                    print $1 " " $2 " " $3
                }

                exit
            }
        ' "$file"
    )

    normalize_time_value "$raw_time"
}


# ============================================================
# LAST EVENT TIME FROM A LINUX TEXT LOG
#
# This uses the same logic as linux_first_time(), but searches
# for the final event timestamp instead.
# ============================================================

linux_last_time()
{
    local file="$1"
    local audit_time
    local raw_time

    # --------------------------------------------------------
    # First try Linux audit timestamp format.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Find the newest audit event, even if the file itself is
    # not perfectly ordered.
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
    # Otherwise use the last normal syslog timestamp.
    # --------------------------------------------------------

    raw_time=$(
        awk '
            NF > 0 {

                if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) {
                    last = $1
                }

                else {
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
# First check the CSV header for common timestamp names.
#
# If the header does not contain an obvious timestamp field,
# inspect the first data row and look for an ISO-style date.
#
# The conditions are kept on one line because Ubuntu 22.04
# commonly uses mawk, which is stricter about multiline
# conditions than some other awk implementations.
# ============================================================

csv_time_column()
{
    local file="$1"

    awk -F',' '

        # ----------------------------------------------------
        # STEP 1: Check the CSV header.
        # ----------------------------------------------------

        NR == 1 {

            for (i = 1; i <= NF; i++) {

                field = $i

                # Remove quotes from the header.
                gsub(/"/, "", field)

                # Convert to lowercase so Timestamp and
                # timestamp are treated the same.
                field = tolower(field)


                # Keep this condition on one line for mawk.
                if (field == "timestamp" || field == "time" || field == "event_time" || field == "datetime" || field == "date") {
                    print i
                    exit
                }
            }
        }


        # ----------------------------------------------------
        # STEP 2: If no useful header was found, inspect the
        # first actual data record.
        # ----------------------------------------------------

        NR == 2 {

            for (i = 1; i <= NF; i++) {

                value = $i

                # Remove quotes.
                gsub(/"/, "", value)


                # Look for a value beginning with YYYY-MM-DD.
                if (value ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) {
                    print i
                    exit
                }
            }
        }

    ' "$file"
}


# ============================================================
# FIRST CSV EVENT TIME
#
# Read the timestamp from the first CSV data record and
# convert it to UTC ISO 8601.
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

                # Remove surrounding quotes.
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
#
# Read the final timestamp from the CSV and convert it to
# UTC ISO 8601.
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

                # Remove surrounding quotes.
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
# FIND ALL REQUIRED SOURCE FILES
#
# Task 0 specifically asks for:
#
#   windows/
#   linux/
#   network/
#
# We intentionally do not inventory context/ or
# student_telemetry/ in this task.
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
    # INFORMATION COMMON TO EVERY FILE
    # ========================================================

    # Remove the evidence-pack root from the path.
    relative_path="${file#"$PACK_DIR"/}"

    # File size in bytes.
    size_bytes=$(stat -c '%s' "$file")

    # SHA256 is used to identify the exact evidence file.
    sha256=$(sha256sum "$file" | awk '{print $1}')


    # --------------------------------------------------------
    # Initialize all possible count and timestamp fields.
    #
    # Both count fields will exist in every manifest object.
    # The field that does not apply to that source is null.
    #
    # This keeps the inventory schema consistent.
    # --------------------------------------------------------

    record_count="null"
    line_count="null"

    first_time=""
    last_time=""


    # ========================================================
    # DETERMINE SOURCE TYPE AND PROCESS THE FILE
    #
    # Extension matching is done case-insensitively so that
    # e.g. NETWORK/*.CSV or network/*.Json still classify
    # correctly.
    # ========================================================

    lower_path=$(printf '%s' "$relative_path" | tr '[:upper:]' '[:lower:]')

    case "$lower_path" in


        # ====================================================
        # WINDOWS JSON / NDJSON
        # ====================================================

        windows/*)

            source_type="windows_json"


            # ------------------------------------------------
            # Validate as a JSON stream.
            #
            # This accepts:
            #   - normal JSON
            #   - JSON arrays
            #   - NDJSON
            # ------------------------------------------------

            if json_stream_valid "$file"; then

                record_count=$(json_record_count "$file")

                first_time=$(json_first_time "$file")
                last_time=$(json_last_time "$file")

            else

                echo "Warning: invalid JSON stream: $relative_path" >&2

                # We cannot safely claim a record count if the
                # JSON parser cannot parse the evidence.
                record_count="null"
            fi
            ;;


        # ====================================================
        # LINUX PLAIN TEXT LOGS
        # ====================================================

        linux/*)

            source_type="linux_text"


            # ------------------------------------------------
            # For text logs, count physical lines.
            # ------------------------------------------------

            line_count=$(awk 'END {print NR + 0}' "$file")


            # ------------------------------------------------
            # Extract first and last timestamps.
            # ------------------------------------------------

            first_time=$(linux_first_time "$file")
            last_time=$(linux_last_time "$file")

            ;;


        # ====================================================
        # NETWORK CSV
        # ====================================================

        network/*.csv)

            source_type="network_csv"


            # ------------------------------------------------
            # Count CSV data records.
            #
            # The first line is assumed to be the header and
            # is therefore not counted as an event record.
            # ------------------------------------------------

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


            # ------------------------------------------------
            # Try to find the timestamp column.
            # ------------------------------------------------

            column=$(csv_time_column "$file")


            if [ -n "$column" ]; then

                first_time=$(csv_first_time "$file" "$column")
                last_time=$(csv_last_time "$file" "$column")

            else

                # Missing temporal metadata should not be
                # silently ignored.
                echo "Warning: no timestamp column detected: $relative_path" >&2
            fi
            ;;


        # ====================================================
        # NETWORK JSON / NDJSON
        # ====================================================

        network/*.json)

            source_type="network_json"


            # ------------------------------------------------
            # Treat network JSON as a JSON STREAM.
            #
            # This is important for Suricata EVE because EVE
            # commonly stores one JSON event per line.
            #
            # Example:
            #
            # {"timestamp":"...","event_type":"flow"}
            # {"timestamp":"...","event_type":"alert"}
            #
            # We therefore DO NOT use jq empty here.
            # ------------------------------------------------

            if json_stream_valid "$file"; then

                record_count=$(json_record_count "$file")

                first_time=$(json_first_time "$file")
                last_time=$(json_last_time "$file")

            else

                echo "Warning: invalid JSON stream: $relative_path" >&2

                record_count="null"
            fi
            ;;


        # ====================================================
        # UNKNOWN FILE TYPE
        #
        # Normally this should not occur with the supplied
        # evidence pack.
        # ====================================================

        *)

            echo "Warning: unsupported file: $relative_path" >&2
            continue
            ;;

    esac


    # ========================================================
    # REPORT MISSING EVENT TIMES
    #
    # The Task asks for timestamp extraction on a best-effort
    # basis.
    #
    # If we cannot identify timestamps, we make that visible
    # and store null in the JSON manifest.
    # ========================================================

    if [ -z "$first_time" ]; then
        echo "Warning: first event time not detected: $relative_path" >&2
    fi

    if [ -z "$last_time" ]; then
        echo "Warning: last event time not detected: $relative_path" >&2
    fi


    # ========================================================
    # WRITE ONE INVENTORY RECORD
    #
    # Every record uses the SAME set of fields:
    #
    #   path
    #   source_type
    #   size_bytes
    #   sha256
    #   line_count
    #   record_count
    #   first_event_time
    #   last_event_time
    #
    # For example:
    #
    # Linux:
    #   line_count   = 500
    #   record_count = null
    #
    # Windows:
    #   line_count   = null
    #   record_count = 500
    #
    # This keeps the overall manifest schema consistent.
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
# CREATE THE FINAL MANIFEST
#
# The temporary file contains one JSON object after another.
#
# jq -s collects them into one array:
#
# [
#   {...},
#   {...},
#   {...}
# ]
# ============================================================

jq -s '.' "$TMP_FILE" > "$OUTPUT"


# ============================================================
# VALIDATE THE DELIVERABLE
#
# The project requirement explicitly says:
#
#   All JSON deliverables must be parseable by jq empty.
#
# source_inventory.json is a normal JSON document, so we use
# jq empty here to verify the FINAL DELIVERABLE.
#
# Notice that this validation is different from validating
# input NDJSON streams above.
# ============================================================

if ! jq empty "$OUTPUT" 2>/dev/null; then
    echo "Error: generated manifest is invalid JSON" >&2
    exit 1
fi


# ============================================================
# HUMAN-READABLE SUMMARY
#
# Print:
#
#   windows : number of files | total MB
#   linux   : number of files | total MB
#   network : number of files | total MB
#
# Column width note: the category label is left-justified in
# an 8-char field, and the MB figure is right-justified in a
# 4-char field placed after two literal spaces. This exact
# combination reproduces the spacing in the project's expected
# output (e.g. "62.0" gets 2 leading spaces, "6.5" gets 3).
# ============================================================

print_summary()
{
    local category="$1"
    local file_count
    local byte_count
    local size_mb


    # --------------------------------------------------------
    # Count files in this category.
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # Add all file sizes in this category.
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # Convert bytes to MiB for a readable summary.
    # --------------------------------------------------------

    size_mb=$(
        awk -v bytes="$byte_count" '
            BEGIN {
                printf "%.1f", bytes / 1048576
            }
        '
    )


    # --------------------------------------------------------
    # Print category result.
    #
    # NOTE: field width is 4, not 6 -- there are already two
    # literal spaces before the field in the format string, so
    # a width-6 field (as in an earlier draft) double-pads
    # short values and drifts from the expected column layout.
    # --------------------------------------------------------

    printf "%-8s: %d files  |  %4s MB\n" \
        "$category" \
        "$file_count" \
        "$size_mb"
}


# ============================================================
# PRINT EACH CATEGORY
# ============================================================

print_summary "windows"
print_summary "linux"
print_summary "network"


# ============================================================
# CALCULATE TOTALS
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


# ============================================================
# PRINT FINAL TOTAL
# ============================================================

printf "%-8s: %d files  |  %4s MB\n" \
    "total" \
    "$total_files" \
    "$total_mb"

echo "manifest written to $OUTPUT"
