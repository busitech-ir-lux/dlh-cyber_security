#!/bin/bash

# ============================================================
# CONFIGURATION
# Define the evidence pack and output file.
# The first script argument can override the default pack path.
# Evidence pack can be given as the first argument.
# If no argument is given, use the primary evidence pack.
# ============================================================


PACK_DIR="${1:-$HOME/evidence_pack_primary}"
OUTPUT="${2:-source_inventory.json}"

TMP_FILE=$(mktemp)

# Start with an empty temporary file.
: > "$TMP_FILE"

# Make sure the evidence pack exists.
if [ ! -d "$PACK_DIR" ]; then
    echo "Error: evidence pack not found: $PACK_DIR"
    rm -f "$TMP_FILE"
    exit 1
fi


# Extract the first timestamp from a JSON or NDJSON file.
json_first_time()
{
    jq -r '
        if type == "array" then .[] else . end
        | objects
        | (
            .timestamp //
            ."@timestamp" //
            .time //
            .event_time //
            .start_time //
            empty
        )
    ' "$1" 2>/dev/null | sed -n '1p'
}


# Extract the last timestamp from a JSON or NDJSON file.
json_last_time()
{
    jq -r '
        if type == "array" then .[] else . end
        | objects
        | (
            .timestamp //
            ."@timestamp" //
            .time //
            .event_time //
            .end_time //
            .start_time //
            empty
        )
    ' "$1" 2>/dev/null | tail -n 1
}


# Extract first timestamp from Linux text logs.
linux_first_time()
{
    file="$1"

    # audit.log normally contains epoch timestamps inside audit(...)
    audit_time=$(grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
        sed -n '1p' |
        sed 's/audit(//')

    if [ -n "$audit_time" ]; then
        seconds=${audit_time%%.*}
        date -u -d "@$seconds" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
        return
    fi

    # Normal syslog/auth.log style timestamp.
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
}


# Extract last timestamp from Linux text logs.
linux_last_time()
{
    file="$1"

    audit_time=$(grep -oE 'audit\([0-9]+(\.[0-9]+)?' "$file" 2>/dev/null |
        tail -n 1 |
        sed 's/audit(//')

    if [ -n "$audit_time" ]; then
        seconds=${audit_time%%.*}
        date -u -d "@$seconds" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
        return
    fi

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
}


# Find timestamp column number in a CSV file.
csv_time_column()
{
    awk -F',' '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                field = $i
                gsub(/"/, "", field)
                field = tolower(field)

                if (field == "timestamp" ||
                    field == "time" ||
                    field == "event_time" ||
                    field == "datetime") {
                    print i
                    exit
                }
            }
        }
    ' "$1"
}


# Process every file in the required directories.
find "$PACK_DIR/windows" \
     "$PACK_DIR/linux" \
     "$PACK_DIR/network" \
     -type f 2>/dev/null |
sort |
while IFS= read -r file
do
    # Relative path inside the evidence pack.
    relative_path="${file#"$PACK_DIR"/}"

    size_bytes=$(stat -c '%s' "$file")
    sha256=$(sha256sum "$file" | awk '{print $1}')

    first_time=""
    last_time=""
    count=0

    case "$relative_path" in

        windows/*)
            source_type="windows_json"

            if jq empty "$file" 2>/dev/null; then
                count=$(jq -s '
                    if length == 0 then
                        0
                    elif length > 1 then
                        length
                    elif (.[0] | type) == "array" then
                        (.[0] | length)
                    else
                        1
                    end
                ' "$file")
            else
                echo "Warning: invalid JSON: $relative_path" >&2
                count=$(wc -l < "$file")
            fi

            first_time=$(json_first_time "$file")
            last_time=$(json_last_time "$file")

            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
                    record_count: $record_count,
                    first_event_time:
                        (if $first_event_time == "" then null
                         else $first_event_time end),
                    last_event_time:
                        (if $last_event_time == "" then null
                         else $last_event_time end)
                }' >> "$TMP_FILE"
            ;;


        linux/*)
            source_type="linux_text"

            count=$(wc -l < "$file")
            first_time=$(linux_first_time "$file")
            last_time=$(linux_last_time "$file")

            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson line_count "$count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
                    line_count: $line_count,
                    first_event_time:
                        (if $first_event_time == "" then null
                         else $first_event_time end),
                    last_event_time:
                        (if $last_event_time == "" then null
                         else $last_event_time end)
                }' >> "$TMP_FILE"
            ;;


        network/*.csv)
            source_type="network_csv"

            count=$(awk '
                END {
                    if (NR > 0)
                        print NR - 1
                    else
                        print 0
                }
            ' "$file")

            column=$(csv_time_column "$file")

            if [ -n "$column" ]; then
                first_time=$(awk -F',' -v col="$column" '
                    NR == 2 {
                        value = $col
                        gsub(/^"|"$/, "", value)
                        print value
                        exit
                    }
                ' "$file")

                last_time=$(awk -F',' -v col="$column" '
                    NR > 1 && $col != "" {
                        value = $col
                        gsub(/^"|"$/, "", value)
                        last = value
                    }
                    END {
                        print last
                    }
                ' "$file")
            fi

            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
                    record_count: $record_count,
                    first_event_time:
                        (if $first_event_time == "" then null
                         else $first_event_time end),
                    last_event_time:
                        (if $last_event_time == "" then null
                         else $last_event_time end)
                }' >> "$TMP_FILE"
            ;;


        network/*.json)
            source_type="network_json"

            if jq empty "$file" 2>/dev/null; then
                count=$(jq -s '
                    if length == 0 then
                        0
                    elif length > 1 then
                        length
                    elif (.[0] | type) == "array" then
                        (.[0] | length)
                    else
                        1
                    end
                ' "$file")
            else
                echo "Warning: invalid JSON: $relative_path" >&2
                count=$(wc -l < "$file")
            fi

            first_time=$(json_first_time "$file")
            last_time=$(json_last_time "$file")

            jq -n \
                --arg path "$relative_path" \
                --arg source_type "$source_type" \
                --argjson size_bytes "$size_bytes" \
                --arg sha256 "$sha256" \
                --argjson record_count "$count" \
                --arg first_event_time "$first_time" \
                --arg last_event_time "$last_time" \
                '{
                    path: $path,
                    source_type: $source_type,
                    size_bytes: $size_bytes,
                    sha256: $sha256,
                    record_count: $record_count,
                    first_event_time:
                        (if $first_event_time == "" then null
                         else $first_event_time end),
                    last_event_time:
                        (if $last_event_time == "" then null
                         else $last_event_time end)
                }' >> "$TMP_FILE"
            ;;
    esac
done


# Combine the individual JSON objects into one JSON array.
jq -s '.' "$TMP_FILE" > "$OUTPUT"

rm -f "$TMP_FILE"


# Human-readable summary.
print_summary()
{
    category="$1"

    file_count=$(jq \
        --arg prefix "$category/" \
        '[.[] | select(.path | startswith($prefix))] | length' \
        "$OUTPUT")

    byte_count=$(jq \
        --arg prefix "$category/" \
        '[.[] | select(.path | startswith($prefix)) | .size_bytes]
         | add // 0' \
        "$OUTPUT")

    size_mb=$(awk -v bytes="$byte_count" \
        'BEGIN { printf "%.1f", bytes / 1048576 }')

    printf "%-8s: %d files  |  %6s MB\n" \
        "$category" "$file_count" "$size_mb"
}


print_summary "windows"
print_summary "linux"
print_summary "network"

total_files=$(jq 'length' "$OUTPUT")
total_bytes=$(jq '[.[].size_bytes] | add // 0' "$OUTPUT")

total_mb=$(awk -v bytes="$total_bytes" \
    'BEGIN { printf "%.1f", bytes / 1048576 }')

printf "%-8s: %d files  |  %6s MB\n" \
    "total" "$total_files" "$total_mb"

echo "manifest written to $OUTPUT"
