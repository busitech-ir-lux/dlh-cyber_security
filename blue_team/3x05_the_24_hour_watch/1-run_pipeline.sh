#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper function
# --------------------------------------------------

fail() {
    echo "[pipeline] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Check required environment variables
# --------------------------------------------------

for var in CAPSTONE_PACK SHIFT_WORKSPACE PIPELINE_BIN
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


# --------------------------------------------------
# 1. Confirm Task 0 intake passed
# --------------------------------------------------

SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"

if [[ ! -s "$SHIFT_START" ]]; then
    fail "shift_start.json is missing or empty"
fi

if ! jq empty "$SHIFT_START" >/dev/null 2>&1; then
    fail "shift_start.json is not valid JSON"
fi

# Confirm important Task 0 checks were successful.
if ! jq -e '
    .prior_project_bins.pipeline == true and
    .prior_project_bins.baseline == true and
    .prior_project_bins.catalog == true and
    .prior_project_bins.triage == true and
    .wazuh_exports_verified == true
' "$SHIFT_START" >/dev/null; then
    fail "shift intake checks did not pass"
fi

echo "[pipeline] intake check: OK"


# --------------------------------------------------
# Check pipeline executable
# --------------------------------------------------

if [[ ! -x "$PIPELINE_BIN" ]]; then
    fail "PIPELINE_BIN is missing or not executable: $PIPELINE_BIN"
fi


# --------------------------------------------------
# Paths
# --------------------------------------------------

OUTPUT_DIR="$SHIFT_WORKSPACE/enriched"
LOG_FILE="$SHIFT_WORKSPACE/runtime/pipeline_run.log"
RUN_JSON="$SHIFT_WORKSPACE/runtime/pipeline_run.json"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$SHIFT_WORKSPACE/runtime"


# --------------------------------------------------
# Try to get pipeline version
# --------------------------------------------------

PIPELINE_VERSION="unknown"

if VERSION_OUTPUT=$("$PIPELINE_BIN" --version 2>/dev/null); then
    if [[ -n "$VERSION_OUTPUT" ]]; then
        PIPELINE_VERSION=$(printf '%s\n' "$VERSION_OUTPUT" | head -1)
    fi
fi


# --------------------------------------------------
# 2. Start pipeline
# --------------------------------------------------

START_EPOCH=$(date -u +%s)
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[pipeline] invoking $PIPELINE_BIN"
echo "[pipeline] input: $CAPSTONE_PACK"
echo "[pipeline] output: $OUTPUT_DIR/"


# --------------------------------------------------
# 3. Run pipeline and save stdout + stderr
# --------------------------------------------------

set +e

"$PIPELINE_BIN" "$CAPSTONE_PACK" "$OUTPUT_DIR" 2>&1 |
    tee "$LOG_FILE" |
    while IFS= read -r line
    do
        echo "[pipeline] $line"
    done

PIPELINE_STATUS=${PIPESTATUS[0]}

set -e


# --------------------------------------------------
# End time
# --------------------------------------------------

END_EPOCH=$(date -u +%s)
ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

DURATION=$((END_EPOCH - START_EPOCH))


# --------------------------------------------------
# Stop if pipeline failed
# --------------------------------------------------

if [[ "$PIPELINE_STATUS" -ne 0 ]]; then
    fail "pipeline exited with status $PIPELINE_STATUS - check $LOG_FILE"
fi

echo "[pipeline] pipeline completed successfully"
echo "[pipeline] duration ${DURATION}s"


# --------------------------------------------------
# 4. Check required pipeline outputs
# --------------------------------------------------

# Enriched events can use either accepted filename.

if [[ -s "$OUTPUT_DIR/enriched_events.jsonl" ]]; then
    EVENTS_FILE="$OUTPUT_DIR/enriched_events.jsonl"

elif [[ -s "$OUTPUT_DIR/enriched_events.json" ]]; then
    EVENTS_FILE="$OUTPUT_DIR/enriched_events.json"

else
    fail "missing enriched_events.jsonl or enriched_events.json"
fi


# Timeline can also use either accepted filename.

if [[ -s "$OUTPUT_DIR/timeline.jsonl" ]]; then
    TIMELINE_FILE="$OUTPUT_DIR/timeline.jsonl"

elif [[ -s "$OUTPUT_DIR/timeline_index.json" ]]; then
    TIMELINE_FILE="$OUTPUT_DIR/timeline_index.json"

else
    fail "missing timeline.jsonl or timeline_index.json"
fi


SOURCE_STATS="$OUTPUT_DIR/source_stats.json"

if [[ ! -s "$SOURCE_STATS" ]]; then
    fail "missing or empty source_stats.json"
fi


# Validate source_stats JSON.

if ! jq empty "$SOURCE_STATS" >/dev/null 2>&1; then
    fail "source_stats.json is not valid JSON"
fi


echo "[pipeline] enriched events: OK"
echo "[pipeline] timeline: OK"
echo "[pipeline] source_stats.json: OK"


# --------------------------------------------------
# 5. Print source counts
# --------------------------------------------------

echo "[pipeline] source counts:"

jq -r '
    to_entries[]
    | select(.key != "overall")
    | select(.value | type == "object")
    | select(.value.record_count != null)
    | "[pipeline] source \(.key)=\(.value.record_count)"
' "$SOURCE_STATS"


# Count how many source types have events.

NONZERO_SOURCES=$(
    jq '
        [
            to_entries[]
            | select(.key != "overall")
            | select(.value | type == "object")
            | select((.value.record_count // 0) > 0)
        ]
        | length
    ' "$SOURCE_STATS"
)


if [[ "$NONZERO_SOURCES" -lt 4 ]]; then
    fail "only $NONZERO_SOURCES source types contain events; at least 4 are required"
fi

echo "[pipeline] non-zero source types: $NONZERO_SOURCES"


# --------------------------------------------------
# Calculate events_out
# --------------------------------------------------

if [[ "$EVENTS_FILE" == *.jsonl ]]; then

    EVENTS_OUT=$(
        grep -cve '^[[:space:]]*$' "$EVENTS_FILE" || true
    )

else

    EVENTS_OUT=$(
        jq '
            if type == "array"
            then length
            else 0
            end
        ' "$EVENTS_FILE"
    )

fi


# --------------------------------------------------
# Read dropped/input counts if pipeline recorded them
# --------------------------------------------------

EVENTS_DROPPED=$(
    jq '
        .overall.events_dropped //
        .overall.dropped_count //
        .events_dropped //
        .dropped_count //
        0
    ' "$SOURCE_STATS"
)


EVENTS_IN=$(
    jq '
        .overall.events_in //
        .overall.input_count //
        .events_in //
        .input_count //
        empty
    ' "$SOURCE_STATS"
)


# If source_stats does not contain events_in,
# calculate it from output + dropped.

if [[ -z "$EVENTS_IN" || "$EVENTS_IN" == "null" ]]; then
    EVENTS_IN=$((EVENTS_OUT + EVENTS_DROPPED))
fi


# --------------------------------------------------
# Build the required source_counts object
# --------------------------------------------------

# This searches source names instead of depending on
# one exact source_stats key name.

SOURCE_COUNTS=$(
    jq '
        def count_source($pattern):
            (
                [
                    to_entries[]
                    | select(.key != "overall")
                    | select(.value | type == "object")
                    | select(.key | test($pattern; "i"))
                    | (.value.record_count // 0)
                ]
                | add
            ) // 0;

        {
            windows_json: count_source("windows"),
            linux_text: count_source("linux"),
            firewall: count_source("firewall"),
            suricata_alert: count_source("suricata"),
            pcap_flow: count_source("pcap|netflow|flow")
        }
    ' "$SOURCE_STATS"
)


# --------------------------------------------------
# Detect dirty-data categories reported by pipeline
# --------------------------------------------------

DIRTY_DATA=()


if grep -Eqi 'clock.?skew|timestamp.?skew' "$LOG_FILE"; then
    DIRTY_DATA+=("clock_skew")
fi


if grep -Eqi 'duplicate' "$LOG_FILE"; then
    DIRTY_DATA+=("duplicate_events")
fi


if grep -Eqi 'sysmon.*(gap|restart)|(gap|restart).*sysmon' "$LOG_FILE"; then
    DIRTY_DATA+=("sysmon_telemetry_gap")
fi


if grep -Eqi 'malformed.*syslog|syslog.*malformed' "$LOG_FILE"; then
    DIRTY_DATA+=("malformed_syslog")
fi


# Convert Bash array into JSON array.

DIRTY_JSON='[]'

if [[ ${#DIRTY_DATA[@]} -gt 0 ]]; then

    DIRTY_JSON=$(
        printf '%s\n' "${DIRTY_DATA[@]}" |
        jq -R . |
        jq -s .
    )

fi


# --------------------------------------------------
# 6. Write pipeline_run.json
# --------------------------------------------------

RESOLVED_PACK=$(readlink -f "$CAPSTONE_PACK")


jq -n \
    --arg pipeline_version "$PIPELINE_VERSION" \
    --arg started_at "$STARTED_AT" \
    --arg ended_at "$ENDED_AT" \
    --arg input_pack "$RESOLVED_PACK" \
    --argjson duration_seconds "$DURATION" \
    --argjson events_in "$EVENTS_IN" \
    --argjson events_out "$EVENTS_OUT" \
    --argjson events_dropped "$EVENTS_DROPPED" \
    --argjson source_counts "$SOURCE_COUNTS" \
    --argjson dirty_data "$DIRTY_JSON" \
    --argjson exit_status "$PIPELINE_STATUS" \
'
{
    pipeline_version: $pipeline_version,
    started_at: $started_at,
    ended_at: $ended_at,
    duration_seconds: $duration_seconds,
    input_pack: $input_pack,
    events_in: $events_in,
    events_out: $events_out,
    events_dropped: $events_dropped,
    source_counts: $source_counts,
    dirty_data_detected: $dirty_data,
    exit_status: $exit_status
}
' > "$RUN_JSON"


# --------------------------------------------------
# Final summary
# --------------------------------------------------

echo "[pipeline] events_in=$EVENTS_IN events_out=$EVENTS_OUT dropped=$EVENTS_DROPPED"

echo "[pipeline] source windows_json=$(jq -r '.windows_json' <<< "$SOURCE_COUNTS")"
echo "[pipeline] source linux_text=$(jq -r '.linux_text' <<< "$SOURCE_COUNTS")"
echo "[pipeline] source firewall=$(jq -r '.firewall' <<< "$SOURCE_COUNTS")"
echo "[pipeline] source suricata_alert=$(jq -r '.suricata_alert' <<< "$SOURCE_COUNTS")"
echo "[pipeline] source pcap_flow=$(jq -r '.pcap_flow' <<< "$SOURCE_COUNTS")"

echo "[pipeline] pipeline_run.json written"
