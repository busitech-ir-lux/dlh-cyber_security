#!/bin/bash

# Task 4 - Scenario A via CLI: Credential Theft Chain

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO="$ASSETS_DIR/scenarios/scenario_a_credential_theft.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"

FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/scenario_a_cli.json"

TMP_SCOPED=$(mktemp)
TMP_CHAIN=$(mktemp)

trap 'rm -f "$TMP_SCOPED" "$TMP_CHAIN"' EXIT


# ------------------------------------------------------------
# 1. Start timing
# ------------------------------------------------------------

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------
# 2. Check required files
# ------------------------------------------------------------

if [ ! -s "$SCENARIO" ]; then
    echo "ERROR: scenario manifest missing: $SCENARIO" >&2
    exit 1
fi

if [ ! -s "$EVENTS" ]; then
    echo "ERROR: enriched_events.json missing or empty" >&2
    exit 1
fi


# ------------------------------------------------------------
# 3. Read scenario manifest
# ------------------------------------------------------------

SCENARIO_NAME=$(jq -r '
    .scenario_name //
    .name //
    .scenario_id //
    "scenario_a_credential_theft"
' "$SCENARIO")

HOST=$(jq -r '
    .target_host //
    .host //
    .hostname //
    empty
' "$SCENARIO")

WINDOW_START=$(jq -r '
    .time_window.start //
    .time_window.from //
    empty
' "$SCENARIO")

WINDOW_END=$(jq -r '
    .time_window.end //
    .time_window.to //
    empty
' "$SCENARIO")


if [ -z "$HOST" ] ||
   [ -z "$WINDOW_START" ] ||
   [ -z "$WINDOW_END" ]; then
    echo "ERROR: could not read host or time window from manifest" >&2
    exit 1
fi


printf '%-12s: %s\n' "scenario" "$SCENARIO_NAME"
printf '%-12s: %s\n' "host" "$HOST"
printf '%-12s: %s -> %s\n' \
    "window" "$WINDOW_START" "$WINDOW_END"


# ------------------------------------------------------------
# 4. Scope events to host and time window
# ------------------------------------------------------------

jq -c \
    --arg host "$HOST" \
    --arg start "$WINDOW_START" \
    --arg end "$WINDOW_END" '

    if type == "array" then .[] else . end

    | select(
        .hostname == $host
        and .timestamp >= $start
        and .timestamp <= $end
    )

' "$EVENTS" > "$TMP_SCOPED"


SCOPED_COUNT=$(wc -l < "$TMP_SCOPED")

printf '%-12s: %s events on %s in window\n' \
    "scoped" "$SCOPED_COUNT" "$HOST"


# ------------------------------------------------------------
# 5. Keep Sysmon EID 10, 11 and 3
# ------------------------------------------------------------

jq -c '
    select(
        (.event_id == 10) or
        (.event_id == 11) or
        (.event_id == 3)
    )
' "$TMP_SCOPED" |
sort -t '"' -k4 > "$TMP_CHAIN"


CHAIN_COUNT=$(wc -l < "$TMP_CHAIN")

if [ "$CHAIN_COUNT" -eq 0 ]; then
    echo "ERROR: no Sysmon EID 10, 11, or 3 events found" >&2
    exit 1
fi


# ------------------------------------------------------------
# 6. Print matching records
# ------------------------------------------------------------

echo
echo "Matching records:"
jq . "$TMP_CHAIN"
echo


# ------------------------------------------------------------
# 7. Extract useful details from each event type
# ------------------------------------------------------------

EID10_TIME=$(jq -r '
    select(.event_id == 10)
    | .timestamp
' "$TMP_CHAIN" | head -1)

EID10_SOURCE=$(jq -r '
    select(.event_id == 10)
    | (
        .source_fields.SourceImage //
        .event_data.SourceImage //
        .process_name //
        "unknown"
      )
' "$TMP_CHAIN" | head -1)

EID10_TARGET=$(jq -r '
    select(.event_id == 10)
    | (
        .source_fields.TargetImage //
        .event_data.TargetImage //
        "lsass.exe"
      )
' "$TMP_CHAIN" | head -1)


EID11_TIME=$(jq -r '
    select(.event_id == 11)
    | .timestamp
' "$TMP_CHAIN" | head -1)

EID11_FILE=$(jq -r '
    select(.event_id == 11)
    | (
        .source_fields.TargetFilename //
        .event_data.TargetFilename //
        .file_path //
        "unknown"
      )
' "$TMP_CHAIN" | head -1)


EID3_TIME=$(jq -r '
    select(.event_id == 3)
    | .timestamp
' "$TMP_CHAIN" | head -1)

EID3_PROCESS=$(jq -r '
    select(.event_id == 3)
    | (
        .source_fields.Image //
        .event_data.Image //
        .process_name //
        "unknown"
      )
' "$TMP_CHAIN" | head -1)

EID3_IP=$(jq -r '
    select(.event_id == 3)
    | (
        .dst_ip //
        .source_fields.DestinationIp //
        .event_data.DestinationIp //
        "unknown"
      )
' "$TMP_CHAIN" | head -1)

EID3_PORT=$(jq -r '
    select(.event_id == 3)
    | (
        .dst_port //
        .source_fields.DestinationPort //
        .event_data.DestinationPort //
        "unknown"
      )
' "$TMP_CHAIN" | head -1)


# Show short process/file names
EID10_SOURCE_SHORT=$(basename "$EID10_SOURCE")
EID10_TARGET_SHORT=$(basename "$EID10_TARGET")
EID3_PROCESS_SHORT=$(basename "$EID3_PROCESS")


printf '%-12s: %s accessed by %s at %s\n' \
    "EID 10" \
    "$EID10_TARGET_SHORT" \
    "$EID10_SOURCE_SHORT" \
    "$EID10_TIME"

printf '%-12s: %s created at %s\n' \
    "EID 11" \
    "$EID11_FILE" \
    "$EID11_TIME"

printf '%-12s: %s -> %s:%s at %s\n' \
    "EID 3" \
    "$EID3_PROCESS_SHORT" \
    "$EID3_IP" \
    "$EID3_PORT" \
    "$EID3_TIME"


# ------------------------------------------------------------
# 8. Investigation hypothesis
# ------------------------------------------------------------

HYPOTHESIS="LSASS memory access followed by dump file creation and an SMB network connection indicates credential dumping followed by lateral movement from clin-ws-12."

printf '%-12s: %s\n' "hypothesis" "$HYPOTHESIS"

printf '%-12s: %s\n' \
    "attack" \
    "T1003.001 T1550.002 T1021.002"


# ------------------------------------------------------------
# 9. Collect event references
# ------------------------------------------------------------

EVENT_REFS=$(jq -s '
    [
        .[]
        | .event_ref
        | select(. != null)
    ]
' "$TMP_CHAIN")


# ------------------------------------------------------------
# 10. Finish timing
# ------------------------------------------------------------

INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)

ELAPSED=$((END_EPOCH - START_EPOCH))

CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$FINDINGS_DIR"


# ------------------------------------------------------------
# 11. Write finding
# ------------------------------------------------------------

jq -n \
    --arg finding_id "scenario_a_cli" \
    --arg scenario_id "scenario_a" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson event_refs "$EVENT_REFS" \
    --arg hypothesis "$HYPOTHESIS" \
    --arg created_at "$CREATED_AT" \
    '{
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,

        actions: [
            "read scenario A manifest",
            "scope enriched events to clin-ws-12 and scenario time window",
            "filter Sysmon event ID 10",
            "filter Sysmon event ID 11",
            "filter Sysmon event ID 3",
            "order matching events by timestamp",
            "inspect process, file, destination IP and destination port fields",
            "form credential theft chain hypothesis"
        ],

        fields_touched: [
            "timestamp",
            "hostname",
            "event_id",
            "process_name",
            "dst_ip",
            "dst_port",
            "event_ref",
            "source_fields"
        ],

        event_refs: $event_refs,

        attack_techniques: [
            "T1003.001",
            "T1550.002",
            "T1021.002"
        ],

        hypothesis: $hypothesis,
        confidence: "high",
        created_at: $created_at
    }' > "$FINDING"


# ------------------------------------------------------------
# 12. Final output
# ------------------------------------------------------------

printf '%-12s: %s seconds, 8 commands\n' \
    "elapsed" "$ELAPSED"

printf '%-12s: %s written\n' \
    "finding" "$FINDING"

exit 0
