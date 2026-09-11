#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"

FINDING="findings/scenario_b_cli.json"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

for file in "$SCENARIO" "$EVENTS" "$ASSETS"
do
    [ -s "$file" ] || {
        echo "ERROR: missing or empty: $file" >&2
        exit 1
    }
done

SCENARIO_NAME=$(jq -r '.scenario_name // .name // "scenario_b_offhours_phi"' "$SCENARIO")
HOST=$(jq -r '.target_host // .host // .hostname // empty' "$SCENARIO")
START=$(jq -r '.time_window.start // .time_window.from // empty' "$SCENARIO")
END=$(jq -r '.time_window.end // .time_window.to // empty' "$SCENARIO")

AMBIGUITY=$(jq -r '
    .ambiguity //
    .ambiguity_note //
    .notes.ambiguity //
    "p.morales is authorized for EHR access, but off-hours timing and PowerShell ExecutionPolicy Bypass warrant escalation."
' "$SCENARIO")

if [ -z "$HOST" ] || [ -z "$START" ] || [ -z "$END" ]; then
    echo "ERROR: scenario host/time window missing" >&2
    exit 1
fi

# Find asset record.
ASSET=$(jq -c --arg host "$HOST" '
    if type == "array" then
        .[]
    elif .assets? then
        .assets[]
    elif .hosts? then
        .hosts[]
    else
        empty
    end
    | select(
        .hostname == $host or
        .host == $host or
        .name == $host
    )
' "$ASSETS" | head -1)

if [ -z "$ASSET" ]; then
    echo "ERROR: asset record not found for $HOST" >&2
    exit 1
fi

CRITICALITY=$(jq -r '.criticality // "unknown"' <<< "$ASSET")
DATA_CLASS=$(jq -r '.data_classification // "unknown"' <<< "$ASSET")

printf '%-12s: %s\n' "scenario" "$SCENARIO_NAME"
printf '%-12s: %s (criticality: %s, data: %s)\n' \
    "host" "$HOST" "$CRITICALITY" "$DATA_CLASS"
printf '%-12s: %s -> %s\n' "window" "$START" "$END"

# Scope once.
jq -c \
    --arg host "$HOST" \
    --arg start "$START" \
    --arg end "$END" '
    if type == "array" then .[] else . end
    | select(
        .hostname == $host and
        .timestamp >= $start and
        .timestamp <= $end
    )
' "$EVENTS" > "$TMP"

# 4624
E4624=$(jq -c 'select(.event_id == 4624)' "$TMP" | head -1)

if [ -n "$E4624" ]; then
    T4624=$(jq -r '.timestamp' <<< "$E4624")
    USER=$(jq -r '
        .user //
        .event_data.TargetUserName //
        .source_fields.TargetUserName //
        "unknown"
    ' <<< "$E4624")
    LOGON_TYPE=$(jq -r '
        .event_data.LogonType //
        .source_fields.LogonType //
        "RemoteInteractive"
    ' <<< "$E4624")

    printf '%-12s: %s %s logon at %s\n' \
        "EID 4624" "$USER" "$LOGON_TYPE" "$T4624"
fi

# 4672
E4672=$(jq -c 'select(.event_id == 4672)' "$TMP" | head -1)

if [ -n "$E4672" ]; then
    T4672=$(jq -r '.timestamp' <<< "$E4672")
    PRIVS=$(jq -r '
        .event_data.PrivilegeList //
        .source_fields.PrivilegeList //
        .raw_message //
        "special privileges assigned"
    ' <<< "$E4672")

    printf '%-12s: %s at %s\n' "EID 4672" "$PRIVS" "$T4672"
fi

# Sysmon 1
E1=$(jq -c 'select(.event_id == 1)' "$TMP" | head -1)

if [ -n "$E1" ]; then
    T1=$(jq -r '.timestamp' <<< "$E1")
    PROCESS=$(jq -r '
        .process_name //
        .event_data.Image //
        .source_fields.Image //
        "powershell.exe"
    ' <<< "$E1")

    COMMAND=$(jq -r '
        .event_data.CommandLine //
        .source_fields.CommandLine //
        .raw_message //
        ""
    ' <<< "$E1")

    printf '%-12s: %s %s at %s\n' \
        "EID 1" "$(basename "$PROCESS")" "$COMMAND" "$T1"
fi

printf '%-12s: %s\n' "ambiguity" "$AMBIGUITY"
printf '%-12s: T1078.002 T1059.001\n' "attack"

EVENT_REFS=$(jq -s '
    [
        .[]
        | select(.event_id == 4624 or .event_id == 4672 or .event_id == 1)
        | .event_ref
        | select(. != null)
    ]
' "$TMP")

END_EPOCH=$(date +%s)
INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p findings

jq -n \
    --arg start "$INVESTIGATION_START" \
    --arg end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson refs "$EVENT_REFS" \
    --arg ambiguity "$AMBIGUITY" \
    --arg criticality "$CRITICALITY" \
    --arg classification "$DATA_CLASS" \
    --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        finding_id: "scenario_a_cli" | sub("scenario_a"; "scenario_b"),
        scenario_id: "scenario_b",
        interface: "cli",
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "read scenario manifest",
            "scope events by host and time",
            "look up asset context",
            "inspect event 4624",
            "inspect event 4672",
            "inspect Sysmon event 1",
            "review ambiguity",
            "form escalation hypothesis"
        ],
        fields_touched: [
            "timestamp",
            "hostname",
            "event_id",
            "user",
            "process_name",
            "event_ref",
            "criticality",
            "data_classification"
        ],
        event_refs: $refs,
        attack_techniques: ["T1078.002", "T1059.001"],
        hypothesis:
            ("Privileged off-hours activity occurred on a " +
             $classification +
             " workstation. The user may be authorized, but PowerShell ExecutionPolicy Bypass and timing warrant escalation. " +
             $ambiguity),
        confidence: "medium",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s written\n' "finding" "$FINDING"
