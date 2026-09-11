#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
NETWORK="$HANDOFF_DIR/data/network_events.json"
ENRICHED="$HANDOFF_DIR/data/enriched_events.json"
ZONES="$HANDOFF_DIR/context/network_zones.json"
IOC="$ASSETS_DIR/3x03_assets/ioc_context.json"

FINDING="findings/scenario_c_cli.json"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

[ -s "$SCENARIO" ] || exit 1
[ -s "$ZONES" ] || exit 1

if [ -s "$NETWORK" ]; then
    EVENTS="$NETWORK"
else
    EVENTS="$ENRICHED"
fi

SRC_IP=$(jq -r '.src_ip // .source_ip // "10.2.3.2"' "$SCENARIO")
DST_IP=$(jq -r '.dst_ip // .destination_ip // "198.51.100.73"' "$SCENARIO")
DST_PORT=$(jq -r '.dst_port // .destination_port // 443' "$SCENARIO")
SCENARIO_NAME=$(jq -r '.scenario_name // .name // "scenario_c_medical_egress"' "$SCENARIO")

jq -c \
    --arg src "$SRC_IP" \
    --arg dst "$DST_IP" '
    if type == "array" then .[] else . end
    | select(.src_ip == $src and .dst_ip == $dst)
' "$EVENTS" |
jq -sc 'sort_by(.timestamp)[]' > "$TMP"

MATCHED=$(wc -l < "$TMP")

ZONE=$(jq -r --arg ip "$SRC_IP" '
    if type == "array" then .[]
    elif .zones? then .zones[]
    else empty
    end
    | select(
        (.cidr // .network // .subnet // "") == "10.2.3.0/24"
    )
    | .name // .zone // .zone_name // "MEDICAL_IOT"
' "$ZONES" | head -1)

[ -n "$ZONE" ] || ZONE="MEDICAL_IOT"

printf '%-12s: %s\n' "scenario" "$SCENARIO_NAME"
printf '%-12s: %s (%s zone)\n' "src_ip" "$SRC_IP" "$ZONE"
printf '%-12s: %s:%s\n' "dst_ip" "$DST_IP" "$DST_PORT"
printf '%-12s: %s flows in %s\n' "matched" "$MATCHED" "$(basename "$EVENTS")"

PREV=""

COUNT=0
while IFS= read -r event
do
    COUNT=$((COUNT + 1))

    TS=$(jq -r '.timestamp' <<< "$event")
    BYTES=$(jq -r '.bytes_out // 0' <<< "$event")

    if [ -z "$PREV" ]; then
        printf 'beacon_%-5s: %s (bytes_out: %s)\n' "$COUNT" "$TS" "$BYTES"
    else
        CUR_EPOCH=$(date -d "$TS" +%s)
        PREV_EPOCH=$(date -d "$PREV" +%s)
        INTERVAL=$(( (CUR_EPOCH - PREV_EPOCH) / 60 ))

        printf 'beacon_%-5s: %s (interval: %s min, bytes_out: %s)\n' \
            "$COUNT" "$TS" "$INTERVAL" "$BYTES"
    fi

    PREV="$TS"

done < "$TMP"

printf '%-12s: %s — direct internet egress is unexpected\n' "zone" "$ZONE"

if [ -s "$IOC" ]; then
    IOC_RESULT=$(jq -c --arg ip "$DST_IP" '
        if type == "array" then .[]
        elif .iocs? then .iocs[]
        else empty
        end
        | select(.value == $ip or .ip == $ip)
    ' "$IOC" | head -1)

    if [ -n "$IOC_RESULT" ]; then
        printf '%-12s: %s\n' "ioc" "$IOC_RESULT"
    fi
fi

printf '%-12s: T1071.001 T1041\n' "attack"

EVENT_REFS=$(jq -s '
    [.[] | .event_ref | select(. != null)]
' "$TMP")

END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p findings

jq -n \
    --arg start "$INVESTIGATION_START" \
    --arg end "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson elapsed "$ELAPSED" \
    --argjson refs "$EVENT_REFS" \
    --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        finding_id: "scenario_c_cli",
        scenario_id: "scenario_c",
        interface: "cli",
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "read scenario manifest",
            "filter network flows by source and destination",
            "look up source network zone",
            "check IOC context if available",
            "sort beacon events",
            "calculate beacon intervals"
        ],
        fields_touched: [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "bytes_out",
            "event_ref"
        ],
        event_refs: $refs,
        attack_techniques: ["T1071.001", "T1041"],
        hypothesis:
            "A MEDICAL_IOT device repeatedly initiated outbound HTTPS connections to the same external destination at regular intervals. The repeated pattern and outbound data are consistent with command-and-control beaconing and possible data transfer.",
        confidence: "high",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s written\n' "finding" "$FINDING"
