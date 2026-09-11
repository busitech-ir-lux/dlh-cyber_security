#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH="$ASSETS_DIR/wazuh_exports"

SEARCH="$WAZUH/scenario_c_search_results.json"
TRACE="$WAZUH/scenario_c_dashboard_trace.json"
ZONES="$HANDOFF_DIR/context/network_zones.json"

CLI_FINDING="findings/scenario_c_cli.json"
FINDING="findings/scenario_c_export.json"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

START_EPOCH=$(date +%s)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

[ -s "$SEARCH" ] || exit 1
[ -s "$TRACE" ] || exit 1

COUNT=$(jq '.events | length' "$SEARCH")

printf '%-12s: %s (%s events)\n' \
    "reading" "$(basename "$SEARCH")" "$COUNT"

jq -c '
    .events
    | sort_by(._source["@timestamp"])
    | .[]
' "$SEARCH" > "$TMP"

SRC=$(jq -r '._source.source.ip' "$TMP" | head -1)
DST=$(jq -r '._source.destination.ip' "$TMP" | head -1)
PORT=$(jq -r '._source.destination.port // 443' "$TMP" | head -1)

printf '%-12s: %s\n' "src_ip" "$SRC"
printf '%-12s: %s:%s\n' "dst_ip" "$DST" "$PORT"

ZONE=$(jq -r '
    ._source.source.zone //
    empty
' "$TMP" | grep -v '^$' | head -1)

FALLBACK=false

if [ -n "$ZONE" ]; then
    printf '%-12s: %s (from source.zone — immediately available)\n' \
        "src_zone" "$ZONE"
else
    FALLBACK=true

    ZONE=$(jq -r '
        if type == "array" then .[]
        elif .zones? then .zones[]
        else empty
        end
        | select(
            (.cidr // .network // .subnet // "") == "10.2.3.0/24"
        )
        | .name // .zone // .zone_name
    ' "$ZONES" | head -1)

    printf '%-12s: %s (fallback: network_zones.json)\n' \
        "src_zone" "$ZONE"
fi

PREV=""
N=0

while IFS= read -r event
do
    N=$((N + 1))
    TS=$(jq -r '._source["@timestamp"]' <<< "$event")

    if [ -z "$PREV" ]; then
        printf 'beacon_%-5s: %s\n' "$N" "$TS"
    else
        A=$(date -d "$PREV" +%s)
        B=$(date -d "$TS" +%s)
        MIN=$(( (B - A) / 60 ))

        printf 'beacon_%-5s: %s (%s min interval)\n' \
            "$N" "$TS" "$MIN"
    fi

    PREV="$TS"

done < "$TMP"

CLICK_PATH=$(jq -c '.click_path' "$TRACE")

if [ "$FALLBACK" = true ]; then
    ACTIONS=$(jq -n \
        --argjson path "$CLICK_PATH" '
        $path + ["fallback lookup: network_zones.json for source zone"]
    ')
else
    ACTIONS="$CLICK_PATH"
fi

EVENT_REFS=$(jq '[.events[] | ._id | select(. != null)]' "$SEARCH")

ELAPSED=$(( $(date +%s) - START_EPOCH ))

mkdir -p findings

jq -n \
    --arg start "$START_TIME" \
    --arg end "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$ACTIONS" \
    --argjson refs "$EVENT_REFS" \
    --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        finding_id: "scenario_c_wazuh_export",
        scenario_id: "scenario_c",
        interface: "wazuh_export",
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "source.ip",
            "destination.ip",
            "destination.port",
            "source.zone",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: ["T1071.001", "T1041"],
        hypothesis:
            "A medical IoT device repeatedly contacted the same external HTTPS destination at regular intervals. The pattern is consistent with command-and-control beaconing and possible outbound data transfer.",
        confidence: "high",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: T1071.001 T1041\n' "attack"
printf '%-12s: %s seconds, 3 file reads\n' "elapsed" "$ELAPSED"

if [ -s "$CLI_FINDING" ]; then
    CLI=$(jq '.time_to_first_answer_seconds' "$CLI_FINDING")
    printf '%-12s: %+d seconds (export - cli)\n' \
        "delta_vs_cli" "$((ELAPSED - CLI))"
fi

printf '%-12s: %s written\n' "finding" "$FINDING"
