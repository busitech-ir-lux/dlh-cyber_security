#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH="$ASSETS_DIR/wazuh_exports"

SEARCH="$WAZUH/scenario_b_search_results.json"
TRACE="$WAZUH/scenario_b_dashboard_trace.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"

CLI_FINDING="findings/scenario_b_cli.json"
FINDING="findings/scenario_b_export.json"

START_EPOCH=$(date +%s)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

for f in "$SEARCH" "$TRACE"
do
    [ -s "$f" ] || exit 1
done

COUNT=$(jq '.events | length' "$SEARCH")

printf '%-12s: %s (%s events)\n' \
    "reading" "$(basename "$SEARCH")" "$COUNT"

HOST=$(jq -r '.events[0]._source.agent.name // "unknown"' "$SEARCH")
USER=$(jq -r '
    [.events[]._source.user.name // empty]
    | map(select(length > 0))
    | first // "unknown"
' "$SEARCH")

printf '%-12s: %s (from agent.name)\n' "host" "$HOST"
printf '%-12s: %s (from user.name)\n' "user" "$USER"

LABEL_CLASS=$(jq -r '
    [
        .events[]
        | ._source.agent.labels.data_classification?
        | select(. != null and . != "")
    ]
    | first // empty
' "$SEARCH")

FALLBACK=false

if [ -n "$LABEL_CLASS" ]; then
    DATA_CLASS="$LABEL_CLASS"
    printf '%-12s: %s (from agent.labels — resolved without fallback)\n' \
        "data_class" "$DATA_CLASS"
else
    FALLBACK=true

    DATA_CLASS=$(jq -r --arg host "$HOST" '
        if type == "array" then .[]
        elif .assets? then .assets[]
        else empty
        end
        | select(.hostname == $host or .name == $host)
        | .data_classification
    ' "$ASSETS" | head -1)

    printf '%-12s: %s (fallback: asset_inventory.json)\n' \
        "data_class" "$DATA_CLASS"
fi

FIRST_TIME=$(jq -r '
    [.events[]._source["@timestamp"]]
    | sort
    | first
' "$SEARCH")

printf '%-12s: %s outside 06:00-18:00 window\n' \
    "off_hours" "$(date -d "$FIRST_TIME" -u +%H:%MZ)"

CLICK_PATH=$(jq -c '.click_path' "$TRACE")
CLICK_COUNT=$(jq '.click_path | length' "$TRACE")

if [ "$FALLBACK" = true ]; then
    ACTIONS=$(jq -n \
        --argjson path "$CLICK_PATH" '
        $path + ["fallback lookup: asset_inventory.json for data_classification"]
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
    --arg class "$DATA_CLASS" \
    --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        finding_id: "scenario_b_wazuh_export",
        scenario_id: "scenario_b",
        interface: "wazuh_export",
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "agent.name",
            "user.name",
            "winlog.event_id",
            "agent.labels"
        ],
        event_refs: $refs,
        attack_techniques: ["T1078.002", "T1059.001"],
        hypothesis:
            ("Off-hours privileged activity occurred on a " +
             $class +
             " clinical workstation. The authorized identity creates ambiguity, but PowerShell ExecutionPolicy Bypass and timing warrant escalation."),
        confidence: "medium",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s steps\n' "click_path" "$CLICK_COUNT"
printf '%-12s: %s seconds\n' "elapsed" "$ELAPSED"
printf '%-12s: %s written\n' "finding" "$FINDING"

if [ -s "$CLI_FINDING" ]; then
    CLI=$(jq '.time_to_first_answer_seconds' "$CLI_FINDING")
    printf '%-12s: %+d seconds (export - cli)\n' \
        "delta_vs_cli" "$((ELAPSED - CLI))"
fi
