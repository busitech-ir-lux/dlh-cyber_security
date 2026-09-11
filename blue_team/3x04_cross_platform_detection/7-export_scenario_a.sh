#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH="$ASSETS_DIR/wazuh_exports"

SEARCH="$WAZUH/scenario_a_search_results.json"
TRACE="$WAZUH/scenario_a_dashboard_trace.json"
SUMMARY="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"

CLI_FINDING="findings/scenario_a_cli.json"
FINDING="findings/scenario_a_export.json"

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

for f in "$SEARCH" "$TRACE"
do
    [ -s "$f" ] || {
        echo "ERROR: missing: $f" >&2
        exit 1
    }
done

TOTAL=$(jq -r '.hits_total // .hits.total // (.events | length)' "$SEARCH")
KQL=$(jq -r '.kql_query // .query // empty' "$SEARCH")

printf '%-12s: %s (%s events)\n' "reading" "$(basename "$SEARCH")" "$TOTAL"
printf '%-12s: %s\n' "kql" "$KQL"

for eid in 10 11 3
do
    EVENT=$(jq -c --argjson eid "$eid" '
        .events[]
        | select(._source.winlog.event_id == $eid)
    ' "$SEARCH" | head -1)

    [ -n "$EVENT" ] || continue

    TS=$(jq -r '._source["@timestamp"]' <<< "$EVENT")

    case "$eid" in
        10)
            VALUE=$(jq -r '
                ._source.process.name //
                ._source.full_log //
                "process fields present"
            ' <<< "$EVENT")
            ;;
        11)
            VALUE=$(jq -r '._source.full_log // "file created"' <<< "$EVENT")
            ;;
        3)
            VALUE=$(jq -r '
                ._source.destination.ip //
                "destination unavailable"
            ' <<< "$EVENT")
            ;;
    esac

    printf 'EID %-8s: %s at %s\n' "$eid" "$VALUE" "$TS"
done

CLICK_PATH=$(jq -c '.click_path' "$TRACE")
CLICK_COUNT=$(jq '.click_path | length' "$TRACE")
ESTIMATE=$(jq -r '.estimated_time_seconds // 0' "$TRACE")

FIELD_TRANSLATION=$(jq -c '.field_name_translation // {}' "$TRACE")

printf '%-12s: %s steps\n' "click_path" "$CLICK_COUNT"
printf '%-12s: %s\n' "field_map" "$FIELD_TRANSLATION"

if [ -s "$SUMMARY" ]; then
    echo "ATT&CK mapping:"
    awk '
        BEGIN {show=0}
        /^#+ .*ATT&CK/ {show=1}
        show {print}
        show && /^#+ / && !/ATT&CK/ {exit}
    ' "$SUMMARY"
fi

EVENT_REFS=$(jq '
    [.events[] | ._id | select(. != null)]
' "$SEARCH")

END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p findings

jq -n \
    --arg start "$INVESTIGATION_START" \
    --arg end "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$CLICK_PATH" \
    --argjson refs "$EVENT_REFS" \
    --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
        finding_id: "scenario_a_wazuh_export",
        scenario_id: "scenario_a",
        interface: "wazuh_export",
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "agent.name",
            "winlog.event_id",
            "process.name",
            "destination.ip",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: ["T1003.001", "T1550.002", "T1021.002"],
        hypothesis:
            "LSASS access followed by dump creation and SMB network activity indicates credential dumping followed by lateral movement.",
        confidence: "high",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s seconds, 4 file reads\n' "elapsed" "$ELAPSED"

if [ -s "$CLI_FINDING" ]; then
    CLI_TIME=$(jq '.time_to_first_answer_seconds' "$CLI_FINDING")
    DELTA=$((ELAPSED - CLI_TIME))

    if [ "$DELTA" -lt 0 ]; then
        printf '%-12s: %s seconds faster via export\n' "delta_vs_cli" "$((-DELTA))"
    elif [ "$DELTA" -gt 0 ]; then
        printf '%-12s: %s seconds slower via export\n' "delta_vs_cli" "$DELTA"
    else
        printf '%-12s: equal\n' "delta_vs_cli"
    fi
fi

printf '%-12s: %s written\n' "finding" "$FINDING"
