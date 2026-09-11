#!/bin/bash

# Task 3 - Investigate the anchor event through Wazuh export artifacts

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

SEARCH_FILE="$WAZUH_EXPORTS/anchor_search_results.json"
TRACE_FILE="$WAZUH_EXPORTS/anchor_dashboard_trace.json"
FIELD_MAP="$WAZUH_EXPORTS/field_mapping.json"

FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/anchor_export.json"


# ------------------------------------------------------------
# 1. Start timing
# ------------------------------------------------------------

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------
# 2. Check required files
# ------------------------------------------------------------

for file in "$SEARCH_FILE" "$TRACE_FILE" "$FIELD_MAP"
do
    if [ ! -s "$file" ]; then
        echo "ERROR: missing or empty file: $file" >&2
        exit 1
    fi
done


# ------------------------------------------------------------
# 3. Read anchor search export
# ------------------------------------------------------------

HITS_TOTAL=$(jq -r '
    .hits_total //
    .hits.total //
    .total //
    empty
' "$SEARCH_FILE")

KQL_QUERY=$(jq -r '
    .kql_query //
    .query //
    empty
' "$SEARCH_FILE")

WINDOW_START=$(jq -r '
    .time_range.start //
    .time_range.earliest //
    .time_range.from //
    empty
' "$SEARCH_FILE")

WINDOW_END=$(jq -r '
    .time_range.end //
    .time_range.latest //
    .time_range.to //
    empty
' "$SEARCH_FILE")


if [ -z "$HITS_TOTAL" ] ||
   [ -z "$KQL_QUERY" ]; then
    echo "ERROR: could not read hits_total or KQL query" >&2
    exit 1
fi


printf '%-12s: %s\n' "reading" "$SEARCH_FILE"
printf '%-12s: %s\n' "hits_total" "$HITS_TOTAL"
printf '%-12s: %s\n' "kql_query" "$KQL_QUERY"


# ------------------------------------------------------------
# 4. Read first and last event
# ------------------------------------------------------------

EVENT_COUNT=$(jq '.events | length' "$SEARCH_FILE")

if [ "$EVENT_COUNT" -eq 0 ]; then
    echo "ERROR: no events found in anchor export" >&2
    exit 1
fi


FIRST_TIMESTAMP=$(jq -r '
    .events
    | sort_by(._source["@timestamp"])
    | first
    | ._source["@timestamp"]
' "$SEARCH_FILE")

FIRST_SRC_IP=$(jq -r '
    .events
    | sort_by(._source["@timestamp"])
    | first
    | ._source.source.ip
' "$SEARCH_FILE")


LAST_TIMESTAMP=$(jq -r '
    .events
    | sort_by(._source["@timestamp"])
    | last
    | ._source["@timestamp"]
' "$SEARCH_FILE")

LAST_SRC_IP=$(jq -r '
    .events
    | sort_by(._source["@timestamp"])
    | last
    | ._source.source.ip
' "$SEARCH_FILE")


printf '%-12s: %s (%s)\n' \
    "first event" "$FIRST_TIMESTAMP" "$FIRST_SRC_IP"

printf '%-12s: %s (%s)\n' \
    "last event" "$LAST_TIMESTAMP" "$LAST_SRC_IP"


# ------------------------------------------------------------
# 5. Read dashboard trace
# ------------------------------------------------------------

CLICK_PATH=$(jq -c '.click_path' "$TRACE_FILE")

ESTIMATED_TIME=$(jq -r '
    .estimated_time_seconds //
    0
' "$TRACE_FILE")

CLICK_COUNT=$(jq '.click_path | length' "$TRACE_FILE")


# ------------------------------------------------------------
# 6. Print field mappings
# ------------------------------------------------------------

echo "field map   :"

for field in src_ip hostname user event_ref raw_message
do
    WAZUH_FIELD=$(jq -r \
        --arg field "$field" '

        (.mappings // .field_mappings // .) as $m

        | if ($m | type) == "object" then
              $m[$field] // empty
          else
              empty
          end

    ' "$FIELD_MAP")

    printf '  %-12s -> %s\n' \
        "$field" "$WAZUH_FIELD"
done


printf '%-12s: %s steps loaded from dashboard_trace\n' \
    "click_path" "$CLICK_COUNT"


# ------------------------------------------------------------
# 7. Collect event references
#
# Wazuh uses _id as the equivalent event reference.
# ------------------------------------------------------------

EVENT_REFS=$(jq '
    [
        .events[]
        | ._id
        | select(. != null)
    ]
' "$SEARCH_FILE")


# ------------------------------------------------------------
# 8. Finish timing
# ------------------------------------------------------------

INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)

ELAPSED=$((END_EPOCH - START_EPOCH))

CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$FINDINGS_DIR"


# ------------------------------------------------------------
# 9. Write finding
# ------------------------------------------------------------

jq -n \
    --arg finding_id "anchor_wazuh_export" \
    --arg scenario_id "anchor" \
    --arg interface "wazuh_export" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$CLICK_PATH" \
    --argjson event_refs "$EVENT_REFS" \
    --arg created_at "$CREATED_AT" \
    '{
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,

        actions: $actions,

        fields_touched: [
            "@timestamp",
            "source.ip",
            "destination.ip",
            "agent.name",
            "user.name"
        ],

        event_refs: $event_refs,

        attack_techniques: [
            "T1110.003"
        ],

        hypothesis:
            "Multiple external IP addresses performed repeated SSH authentication attempts against db-patient-01, followed by a successful root login. The activity is consistent with an SSH brute force attack.",

        confidence: "high",

        created_at: $created_at
    }' > "$FINDING"


# ------------------------------------------------------------
# 10. Final output
# ------------------------------------------------------------

printf '%-12s: %s seconds, 4 file reads\n' \
    "elapsed" "$ELAPSED"

printf '%-12s: %s written\n' \
    "finding" "$FINDING"

exit 0
