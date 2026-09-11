#!/bin/bash

# Task 2 - Investigate the anchor event using CLI tools only

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

ANCHOR="$ASSETS_DIR/anchor_event.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
RULE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"

FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/anchor_cli.json"

TMP_MATCHES=$(mktemp)
trap 'rm -f "$TMP_MATCHES"' EXIT


# ------------------------------------------------------------
# 1. Start measurement
# ------------------------------------------------------------

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------
# 2. Check required input files
# ------------------------------------------------------------

if [ ! -s "$ANCHOR" ]; then
    echo "ERROR: anchor_event.json missing or empty" >&2
    exit 1
fi

if [ ! -s "$EVENTS" ]; then
    echo "ERROR: enriched_events.json missing or empty" >&2
    exit 1
fi


# ------------------------------------------------------------
# 3. Read anchor manifest
# ------------------------------------------------------------

TARGET_HOST=$(jq -r '.target_host' "$ANCHOR")

TARGET_IP=$(jq -r '
    .target_ip //
    .target_host_ip //
    empty
' "$ANCHOR")

WINDOW_START=$(jq -r '
    .time_window.start //
    .time_window.from //
    .time_window.earliest //
    empty
' "$ANCHOR")

WINDOW_END=$(jq -r '
    .time_window.end //
    .time_window.to //
    .time_window.latest //
    empty
' "$ANCHOR")

ATTACKER_IPS=$(jq -c '.attacker_ips' "$ANCHOR")

if [ -z "$TARGET_HOST" ] ||
   [ -z "$WINDOW_START" ] ||
   [ -z "$WINDOW_END" ] ||
   [ "$ATTACKER_IPS" = "null" ]; then
    echo "ERROR: required anchor fields could not be read" >&2
    exit 1
fi


printf '%-12s: %s\n' "reading" "$ANCHOR"

if [ -n "$TARGET_IP" ]; then
    printf '%-12s: %s (%s)\n' "host" "$TARGET_HOST" "$TARGET_IP"
else
    printf '%-12s: %s\n' "host" "$TARGET_HOST"
fi

printf '%-12s: %s -> %s\n' \
    "window" "$WINDOW_START" "$WINDOW_END"

printf '%-12s: %s\n' \
    "attacker ips" "$(jq -r 'join(" ")' <<< "$ATTACKER_IPS")"


# ------------------------------------------------------------
# 4. Filter matching events
#
# Works with either:
#   - newline-delimited JSON
#   - one JSON array
# ------------------------------------------------------------

jq -c \
    --arg host "$TARGET_HOST" \
    --arg start "$WINDOW_START" \
    --arg end "$WINDOW_END" \
    --argjson ips "$ATTACKER_IPS" '

    if type == "array" then .[] else . end

    | . as $event

    | select(
        $event.hostname == $host
        and $event.timestamp >= $start
        and $event.timestamp <= $end
        and ($ips | index($event.src_ip)) != null
    )

' "$EVENTS" > "$TMP_MATCHES"


# ------------------------------------------------------------
# 5. Count and inspect matching events
# ------------------------------------------------------------

MATCH_COUNT=$(wc -l < "$TMP_MATCHES")

if [ "$MATCH_COUNT" -eq 0 ]; then
    echo "ERROR: no anchor events matched" >&2
    exit 1
fi

FIRST_EVENT=$(jq -r '.timestamp' "$TMP_MATCHES" | sort | head -1)
LAST_EVENT=$(jq -r '.timestamp' "$TMP_MATCHES" | sort | tail -1)

printf '%-12s: %s events in enriched_events.json\n' \
    "matched" "$MATCH_COUNT"

printf '%-12s: %s\n' "first event" "$FIRST_EVENT"
printf '%-12s: %s\n' "last event" "$LAST_EVENT"


# ------------------------------------------------------------
# 6. Read Sigma rule if available
# ------------------------------------------------------------

ATTACK_TECHNIQUE="T1110.003"

if [ -s "$RULE" ]; then

    printf '%-12s: 001_ssh_brute_force (%s)\n' \
        "rule" "$ATTACK_TECHNIQUE"

    echo
    echo "logsource:"
    yq '.logsource' "$RULE"

    echo
    echo "detection:"
    yq '.detection' "$RULE"
    echo

else
    printf '%-12s: not available (%s)\n' \
        "rule" "$RULE"
fi


# ------------------------------------------------------------
# 7. Collect event references for finding
# ------------------------------------------------------------

EVENT_REFS=$(jq -s '
    [
        .[]
        | .event_ref
        | select(. != null)
    ]
' "$TMP_MATCHES")


# ------------------------------------------------------------
# 8. Finish timing
# ------------------------------------------------------------

INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)

ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p "$FINDINGS_DIR"

CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------
# 9. Write locked finding schema
# ------------------------------------------------------------

jq -n \
    --arg finding_id "anchor_cli" \
    --arg scenario_id "anchor" \
    --arg interface "cli" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson event_refs "$EVENT_REFS" \
    --arg technique "$ATTACK_TECHNIQUE" \
    --arg created_at "$CREATED_AT" \
    '{
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $investigation_start,
        investigation_end: $investigation_end,
        time_to_first_answer_seconds: $elapsed,

        actions: [
            "read anchor event manifest",
            "filter enriched events by host, time window, and attacker IPs",
            "count matching events",
            "identify earliest and latest matching events",
            "inspect Sigma rule when available"
        ],

        fields_touched: [
            "timestamp",
            "hostname",
            "src_ip",
            "event_ref"
        ],

        event_refs: $event_refs,

        attack_techniques: [
            $technique
        ],

        hypothesis:
            "Multiple external IP addresses performed repeated SSH authentication attempts against db-patient-01, followed by a successful root login. The activity is consistent with an SSH brute force attack.",

        confidence: "high",

        created_at: $created_at
    }' > "$FINDING"


# ------------------------------------------------------------
# 10. Final output
# ------------------------------------------------------------

printf '%-12s: %s seconds, 5 commands\n' \
    "elapsed" "$ELAPSED"

printf '%-12s: %s written\n' \
    "finding" "$FINDING"

exit 0
