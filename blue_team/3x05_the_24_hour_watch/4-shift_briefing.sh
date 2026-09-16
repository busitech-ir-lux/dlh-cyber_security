#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[brief] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required variables
# --------------------------------------------------

for var in ASSETS_DIR SHIFT_WORKSPACE
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


ADVISORY="$ASSETS_DIR/hc_red7_advisory.md"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
CHANGE_FILE="$ASSETS_DIR/change_tickets.json"
NOTES_FILE="$ASSETS_DIR/prior_shift_notes.md"

BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"

OUTPUT="$SHIFT_WORKSPACE/alerts/shift_briefing.json"


# --------------------------------------------------
# 1. Check all required files
# --------------------------------------------------

echo -n "[brief] checking input files... "

for file in \
    "$ADVISORY" \
    "$IOC_FILE" \
    "$CHANGE_FILE" \
    "$NOTES_FILE" \
    "$BASELINE_RUN" \
    "$SHIFT_START"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done

echo "OK"


# --------------------------------------------------
# Validate JSON files
# --------------------------------------------------

for file in \
    "$IOC_FILE" \
    "$CHANGE_FILE" \
    "$BASELINE_RUN" \
    "$SHIFT_START"
do
    if ! jq empty "$file" >/dev/null 2>&1; then
        fail "invalid JSON: $file"
    fi
done


# --------------------------------------------------
# 2. IOC information
# --------------------------------------------------

IOC_COUNT=$(jq '.iocs | length' "$IOC_FILE")


# Count IOC types.

IOC_BY_TYPE=$(
    jq '
    {
        ip: (
            [.iocs[] | select((.type // "") == "ip")]
            | length
        ),

        domain: (
            [.iocs[] | select((.type // "") == "domain")]
            | length
        ),

        hash: (
            [.iocs[] | select((.type // "") == "hash")]
            | length
        ),

        account: (
            [.iocs[] | select((.type // "") == "account")]
            | length
        ),

        service_name: (
            [.iocs[] | select((.type // "") == "service_name")]
            | length
        ),

        port: (
            [.iocs[] | select((.type // "") == "port")]
            | length
        )
    }
    ' "$IOC_FILE"
)


# Flat IOC list for later fast lookup.

IOC_VALUES=$(
    jq '
        [
            .iocs[]
            | (
                .value //
                .indicator //
                .ioc //
                empty
            )
            | tostring
        ]
    ' "$IOC_FILE"
)


IP_COUNT=$(jq '.ip' <<< "$IOC_BY_TYPE")
DOMAIN_COUNT=$(jq '.domain' <<< "$IOC_BY_TYPE")
HASH_COUNT=$(jq '.hash' <<< "$IOC_BY_TYPE")
ACCOUNT_COUNT=$(jq '.account' <<< "$IOC_BY_TYPE")
SERVICE_COUNT=$(jq '.service_name' <<< "$IOC_BY_TYPE")
PORT_COUNT=$(jq '.port' <<< "$IOC_BY_TYPE")


# --------------------------------------------------
# 3. Advisory information
# --------------------------------------------------

CLUSTER_ID=$(
    grep -o -m1 'HC-RED7' "$ADVISORY" || true
)

if [[ "$CLUSTER_ID" != "HC-RED7" ]]; then
    fail "HC-RED7 not found in advisory"
fi


# Extract ATT&CK technique IDs.
# Supports normal text and markdown bullets.

TACTICS=$(
    grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' "$ADVISORY" |
    sort -u |
    jq -R . |
    jq -s .
)


# Count advisory note lines.
# This is printed for visibility even though it is
# not part of the locked output schema.

NOTE_COUNT=$(
    grep -ciE '(^|[[:space:]])note[: ]' "$ADVISORY" || true
)


echo "[brief] cluster $CLUSTER_ID loaded"

echo -n "[brief] tactics: "
jq -r '.[]' <<< "$TACTICS" | tr '\n' ' '
echo


# --------------------------------------------------
# Cross-check cluster ID with Task 0
# --------------------------------------------------

EXPECTED_CLUSTER=$(
    jq -r '.advisory_cluster_id // empty' "$SHIFT_START"
)


if [[ "$CLUSTER_ID" != "$EXPECTED_CLUSTER" ]]; then
    fail "cluster ID mismatch: advisory=$CLUSTER_ID shift_start=$EXPECTED_CLUSTER"
fi


# --------------------------------------------------
# 4. Extract approved change tickets
# --------------------------------------------------
#
# Supports:
#   [...]
#
# or:
#   {"tickets":[...]}
#
# or:
#   {"change_tickets":[...]}
# --------------------------------------------------

CHANGE_TICKETS=$(
    jq '
    (
        if type == "array" then
            .
        elif (.tickets | type?) == "array" then
            .tickets
        elif (.change_tickets | type?) == "array" then
            .change_tickets
        else
            []
        end
    )

    |

    map(
        select(
            (
                .status //
                .approval_status //
                "approved"
            )
            | tostring
            | ascii_downcase
            == "approved"
        )

        |

        {
            ticket_id: (
                .ticket_id //
                .id //
                .change_id //
                ""
                | tostring
            ),

            window_start: (
                .window_start //
                .start //
                .start_time //
                ""
                | tostring
            ),

            window_end: (
                .window_end //
                .end //
                .end_time //
                ""
                | tostring
            ),

            hosts: (
                if (.hosts | type?) == "array" then
                    .hosts
                elif .host != null then
                    [.host]
                else
                    []
                end
            ),

            owner: (
                .owner //
                .approved_by //
                .requester //
                ""
                | tostring
            ),

            approved_activity: (
                .approved_activity //
                .activity //
                .description //
                ""
                | tostring
            )
        }
    )
    ' "$CHANGE_FILE"
)


CHANGE_COUNT=$(jq 'length' <<< "$CHANGE_TICKETS")


# --------------------------------------------------
# 5. Extract prior-shift open items
# --------------------------------------------------
#
# Reads bullet lines after "Open Items"
# until the next Markdown heading.
# --------------------------------------------------

OPEN_ITEMS=$(
    awk '
        BEGIN {
            inside = 0
        }

        /^#+[[:space:]]*Open Items/ {
            inside = 1
            next
        }

        inside && /^#+[[:space:]]/ {
            exit
        }

        inside && /^[[:space:]]*[-*][[:space:]]+/ {
            line = $0
            sub(/^[[:space:]]*[-*][[:space:]]+/, "", line)
            print line
        }
    ' "$NOTES_FILE" |
    jq -R . |
    jq -s .
)


OPEN_ITEM_COUNT=$(jq 'length' <<< "$OPEN_ITEMS")


# --------------------------------------------------
# 6. Baseline context
# --------------------------------------------------

HOT_HOSTS=$(
    jq '.hot_hosts // []' "$BASELINE_RUN"
)

HOSTS_WITH_DEVIATIONS=$(
    jq '.hosts_with_deviations // 0' "$BASELINE_RUN"
)

HOT_HOST_COUNT=$(jq 'length' <<< "$HOT_HOSTS")


# --------------------------------------------------
# Print summary
# --------------------------------------------------

echo "[brief] IOCs: ip=$IP_COUNT domain=$DOMAIN_COUNT hash=$HASH_COUNT account=$ACCOUNT_COUNT service_name=$SERVICE_COUNT port=$PORT_COUNT total=$IOC_COUNT"

echo "[brief] active change tickets in window: $CHANGE_COUNT"

echo "[brief] prior shift open items: $OPEN_ITEM_COUNT"

echo "[brief] baseline hot hosts: $HOT_HOST_COUNT"

echo "[brief] advisory notes: $NOTE_COUNT"

echo "[brief] cluster ID cross-check: OK"


# --------------------------------------------------
# 7. Write shift_briefing.json
# --------------------------------------------------

mkdir -p "$SHIFT_WORKSPACE/alerts"


jq -n \
    --arg cluster_id "$CLUSTER_ID" \
    --argjson cluster_tactics "$TACTICS" \
    --argjson ioc_count "$IOC_COUNT" \
    --argjson ioc_by_type "$IOC_BY_TYPE" \
    --argjson ioc_values "$IOC_VALUES" \
    --argjson active_change_tickets "$CHANGE_TICKETS" \
    --argjson prior_shift_open_items "$OPEN_ITEMS" \
    --argjson baseline_hot_hosts "$HOT_HOSTS" \
    --argjson hosts_with_deviations "$HOSTS_WITH_DEVIATIONS" \
'
{
    cluster_id: $cluster_id,

    cluster_tactics: $cluster_tactics,

    ioc_count: $ioc_count,

    ioc_by_type: $ioc_by_type,

    ioc_values: $ioc_values,

    active_change_tickets: $active_change_tickets,

    prior_shift_open_items: $prior_shift_open_items,

    baseline_hot_hosts: $baseline_hot_hosts,

    hosts_with_deviations: $hosts_with_deviations
}
' > "$OUTPUT"


echo "[brief] shift_briefing.json written"
