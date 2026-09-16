#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[inv-B] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS_JSONL="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
EVENTS_JSON="$SHIFT_WORKSPACE/enriched/enriched_events.json"

CHANGE_FILE="$ASSETS_DIR/change_tickets.json"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
ASSETS_FILE="$ASSETS_DIR/assets.json"

OUTPUT="$SHIFT_WORKSPACE/investigations/incident_B.json"


# --------------------------------------------------
# Required files
# --------------------------------------------------

for file in \
    "$INCIDENTS" \
    "$CHANGE_FILE" \
    "$IOC_FILE" \
    "$ASSETS_FILE"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# --------------------------------------------------
# Temporary working directory
# --------------------------------------------------

TMP_DIR=$(mktemp -d)

trap 'rm -rf "$TMP_DIR"' EXIT


ALL_EVENTS="$TMP_DIR/all_events.json"
INCIDENT_EVENTS="$TMP_DIR/incident_events.json"
TICKETS="$TMP_DIR/tickets.json"
IOC_MATCHES_FILE="$TMP_DIR/ioc_matches.json"
EVENT_REFS_FILE="$TMP_DIR/event_refs.json"


# --------------------------------------------------
# Investigation start
# --------------------------------------------------

START_EPOCH=$(date -u +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------
# 1. Load Incident B
# --------------------------------------------------

INCIDENT=$(
    jq -c '
        .incidents[]
        | select(.incident_id | endswith("-B"))
    ' "$INCIDENTS" |
    head -1
)


if [[ -z "$INCIDENT" ]]; then
    fail "Incident B not found"
fi


INCIDENT_ID=$(jq -r '.incident_id' <<< "$INCIDENT")
HOSTS_JSON=$(jq -c '.host_list' <<< "$INCIDENT")
USERS_JSON=$(jq -c '.user_list // []' <<< "$INCIDENT")

FIRST_SEEN=$(jq -r '.first_seen' <<< "$INCIDENT")
LAST_SEEN=$(jq -r '.last_seen' <<< "$INCIDENT")


echo "[inv-B] loading $INCIDENT_ID"


# Use first identified account.

INCIDENT_USER=$(
    jq -r '.[0] // empty' <<< "$USERS_JSON"
)


# --------------------------------------------------
# Investigation window: ±15 minutes
# --------------------------------------------------

WINDOW_START=$(
    date -u \
        -d "$FIRST_SEEN -15 minutes" \
        +"%Y-%m-%dT%H:%M:%SZ"
)

WINDOW_END=$(
    date -u \
        -d "$LAST_SEEN +15 minutes" \
        +"%Y-%m-%dT%H:%M:%SZ"
)


# --------------------------------------------------
# 2. Load enriched events
# --------------------------------------------------

if [[ -s "$EVENTS_JSONL" ]]; then

    jq -s '.' "$EVENTS_JSONL" > "$ALL_EVENTS"

elif [[ -s "$EVENTS_JSON" ]]; then

    jq '
        if type == "array"
        then .
        else [.]
        end
    ' "$EVENTS_JSON" > "$ALL_EVENTS"

else

    fail "enriched events file is missing"
fi


# --------------------------------------------------
# Filter events by host and time window
# --------------------------------------------------

jq \
    --argjson hosts "$HOSTS_JSON" \
    --arg start "$WINDOW_START" \
    --arg end "$WINDOW_END" \
'
[
    .[]

    |

    (
        .host //
        .hostname //
        .host.name //
        ""
    )
    | tostring
    | ascii_downcase as $host

    |

    (
        .timestamp //
        ."@timestamp" //
        .event_time //
        .time //
        ""
    ) as $time

    |

    select(
        $hosts
        | map(ascii_downcase)
        | index($host)
    )

    |

    select(
        $time >= $start
        and
        $time <= $end
    )
]
' "$ALL_EVENTS" > "$INCIDENT_EVENTS"


EVENT_COUNT=$(jq 'length' "$INCIDENT_EVENTS")


echo "[inv-B] events in window: $EVENT_COUNT"


if [[ "$EVENT_COUNT" -eq 0 ]]; then
    fail "no events found for Incident B"
fi


# --------------------------------------------------
# Collect event references
# --------------------------------------------------

jq '
[
    .[]
    |
    (
        .event_id //
        .id //
        .event.id //
        .event_uid //
        empty
    )
    | tostring
]
| unique
' "$INCIDENT_EVENTS" > "$EVENT_REFS_FILE"


# --------------------------------------------------
# 3. Normalize change tickets
# --------------------------------------------------

jq '
if type == "array" then

    .

elif (.tickets | type?) == "array" then

    .tickets

elif (.change_tickets | type?) == "array" then

    .change_tickets

else

    []

end
' "$CHANGE_FILE" > "$TICKETS"


# --------------------------------------------------
# Look specifically for the ticket mentioned
# in the project context.
# --------------------------------------------------

TICKET=$(
    jq -c '
        .[]
        |
        select(
            (
                .ticket_id //
                .id //
                .change_id //
                ""
            ) == "CHG-2026-0341"
        )
    ' "$TICKETS" |
    head -1
)


# If exact ticket was not found, try a ticket
# containing one of the incident hosts.

if [[ -z "$TICKET" ]]; then

    TICKET=$(
        jq -c \
            --argjson hosts "$HOSTS_JSON" \
        '
        .[]

        |

        (
            .hosts //
            []
        ) as $ticket_hosts

        |

        select(
            [
                $hosts[]
                | ascii_downcase
            ]
            -
            [
                $ticket_hosts[]
                | ascii_downcase
            ]
            | length < ($hosts | length)
        )
        ' "$TICKETS" |
        head -1
    )

fi


if [[ -z "$TICKET" ]]; then

    echo "[inv-B] ticket match: NONE"

    TICKET_ID="none"
    HOST_MATCH=false
    WINDOW_MATCH=false
    OWNER_MATCH=false
    SCOPE_MATCH=false

    TICKET_OWNER=""
    APPROVED_ACTIVITY=""

else

    TICKET_ID=$(
        jq -r '
            .ticket_id //
            .id //
            .change_id //
            "unknown"
        ' <<< "$TICKET"
    )

    echo "[inv-B] ticket match: $TICKET_ID FOUND"


    # --------------------------------------------------
    # Ticket host check
    # --------------------------------------------------

    TICKET_HOSTS=$(jq -c '.hosts // []' <<< "$TICKET")


    HOST_MATCH=$(
        jq -n \
            --argjson incident "$HOSTS_JSON" \
            --argjson ticket "$TICKET_HOSTS" \
        '
        (
            [
                $incident[]
                | ascii_downcase
            ]
            -
            [
                $ticket[]
                | ascii_downcase
            ]
        )
        | length == 0
        '
    )


    if [[ "$HOST_MATCH" == "true" ]]; then

        echo "[inv-B]   host match:   OK ($(jq -r 'join(",")' <<< "$HOSTS_JSON") in ticket)"

    else

        echo "[inv-B]   host match:   FAIL (incident host not fully covered)"

    fi


    # --------------------------------------------------
    # Ticket time-window check
    # --------------------------------------------------

    TICKET_START=$(
        jq -r '
            .window_start //
            .start //
            .start_time //
            empty
        ' <<< "$TICKET"
    )

    TICKET_END=$(
        jq -r '
            .window_end //
            .end //
            .end_time //
            empty
        ' <<< "$TICKET"
    )


    WINDOW_MATCH=false


    if [[ -n "$TICKET_START" && -n "$TICKET_END" ]]; then

        INCIDENT_START_EPOCH=$(date -u -d "$FIRST_SEEN" +%s)
        INCIDENT_END_EPOCH=$(date -u -d "$LAST_SEEN" +%s)

        TICKET_START_EPOCH=$(date -u -d "$TICKET_START" +%s)
        TICKET_END_EPOCH=$(date -u -d "$TICKET_END" +%s)


        if (( INCIDENT_START_EPOCH >= TICKET_START_EPOCH &&
              INCIDENT_END_EPOCH <= TICKET_END_EPOCH ))
        then

            WINDOW_MATCH=true

        fi

    fi


    if [[ "$WINDOW_MATCH" == "true" ]]; then

        echo "[inv-B]   window match: OK (within approved window)"

    else

        echo "[inv-B]   window match: FAIL (outside approved window)"

    fi


    # --------------------------------------------------
    # Ticket owner check
    # --------------------------------------------------

    TICKET_OWNER=$(
        jq -r '
            .owner //
            .approved_by //
            .requester //
            empty
        ' <<< "$TICKET"
    )


    OWNER_MATCH=false


    # First check whether the account itself matches.

    if [[ -n "$INCIDENT_USER" &&
          "${INCIDENT_USER,,}" == "${TICKET_OWNER,,}" ]]
    then

        OWNER_MATCH=true

    fi


    # IMPORTANT:
    # Project context explicitly states that
    # rad_admin_miller is on annual leave.
    #
    # Therefore activity performed using this account
    # cannot be treated as valid approved maintenance
    # simply because the username appears on the ticket.

    if [[ "${INCIDENT_USER,,}" == "rad_admin_miller" ]]; then

        OWNER_MATCH=false

        echo "[inv-B]   owner match:  FAIL ($INCIDENT_USER — account on annual leave)"

    elif [[ "$OWNER_MATCH" == "true" ]]; then

        echo "[inv-B]   owner match:  OK ($INCIDENT_USER)"

    else

        echo "[inv-B]   owner match:  FAIL (incident user=$INCIDENT_USER ticket owner=$TICKET_OWNER)"

    fi


    # --------------------------------------------------
    # Approved activity description
    # --------------------------------------------------

    APPROVED_ACTIVITY=$(
        jq -r '
            .approved_activity //
            .activity //
            .description //
            ""
        ' <<< "$TICKET"
    )

fi


# --------------------------------------------------
# 4. Check outbound destination IPs against IOC feed
# --------------------------------------------------

IOC_VALUES=$(
    jq -c '
    [
        .iocs[]
        |
        {
            value: (
                .value //
                .indicator //
                ""
                | tostring
            ),

            type: (.type // "unknown"),

            confidence: (.confidence // "unknown"),

            cluster: (
                .cluster //
                .cluster_id //
                "unknown"
            )
        }
    ]
    ' "$IOC_FILE"
)


jq \
    --argjson iocs "$IOC_VALUES" \
'
[
    .[]

    |

    (
        .dst_ip //
        .destination.ip //
        .dst.ip //
        empty
    )
    | tostring as $dst

    |

    $iocs[]

    |

    select(.value == $dst)
]

| unique_by(.value)
' "$INCIDENT_EVENTS" > "$IOC_MATCHES_FILE"


IOC_COUNT=$(jq 'length' "$IOC_MATCHES_FILE")


if [[ "$IOC_COUNT" -gt 0 ]]; then

    jq -r '
        .[]
        |
        "[inv-B] ioc_match: \(.value) (type: \(.type), confidence: \(.confidence), cluster: \(.cluster))"
    ' "$IOC_MATCHES_FILE"

else

    echo "[inv-B] ioc_match: none"

fi


# --------------------------------------------------
# Ticket scope check
# --------------------------------------------------

SCOPE_MATCH=true


# IOC outbound communication is outside a normal
# disk-expansion scope unless specifically authorized.

if [[ "$IOC_COUNT" -gt 0 ]]; then

    SCOPE_MATCH=false

fi


# Also treat clear disk-maintenance tickets as not
# authorizing unrelated outbound C2/network activity.

if grep -qiE 'disk|volume|storage|partition|filesystem' \
    <<< "$APPROVED_ACTIVITY"
then

    if [[ "$IOC_COUNT" -gt 0 ]]; then
        SCOPE_MATCH=false
    fi

fi


if [[ "$SCOPE_MATCH" == "true" ]]; then

    echo "[inv-B]   scope match:  OK"

else

    IOC_LIST_TEXT=$(
        jq -r '[.[].value] | join(",")' "$IOC_MATCHES_FILE"
    )

    echo "[inv-B]   scope match:  FAIL (outbound $IOC_LIST_TEXT not covered by approved activity)"

fi


# --------------------------------------------------
# 5. Asset context
# --------------------------------------------------

echo "[inv-B] affected assets:"


jq -r \
    --argjson hosts "$HOSTS_JSON" \
'
(
    if type == "array" then
        .

    elif (.assets | type?) == "array" then
        .assets

    else
        []
    end
)

|

.[]

|

(
    .host //
    .hostname //
    .name //
    ""
) as $host

|

select(
    $hosts
    | map(ascii_downcase)
    | index($host | ascii_downcase)
)

|

"[inv-B] host: \($host) (criticality: \(.criticality // "unknown"), data_class: \(.data_classification // "unknown"))"
' "$ASSETS_FILE"


# --------------------------------------------------
# 6. Verdict
# --------------------------------------------------

# --------------------------------------------------
# Final ticket decision
#
# Task rule:
# ANY mismatch means the approved change does NOT
# cover the observed activity -> TP
#
# Only a complete match can be considered FP.
# --------------------------------------------------

if [[ "$HOST_MATCH" != "true" ||
      "$WINDOW_MATCH" != "true" ||
      "$OWNER_MATCH" != "true" ||
      "$SCOPE_MATCH" != "true" ]]
then

    VERDICT="TP"

    echo "[inv-B] verdict: TP (approved change does not fully cover observed activity)"

else

    VERDICT="FP"

    echo "[inv-B] verdict: FP (host, window, owner and scope all match approved change)"

fi


# --------------------------------------------------
# ATT&CK techniques
# --------------------------------------------------

TECHNIQUES='[]'


# Account use -> Valid Accounts

if [[ -n "$INCIDENT_USER" ]]; then

    TECHNIQUES=$(
        jq -c '. + ["T1078"]' <<< "$TECHNIQUES"
    )

fi


# Outbound HTTPS / IOC communication -> Web Protocols

if [[ "$IOC_COUNT" -gt 0 ]]; then

    TECHNIQUES=$(
        jq -c '. + ["T1071.001"] | unique' <<< "$TECHNIQUES"
    )

fi


# --------------------------------------------------
# Hypothesis
# --------------------------------------------------

if [[ "$VERDICT" == "TP" && "$IOC_COUNT" -gt 0 ]]; then

    HYPOTHESIS="An apparently approved maintenance session was abused for malicious activity, including outbound communication with a known HC-RED7 IOC."

else

    HYPOTHESIS="The incident overlaps approved maintenance, but available evidence is insufficient to fully confirm malicious activity."

fi


# --------------------------------------------------
# Confidence and ambiguity
# --------------------------------------------------

if [[ "$VERDICT" == "TP" &&
      "$IOC_COUNT" -gt 0 &&
      "$TICKET_FULL_MATCH" == "false" ]]
then

    CONFIDENCE="high"
    AMBIGUITY_NOTES=""

elif [[ "$VERDICT" == "TP" ]]; then

    CONFIDENCE="medium"

    AMBIGUITY_NOTES="The approved change does not fully match the observed activity. Confirm the actor using authentication logs and change-owner availability records."

else

    CONFIDENCE="medium"

    AMBIGUITY_NOTES="The activity matches the change ticket, but additional network and authentication evidence is needed to rule out abuse of the maintenance window."

fi


echo "[inv-B] verdict: $VERDICT"


echo "[inv-B] confidence: $CONFIDENCE"


# --------------------------------------------------
# Ticket outcome narrative
# --------------------------------------------------

TICKET_OUTCOME="ticket_match_outcome: ticket=$TICKET_ID host_match=$HOST_MATCH window_match=$WINDOW_MATCH owner_match=$OWNER_MATCH scope_match=$SCOPE_MATCH verdict=$VERDICT"


# --------------------------------------------------
# IOC narrative
# --------------------------------------------------

IOC_VALUES_TEXT=$(
    jq -r '
        [.[].value]
        | join(",")
    ' "$IOC_MATCHES_FILE"
)


if [[ -z "$IOC_VALUES_TEXT" ]]; then
    IOC_VALUES_TEXT="none"
fi


IOC_ACTION="matches_ioc: $IOC_VALUES_TEXT"


# --------------------------------------------------
# Event references
# --------------------------------------------------

EVENT_REFS=$(cat "$EVENT_REFS_FILE")


# --------------------------------------------------
# Investigation timing
# --------------------------------------------------

FIRST_ANSWER_EPOCH=$(date -u +%s)

TIME_TO_FIRST=$((FIRST_ANSWER_EPOCH - START_EPOCH))

INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------
# Actions list
#
# Includes the ticket-match outcome and IOC matches
# as required without changing the locked schema.
# --------------------------------------------------

ACTIONS=$(
    jq -n \
        --arg a1 "Loaded Incident B from incidents.json using jq" \
        --arg a2 "Filtered enriched events by incident host and ±15 minute time window using jq" \
        --arg a3 "Compared incident host, time window, user and activity scope with change_tickets.json" \
        --arg a4 "$TICKET_OUTCOME" \
        --arg a5 "Checked outbound destination IPs against ioc_feed.json" \
        --arg a6 "$IOC_ACTION" \
        --arg a7 "Reviewed affected host criticality and data classification in assets.json" \
    '
    [
        $a1,
        $a2,
        $a3,
        $a4,
        $a5,
        $a6,
        $a7
    ]
    '
)


# --------------------------------------------------
# 7. Write Locked Finding Schema
# --------------------------------------------------

mkdir -p "$SHIFT_WORKSPACE/investigations"


jq -n \
    --arg finding_id "FIND-B-001" \
    --arg incident_id "$INCIDENT_ID" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson time_to_first "$TIME_TO_FIRST" \
    --argjson actions "$ACTIONS" \
    --argjson event_refs "$EVENT_REFS" \
    --argjson techniques "$TECHNIQUES" \
    --arg hypothesis "$HYPOTHESIS" \
    --arg confidence "$CONFIDENCE" \
    --arg ambiguity "$AMBIGUITY_NOTES" \
    --arg created_at "$INVESTIGATION_END" \
'
{
    finding_id: $finding_id,

    incident_id: $incident_id,

    interface: "cli",

    investigation_start: $investigation_start,

    investigation_end: $investigation_end,

    time_to_first_answer_seconds: $time_to_first,

    actions: $actions,

    event_refs: $event_refs,

    attack_techniques: $techniques,

    hypothesis: $hypothesis,

    confidence: $confidence,

    ambiguity_notes: $ambiguity,

    created_at: $created_at
}
' > "$OUTPUT"


# --------------------------------------------------
# Final validation
# --------------------------------------------------

if [[ ! -s "$OUTPUT" ]]; then
    fail "incident_B.json was not created"
fi


# If confidence is not high, ambiguity_notes is required.

if [[ "$CONFIDENCE" != "high" ]]; then

    NOTES=$(
        jq -r '.ambiguity_notes // empty' "$OUTPUT"
    )

    if [[ -z "$NOTES" ]]; then
        fail "ambiguity_notes required for medium/low confidence"
    fi

fi


# Ticket outcome must be documented.

if ! jq -e '
    .actions[]
    | select(
        startswith("ticket_match_outcome:")
    )
' "$OUTPUT" >/dev/null
then

    fail "ticket match outcome is not documented"
fi


# If IOC matches existed, ensure they were documented.

if [[ "$IOC_COUNT" -gt 0 ]]; then

    if ! jq -e '
        .actions[]
        | select(
            startswith("matches_ioc:")
        )
    ' "$OUTPUT" >/dev/null
    then

        fail "IOC match was found but not documented"
    fi

fi


echo "[inv-B] incident_B.json written"
