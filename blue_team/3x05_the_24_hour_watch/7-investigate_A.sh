#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[inv-A] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
BASELINE_RUN="$SHIFT_WORKSPACE/runtime/baseline_run.json"
BASELINE_FILE="$SHIFT_WORKSPACE/enriched/baseline.json"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
ASSETS_FILE="$ASSETS_DIR/assets.json"

OUTPUT="$SHIFT_WORKSPACE/investigations/incident_A.json"


# --------------------------------------------------
# Check files
# --------------------------------------------------

for file in "$INCIDENTS" "$IOC_FILE"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


# Find enriched events file.

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then
    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
    EVENTS_TYPE="jsonl"

elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then
    EVENTS_FILE="$SHIFT_WORKSPACE/enriched/enriched_events.json"
    EVENTS_TYPE="json"

else
    fail "enriched events file is missing"
fi


# Prefer baseline_run because Task 2 created a known schema.

if [[ -s "$BASELINE_RUN" ]]; then
    BASELINE_SOURCE="$BASELINE_RUN"

elif [[ -s "$BASELINE_FILE" ]]; then
    BASELINE_SOURCE="$BASELINE_FILE"

else
    fail "baseline data is missing"
fi


# --------------------------------------------------
# Temporary files
# --------------------------------------------------

TMP_DIR=$(mktemp -d)

trap 'rm -rf "$TMP_DIR"' EXIT


ALL_EVENTS="$TMP_DIR/all_events.json"
WINDOW_EVENTS="$TMP_DIR/window_events.json"
TOP_EVENTS="$TMP_DIR/top_events.json"
MARKERS="$TMP_DIR/markers.json"
ACTIONS_FILE="$TMP_DIR/actions.txt"
TECH_FILE="$TMP_DIR/techniques.txt"


touch "$ACTIONS_FILE"
touch "$TECH_FILE"


record_action() {
    printf '%s\n' "$1" >> "$ACTIONS_FILE"
}


# --------------------------------------------------
# Investigation start time
# --------------------------------------------------

START_EPOCH=$(date -u +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------
# 1. Load Incident A
# --------------------------------------------------

record_action \
"jq -c '.incidents[] | select(.incident_id | endswith(\"-A\"))' $INCIDENTS"

INCIDENT=$(
    jq -c '
        .incidents[]
        | select(.incident_id | endswith("-A"))
    ' "$INCIDENTS" |
    head -1
)


if [[ -z "$INCIDENT" ]]; then
    fail "Incident A not found"
fi


record_action \
"jq -r '.incident_id' incidents.json"

INCIDENT_ID=$(jq -r '.incident_id' <<< "$INCIDENT")


record_action \
"jq -c '.host_list' incident_A"

HOSTS_JSON=$(jq -c '.host_list' <<< "$INCIDENT")


record_action \
"jq -r '.alert_ids | length' incident_A"

ALERT_COUNT=$(jq -r '.alert_ids | length' <<< "$INCIDENT")


record_action \
"jq -r '.tentative_category' incident_A"

CATEGORY=$(jq -r '.tentative_category // "unknown"' <<< "$INCIDENT")


record_action \
"jq -r '.first_seen' incident_A"

FIRST_SEEN=$(jq -r '.first_seen' <<< "$INCIDENT")


record_action \
"jq -r '.last_seen' incident_A"

LAST_SEEN=$(jq -r '.last_seen' <<< "$INCIDENT")


echo "[inv-A] loading $INCIDENT_ID"

echo -n "[inv-A] host_list: "

record_action \
"jq -r '.host_list | join(\" \")' incident_A"

jq -r '.host_list | join(" ")' <<< "$INCIDENT"

echo "[inv-A] alert count: $ALERT_COUNT"
echo "[inv-A] tentative category: $CATEGORY"


# --------------------------------------------------
# Create investigation time window
# --------------------------------------------------

if [[ -z "$FIRST_SEEN" || "$FIRST_SEEN" == "null" ]]; then
    fail "incident first_seen is missing"
fi

if [[ -z "$LAST_SEEN" || "$LAST_SEEN" == "null" ]]; then
    fail "incident last_seen is missing"
fi


WINDOW_START=$(
    date -u -d "$FIRST_SEEN -15 minutes" +"%Y-%m-%dT%H:%M:%SZ"
)

WINDOW_END=$(
    date -u -d "$LAST_SEEN +15 minutes" +"%Y-%m-%dT%H:%M:%SZ"
)


# --------------------------------------------------
# Integrity hashes
# --------------------------------------------------

EVENTS_HASH=$(sha256sum "$EVENTS_FILE" | awk '{print $1}')
IOC_HASH=$(sha256sum "$IOC_FILE" | awk '{print $1}')

echo "[inv-A] enriched events SHA256: $EVENTS_HASH"
echo "[inv-A] IOC feed SHA256: $IOC_HASH"


# --------------------------------------------------
# 2. Convert events to JSON array
# --------------------------------------------------

if [[ "$EVENTS_TYPE" == "jsonl" ]]; then

    record_action \
    "jq -s '.' $EVENTS_FILE"

    jq -s '.' "$EVENTS_FILE" > "$ALL_EVENTS"

else

    record_action \
    "jq 'if type == \"array\" then . else [.] end' $EVENTS_FILE"

    jq '
        if type == "array"
        then .
        else [.]
        end
    ' "$EVENTS_FILE" > "$ALL_EVENTS"

fi


# --------------------------------------------------
# Filter by host + investigation time window
# --------------------------------------------------

record_action \
"jq --argjson hosts HOSTS --arg start '$WINDOW_START' --arg end '$WINDOW_END' '<host/time filter>' all_events.json"


jq \
    --argjson hosts "$HOSTS_JSON" \
    --arg start "$WINDOW_START" \
    --arg end "$WINDOW_END" \
'
def hostname:
    (
        .host //
        .hostname //
        .host.name //
        ""
    )
    | tostring
    | ascii_downcase;

def timestamp:
    (
        .timestamp //
        ."@timestamp" //
        .event_time //
        .time //
        ""
    );

def epoch:
    try (timestamp | fromdateiso8601)
    catch null;

[
    .[]
    |
    (hostname) as $host
    |
    (epoch) as $epoch

    | select($hosts | map(ascii_downcase) | index($host))

    | select($epoch != null)

    | select(
        $epoch >= ($start | fromdateiso8601)
        and
        $epoch <= ($end | fromdateiso8601)
    )
]
' "$ALL_EVENTS" > "$WINDOW_EVENTS"


EVENT_COUNT=$(grep -c '"timestamp"\|"@timestamp"\|"event_time"\|"time"' "$WINDOW_EVENTS" || true)

# Get correct array length.

record_action \
"jq 'length' window_events.json"

EVENT_COUNT=$(jq 'length' "$WINDOW_EVENTS")


echo "[inv-A] events in window: $EVENT_COUNT"


if [[ "$EVENT_COUNT" -lt 6 ]]; then
    fail "fewer than 6 events found in incident window"
fi


# --------------------------------------------------
# 3. Select the 6 most analytically useful events
# --------------------------------------------------

record_action \
"jq '<rank authentication/process/network events and select top 6>' window_events.json"


jq '
def timestamp:
    (
        .timestamp //
        ."@timestamp" //
        .event_time //
        .time //
        ""
    );

def hostname:
    (
        .host //
        .hostname //
        .host.name //
        ""
    )
    | tostring
    | ascii_downcase;

def source:
    (
        .source_type //
        .source //
        .event.source //
        "unknown"
    )
    | tostring;

def category:
    (
        .event_category //
        .category //
        .event.category //
        "unknown"
    )
    | tostring;

def message:
    (
        .raw_message //
        .message //
        .event.original //
        .raw //
        ""
    )
    | tostring;

def eventid:
    (
        .event_id //
        .id //
        .event.id //
        .event_uid //
        ""
    )
    | tostring;

def score:
    (
        category | ascii_downcase
    ) as $category

    |

    (
        message | ascii_downcase
    ) as $message

    |

    (
        if ($category | test("auth|login|logon"))
        then 40

        elif ($category | test("process|service|registry|task"))
        then 40

        elif ($category | test("network|firewall|suricata|dns"))
        then 35

        else 10
        end
    )

    +

    (
        if (
            $message
            | test(
                "failed|successful|service|powershell|cmd|beacon|smb|ssh|rdp|connection"
            )
        )
        then 10
        else 0
        end
    );

[
    .[]

    | {
        event_id: eventid,
        timestamp: timestamp,
        host: hostname,
        source_type: source,
        event_category: category,
        raw_message: message,
        src_ip: (
            .src_ip //
            .source.ip //
            .src.ip //
            null
        ),
        dst_ip: (
            .dst_ip //
            .destination.ip //
            .dst.ip //
            null
        ),
        _score: score
    }

    | select(.event_id != "")
]

| unique_by(.event_id)

| sort_by(-._score, .timestamp)

| .[0:6]

| sort_by(.timestamp)
' "$WINDOW_EVENTS" > "$TOP_EVENTS"


record_action \
"jq 'length' top_events.json"

TOP_COUNT=$(jq 'length' "$TOP_EVENTS")


if [[ "$TOP_COUNT" -lt 6 ]]; then
    fail "fewer than 6 usable events with event IDs"
fi


# Time to first useful answer.

FIRST_ANSWER_EPOCH=$(date -u +%s)

TIME_TO_FIRST=$((FIRST_ANSWER_EPOCH - START_EPOCH))


echo "[inv-A] timeline (top 6):"


record_action \
"jq -r '.[] | \"  \\(.timestamp) \\(.host) \\(.source_type) \\(.event_category) \\(.raw_message[0:80])\"' top_events.json"


jq -r '
    .[]
    |
    "  \(.timestamp)  \(.host)  \(.source_type)  \(.event_category)  \(.raw_message[0:80])"
' "$TOP_EVENTS"


# --------------------------------------------------
# Event references
# --------------------------------------------------

record_action \
"jq -r '.[].event_id' top_events.json"

mapfile -t EVENT_REFS < <(
    jq -r '.[].event_id' "$TOP_EVENTS"
)


if [[ "${#EVENT_REFS[@]}" -lt 6 ]]; then
    fail "finding would contain fewer than 6 event_refs"
fi


# --------------------------------------------------
# 4. Check source and destination IPs against IOC feed
# --------------------------------------------------

record_action \
"jq '[.iocs[] | select((.type // \"\") == \"ip\") | .value]' $IOC_FILE"

IOC_VALUES=$(
    jq -c '
        [
            .iocs[]
            | select(
                (.type // "" | ascii_downcase) == "ip"
            )
            | (
                .value //
                .indicator //
                empty
            )
            | tostring
        ]
    ' "$IOC_FILE"
)


record_action \
"jq --argjson iocs IOC_VALUES '<src_ip/dst_ip IOC comparison>' window_events.json"

mapfile -t IOC_MATCHES < <(
    jq -r \
        --argjson iocs "$IOC_VALUES" \
    '
        [
            .[]

            |
            (
                .src_ip //
                .source.ip //
                .src.ip //
                empty
            ),

            (
                .dst_ip //
                .destination.ip //
                .dst.ip //
                empty
            )

            | tostring

            | select($iocs | index(.))
        ]

        | unique[]

    ' "$WINDOW_EVENTS"
)


echo "[inv-A] ioc_matches: ${#IOC_MATCHES[@]}"


for ioc in "${IOC_MATCHES[@]}"
do
    echo "[inv-A] IOC match: $ioc"
done


# --------------------------------------------------
# 5. Baseline deviations for incident hosts
# --------------------------------------------------

record_action \
"jq --argjson hosts HOSTS '<incident host deviation filter>' $BASELINE_SOURCE"


jq \
    --argjson hosts "$HOSTS_JSON" \
'
def normalize_host:
    (
        .host //
        .hostname //
        ""
    )
    | tostring
    | ascii_downcase;

(
    if (.deviation_markers | type?) == "array"
    then .deviation_markers

    elif (.markers | type?) == "array"
    then .markers

    else []
    end
)

|

[
    .[]
    |
    (normalize_host) as $host

    | select(
        $hosts
        | map(ascii_downcase)
        | index($host)
    )
]
' "$BASELINE_SOURCE" > "$MARKERS"


record_action \
"jq 'length' markers.json"

MARKER_COUNT=$(jq 'length' "$MARKERS")


echo "[inv-A] baseline deviations: $MARKER_COUNT markers"


record_action \
"jq -r '.[] | \"  \\(.host) \\(.marker) \\(.observed_value)\"' markers.json"


jq -r '
    .[]
    |
    "  \(.host // "unknown")  \(.marker // "unknown")  \(.observed_value // "")"
' "$MARKERS"


# --------------------------------------------------
# Optional asset context
# --------------------------------------------------

if [[ -s "$ASSETS_FILE" ]]; then

    record_action \
    "jq --argjson hosts HOSTS '<matching incident assets>' $ASSETS_FILE"

    echo "[inv-A] asset context:"

    jq -r \
        --argjson hosts "$HOSTS_JSON" \
    '
        (
            if type == "array"
            then .

            elif (.assets | type?) == "array"
            then .assets

            else []
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

        "  \($host) criticality=\(.criticality // "unknown") zone=\(.zone // "unknown")"
    ' "$ASSETS_FILE"

fi


# --------------------------------------------------
# 6. Derive ATT&CK techniques from observed evidence
# --------------------------------------------------

record_action \
"jq -r '.[] | [.event_category,.source_type,.raw_message] | join(\" \")' top_events.json"


BEHAVIOR_TEXT=$(
    jq -r '
        .[]
        |
        [
            .event_category,
            .source_type,
            .raw_message
        ]
        | join(" ")
    ' "$TOP_EVENTS" |
    tr '[:upper:]' '[:lower:]'
)


add_technique() {

    local technique="$1"

    if ! grep -qx "$technique" "$TECH_FILE"; then
        echo "$technique" >> "$TECH_FILE"
    fi
}


# Brute force / failed authentication.

if grep -Eq \
'brute|failed logon|failed login|authentication failure|4625' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1110"
fi


# Valid accounts / successful login.

if grep -Eq \
'successful logon|successful login|logon success|4624|valid account' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1078"
fi


# Windows service persistence.

if grep -Eq \
'new service|service installed|service created|7045|sc.exe' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1543.003"
fi


# PowerShell.

if grep -Eq \
'powershell|pwsh' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1059.001"
fi


# Scheduled task.

if grep -Eq \
'scheduled task|schtasks' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1053.005"
fi


# SMB lateral movement.

if grep -Eq \
'smb|port 445|tcp/445|:445' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1021.002"
fi


# Web / HTTP C2.

if grep -Eq \
'beacon|http|https|web traffic' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1071.001"
fi


# DNS communication.

if grep -Eq \
'dns query|dns traffic|port 53|udp/53' \
<<< "$BEHAVIOR_TEXT"
then
    add_technique "T1071.004"
fi


TECH_COUNT=$(grep -c . "$TECH_FILE" || true)


if [[ "$TECH_COUNT" -lt 2 ]]; then

    echo "[inv-A] detected techniques:" >&2
    cat "$TECH_FILE" >&2

    fail "fewer than 2 ATT&CK techniques are supported by the selected evidence"
fi


echo -n "[inv-A] techniques: "
tr '\n' ' ' < "$TECH_FILE"
echo


# --------------------------------------------------
# Build hypothesis
# --------------------------------------------------

if grep -qx "T1110" "$TECH_FILE" &&
   grep -qx "T1543.003" "$TECH_FILE"
then

    HYPOTHESIS="Credential attack activity was followed by service-based persistence on the affected host."

elif grep -qx "T1078" "$TECH_FILE" &&
     grep -qx "T1021.002" "$TECH_FILE"
then

    HYPOTHESIS="A valid account appears to have been used for SMB-based lateral movement."

elif grep -qx "T1543.003" "$TECH_FILE" &&
     grep -qx "T1071.001" "$TECH_FILE"
then

    HYPOTHESIS="Service-based persistence was followed by suspicious outbound web communication."

else

    HYPOTHESIS="The correlated authentication, process, and network events support a multi-step intrusion pattern."

fi


echo "[inv-A] hypothesis: $HYPOTHESIS"


# --------------------------------------------------
# Confidence
# --------------------------------------------------

if [[ "${#IOC_MATCHES[@]}" -gt 0 && "$MARKER_COUNT" -gt 0 ]]; then

    CONFIDENCE="high"

    AMBIGUITY_NOTES="No material ambiguity remains after IOC, baseline, timeline, and asset-context correlation."

elif [[ "${#IOC_MATCHES[@]}" -gt 0 || "$MARKER_COUNT" -gt 0 ]]; then

    CONFIDENCE="medium"

    AMBIGUITY_NOTES="Confirm whether the exact host and time window were authorized by reviewing the matching change ticket and raw source logs."

else

    CONFIDENCE="low"

    AMBIGUITY_NOTES="Confirm the activity using the original authentication, process, and network logs for this host and time window."

fi


echo "[inv-A] confidence: $CONFIDENCE"


# --------------------------------------------------
# Build JSON arrays
# --------------------------------------------------

record_action \
"jq -R . event_refs | jq -s ."

EVENT_REFS_JSON=$(
    printf '%s\n' "${EVENT_REFS[@]}" |
    jq -R . |
    jq -s .
)


record_action \
"jq -R . attack_techniques | jq -s ."

TECHNIQUES_JSON=$(
    cat "$TECH_FILE" |
    jq -R . |
    jq -s .
)


# --------------------------------------------------
# Investigation end
# --------------------------------------------------

INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# Add the final jq command before serialising actions.

record_action \
"jq -n '<write Locked Finding Schema>' > $OUTPUT"


# Commands used to serialize the action list itself.

record_action \
"jq -R . actions.txt | jq -s ."


ACTIONS_JSON=$(
    jq -R . "$ACTIONS_FILE" |
    jq -s .
)


# --------------------------------------------------
# 7. Write Locked Finding Schema
# --------------------------------------------------

jq -n \
    --arg finding_id "FIND-A-001" \
    --arg incident_id "$INCIDENT_ID" \
    --arg investigation_start "$INVESTIGATION_START" \
    --arg investigation_end "$INVESTIGATION_END" \
    --argjson time_to_first_answer "$TIME_TO_FIRST" \
    --argjson actions "$ACTIONS_JSON" \
    --argjson event_refs "$EVENT_REFS_JSON" \
    --argjson techniques "$TECHNIQUES_JSON" \
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

    time_to_first_answer_seconds: $time_to_first_answer,

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
# Final safety checks
# --------------------------------------------------

if [[ "${#EVENT_REFS[@]}" -lt 6 ]]; then
    fail "incident_A.json contains fewer than 6 event references"
fi


if [[ "$TECH_COUNT" -lt 2 ]]; then
    fail "incident_A.json contains fewer than 2 ATT&CK techniques"
fi


if [[ ! -s "$OUTPUT" ]]; then
    fail "incident_A.json was not written"
fi


echo "[inv-A] incident_A.json written"
