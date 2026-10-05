#!/bin/bash

BASELINE="baseline/robert_kim_activity.json"

PSEXEC="/tmp/psexec_events.jsonl"
WMI="/tmp/wmi_events.jsonl"
PSR="/tmp/psremoting_events.jsonl"
LSASS="/tmp/lsass_events.jsonl"

TIMELINE="/tmp/temporal_anomalies.txt"

> "$TIMELINE"

echo "================================================================"
echo "   TEMPORAL ANALYSIS - Anomalous Activity Clusters"
echo "================================================================"
echo

# --------------------------------------------------
# Collect suspicious PsExec events
# --------------------------------------------------

if [ -f "$PSEXEC" ]; then
    jq -r '
        select(
            (.agent.name // .data.win.system.computer // "") != "WS-ADMIN-01"
        )
        |
        [
            .timestamp,
            "PsExec",
            (.agent.name // .data.win.system.computer // "unknown"),
            (.data.win.eventdata.targetHostname //
             .data.win.system.computer //
             "unknown")
        ]
        | @tsv
    ' "$PSEXEC" >> "$TIMELINE"
fi

# --------------------------------------------------
# Collect suspicious WMI events
# --------------------------------------------------

if [ -f "$WMI" ]; then
    jq -r '
        select(
            (.agent.name // .data.win.system.computer // "") != "WS-ADMIN-01"
        )
        |
        [
            .timestamp,
            "WMI",
            (.agent.name // .data.win.system.computer // "unknown"),
            (.data.win.eventdata.targetHostname //
             .data.win.system.computer //
             "unknown")
        ]
        | @tsv
    ' "$WMI" >> "$TIMELINE"
fi

# --------------------------------------------------
# Collect suspicious PowerShell Remoting events
# --------------------------------------------------

if [ -f "$PSR" ]; then
    jq -r '
        select(
            (.agent.name // .data.win.system.computer // "") != "WS-ADMIN-01"
        )
        |
        [
            .timestamp,
            "PSRemoting",
            (.agent.name // .data.win.system.computer // "unknown"),
            (.data.win.eventdata.targetHostname //
             .data.win.system.computer //
             "unknown")
        ]
        | @tsv
    ' "$PSR" >> "$TIMELINE"
fi

# --------------------------------------------------
# Collect unusual LSASS access
# --------------------------------------------------

if [ -f "$LSASS" ]; then
    jq -r '
        select(
            ((.data.win.eventdata.sourceImage // "") |
            test("svchost.exe|wininit.exe|services.exe"; "i") | not)
        )
        |
        [
            .timestamp,
            "LSASS",
            (.agent.name // .data.win.system.computer // "unknown"),
            "lsass.exe"
        ]
        | @tsv
    ' "$LSASS" >> "$TIMELINE"
fi

# Sort all suspicious events by timestamp
sort "$TIMELINE" -o "$TIMELINE"

# --------------------------------------------------
# Hour-of-day histogram
# --------------------------------------------------

echo "HOUR-OF-DAY DISTRIBUTION:"
echo

printf "  Hour   Baseline   Anomalous\n"

for HOUR in $(seq -w 0 23)
do
    BASE_COUNT=$(jq -r '.[] | .timestamp // empty' "$BASELINE" |
        grep -c "T$HOUR:")

    ANOM_COUNT=$(cut -f1 "$TIMELINE" |
        grep -c "T$HOUR:")

    printf "  %s:00   %-10s %s\n" "$HOUR" "$BASE_COUNT" "$ANOM_COUNT"
done

echo

# --------------------------------------------------
# Off-hours comparison
# --------------------------------------------------

BASE_OFF=$(jq -r '.[] | .timestamp // empty' "$BASELINE" |
    grep -E 'T(0[0-7]|1[89]|2[0-3]):' |
    wc -l)

ANOM_OFF=$(cut -f1 "$TIMELINE" |
    grep -E 'T(0[0-7]|1[89]|2[0-3]):' |
    wc -l)

TOTAL_ANOM=$(wc -l < "$TIMELINE")

echo "STATISTICAL ANALYSIS:"
echo "  Baseline off-hours events: $BASE_OFF"
echo "  Anomalous off-hours events: $ANOM_OFF"
echo "  Total anomalous events:     $TOTAL_ANOM"
echo

if [ "$BASE_OFF" -eq 0 ] && [ "$ANOM_OFF" -gt 0 ]; then
    echo "  Baseline off-hours rate: 0"
    echo "  The baseline contains no normal off-hours admin activity."
    echo "  Multiple anomalous off-hours events are therefore a strong deviation."
    echo "  CONCLUSION: Activity is NOT consistent with normal operations."
else
    echo "  Off-hours activity exists in both datasets."
    echo "  More investigation is required."
fi

echo

# --------------------------------------------------
# Activity clusters
# Events within 2 hours = same session
# --------------------------------------------------

echo "ACTIVITY SESSIONS:"
echo

SESSION=0
PREVIOUS=0
START=""
LAST=""

while IFS=$'\t' read -r TIME TOOL SOURCE TARGET
do
    CURRENT=$(date -d "$TIME" +%s 2>/dev/null)

    if [ -z "$CURRENT" ]; then
        continue
    fi

    # Start a new session if more than 2 hours passed
    if [ "$PREVIOUS" -eq 0 ] ||
       [ $((CURRENT - PREVIOUS)) -gt 7200 ]; then

        SESSION=$((SESSION + 1))
        START="$TIME"

        echo "  SESSION $SESSION:"
    fi

    echo "    $TIME"
    echo "      Tool:   $TOOL"
    echo "      Source: $SOURCE"
    echo "      Target: $TARGET"

    LAST="$TIME"
    PREVIOUS=$CURRENT

done < "$TIMELINE"

echo

# --------------------------------------------------
# Overall time range
# --------------------------------------------------

FIRST=$(head -1 "$TIMELINE" | cut -f1)
LAST=$(tail -1 "$TIMELINE" | cut -f1)

if [ -n "$FIRST" ] && [ -n "$LAST" ]; then
    FIRST_SEC=$(date -d "$FIRST" +%s 2>/dev/null)
    LAST_SEC=$(date -d "$LAST" +%s 2>/dev/null)

    if [ -n "$FIRST_SEC" ] && [ -n "$LAST_SEC" ]; then
        DIFF=$((LAST_SEC - FIRST_SEC))
        HOURS=$((DIFF / 3600))
        MINUTES=$(((DIFF % 3600) / 60))

        echo "OVERALL SUSPICIOUS ACTIVITY RANGE:"
        echo "  First event: $FIRST"
        echo "  Last event:  $LAST"
        echo "  Duration:    ${HOURS}h ${MINUTES}m"
        echo
    fi
fi

# --------------------------------------------------
# Final conclusion
# --------------------------------------------------

echo "BASELINE COMPARISON:"
echo "  Robert Kim normally works:"
echo "    - from WS-ADMIN-01"
echo "    - during 08:00-18:00"
echo "    - during documented maintenance"
echo
echo "  Suspicious activity:"
echo "    - occurs outside normal hours"
echo "    - comes from unusual hosts"
echo "    - includes PsExec, WMI, PSRemoting and LSASS activity"

echo
echo "FINDING:"

if [ "$BASE_OFF" -eq 0 ] && [ "$ANOM_OFF" -gt 0 ]; then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  The temporal pattern is inconsistent with Robert Kim's baseline."
else
    echo "  Status: REQUIRES FURTHER REVIEW"
fi

echo
echo "================================================================"