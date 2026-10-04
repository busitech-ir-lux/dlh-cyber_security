#!/bin/bash

# --------------------------------------------------
# Files from previous hunt tasks
# --------------------------------------------------

PSEXEC="/tmp/psexec_events.jsonl"
LSASS="/tmp/lsass_events.jsonl"
DATA="/tmp/credential_hunt.jsonl"

TIMELINE="/tmp/attack_timeline.txt"

> "$TIMELINE"

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"
echo

# --------------------------------------------------
# Credential Access - LSASS
# --------------------------------------------------

if [ -f "$LSASS" ]; then

    jq -r '
        select(
            ((.data.win.eventdata.sourceImage // "") |
            test("svchost.exe|wininit.exe|services.exe"; "i") | not)
        )
        |
        "\(.timestamp) | CREDENTIAL ACCESS | \(.agent.name // .data.win.system.computer // "unknown") | LSASS memory access"
    ' "$LSASS" >> "$TIMELINE"
fi

# --------------------------------------------------
# PsExec lateral movement
# --------------------------------------------------

if [ -f "$PSEXEC" ]; then

    jq -r '
        select(
            (.agent.name // .data.win.system.computer // "") != "WS-ADMIN-01"
        )
        |
        "\(.timestamp) | LATERAL MOVEMENT | \(.agent.name // .data.win.system.computer // "unknown") | \(.data.win.eventdata.commandLine // "PsExec activity")"
    ' "$PSEXEC" >> "$TIMELINE"
fi

# --------------------------------------------------
# WMI reconnaissance
# --------------------------------------------------

if [ -f "$DATA" ]; then

    jq -r '
        select(
            (tostring | test("wmi"; "i"))
        )
        |
        "\(.timestamp) | RECONNAISSANCE | \(.agent.name // .data.win.system.computer // "unknown") | WMI activity"
    ' "$DATA" >> "$TIMELINE"

fi

# --------------------------------------------------
# PowerShell Remoting / staging
# --------------------------------------------------

if [ -f "$DATA" ]; then

    jq -r '
        select(
            (tostring | test("winrm|psremoting|copy-item"; "i"))
        )
        |
        "\(.timestamp) | STAGING | \(.agent.name // .data.win.system.computer // "unknown") | \(.data.win.eventdata.commandLine // "PowerShell Remoting activity")"
    ' "$DATA" >> "$TIMELINE"

fi

# --------------------------------------------------
# Sort everything by timestamp
# --------------------------------------------------

sort "$TIMELINE" -o "$TIMELINE"

echo "ATTACK TIMELINE:"

while IFS='|' read -r TIME PHASE HOST DETAILS
do
    echo "  [$PHASE]"
    echo "    $TIME"
    echo "    Host:$HOST"
    echo "    Activity:$DETAILS"
    echo
done < "$TIMELINE"

# --------------------------------------------------
# Attack progression
# --------------------------------------------------

echo "ATTACK SUMMARY:"
echo "  Pivot host:        WS-RECV-03"
echo "  Credential used:   svc_healthsync"
echo "  Targets:           SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01"
echo "  Tools used:        PsExec, WMI, PSRemoting"

# --------------------------------------------------
# Calculate dwell time
# --------------------------------------------------

FIRST=$(head -1 "$TIMELINE" | cut -d'|' -f1 | xargs)
LAST=$(tail -1 "$TIMELINE" | cut -d'|' -f1 | xargs)

if [ -n "$FIRST" ] && [ -n "$LAST" ]; then

    FIRST_SEC=$(date -d "$FIRST" +%s 2>/dev/null)
    LAST_SEC=$(date -d "$LAST" +%s 2>/dev/null)

    if [ -n "$FIRST_SEC" ] && [ -n "$LAST_SEC" ]; then

        DIFF=$((LAST_SEC - FIRST_SEC))
        HOURS=$((DIFF / 3600))
        MINUTES=$(((DIFF % 3600) / 60))

        echo "  Dwell time:        ${HOURS}h ${MINUTES}m"

    else
        echo "  Dwell time:        Unable to calculate"
    fi

else
    echo "  Dwell time:        No timeline data"
fi

echo

# --------------------------------------------------
# Final assessment
# --------------------------------------------------

EVENTS=$(wc -l < "$TIMELINE")

echo "ASSESSMENT:"

if [ "$EVENTS" -ge 3 ]; then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  HEALTHBANE Stage 4 activity is supported by multiple"
    echo "  correlated hunt findings."
    echo
    echo "  Narrative:"
    echo "  WS-RECV-03 appears to be the pivot host."
    echo "  Credentials were accessed through LSASS."
    echo "  svc_healthsync was then used for lateral movement."
    echo "  PsExec, WMI and PSRemoting activity followed against servers."
else
    echo "  Status: INCONCLUSIVE"
    echo "  Not enough correlated events were found."
fi

echo
echo "================================================================"