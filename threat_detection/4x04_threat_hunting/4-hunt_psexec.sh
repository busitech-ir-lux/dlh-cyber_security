#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
SCHEDULE="reference/admin_schedule.txt"

TMP="/tmp/psexec_events.jsonl"

# --------------------------------------------------
# Extract PsExec events from both SIEM files
# --------------------------------------------------

jq -c '
    if type == "array" then .[] else . end
' "$ALERTS" "$SYSMON" |
jq -c '
    select(
        ((.data.win.eventdata.image // "") | test("PsExec"; "i"))
        or
        ((.data.win.eventdata.commandLine // "") | test("psexec"; "i"))
    )
' > "$TMP"

TOTAL=$(wc -l < "$TMP")

BASELINE=0
ANOMALOUS=0
NUMBER=0

echo "================================================================"
echo "   HUNT EXECUTION - H1: Lateral Movement via PsExec"
echo "   Technique: T1021.002 SMB/Windows Admin Shares"
echo "================================================================"
echo

echo "ANOMALOUS EVENTS:"

# --------------------------------------------------
# Check every PsExec event
# --------------------------------------------------

while IFS=$'\t' read -r TIME SOURCE USER COMMAND TARGET PID
do
    FLAGS=""
    BAD=0

    # Get hour and day
    HOUR=$(date -d "$TIME" "+%H" 2>/dev/null)
    DAY=$(date -d "$TIME" "+%A" 2>/dev/null)

    # Normal source should be WS-ADMIN-01
    if [ "$SOURCE" != "WS-ADMIN-01" ]; then
        FLAGS="$FLAGS
      [!] Source host is NOT WS-ADMIN-01"
        BAD=1
    fi

    # Normal time should be 08:00-18:00
    if [ "$HOUR" -lt 8 ] 2>/dev/null || [ "$HOUR" -ge 18 ] 2>/dev/null; then
        FLAGS="$FLAGS
      [!] Time is outside business hours"
        BAD=1
    fi

    # Check maintenance day against admin schedule
    if ! grep -qi "$DAY" "$SCHEDULE"; then
        FLAGS="$FLAGS
      [!] Day is not in Robert Kim's maintenance schedule"
        BAD=1
    fi

    # Normal user should be Robert Kim
    if [[ "$USER" != *"robert.kim"* ]]; then
        FLAGS="$FLAGS
      [!] User is NOT Robert Kim"
        BAD=1
    fi

    # Service account check
    if [[ "$USER" == *"svc"* ]]; then
        FLAGS="$FLAGS
      [!] User is a service account"
        BAD=1
    fi

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    if [ "$BAD" -eq 0 ]; then
        BASELINE=$((BASELINE + 1))
    else
        ANOMALOUS=$((ANOMALOUS + 1))
        NUMBER=$((NUMBER + 1))

        echo
        echo "  [A$NUMBER] $TIME"
        echo "    Source: $SOURCE"
        echo "    User: $USER"
        echo "    Command: $COMMAND"
        echo "    Target: $TARGET"
        echo "    PID: $PID"
        echo "    ANOMALY FLAGS:"
        echo "$FLAGS"
    fi

done < <(
    jq -r '
        [
            (.timestamp // "unknown"),
            (.agent.name // .data.win.system.computer // "unknown"),
            (.data.win.eventdata.user // .data.win.eventdata.userName // "unknown"),
            (.data.win.eventdata.commandLine // "unknown"),
            (.data.win.eventdata.targetHostname // "unknown"),
            (.data.win.eventdata.processId // "unknown")
        ]
        | @tsv
    ' "$TMP"
)

echo
echo "QUERY RESULTS:"
echo "  Total PsExec events in 14 days: $TOTAL"
echo "  Baseline: $BASELINE"
echo "  ANOMALOUS: $ANOMALOUS"

echo

# --------------------------------------------------
# Final finding
# --------------------------------------------------

echo "FINDING:"

if [ "$ANOMALOUS" -gt 0 ]; then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  Evidence: PsExec activity does not match Robert Kim's baseline"
    echo "  Recommendation: ESCALATE"
else
    echo "  Status: NO POSITIVE FINDING"
    echo "  Evidence: PsExec activity matches Robert Kim's baseline"
    echo "  Recommendation: No escalation"
fi

echo
echo "================================================================"