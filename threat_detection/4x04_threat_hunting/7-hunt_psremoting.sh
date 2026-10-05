#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
SCHEDULE="reference/admin_schedule.txt"

DATA="/tmp/psremoting_hunt_data.jsonl"
PSR="/tmp/psremoting_events.jsonl"

# --------------------------------------------------
# Prepare data
# --------------------------------------------------

jq -c 'if type == "array" then .[] else . end' \
    "$ALERTS" "$SYSMON" > "$DATA"

# --------------------------------------------------
# Find PowerShell Remoting activity
# --------------------------------------------------

jq -c '
    select(
        tostring |
        test(
            "Enter-PSSession|Invoke-Command|New-PSSession|wsmprovhost.exe|Copy-Item";
            "i"
        )
    )
' "$DATA" > "$PSR"

TOTAL=$(wc -l < "$PSR")
BASELINE=0
ANOMALOUS=0
NUMBER=0

echo "================================================================"
echo "   HUNT EXECUTION - H4: PowerShell Remoting"
echo "   Technique: T1021.006 Windows Remote Management"
echo "================================================================"
echo

echo "ANOMALOUS EVENTS:"

# --------------------------------------------------
# Check events against baseline
# --------------------------------------------------

while IFS=$'\t' read -r TIME SOURCE TARGET USER PROCESS COMMAND
do
    BAD=0
    FLAGS=""

    HOUR=$(date -d "$TIME" "+%H" 2>/dev/null)
    DAY=$(date -d "$TIME" "+%A" 2>/dev/null)

    # Normal source
    if [ "$SOURCE" != "WS-ADMIN-01" ]; then
        FLAGS="$FLAGS
      [!] Source is not WS-ADMIN-01"
        BAD=1
    fi

    # Normal business hours
    if [ "$HOUR" -lt 8 ] 2>/dev/null || [ "$HOUR" -ge 18 ] 2>/dev/null; then
        FLAGS="$FLAGS
      [!] Activity is outside business hours"
        BAD=1
    fi

    # Maintenance day
    if ! grep -qi "$DAY" "$SCHEDULE"; then
        FLAGS="$FLAGS
      [!] Day is outside Robert Kim's maintenance schedule"
        BAD=1
    fi

    # Normal user
    if [[ "$USER" != *"robert.kim"* ]]; then
        FLAGS="$FLAGS
      [!] User does not match Robert Kim baseline"
        BAD=1
    fi

    # Service account use
    if [[ "$USER" == *"svc_"* ]]; then
        FLAGS="$FLAGS
      [!] Service account used for PowerShell Remoting"
        BAD=1
    fi

    # File staging pattern
    if [[ "$COMMAND" == *"Copy-Item"* ]]; then
        FLAGS="$FLAGS
      [!] Copy-Item may indicate remote file staging"
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
        echo "    Target: $TARGET"
        echo "    User: $USER"
        echo "    Process: $PROCESS"
        echo "    Command: $COMMAND"
        echo "    ANOMALY FLAGS:"
        echo "$FLAGS"
    fi

done < <(
    jq -r '
        [
            (.timestamp // "unknown"),

            (.data.win.eventdata.sourceHostname //
             .data.win.eventdata.workstationName //
             .agent.name //
             "unknown"),

            (.data.win.eventdata.targetHostname //
             .data.win.eventdata.computerName //
             .data.win.system.computer //
             "unknown"),

            (.data.win.eventdata.user //
             .data.win.eventdata.userName //
             .data.win.eventdata.targetUserName //
             "unknown"),

            (.data.win.eventdata.image //
             "unknown"),

            (.data.win.eventdata.commandLine //
             "unknown")
        ]
        | @tsv
    ' "$PSR"
)

echo
echo "QUERY RESULTS:"
echo "  Total PSRemoting events: $TOTAL"
echo "  Baseline: $BASELINE"
echo "  ANOMALOUS: $ANOMALOUS"

echo

# --------------------------------------------------
# Correlate with earlier hunt activity
# --------------------------------------------------

echo "CORRELATION WITH PREVIOUS FINDINGS:"

echo "  PsExec:"
grep -i "psexec" "$DATA" | head -3

echo
echo "  WMI:"
grep -Ei "wmic|wmiprvse|Invoke-WmiMethod" "$DATA" | head -3

echo
echo "  Credential access:"
grep -i "lsass.exe" "$DATA" | head -3

echo

# --------------------------------------------------
# Staging possibility
# --------------------------------------------------

echo "STAGING CHECK:"

if grep -qi "Copy-Item" "$PSR"; then
    echo "  Copy-Item activity was found."
    echo "  This may indicate files were staged on remote servers."
else
    echo "  No Copy-Item staging activity found."
fi

echo

# --------------------------------------------------
# Final finding
# --------------------------------------------------

echo "FINDING:"

if [ "$ANOMALOUS" -gt 0 ]; then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  PowerShell Remoting activity was found outside"
    echo "  Robert Kim's normal admin baseline."
    echo "  Pattern may indicate remote access or staging."
    echo "  Recommendation: ESCALATE"
else
    echo "  Status: NO POSITIVE FINDING"
    echo "  PowerShell Remoting activity matched the baseline."
fi

echo
echo "================================================================"