#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

DATA="/tmp/wmi_hunt_data.jsonl"
WMI="/tmp/wmi_events.jsonl"

# --------------------------------------------------
# Prepare SIEM data
# --------------------------------------------------

jq -c 'if type == "array" then .[] else . end' \
    "$ALERTS" "$SYSMON" > "$DATA"

# --------------------------------------------------
# Extract WMI-related events
# --------------------------------------------------

jq -c '
    select(
        (tostring | test(
            "wmiprvse.exe|wmic.exe|Invoke-WmiMethod|wmi";
            "i"
        ))
    )
' "$DATA" > "$WMI"

TOTAL=$(wc -l < "$WMI")
BASELINE=0
ANOMALOUS=0
NUMBER=0

echo "================================================================"
echo "   HUNT EXECUTION - H3: Lateral Movement via WMI"
echo "   Technique: T1047 Windows Management Instrumentation"
echo "================================================================"
echo

echo "ANOMALOUS EVENTS:"

# --------------------------------------------------
# Check each WMI event
# --------------------------------------------------

while IFS=$'\t' read -r TIME SOURCE TARGET USER PROCESS COMMAND PARENT CHILD
do
    BAD=0
    FLAGS=""

    HOUR=$(date -d "$TIME" "+%H" 2>/dev/null)

    # Normal source should be WS-ADMIN-01
    if [ "$SOURCE" != "WS-ADMIN-01" ]; then
        FLAGS="$FLAGS
      [!] Source is not WS-ADMIN-01"
        BAD=1
    fi

    # Normal time should be 08:00-18:00
    if [ "$HOUR" -lt 8 ] 2>/dev/null || [ "$HOUR" -ge 18 ] 2>/dev/null; then
        FLAGS="$FLAGS
      [!] Activity is outside business hours"
        BAD=1
    fi

    # Robert Kim should be the normal admin user
    if [[ "$USER" != *"robert.kim"* ]]; then
        FLAGS="$FLAGS
      [!] User does not match Robert Kim baseline"
        BAD=1
    fi

    # Service account use is suspicious
    if [[ "$USER" == *"svc_"* ]]; then
        FLAGS="$FLAGS
      [!] Service account used with WMI"
        BAD=1
    fi

    # Suspicious WMI child process
    if [[ "$PARENT" == *"wmiprvse.exe"* ]] &&
       ([[ "$CHILD" == *"cmd.exe"* ]] ||
        [[ "$CHILD" == *"powershell.exe"* ]]); then

        FLAGS="$FLAGS
      [!] wmiprvse.exe spawned command shell"
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
        echo "    Parent: $PARENT"
        echo "    Child: $CHILD"
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
             .data.win.system.computer //
             "unknown"),

            (.data.win.eventdata.user //
             .data.win.eventdata.userName //
             .data.win.eventdata.targetUserName //
             "unknown"),

            (.data.win.eventdata.image //
             "unknown"),

            (.data.win.eventdata.commandLine //
             "unknown"),

            (.data.win.eventdata.parentImage //
             "unknown"),

            (.data.win.eventdata.image //
             "unknown")
        ]
        | @tsv
    ' "$WMI"
)

echo
echo "QUERY RESULTS:"
echo "  Total WMI-related events: $TOTAL"
echo "  Baseline: $BASELINE"
echo "  ANOMALOUS: $ANOMALOUS"

echo

# --------------------------------------------------
# False positive analysis
# --------------------------------------------------

echo "FALSE POSITIVE ANALYSIS:"
echo "  Legitimate WMI should match Robert Kim's baseline:"
echo "    - Source: WS-ADMIN-01"
echo "    - User: Robert Kim"
echo "    - Time: 08:00-18:00"
echo "    - Normal inventory/admin activity"
echo
echo "  Anomalies are suspicious when they:"
echo "    - come from non-admin workstations"
echo "    - happen off-hours"
echo "    - use service accounts"
echo "    - spawn cmd.exe or powershell.exe"

echo

# --------------------------------------------------
# Correlate with PsExec
# --------------------------------------------------

echo "PSEXEC CORRELATION:"

jq -r '
    select(
        (tostring | test("psexec"; "i"))
    )
    |
    [
        (.timestamp // "unknown"),
        (.agent.name // .data.win.system.computer // "unknown"),
        (.data.win.eventdata.commandLine // "unknown")
    ]
    | @tsv
' "$DATA" |
while IFS=$'\t' read -r TIME HOST COMMAND
do
    echo "  $TIME"
    echo "    Host: $HOST"
    echo "    Command: $COMMAND"
done

echo

# --------------------------------------------------
# Final finding
# --------------------------------------------------

echo "FINDING:"

if [ "$ANOMALOUS" -gt 0 ]; then
    echo "  Status: POSITIVE - HIGH CONFIDENCE"
    echo "  WMI activity was found outside Robert Kim's normal baseline."
    echo "  Pattern may show remote execution or reconnaissance."
    echo "  Recommendation: ESCALATE"
else
    echo "  Status: NO POSITIVE FINDING"
    echo "  WMI activity matched the normal admin baseline."
fi

echo
echo "================================================================"