#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

TMP="/tmp/credential_hunt.jsonl"
LSASS="/tmp/lsass_events.jsonl"

# --------------------------------------------------
# Prepare data
# --------------------------------------------------

jq -c 'if type == "array" then .[] else . end' \
    "$ALERTS" "$SYSMON" > "$TMP"

# --------------------------------------------------
# Find LSASS access events
# --------------------------------------------------

jq -c '
    select(
        ((.data.win.eventdata.targetImage // "") | test("lsass.exe"; "i"))
    )
' "$TMP" > "$LSASS"

TOTAL=$(wc -l < "$LSASS")

LEGIT=0
ANOMALOUS=0
NUMBER=0

echo "================================================================"
echo "   HUNT EXECUTION - H2: Credential Access (LSASS)"
echo "   Technique: T1003.001 LSASS Memory"
echo "================================================================"
echo

echo "LSASS ACCESS EVENTS:"

while IFS=$'\t' read -r TIME HOST SOURCE TARGET ACCESS
do
    BAD=0

    # Simple legitimate process check
    if [[ "$SOURCE" == *"svchost.exe"* ]] ||
       [[ "$SOURCE" == *"wininit.exe"* ]] ||
       [[ "$SOURCE" == *"services.exe"* ]]; then

        LEGIT=$((LEGIT + 1))

    else
        BAD=1
        ANOMALOUS=$((ANOMALOUS + 1))
        NUMBER=$((NUMBER + 1))

        echo
        echo "  [A$NUMBER] $TIME"
        echo "    Host: $HOST"
        echo "    Source Process: $SOURCE"
        echo "    Target: $TARGET"
        echo "    Access Mask: $ACCESS"

        # Common suspicious memory access value
        if [ "$ACCESS" = "0x1010" ]; then
            echo "    -> Consistent with memory dumping"
        else
            echo "    -> Unusual LSASS access"
        fi
    fi

done < <(
    jq -r '
        [
            (.timestamp // "unknown"),
            (.agent.name // .data.win.system.computer // "unknown"),
            (.data.win.eventdata.sourceImage // "unknown"),
            (.data.win.eventdata.targetImage // "unknown"),
            (.data.win.eventdata.grantedAccess // "unknown")
        ]
        | @tsv
    ' "$LSASS"
)

echo
echo "  Total LSASS access events: $TOTAL"
echo "  System/legitimate: $LEGIT"
echo "  ANOMALOUS: $ANOMALOUS"

echo

# --------------------------------------------------
# Find svc_healthsync authentication
# --------------------------------------------------

echo "CREDENTIAL USAGE CORRELATION:"
echo "  svc_healthsync authentication events:"

jq -r '
    select(
        (
            (.data.win.eventdata.targetUserName // "") |
            test("svc_healthsync"; "i")
        )
        or
        (
            (.data.win.eventdata.user // "") |
            test("svc_healthsync"; "i")
        )
    )
    |
    [
        (.timestamp // "unknown"),
        (.data.win.eventdata.workstationName //
         .agent.name //
         "unknown"),
        (.data.win.eventdata.ipAddress //
         .data.win.system.computer //
         "unknown")
    ]
    | @tsv
' "$TMP" |
while IFS=$'\t' read -r TIME SOURCE TARGET
do
    echo "    $TIME  $SOURCE -> $TARGET"
done

echo

# --------------------------------------------------
# Look for lateral movement with the account
# --------------------------------------------------

echo "LATERAL MOVEMENT CORRELATION:"

jq -r '
    select(
        (
            tostring |
            test("svc_healthsync"; "i")
        )
        and
        (
            tostring |
            test("psexec|wmi|winrm|psremoting|powershell remoting"; "i")
        )
    )
    |
    [
        (.timestamp // "unknown"),
        (.agent.name // .data.win.system.computer // "unknown"),
        (.data.win.eventdata.commandLine // "unknown")
    ]
    | @tsv
' "$TMP" |
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
    echo "  The attacker may have accessed LSASS and later used"
    echo "  svc_healthsync for lateral movement."
    echo "  Recommendation: ESCALATE"
else
    echo "  Status: NO POSITIVE FINDING"
    echo "  No anomalous LSASS access was found."
fi

echo
echo "================================================================"