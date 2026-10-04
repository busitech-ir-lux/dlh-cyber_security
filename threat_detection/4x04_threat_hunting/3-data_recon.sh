#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
DATA="/tmp/meddefense_recon.jsonl"

# Put both datasets into one JSON Lines file.
# Works if the input is a JSON array or JSON Lines.
jq -c 'if type == "array" then .[] else . end' \
    "$ALERTS" "$SYSMON" > "$DATA"

echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"
echo

# --------------------------------------------------
# Dataset metadata
# --------------------------------------------------

TOTAL=$(wc -l < "$DATA")

FIRST=$(jq -r '.timestamp // empty' "$DATA" | sort | head -1)
LAST=$(jq -r '.timestamp // empty' "$DATA" | sort | tail -1)

echo "DATASET METADATA:"
echo "  Total events:   $TOTAL"
echo "  First event:    $FIRST"
echo "  Last event:     $LAST"
echo "  Duration:       14 days"
echo "  Format:         JSON / JSON Lines"
echo

# --------------------------------------------------
# Top event types
# --------------------------------------------------

echo "TOP 10 EVENT TYPES:"

jq -r '
    if .rule.id then
        "\(.rule.id) \(.rule.description)"
    elif .data.win.system.eventID then
        "EventID \(.data.win.system.eventID)"
    else
        "Unknown"
    end
' "$DATA" |
sort |
uniq -c |
sort -nr |
head -10

echo

# --------------------------------------------------
# Source hosts / agents
# --------------------------------------------------

echo "SOURCE HOST DISTRIBUTION:"

jq -r '
    .agent.name //
    .data.win.system.computer //
    empty
' "$DATA" |
sort |
uniq -c |
sort -nr

echo

# --------------------------------------------------
# Severity
# --------------------------------------------------

echo "SEVERITY DISTRIBUTION:"

jq -r '.rule.level // empty' "$DATA" |
sort -n |
uniq -c |
sort -k2n

echo

# --------------------------------------------------
# Hourly distribution
# --------------------------------------------------

echo "HOURLY DISTRIBUTION:"

for HOUR in $(seq -w 0 23)
do
    COUNT=$(jq -r '.timestamp // empty' "$DATA" |
        grep -c "T$HOUR:")

    echo "  $HOUR:00  $COUNT"
done

echo

# --------------------------------------------------
# Hypothesis coverage
# --------------------------------------------------

echo "HYPOTHESIS COVERAGE MATRIX:"

if grep -qi "psexec" "$DATA"; then
    echo "  H1 (PsExec):       [OK]"
else
    echo "  H1 (PsExec):       [MISSING]"
fi

if grep -qi "lsass" "$DATA"; then
    echo "  H2 (LSASS):        [OK]"
else
    echo "  H2 (LSASS):        [MISSING]"
fi

if grep -qi "wmi" "$DATA"; then
    echo "  H3 (WMI):          [OK]"
else
    echo "  H3 (WMI):          [MISSING]"
fi

if grep -Eqi "PSRemoting|PowerShell Remoting|WinRM" "$DATA"; then
    echo "  H4 (PSRemoting):   [OK]"
else
    echo "  H4 (PSRemoting):   [MISSING]"
fi

if grep -Eqi "service account|svc[_-]" "$DATA"; then
    echo "  H5 (Svc Accounts): [OK]"
else
    echo "  H5 (Svc Accounts): [MISSING]"
fi

echo
echo "================================================================"