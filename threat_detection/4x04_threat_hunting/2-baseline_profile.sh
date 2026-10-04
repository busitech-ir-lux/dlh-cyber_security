#!/bin/bash

BASELINE="baseline/robert_kim_activity.json"

echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: baseline/robert_kim_activity.json"
echo "================================================================"
echo

# -----------------------------
# Tool usage
# -----------------------------

echo "TOOL USAGE SUMMARY:"

echo -n "  PsExec events:          "
jq '[.[] | select(.tool == "PsExec")] | length' "$BASELINE"

echo -n "  WMI events:             "
jq '[.[] | select(.tool == "WMI")] | length' "$BASELINE"

echo -n "  PSRemoting events:      "
jq '[.[] | select(.tool == "PSRemoting")] | length' "$BASELINE"

echo -n "  Total admin events:     "
jq 'length' "$BASELINE"

echo

# -----------------------------
# Source hosts
# -----------------------------

echo "SOURCE HOST:"

jq -r '.[].source_host' "$BASELINE" |
sort |
uniq -c |
sort -nr

echo "  -> BASELINE: All normal admin activity should come from WS-ADMIN-01"

echo

# -----------------------------
# Time distribution
# -----------------------------

echo "TIME DISTRIBUTION:"

echo -n "  08:00-18:00: "
jq '[.[] |
    (.timestamp[11:13] | tonumber) as $hour |
    select($hour >= 8 and $hour < 18)
] | length' "$BASELINE"

echo -n "  18:00-08:00: "
jq '[.[] |
    (.timestamp[11:13] | tonumber) as $hour |
    select($hour < 8 or $hour >= 18)
] | length' "$BASELINE"

echo "  -> BASELINE: Normal activity is during business hours"

echo

# -----------------------------
# Day of week
# -----------------------------

echo "DAY-OF-WEEK DISTRIBUTION:"

jq -r '.[].timestamp[0:10]' "$BASELINE" |
while read -r day
do
    date -d "$day" "+%A"
done |
sort |
uniq -c |
sort -nr

echo

# -----------------------------
# Target hosts
# -----------------------------

echo "TARGET HOSTS:"

jq -r '.[].target_host' "$BASELINE" |
sort |
uniq -c |
sort -nr

echo

# -----------------------------
# User accounts
# -----------------------------

echo "USER ACCOUNTS:"

jq -r '.[].user' "$BASELINE" |
sort |
uniq -c |
sort -nr

echo "  -> BASELINE: Robert Kim should use his named account"
echo "  -> BASELINE: Service accounts should not be used interactively"

echo

# -----------------------------
# Baseline summary
# -----------------------------

echo "BASELINE SUMMARY:"
echo "  Normal source:  WS-ADMIN-01"
echo "  Normal time:    08:00-18:00"
echo "  Normal account: MEDDEFENSE\\robert.kim"
echo "  Normal tools:   PsExec, WMI, PSRemoting"
echo "  Normal targets: See TARGET HOSTS above"

echo

# -----------------------------
# Later hunt rules
# -----------------------------

echo "ANOMALY DETECTION CRITERIA:"
echo "  [!] Admin tool from any host other than WS-ADMIN-01"
echo "  [!] Admin tool usage outside business hours"
echo "  [!] Service account used interactively from workstation"
echo "  [!] WMI targeting unusual hosts"
echo "  [!] Unexpected user account using admin tools"

echo
echo "================================================================"