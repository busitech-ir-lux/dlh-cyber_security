#!/bin/bash

# ---------------------------------------------
# File paths
# ---------------------------------------------

ADVISORY="reference/hc3_advisory_004.txt"
ATTACK_MAP="reference/4x03_attack_mapping.json"

# ---------------------------------------------
# Header
# ---------------------------------------------

echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"
echo

# ---------------------------------------------
# Stage 4 TTPs from advisory
# ---------------------------------------------

echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"

grep -qi "PsExec" "$ADVISORY" &&
    echo "    [*] PsExec for remote command execution on servers"

grep -qi "WMI" "$ADVISORY" &&
    echo "    [*] WMI for remote process creation and enumeration"

grep -qi "PowerShell Remoting" "$ADVISORY" &&
    echo "    [*] PowerShell Remoting for interactive access and staging"

grep -qi "LSASS" "$ADVISORY" &&
    echo "    [*] Credential dumping via LSASS memory access"

grep -qi "service account" "$ADVISORY" &&
    echo "    [*] Service account abuse for lateral authentication"

grep -qi "off-hours" "$ADVISORY" &&
    echo "    [*] Off-hours operations to avoid detection"

echo

# ---------------------------------------------
# ATT&CK coverage
# ---------------------------------------------

echo "ATT&CK COVERAGE GAP ANALYSIS:"

echo "  OBSERVED:"
jq -r '.[] | select(.state == "OBSERVED") |
    "    \(.technique_id)  \(.technique_name)"' "$ATTACK_MAP"

echo

echo "  INFERRED:"
jq -r '.[] | select(.state == "INFERRED") |
    "    \(.technique_id)  \(.technique_name)"' "$ATTACK_MAP"

echo

echo "  NOT COVERED:"
jq -r '.[] | select(.state == "NOT COVERED") |
    "    \(.technique_id)  \(.technique_name)"' "$ATTACK_MAP"

echo

# ---------------------------------------------
# Stage 4 techniques that are not covered
# ---------------------------------------------

echo "  Stage 4 techniques in gap:"

jq -r '
.[] |
select(.state == "NOT COVERED") |
select(
    .technique_id == "T1021.002" or
    .technique_id == "T1047" or
    .technique_id == "T1021.006" or
    .technique_id == "T1003.001" or
    .technique_id == "T1078.002"
) |
"    \(.technique_id)  \(.technique_name)  NOT COVERED"
' "$ATTACK_MAP"

echo

# ---------------------------------------------
# Hunt priority
# ---------------------------------------------

echo "HUNT PRIORITY RANKING:"
echo "  P1: T1021.002 PsExec"
echo "  P2: T1003.001 LSASS"
echo "  P3: T1047 WMI"
echo "  P4: T1021.006 PSRemoting"
echo "  P5: T1078.002 Domain Accounts"

echo

# ---------------------------------------------
# Data sources
# ---------------------------------------------

echo "DATA SOURCES:"
echo "  Primary: siem_export/wazuh_alerts_14d.json"
echo "  Secondary: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Baseline: baseline/robert_kim_activity.json"

echo

# ---------------------------------------------
# False-positive controls
# ---------------------------------------------

echo "FALSE-POSITIVE CONTROLS:"
echo "  Robert Kim schedule: reference/admin_schedule.txt"
echo "  Service account matrix: reference/service_accounts.txt"
echo "  Network topology: reference/network_topology.txt"

echo
echo "TIME WINDOW: 14 days"
echo
echo "SCOPE:"
echo "  HEALTHBANE Stage 4 lateral movement and credential abuse"

echo
echo "HUNT TARGETS:"
echo "  PsExec, WMI, PowerShell Remoting, LSASS and service account abuse"

echo
echo "================================================================"