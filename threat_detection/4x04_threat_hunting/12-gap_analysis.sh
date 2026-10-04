#!/bin/bash

echo "================================================================"
echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"
echo "================================================================"
echo

# --------------------------------------------------
# GAP 1 - PsExec
# --------------------------------------------------

echo "GAP 1: T1021.002 PsExec Lateral Movement"
echo "  Hunt Finding: PsExec used from non-admin workstation"
echo "  Why Missed: Missing rule"
echo "  Data Source: Sysmon Event 1"
echo "  Detection Logic:"
echo "    - Image or CommandLine contains PsExec"
echo "    - Source host is not WS-ADMIN-01"
echo "    - Or activity happens outside normal admin hours"
echo "    - Allow Robert Kim's approved activity"
echo "  Priority: P1"
echo

# --------------------------------------------------
# GAP 2 - LSASS
# --------------------------------------------------

echo "GAP 2: T1003.001 LSASS Credential Access"
echo "  Hunt Finding: Non-system process accessed lsass.exe"
echo "  Why Missed: Missing rule"
echo "  Data Source: Sysmon Event 10"
echo "  Detection Logic:"
echo "    - TargetImage contains lsass.exe"
echo "    - Source process is not allowlisted"
echo "    - Check suspicious memory access rights"
echo "  Priority: P1"
echo

# --------------------------------------------------
# GAP 3 - WMI
# --------------------------------------------------

echo "GAP 3: T1047 WMI Remote Execution"
echo "  Hunt Finding: WMI used for remote execution/reconnaissance"
echo "  Why Missed: Missing rule"
echo "  Data Source: Sysmon Event 1"
echo "  Detection Logic:"
echo "    - Detect WMI-related processes or commands"
echo "    - Compare source host with admin baseline"
echo "    - Alert on unusual targets or off-hours activity"
echo "    - Allow approved Robert Kim activity"
echo "  Priority: P2"
echo

# --------------------------------------------------
# GAP 4 - PowerShell Remoting
# --------------------------------------------------

echo "GAP 4: T1021.006 PowerShell Remoting"
echo "  Hunt Finding: PSRemoting used for remote access/staging"
echo "  Why Missed: Rule too specific or missing"
echo "  Data Source: PowerShell logs + Sysmon Event 1"
echo "  Detection Logic:"
echo "    - Detect WinRM / PSRemoting activity"
echo "    - Look for Invoke-Command, Enter-PSSession or Copy-Item"
echo "    - Compare user, source host and time with baseline"
echo "    - Allow approved admin sessions"
echo "  Priority: P2"
echo

# --------------------------------------------------
# GAP 5 - Service account misuse
# --------------------------------------------------

echo "GAP 5: T1078.002 Service Account Misuse"
echo "  Hunt Finding: Service account used from workstation"
echo "  Why Missed: Missing behavioral rule"
echo "  Data Source: Windows Event 4624"
echo "  Detection Logic:"
echo "    - Match service account usernames"
echo "    - Compare source host with service account matrix"
echo "    - Alert on workstation source"
echo "    - Alert on interactive logon types"
echo "  Priority: P1"
echo

# --------------------------------------------------
# GAP 6 - NTLM / Pass-the-Hash style activity
# --------------------------------------------------

echo "GAP 6: NTLM / Pass-the-Hash-style Activity"
echo "  Hunt Finding: NTLM authentication with suspicious service account use"
echo "  Why Missed: Missing correlation rule"
echo "  Data Source: Windows Event 4624"
echo "  Detection Logic:"
echo "    - Authentication package is NTLM"
echo "    - Service account used from unexpected source"
echo "    - Correlate with PsExec, WMI or PSRemoting activity"
echo "    - Allow known legitimate NTLM use if documented"
echo "  Priority: P2"
echo

# --------------------------------------------------
# Summary
# --------------------------------------------------

echo "SUMMARY:"
echo "  Most required data was already present."
echo "  The main problem was missing detection logic."
echo "  Some existing rules were too specific."
echo "  Proactive hunting exposed the Stage 4 gaps."
echo
echo "  Highest priority gaps:"
echo "    P1 - PsExec lateral movement"
echo "    P1 - LSASS access"
echo "    P1 - Service account misuse"
echo

echo "================================================================"