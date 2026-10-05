#!/bin/bash

echo "================================================================"
echo "   HUNT HYPOTHESES - HEALTHBANE Stage 4"
echo "================================================================"
echo

# --------------------------------------------------
# H1 - PsExec
# --------------------------------------------------

echo "HYPOTHESIS H1: Lateral Movement via PsExec"
echo "  Technique: T1021.002 SMB/Windows Admin Shares"
echo "  Statement: IF the attacker used PsExec for lateral movement, THEN"
echo "             process creation events should show PsExec from a"
echo "             non-admin workstation or outside maintenance hours."
echo "  Data Source: siem_export/wazuh_alerts_14d.json"
echo "  Search: Image or CommandLine contains PsExec/psexec"
echo "  jq idea:"
echo "    select((.data.win.eventdata.image // \"\") | test(\"psexec\"; \"i\"))"
echo "  Positive: PsExec from host other than WS-ADMIN-01 or off-hours"
echo "  FP Exclusion: Robert Kim activity from WS-ADMIN-01 during maintenance"
echo "  Baseline Rate: Expected only during Robert Kim maintenance"
echo

# --------------------------------------------------
# H2 - LSASS
# --------------------------------------------------

echo "HYPOTHESIS H2: Credential Access via LSASS"
echo "  Technique: T1003.001 LSASS Memory"
echo "  Statement: IF the attacker dumped credentials from LSASS, THEN"
echo "             Sysmon should show a non-system process accessing lsass.exe."
echo "  Data Source: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Search: TargetImage contains lsass.exe"
echo "  jq idea:"
echo "    select((.data.win.eventdata.targetImage // \"\") | test(\"lsass.exe\"; \"i\"))"
echo "  Positive: Non-system process accessing lsass.exe"
echo "  FP Exclusion: Known Windows/system processes"
echo "  Baseline Rate: Very low for unusual processes"
echo

# --------------------------------------------------
# H3 - WMI
# --------------------------------------------------

echo "HYPOTHESIS H3: Remote Execution via WMI"
echo "  Technique: T1047 WMI"
echo "  Statement: IF the attacker used WMI remotely, THEN"
echo "             WMI-related process activity should appear from unusual"
echo "             source hosts, users or targets."
echo "  Data Source: siem_export/wazuh_raw_sysmon_14d.json"
echo "  Search: CommandLine or process fields contain wmi/wmic/wmiprvse"
echo "  jq idea:"
echo "    select(tostring | test(\"wmi|wmic|wmiprvse\"; \"i\"))"
echo "  Positive: WMI activity outside Robert Kim's normal baseline"
echo "  FP Exclusion: Approved WMI activity from WS-ADMIN-01"
echo "  Baseline Rate: Expected only during legitimate admin activity"
echo

# --------------------------------------------------
# H4 - PowerShell Remoting
# --------------------------------------------------

echo "HYPOTHESIS H4: PowerShell Remoting"
echo "  Technique: T1021.006 Windows Remote Management"
echo "  Statement: IF the attacker used PowerShell Remoting, THEN"
echo "             SIEM data should show WinRM or remote PowerShell activity"
echo "             from an unexpected source, user or time."
echo "  Data Source: siem_export/wazuh_alerts_14d.json"
echo "  Search: CommandLine contains WinRM, PSRemoting, Invoke-Command or Enter-PSSession"
echo "  jq idea:"
echo "    select(tostring | test(\"winrm|psremoting|invoke-command|enter-pssession\"; \"i\"))"
echo "  Positive: Remote PowerShell activity outside normal admin baseline"
echo "  FP Exclusion: Robert Kim approved remote administration"
echo "  Baseline Rate: Expected only during maintenance/admin work"
echo

# --------------------------------------------------
# H5 - Service account abuse
# --------------------------------------------------

echo "HYPOTHESIS H5: Service Account Abuse"
echo "  Technique: T1078.002 Domain Accounts"
echo "  Statement: IF the attacker stole and used a service account, THEN"
echo "             authentication events should show that account from an"
echo "             unauthorized host or workstation."
echo "  Data Source: siem_export/wazuh_alerts_14d.json"
echo "  Search: TargetUserName or User contains svc_"
echo "  jq idea:"
echo "    select(tostring | test(\"svc_\"; \"i\"))"
echo "  Positive: Service account used from host not allowed by authorization matrix"
echo "  FP Exclusion: Approved service account host and normal service activity"
echo "  Baseline Rate: Service accounts should only appear from approved hosts"
echo

echo "================================================================"