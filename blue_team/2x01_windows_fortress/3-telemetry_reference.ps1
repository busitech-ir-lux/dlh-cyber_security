<#
Script Name: 3-telemetry_reference.ps1
Purpose: Build a machine-readable Windows telemetry reference.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "$PSScriptRoot\windows_event_reference.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$events = @(
    [pscustomobject]@{event_id=4624;event_name="Successful Logon";log_source="Security";audit_or_sensor_dependency="Audit Logon - Success";security_meaning="A user or computer logged on successfully";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Phase 3 - Lateral Movement";example_suspicious_pattern="Admin logon from an unusual workstation or Logon Type 10 at night";validation_method="Sign in successfully and query Security Event ID 4624"},
    [pscustomobject]@{event_id=4625;event_name="Failed Logon";log_source="Security";audit_or_sensor_dependency="Audit Logon - Failure";security_meaning="A failed logon attempt was recorded";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Phase 2 - Credential Access";example_suspicious_pattern="One source tries many accounts in a short time";validation_method="Enter an incorrect password and query Event ID 4625"},
    [pscustomobject]@{event_id=4648;event_name="Explicit Credentials";log_source="Security";audit_or_sensor_dependency="Audit Logon - Success";security_meaning="A process used supplied credentials";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Phase 3 - Lateral Movement";example_suspicious_pattern="runas or remote administration using another account";validation_method="Use runas and query Event ID 4648"},
    [pscustomobject]@{event_id=4672;event_name="Special Privileges Assigned";log_source="Security";audit_or_sensor_dependency="Audit Special Logon - Success";security_meaning="A privileged account received sensitive rights";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Phase 3 - Privilege Escalation";example_suspicious_pattern="Unexpected user receives administrator privileges";validation_method="Log on with an administrator and query Event ID 4672"},
    [pscustomobject]@{event_id=4688;event_name="Process Creation";log_source="Security";audit_or_sensor_dependency="Audit Process Creation - Success";security_meaning="A new process started";normal_frequency="Very High";triage_priority="High";crimson_tide_phase="Phase 3 - Execution";example_suspicious_pattern="powershell.exe -enc or Office spawning cmd.exe";validation_method="Start notepad.exe and query Event ID 4688"},
    [pscustomobject]@{event_id=4720;event_name="User Account Created";log_source="Security";audit_or_sensor_dependency="Audit User Account Management - Success";security_meaning="A user account was created";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Phase 5 - Persistence";example_suspicious_pattern="New account created outside change hours";validation_method="Create a test account and query Event ID 4720"},
    [pscustomobject]@{event_id=4726;event_name="User Account Deleted";log_source="Security";audit_or_sensor_dependency="Audit User Account Management - Success";security_meaning="A user account was deleted";normal_frequency="Low";triage_priority="Medium";crimson_tide_phase="Phase 7 - Defense Evasion";example_suspicious_pattern="Recently created attacker account is deleted";validation_method="Delete a test account and query Event ID 4726"},
    [pscustomobject]@{event_id=4732;event_name="Member Added to Local Group";log_source="Security";audit_or_sensor_dependency="Audit Security Group Management - Success";security_meaning="A member was added to a local security group";normal_frequency="Low";triage_priority="Critical";crimson_tide_phase="Phase 3 - Privilege Escalation";example_suspicious_pattern="User added to Administrators or Remote Desktop Users";validation_method="Add a test user to a local group and query Event ID 4732"},
    [pscustomobject]@{event_id=1102;event_name="Audit Log Cleared";log_source="Security";audit_or_sensor_dependency="Security log service";security_meaning="The Security audit log was cleared";normal_frequency="Rare";triage_priority="Critical";crimson_tide_phase="Phase 7 - Defense Evasion";example_suspicious_pattern="Security log cleared after suspicious execution";validation_method="Clear a lab Security log and query Event ID 1102"},

    [pscustomobject]@{event_id=4103;event_name="PowerShell Module Logging";log_source="Microsoft-Windows-PowerShell/Operational";audit_or_sensor_dependency="PowerShell Module Logging";security_meaning="Records PowerShell module and command activity";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Phase 3 - Execution";example_suspicious_pattern="Reconnaissance or credential commands loaded from a module";validation_method="Run Get-Process and query Event ID 4103"},
    [pscustomobject]@{event_id=4104;event_name="PowerShell Script Block";log_source="Microsoft-Windows-PowerShell/Operational";audit_or_sensor_dependency="PowerShell Script Block Logging";security_meaning="Records decoded PowerShell script content";normal_frequency="Medium";triage_priority="Critical";crimson_tide_phase="Phase 3 - Execution";example_suspicious_pattern="Encoded command decodes to download or credential theft code";validation_method="Run a test script and query Event ID 4104"},

    [pscustomobject]@{event_id=1;event_name="Process Create";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 1 enabled";security_meaning="Detailed process, parent, command line and hashes";normal_frequency="Very High";triage_priority="High";crimson_tide_phase="Phase 3 - Execution";example_suspicious_pattern="rclone.exe, psexec.exe, powershell -enc, or vssadmin delete shadows";validation_method="Start a process and query Sysmon Event ID 1"},
    [pscustomobject]@{event_id=3;event_name="Network Connection";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 3 enabled";security_meaning="A process made a network connection";normal_frequency="Very High";triage_priority="High";crimson_tide_phase="Phase 4 - Exfiltration";example_suspicious_pattern="Server process connects to an unusual external IP";validation_method="Make a test TCP connection and query Sysmon Event ID 3"},
    [pscustomobject]@{event_id=7;event_name="Image Loaded";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 7 enabled";security_meaning="A DLL or executable image was loaded";normal_frequency="Very High";triage_priority="Medium";crimson_tide_phase="Phase 3 - Execution";example_suspicious_pattern="Unsigned DLL loaded into a trusted process";validation_method="Start an application and query Sysmon Event ID 7"},
    [pscustomobject]@{event_id=11;event_name="File Create";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 11 enabled";security_meaning="A process created a file";normal_frequency="High";triage_priority="High";crimson_tide_phase="Phase 6 - Ransomware Deployment";example_suspicious_pattern="Executable created in Temp, Startup, or a shared folder";validation_method="Create C:\Windows\Temp\sysmon_test.txt and query Event ID 11"},
    [pscustomobject]@{event_id=13;event_name="Registry Value Set";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 13 enabled";security_meaning="A registry value was created or changed";normal_frequency="High";triage_priority="High";crimson_tide_phase="Phase 5 - Persistence";example_suspicious_pattern="Run key, service, or PsExec registry modification";validation_method="Set a lab registry value and query Event ID 13"},
    [pscustomobject]@{event_id=22;event_name="DNS Query";log_source="Microsoft-Windows-Sysmon/Operational";audit_or_sensor_dependency="Sysmon Event 22 enabled";security_meaning="A process requested a DNS name";normal_frequency="Very High";triage_priority="Medium";crimson_tide_phase="Phase 4 - Command and Control";example_suspicious_pattern="Unexpected process resolves a newly seen domain";validation_method="Resolve-DnsName example.com and query Event ID 22"}
)

$events | ConvertTo-Json -Depth 4 | Set-Content $OutputFile -Encoding UTF8

$securityCount = @($events | Where-Object log_source -eq "Security").Count
$powerShellCount = @($events | Where-Object log_source -like "*PowerShell*").Count
$sysmonCount = @($events | Where-Object log_source -like "*Sysmon*").Count

Write-Host "Security events mapped: $securityCount"
Write-Host "PowerShell events mapped: $powerShellCount"
Write-Host "Sysmon events mapped: $sysmonCount"
Write-Host "Total events documented: $($events.Count)"
Write-Host "Reference saved to: $OutputFile"
