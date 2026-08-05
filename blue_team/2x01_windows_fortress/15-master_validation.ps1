<#
Script Name: 15-master_validation.ps1
Purpose: Validate the MedDefense hardened Windows state.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "$PSScriptRoot\validation_results.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Section, [string]$Check, [string]$Status, [string]$Value, [bool]$Critical) {
    $results.Add([pscustomobject]@{
        section=$Section; check=$Check; status=$Status; value=$Value; critical=$Critical
    })
    Write-Host "[$Status] $Check`: $Value"
}

$policy = Get-ADDefaultDomainPasswordPolicy
Write-Host "--- Password & Lockout ---"
Add-Result "Password & Lockout" "Minimum length" `
    $(if($policy.MinPasswordLength -ge 14){"PASS"}else{"FAIL"}) `
    "$($policy.MinPasswordLength)" $true
Add-Result "Password & Lockout" "Lockout threshold" `
    $(if($policy.LockoutThreshold -eq 5){"PASS"}else{"FAIL"}) `
    "$($policy.LockoutThreshold)" $true

Write-Host "`n--- Audit Policy ---"
$audit = (& auditpol.exe /get /subcategory:"Process Creation" /r) -join "`n"
Add-Result "Audit Policy" "Process Creation" `
    $(if($audit -match "Success"){"PASS"}else{"FAIL"}) `
    $(if($audit -match "Success"){"Success"}else{"Not enabled"}) $true

$cmdLine = (Get-ItemProperty `
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Add-Result "Audit Policy" "Command-line logging" `
    $(if($cmdLine -eq 1){"PASS"}else{"FAIL"}) `
    $(if($cmdLine -eq 1){"Enabled"}else{"Disabled"}) $true

$securityLog = Get-WinEvent -ListLog Security
Add-Result "Audit Policy" "Security log" `
    $(if($securityLog.MaximumSizeInBytes -ge 1073741824){"PASS"}else{"WARN"}) `
    "$([math]::Round($securityLog.MaximumSizeInBytes / 1GB, 2)) GB" $false

Write-Host "`n--- PowerShell ---"
$psBase = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
$sbl = (Get-ItemProperty "$psBase\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$trans = (Get-ItemProperty "$psBase\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
Add-Result "PowerShell" "Script Block Logging" $(if($sbl -eq 1){"PASS"}else{"FAIL"}) $(if($sbl -eq 1){"Enabled"}else{"Disabled"}) $true
Add-Result "PowerShell" "Transcription" $(if($trans -eq 1){"PASS"}else{"WARN"}) $(if($trans -eq 1){"Enabled"}else{"Disabled"}) $false

Write-Host "`n--- Sysmon ---"
$sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
$sysmonStatus = if($sysmon){[string]$sysmon.Status}else{"Not installed"}
Add-Result "Sysmon" "Service" $(if($sysmonStatus -eq "Running"){"PASS"}else{"FAIL"}) $sysmonStatus $true
$configPath = "$PSScriptRoot\sysmonconfig_tuned.xml"
$ruleCount = if(Test-Path $configPath) {
    ([regex]::Matches((Get-Content $configPath -Raw), "MedDefense-")).Count
} else { 0 }
Add-Result "Sysmon" "Custom rules" $(if($ruleCount -ge 5){"PASS"}else{"WARN"}) "$ruleCount present" $false

Write-Host "`n--- Kerberos ---"
$desAccounts = @(Get-ADUser -Filter {UseDESKeyOnly -eq $true})
Add-Result "Kerberos" "DES" $(if(-not $desAccounts.Count){"PASS"}else{"FAIL"}) $(if(-not $desAccounts.Count){"Disabled"}else{"Enabled"}) $true
$kerb = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ErrorAction SilentlyContinue).SupportedEncryptionTypes
Add-Result "Kerberos" "RC4" $(if($kerb -eq 24){"PASS"}else{"FAIL"}) $(if($kerb -eq 24){"Disabled"}else{"Enabled or unknown"}) $true

Write-Host "`n--- SMB ---"
$smb = Get-SmbServerConfiguration
Add-Result "SMB" "SMBv1" $(if(-not $smb.EnableSMB1Protocol){"PASS"}else{"FAIL"}) $(if(-not $smb.EnableSMB1Protocol){"Disabled"}else{"Enabled"}) $true
Add-Result "SMB" "Signing" $(if($smb.RequireSecuritySignature){"PASS"}else{"FAIL"}) $(if($smb.RequireSecuritySignature){"Required"}else{"Not required"}) $true

Write-Host "`n--- Firewall ---"
$profiles = Get-NetFirewallProfile
$firewallPass = -not @($profiles | Where-Object {
    -not $_.Enabled -or $_.DefaultInboundAction -ne "Block"
}).Count
Add-Result "Firewall" "All profiles" $(if($firewallPass){"PASS"}else{"FAIL"}) $(if($firewallPass){"ON, DefaultInbound: Block"}else{"Non-compliant"}) $true

Write-Host "`n--- RDP ---"
$nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
Add-Result "RDP" "NLA" $(if($nla -eq 1){"PASS"}else{"FAIL"}) $(if($nla -eq 1){"Required"}else{"Not required"}) $true
$rdpMembers = @(Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue)
$onlyAdmins = @($rdpMembers | Where-Object Name -notmatch "G_IT_Admins").Count -eq 0
Add-Result "RDP" "G_IT_Admins only" $(if($onlyAdmins){"PASS"}else{"FAIL"}) "$($rdpMembers.Name -join ', ')" $true

Write-Host "`n--- Service Accounts ---"
$svc = @(Get-ADUser -Filter * -Properties AccountNotDelegated, PasswordLastSet |
    Where-Object SamAccountName -match "(?i)svc")
$restricted = @($svc | Where-Object AccountNotDelegated).Count
Add-Result "Service Accounts" "Delegation restricted" $(if($restricted -eq $svc.Count){"PASS"}else{"FAIL"}) "$restricted/$($svc.Count)" $true
foreach($account in $svc) {
    $age = if($account.PasswordLastSet){[math]::Floor(((Get-Date)-$account.PasswordLastSet).TotalDays)}else{-1}
    if($age -gt 180) { Add-Result "Service Accounts" "$($account.SamAccountName) password age" "WARN" "$age days" $false }
}

$results | ConvertTo-Json -Depth 4 | Set-Content $OutputFile -Encoding UTF8
$criticalFails = @($results | Where-Object {$_.critical -and $_.status -eq "FAIL"}).Count
if($criticalFails -gt 0) { exit 1 }
exit 0
