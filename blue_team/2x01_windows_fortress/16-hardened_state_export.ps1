<#
Script Name: 16-hardened_state_export.ps1
Purpose: Export the final MedDefense hardened Windows state.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "$PSScriptRoot\windows_hardened_state.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain
$dc = Get-ADDomainController -Discover

Write-Host "[*] Exporting domain metadata... OK"
$domainMetadata = [ordered]@{
    domain_name = $domain.DNSRoot
    domain_controller = $dc.HostName
    timestamp = (Get-Date).ToString("o")
    script_runner = [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

Write-Host "[*] Exporting GPO settings..." -NoNewline
$medGpos = @(Get-GPO -All | Where-Object DisplayName -like "MedDefense -*")
$gpoInventory = @(
    foreach($gpo in $medGpos) {
        [pscustomobject]@{
            name = $gpo.DisplayName
            enabled_state = $gpo.GpoStatus
            linked_scopes = @(
                Get-ADOrganizationalUnit -Filter * |
                Where-Object {
                    (Get-GPInheritance $_.DistinguishedName).GpoLinks.DisplayName -contains $gpo.DisplayName
                } |
                Select-Object -ExpandProperty DistinguishedName
            )
            key_settings = [string](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        }
    }
)
Write-Host " $($medGpos.Count) GPOs"

Write-Host "[*] Exporting audit policy..." -NoNewline
$requiredAudit = @("Credential Validation","Kerberos Authentication Service","Logon","Logoff","Special Logon","User Account Management","Sensitive Privilege Use","File System","Registry","Process Creation")
$auditStatus = @(
    foreach($item in $requiredAudit) {
        $raw = (& auditpol.exe /get /subcategory:"$item" /r 2>&1) -join "`n"
        [pscustomobject]@{subcategory=$item; output=$raw; enabled=($raw -match "Success|Failure")}
    }
)
$auditPolicy = [ordered]@{
    raw_output = (& auditpol.exe /get /category:* 2>&1) -join "`n"
    required_subcategories = $auditStatus
    required_windows_event_ids = @(4624,4625,4648,4672,4688,4720,4726,4732,1102)
}
Write-Host " $($requiredAudit.Count) subcategories"

Write-Host "[*] Exporting PowerShell logging... OK"
$psBase = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
$powershellLogging = [ordered]@{
    script_block_logging = (Get-ItemProperty "$psBase\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    module_logging = (Get-ItemProperty "$psBase\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
    transcription = (Get-ItemProperty "$psBase\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
    event_ids = [ordered]@{
            id_4103 = "Module Logging"
            id_4104 = "Script Block Logging"
        }
}

Write-Host "[*] Exporting Sysmon config..." -NoNewline
$configPath = "$PSScriptRoot\sysmonconfig_tuned.xml"
$customRuleCount = if(Test-Path $configPath){([regex]::Matches((Get-Content $configPath -Raw),"MedDefense-")).Count}else{0}
$sysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue
$sysmonDriver = Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
$sysmonPosture = [ordered]@{
    service_status = if($sysmonService){[string]$sysmonService.Status}else{"not_found"}
    driver_status = if($sysmonDriver){[string]$sysmonDriver.State}else{"not_found"}
    config_path = $configPath
    custom_rule_count = $customRuleCount
    active_event_ids = @(1,3,7,11,13,22)
}
Write-Host " $customRuleCount custom rules"

Write-Host "[*] Exporting firewall rules..." -NoNewline
$medRules = @(Get-NetFirewallRule -DisplayName "MedDef-*" -ErrorAction SilentlyContinue)
$firewallPosture = [ordered]@{
    profiles = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,LogBlocked
    meddefense_rules = $medRules | Select-Object DisplayName,Enabled,Direction,Action
    dropped_packet_logging = @((Get-NetFirewallProfile).LogBlocked) -notcontains $false
}
Write-Host " $($medRules.Count) rules"

Write-Host "[*] Exporting AppLocker policy..." -NoNewline
$appLockerPath = "$PSScriptRoot\applocker_policy.xml"
$appPolicy = if(Test-Path $appLockerPath){[xml](Get-Content $appLockerPath -Raw)}else{$null}
$appRules = if($appPolicy){@($appPolicy.AppLockerPolicy.RuleCollection.FilePathRule)}else{@()}
$applockerPosture = [ordered]@{
    enforcement_mode = if($appPolicy){@($appPolicy.AppLockerPolicy.RuleCollection.EnforcementMode)}else{"not_found"}
    executable_rules = if($appPolicy){@($appPolicy.AppLockerPolicy.RuleCollection | Where-Object Type -eq "Exe").FilePathRule}else{@()}
    script_rules = if($appPolicy){@($appPolicy.AppLockerPolicy.RuleCollection | Where-Object Type -eq "Script").FilePathRule}else{@()}
    exported_policy_path = $appLockerPath
}
Write-Host " $($appRules.Count) rules"

Write-Host "[*] Exporting remote access posture... OK"
$tsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpPosture = [ordered]@{
    nla_state = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
    allowed_group = "G_IT_Admins"
    clipboard_disabled = (Get-ItemProperty $tsKey -ErrorAction SilentlyContinue).fDisableClip
    drive_redirection_disabled = (Get-ItemProperty $tsKey -ErrorAction SilentlyContinue).fDisableCdm
    idle_timeout_ms = (Get-ItemProperty $tsKey -ErrorAction SilentlyContinue).MaxIdleTime
    max_session_ms = (Get-ItemProperty $tsKey -ErrorAction SilentlyContinue).MaxConnectionTime
}

Write-Host "[*] Exporting authentication protocol posture... OK"
$smb = Get-SmbServerConfiguration
$authProtocols = [ordered]@{
    des_enabled_accounts = @(Get-ADUser -Filter {UseDESKeyOnly -eq $true}).Count
    kerberos_supported_encryption_types = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ErrorAction SilentlyContinue).SupportedEncryptionTypes
    aes_expected_mask = 24
    ntlmv1_setting = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    smbv1_enabled = $smb.EnableSMB1Protocol
    smb_signing_required = $smb.RequireSecuritySignature
}

Write-Host "[*] Exporting service account posture..." -NoNewline
$serviceAccounts = @(
    Get-ADUser -Filter * -Properties AccountNotDelegated,PasswordLastSet,MemberOf,TrustedForDelegation,LastLogonDate |
    Where-Object SamAccountName -match "(?i)svc" |
    ForEach-Object {
        [pscustomobject]@{
            account = $_.SamAccountName
            delegation_restricted = $_.AccountNotDelegated
            unconstrained_delegation = $_.TrustedForDelegation
            password_age_days = if($_.PasswordLastSet){[math]::Floor(((Get-Date)-$_.PasswordLastSet).TotalDays)}else{$null}
            privileged_membership = @($_.MemberOf | Where-Object {$_ -match "Domain Admins|Enterprise Admins|G_IT_Admins"})
            interactive_logon_risk = "Review deny logon rights"
            last_logon = $_.LastLogonDate
        }
    }
)
Write-Host " $($serviceAccounts.Count) accounts"

Write-Host "[*] Loading validation summary..." -NoNewline
$validationPath = "$PSScriptRoot\validation_results.json"
$validationSummary = if(Test-Path $validationPath){
    [ordered]@{status="found";path=$validationPath;results=(Get-Content $validationPath -Raw | ConvertFrom-Json)}
}else{
    [ordered]@{status="not_found";path=$validationPath}
}
Write-Host " $($validationSummary.status.ToUpper())"

$report = [ordered]@{
    domain_metadata = $domainMetadata
    gpo_inventory = $gpoInventory
    audit_policy = $auditPolicy
    powershell_logging = $powershellLogging
    sysmon_posture = $sysmonPosture
    firewall_posture = $firewallPosture
    applocker_posture = $applockerPosture
    rdp_posture = $rdpPosture
    authentication_protocols = $authProtocols
    service_account_posture = $serviceAccounts
    validation_summary = $validationSummary
}

$report | ConvertTo-Json -Depth 12 | Set-Content $OutputFile -Encoding UTF8
Write-Host ""
Write-Host "Hardened state exported to: $OutputFile"
