<#
Script Name: 5-audit_policy.ps1
Purpose: Configure Advanced Audit Policy and Security log settings.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - Advanced Audit Policy"
$domain = Get-ADDomain
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

Write-Host "[*] Creating GPO: `"$gpoName`"..." -NoNewline
if (-not $gpo) { $gpo = New-GPO $gpoName; Write-Host " CREATED" }
else { Write-Host " EXISTS" }

$settings = @(
    @{Name="Credential Validation"; Success="enable"; Failure="enable"},
    @{Name="Kerberos Authentication Service"; Success="enable"; Failure="enable"},
    @{Name="Logon"; Success="enable"; Failure="enable"},
    @{Name="Logoff"; Success="enable"; Failure="disable"},
    @{Name="Special Logon"; Success="enable"; Failure="disable"},
    @{Name="User Account Management"; Success="enable"; Failure="enable"},
    @{Name="Sensitive Privilege Use"; Success="enable"; Failure="enable"},
    @{Name="File System"; Success="enable"; Failure="enable"},
    @{Name="Registry"; Success="enable"; Failure="enable"},
    @{Name="Process Creation"; Success="enable"; Failure="disable"}
)

Write-Host "[*] Configuring Audit Categories..."
foreach ($item in $settings) {
    auditpol.exe /set /subcategory:"$($item.Name)" `
        /success:$($item.Success) /failure:$($item.Failure) | Out-Null
    $mode = if ($item.Failure -eq "enable") { "Success, Failure" } else { "Success" }
    Write-Host ("    {0,-28} {1,-18} [SET]" -f ($item.Name + ":"), $mode)
}

Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 | Out-Null
Write-Host "[*] Enabling CommandLine in process creation events (Event ID 4688)... [SET]"

# Only administrators can Clear the Security log by default. Reinforce log access.
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
    -ValueName "CustomSD" -Type String `
    -Value "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)" | Out-Null
Write-Host "[*] Restricting Security log clearing...                  [SET]"

Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "MaxSize" -Type DWord -Value 1073741824 | Out-Null
wevtutil.exe sl Security /ms:1073741824
Write-Host "[*] Setting Security log max size to 1 GB...              [SET]"

if (-not (Get-GPInheritance $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
gpupdate.exe /force | Out-Null
Write-Host "[*] Linking GPO and forcing update... COMPLETE"

auditpol.exe /get /category:*
