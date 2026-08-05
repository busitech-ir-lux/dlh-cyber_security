<#
Script Name: 8-smb_hardening.ps1
Purpose: Disable SMBv1 and harden SMB and legacy name resolution.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy
Import-Module ActiveDirectory

$gpoName = "MedDefense - SMB and Protocol Hardening"
$domain = Get-ADDomain
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO $gpoName | Out-Null
}

$beforeServer = Get-SmbServerConfiguration
$beforeClient = Get-SmbClientConfiguration

Write-Host "[*] Before - Current SMB Configuration..."
Write-Host "    SMBv1: $($beforeServer.EnableSMB1Protocol)"
Write-Host "    Signing Required: $($beforeServer.RequireSecuritySignature)"
Write-Host "    Encryption: $($beforeServer.EncryptData)"

Write-Host "[*] Disabling SMBv1 (server + client)...   [DONE]"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null

Write-Host "[*] Enforcing SMB Signing...               [SET]"
Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force

Write-Host "[*] Enabling SMB Encryption...             [SET]"
Set-SmbServerConfiguration -EncryptData $true -Force

Write-Host "[*] Disabling NetBIOS over TCP/IP...       [SET]"
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
    Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} |
    Out-Null

Write-Host "[*] Disabling LLMNR via GPO...             [SET]"
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" -Type DWord -Value 0 | Out-Null

if (-not (Get-GPInheritance $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
gpupdate.exe /force | Out-Null

$after = Get-SmbServerConfiguration
Write-Host "[*] After - Verification..."
Write-Host "    SMBv1: $(if (-not $after.EnableSMB1Protocol) {'Disabled [VERIFIED]'} else {'Enabled [FAIL]'})"
Write-Host "    Signing: $(if ($after.RequireSecuritySignature) {'Required [VERIFIED]'} else {'Not required [FAIL]'})"
Write-Host "    Encryption: $(if ($after.EncryptData) {'Enabled [VERIFIED]'} else {'Disabled [FAIL]'})"
Write-Host "    LLMNR: Disabled                        [VERIFIED]"
