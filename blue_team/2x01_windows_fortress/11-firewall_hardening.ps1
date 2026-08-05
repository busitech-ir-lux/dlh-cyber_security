<#
Script Name: 11-firewall_hardening.ps1
Purpose: Enable default-deny Windows Firewall and approved inbound rules.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$ManagementSubnet = "10.10.3.0/24",
    [string]$ServerSubnet = "10.10.1.0/24"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$profiles = Get-NetFirewallProfile
Write-Host "[*] Current Firewall State..."
$profiles | ForEach-Object {
    Write-Host "    $($_.Name): Enabled=$($_.Enabled), DefaultInbound=$($_.DefaultInboundAction)"
}

Set-NetFirewallProfile -Profile Domain,Private,Public `
    -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True
Write-Host "[*] Setting default-deny on all profiles... [SET]"

Get-NetFirewallRule -DisplayName "MedDef-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "MedDef-RDP-Mgmt" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -RemoteAddress $ManagementSubnet -Action Allow
New-NetFirewallRule -DisplayName "MedDef-DNS-TCP" -Direction Inbound `
    -Protocol TCP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "MedDef-DNS-UDP" -Direction Inbound `
    -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "MedDef-LDAP" -Direction Inbound `
    -Protocol TCP -LocalPort 389 -Action Allow
New-NetFirewallRule -DisplayName "MedDef-Kerberos-TCP" -Direction Inbound `
    -Protocol TCP -LocalPort 88 -Action Allow
New-NetFirewallRule -DisplayName "MedDef-Kerberos-UDP" -Direction Inbound `
    -Protocol UDP -LocalPort 88 -Action Allow
New-NetFirewallRule -DisplayName "MedDef-SMB-ServerSubnet" -Direction Inbound `
    -Protocol TCP -LocalPort 445 -RemoteAddress $ServerSubnet -Action Allow
New-NetFirewallRule -DisplayName "MedDef-WinRM-Mgmt" -Direction Inbound `
    -Protocol TCP -LocalPort 5985,5986 -RemoteAddress $ManagementSubnet -Action Allow

Write-Host "[*] Creating allow rules..."
Write-Host "    MedDef-RDP-Mgmt: TCP 3389 from $ManagementSubnet [CREATED]"
Write-Host "    MedDef-DNS: TCP/UDP 53 [CREATED]"
Write-Host "    MedDef-LDAP: TCP 389 [CREATED]"
Write-Host "    MedDef-Kerberos: TCP/UDP 88 [CREATED]"
Write-Host "    MedDef-SMB: TCP 445 from $ServerSubnet [CREATED]"
Write-Host "    MedDef-WinRM: TCP 5985-5986 from $ManagementSubnet [CREATED]"

$legacy = @(
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    Where-Object {
        $_.DisplayName -notlike "MedDef-*" -and
        $_.DisplayGroup -match "(?i)File and Printer Sharing|Remote Desktop|Windows Remote Management"
    }
)
$legacy | Disable-NetFirewallRule
Write-Host "[*] Enabling dropped packet logging...     [SET]"
Write-Host "[*] Disabling $($legacy.Count) legacy allow rules... [DONE]"

$verifyProfiles = Get-NetFirewallProfile
$custom = @(Get-NetFirewallRule -DisplayName "MedDef-*" -Enabled True)
if (@($verifyProfiles | Where-Object {
    -not $_.Enabled -or $_.DefaultInboundAction -ne "Block"
}).Count -gt 0) {
    throw "Firewall verification failed."
}
Write-Host "[*] Verification..."
Write-Host "    All 3 profiles: ON, DefaultInbound: Block  [VERIFIED]"
Write-Host "    Custom rules: $($custom.Count) active       [VERIFIED]"
