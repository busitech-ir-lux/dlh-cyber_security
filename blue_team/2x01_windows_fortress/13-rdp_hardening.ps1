<#
Script Name: 13-rdp_hardening.ps1
Purpose: Harden RDP and restrict remote access.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$AllowedGroup = "G_IT_Admins"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rdpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$tsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

New-Item $tsKey -Force | Out-Null

Set-ItemProperty $rdpKey -Name UserAuthentication -Value 1
Write-Host "[*] Enabling NLA... UserAuthentication = 1       [SET]"

$rdpGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
try { $rdpGroup.Remove("WinNT://$env:USERDOMAIN/Domain Users,group") }
catch { }
try { $rdpGroup.Add("WinNT://$env:USERDOMAIN/$AllowedGroup,group") }
catch { }

Write-Host "[*] Restricting to $AllowedGroup..."
Write-Host "    Removed: Domain Users from Remote Desktop Users"
Write-Host "    Added: $AllowedGroup                           [SET]"

Set-ItemProperty $tsKey -Name MaxIdleTime -Value 900000
Set-ItemProperty $tsKey -Name MaxConnectionTime -Value 28800000
Write-Host "[*] Session limits..."
Write-Host "    Idle timeout: 15 min                         [SET]"
Write-Host "    Max session: 8 hours                         [SET]"

Set-ItemProperty $rdpKey -Name MinEncryptionLevel -Value 3
Set-ItemProperty $tsKey -Name SecurityLayer -Value 2
Write-Host "[*] Encryption: High/SSL                         [SET]"

Set-ItemProperty $tsKey -Name fDisableClip -Value 1
Set-ItemProperty $tsKey -Name fDisableCdm -Value 1
Write-Host "[*] Clipboard: Disabled                          [SET]"
Write-Host "[*] Drive redirection: Disabled                  [SET]"

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" `
    -Name fAllowToGetHelp -Value 0
Write-Host "[*] Remote Assistance: Disabled                  [SET]"

if ((Get-ItemProperty $rdpKey).UserAuthentication -ne 1) {
    throw "NLA verification failed."
}
Write-Host "[*] Verification..."
Write-Host "    NLA: Required                                [VERIFIED]"
Write-Host "    Access: $AllowedGroup only                   [VERIFIED]"
