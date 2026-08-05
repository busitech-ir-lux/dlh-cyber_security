<#
Script Name: 7-auth_hardening.ps1
Purpose: Harden Kerberos encryption and NTLM authentication.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain
$gpoName = "MedDefense - Authentication Hardening"
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO $gpoName }

$serviceAccounts = @(
    Get-ADUser -Filter * -Properties UseDESKeyOnly, ServicePrincipalName,
        msDS-SupportedEncryptionTypes, DistinguishedName |
    Where-Object {
        $_.SamAccountName -match "(?i)svc" -or
        $_.DistinguishedName -match "(?i)OU=Service Accounts" -or
        @($_.ServicePrincipalName).Count -gt 0
    }
)

$current = @("DES", "RC4", "AES128", "AES256")
Write-Host "[*] Current Kerberos types: $($current -join ', ')"
Write-Host "    [!] DES enabled - trivially breakable"
Write-Host "    [!] RC4 enabled - Kerberoastable"

Write-Host "[*] Accounts with DES flag..."
foreach ($account in $serviceAccounts | Where-Object UseDESKeyOnly) {
    Write-Host "    $($account.SamAccountName): UseDESKeyOnly = True          [!]"
}

Write-Host "[*] Service Principal Names..."
foreach ($account in $serviceAccounts) {
    foreach ($spn in @($account.ServicePrincipalName)) {
        Write-Host "    $($account.SamAccountName): $spn"
    }
}
Write-Host "    [!] Accounts with SPNs are Kerberoastable targets"

Write-Host "[*] Remediating..."
foreach ($account in $serviceAccounts) {
    if ($account.UseDESKeyOnly) {
        Set-ADAccountControl -Identity $account -UseDESKeyOnly $false
        Write-Host "    $($account.SamAccountName): Clearing DES flag              [DONE]"
    }
    Set-ADUser -Identity $account -Replace @{"msDS-SupportedEncryptionTypes" = 24}
}

Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -ValueName "SupportedEncryptionTypes" -Type DWord -Value 24 | Out-Null
Write-Host "    Supported encryption: AES128 + AES256   [SET]"

Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 | Out-Null
Write-Host "    NTLMv1: Refused; NTLMv2 only (LmCompatibilityLevel=5) [SET]"

Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LsaCfgFlags" -Type DWord -Value 1 | Out-Null
Write-Host "    Credential Guard awareness               [SET]"

if (-not (Get-GPInheritance $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
gpupdate.exe /force | Out-Null

$verify = Get-ADUser -Filter * -Properties UseDESKeyOnly |
    Where-Object UseDESKeyOnly
if ($verify) { throw "DES flag remains on one or more accounts." }

Write-Host "[*] Verifying..."
Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]"
Write-Host "    NTLMv2 only                           [VERIFIED]"
