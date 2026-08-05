<#
Script Name: 4-password_policy.ps1
Purpose: Configure the MedDefense password and lockout policy.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

# MinimumPasswordLength = 14
# ComplexityEnabled = True
# PasswordHistoryCount = 24
# MaximumPasswordAge = 0
# MinimumPasswordAge = 1 day
# LockoutThreshold = 5
# LockoutDuration = 15 minutes
# LockoutObservationWindow = 15 minutes

$gpoName = "MedDefense - Password and Lockout Policy"
$domain = Get-ADDomain
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

Write-Host "[*] Creating GPO: `"$gpoName`"..." -NoNewline
if (-not $gpo) {
    $gpo = New-GPO -Name $gpoName
    Write-Host " CREATED"
}
else {
    Write-Host " EXISTS"
}

Write-Host "[*] Configuring Password Policy..."
Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
    -MinPasswordLength 14 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge ([timespan]::Zero) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15)

Write-Host "    Minimum Length: 14            [SET]"
Write-Host "    Complexity: Enabled           [SET]"
Write-Host "    History: 24                   [SET]"
Write-Host "    Maximum Age: 0                [SET]"
Write-Host "    Minimum Age: 1 day            [SET]"
Write-Host "[*] Configuring Account Lockout..."
Write-Host "    Threshold: 5 attempts         [SET]"
Write-Host "    Duration: 15 minutes          [SET]"
Write-Host "    Reset Counter: 15 minutes     [SET]"

Write-Host "[*] Linking GPO to domain root..." -NoNewline
if (-not (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
Write-Host " LINKED"

Write-Host "[*] Forcing Group Policy update..." -NoNewline
gpupdate.exe /force | Out-Null
Write-Host " COMPLETE"

$verify = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot
# Verify effective password and lockout policy
if ($verify.MinPasswordLength -ne 14 -or
    -not $verify.ComplexityEnabled -or
    $verify.PasswordHistoryCount -ne 24 -or
    $verify.LockoutThreshold -ne 5) {
    throw "Policy verification failed."
}

Write-Host "[*] Effective policy verified."
