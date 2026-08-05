<#
Script Name: 14-service_accounts.ps1
Purpose: Audits all MedDefense service accounts, identifies excessive privileges and security weaknesses, then implements hardening measures that would have prevented the svc_ehr compromise. Excessive group memberships and delegation settings are detected and remediated. Detects suspicious logons like the 03:17 AM activity seen with svc_ehr during the Crimson Tide attack.

Author: Mahdi
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [int]$OldPasswordDays = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$now = Get-Date
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")

$accounts = @(
    Get-ADUser -Filter * -Properties MemberOf, PasswordLastSet, LastLogonDate,
        TrustedForDelegation, UseDESKeyOnly, ServicePrincipalName,
        AccountNotDelegated, DistinguishedName |
    Where-Object {
        $_.SamAccountName -match "(?i)svc" -or
        $_.DistinguishedName -match "(?i)OU=Service Accounts" -or
        @($_.ServicePrincipalName).Count -gt 0
    }
)

foreach ($account in $accounts) {
    $groups = @(
        $account.MemberOf | ForEach-Object {
            (Get-ADGroup $_).Name
        }
    )
    $age = if ($account.PasswordLastSet) {
        [math]::Floor(($now - $account.PasswordLastSet).TotalDays)
    }
    else { -1 }

    Write-Host "$($account.SamAccountName):"
    if ($groups | Where-Object { $_ -in $privilegedGroups }) { Write-Host "  excessive privileges: privileged group membership [!]" }
    if ($age -gt $OldPasswordDays) { Write-Host "  old passwords: password age exceeds threshold [!]" }
    if ($account.TrustedForDelegation) { Write-Host "  unconstrained delegation: enabled [!]" }
    if ($account.LastLogonDate -and $account.LastLogonDate.Hour -lt 5) { Write-Host "  suspicious logons: off-hours last logon [!!!]" }
    Write-Host "  Groups: $($groups -join ', ')"
    Write-Host "  Password age: $age days $(if($age -gt $OldPasswordDays){'[!]'}else{'[OK]'})"
    Write-Host "  Delegation: $(if($account.TrustedForDelegation){'Unconstrained [!]'}else{'Restricted'})"
    Write-Host "  UseDESKeyOnly: $($account.UseDESKeyOnly)"
    Write-Host "  SPNs: $(@($account.ServicePrincipalName) -join ', ')"
    Write-Host "  Last logon: $($account.LastLogonDate)"

    Set-ADAccountControl -Identity $account `
        -AccountNotDelegated $true ` # Account is sensitive and cannot be delegated
        -TrustedForDelegation $false `
        -UseDESKeyOnly $false

    foreach ($groupName in $privilegedGroups) {
        if ($groups -contains $groupName) {
            Remove-ADGroupMember -Identity $groupName -Members $account `
                -Confirm:$false
            Write-Host "  Removed from: $groupName [DONE]"
        }
    }
}

# Apply local deny rights to the service-account group.
$serviceGroup = Get-ADGroup "Service Accounts" -ErrorAction SilentlyContinue
if ($serviceGroup) {
    $sid = $serviceGroup.SID.Value
    $cfg = "$env:TEMP\secpol.cfg"
    secedit.exe /export /cfg $cfg | Out-Null
    $text = Get-Content $cfg
    $text = $text -replace "^SeDenyInteractiveLogonRight.*", "SeDenyInteractiveLogonRight = *$sid"
    $text = $text -replace "^SeDenyRemoteInteractiveLogonRight.*", "SeDenyRemoteInteractiveLogonRight = *$sid"
    $text | Set-Content $cfg -Encoding Unicode
    secedit.exe /configure /db "$env:TEMP\service_accounts.sdb" /cfg $cfg /areas USER_RIGHTS | Out-Null
    Write-Host "Deny interactive logon and RDP logon rights: [SET]"
}

Write-Host "Service accounts processed: $($accounts.Count)"
