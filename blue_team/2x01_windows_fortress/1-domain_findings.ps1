<#
Script Name: 1-domain_findings.ps1
Purpose: Extract actionable security findings from meddefense.local.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$DomainName = "meddefense.local",
    [string]$OutputFile = "$PSScriptRoot\domain_security_findings.json",
    [int]$StaleComputerDays = 90,
    [int]$StaleServicePasswordDays = 365
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$findings = [System.Collections.Generic.List[object]]::new()
$script:findingNumber = 0

function Add-Finding {
    param(
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW")][string]$Severity,
        [string]$Category, [string]$Asset, [object]$Evidence,
        [string]$Risk, [string]$Remediation, [string]$MappedTask
    )

    $script:findingNumber++
    $findings.Add([pscustomobject][ordered]@{
        id = "MD-AD-{0:D3}" -f $script:findingNumber
        severity = $Severity
        category = $Category
        asset = $Asset
        evidence = $Evidence
        risk = $Risk
        recommended_remediation = $Remediation
        mapped_task = $MappedTask
    })
}

function Get-GroupNames([object]$Account) {
    try {
        @(Get-ADPrincipalGroupMembership $Account |
            Select-Object -ExpandProperty Name | Sort-Object)
    }
    catch { @("GROUP QUERY FAILED") }
}

function Get-PrivilegedUsers([string]$GroupName, [string]$Server) {
    try {
        @(Get-ADGroupMember $GroupName -Recursive -Server $Server |
            Where-Object ObjectClass -eq "user" |
            ForEach-Object {
                Get-ADUser $_ -Server $Server `
                    -Properties Enabled, PasswordLastSet, LastLogonDate
            })
    }
    catch { @() }
}

function Get-KerberosTypes([int]$Mask) {
    $types = @()
    if ($Mask -band 0x03) { $types += "DES" }
    if ($Mask -band 0x04) { $types += "RC4" }
    if ($Mask -band 0x08) { $types += "AES128" }
    if ($Mask -band 0x10) { $types += "AES256" }
    if (-not $types) { $types = @("NOT EXPLICITLY SET") }
    $types
}

Write-Host "Auditing $DomainName..."

$domain = Get-ADDomain $DomainName
$forest = Get-ADForest
$server = $domain.PDCEmulator
$now = Get-Date
$computerCutoff = $now.AddDays(-$StaleComputerDays)
$passwordCutoff = $now.AddDays(-$StaleServicePasswordDays)
$serviceLogonCutoff = $now.AddDays(-90)

$userProperties = @(
    "Enabled", "PasswordNeverExpires", "PasswordLastSet", "LastLogonDate",
    "TrustedForDelegation", "UseDESKeyOnly", "ServicePrincipalName",
    "DistinguishedName"
)

$users = @(Get-ADUser -Filter * -Server $server -Properties $userProperties)

# PasswordNeverExpires accounts
$neverExpires = @(
    $users | Where-Object PasswordNeverExpires | Sort-Object SamAccountName |
    ForEach-Object {
        [pscustomobject]@{
            account_name = $_.SamAccountName
            enabled = [bool]$_.Enabled
            group_memberships = @(Get-GroupNames $_)
            password_last_set = $_.PasswordLastSet
            service_account = (
                $_.SamAccountName -match "(?i)svc" -or
                $_.DistinguishedName -match "(?i)OU=Service Accounts" -or
                @($_.ServicePrincipalName).Count -gt 0
            )
        }
    }
)

if ($neverExpires.Count) {
    Add-Finding "HIGH" "Account Security" "$DomainName users" `
        ([pscustomobject]@{
            summary = "$($neverExpires.Count) accounts with PasswordNeverExpires"
            accounts = $neverExpires
        }) `
        "Long-lived credentials remain useful after theft or compromise." `
        "Remove PasswordNeverExpires where possible, use gMSAs for services, and rotate approved exceptions." `
        "Task 5 - Service Account Control"
}

# Disabled accounts in privileged groups
$privilegedGroups = @(
    @{ Name = "Domain Admins"; Server = $server },
    @{ Name = "Enterprise Admins"; Server = $forest.RootDomain },
    @{ Name = "G_IT_Admins"; Server = $server }
)

$disabledPrivileged = @(
    foreach ($item in $privilegedGroups) {
        foreach ($user in @(Get-PrivilegedUsers $item.Name $item.Server)) {
            if (-not $user.Enabled) {
                [pscustomobject]@{
                    account_name = $user.SamAccountName
                    privileged_group = $item.Name
                    enabled = $false
                    password_last_set = $user.PasswordLastSet
                    last_logon = $user.LastLogonDate
                }
            }
        }
    }
)

if ($disabledPrivileged.Count) {
    Add-Finding "HIGH" "Privileged Access" "Privileged groups" `
        ([pscustomobject]@{
            summary = "$($disabledPrivileged.Count) disabled privileged memberships"
            accounts = $disabledPrivileged
        }) `
        "Unused privileged membership creates unnecessary attack paths and inaccurate access reviews." `
        "Remove disabled accounts from privileged groups and document approved exceptions." `
        "Task 6 - Privileged Group and Stale Object Cleanup"
}

# Stale computer objects
$staleComputers = @(
    Get-ADComputer -Filter * -Server $server `
        -Properties Enabled, LastLogonDate, PasswordLastSet,
        OperatingSystem, WhenCreated |
    Where-Object {
        ($_.LastLogonDate -and $_.LastLogonDate -lt $computerCutoff) -or
        (-not $_.LastLogonDate -and $_.WhenCreated -lt $computerCutoff)
    } |
    Select-Object Name, Enabled, OperatingSystem, LastLogonDate,
        PasswordLastSet, WhenCreated, DistinguishedName
)

if ($staleComputers.Count) {
    Add-Finding "MEDIUM" "Stale Objects" "$DomainName computers" `
        ([pscustomobject]@{
            summary = "Stale computer objects: $($staleComputers.Count)"
            threshold_days = $StaleComputerDays
            computers = $staleComputers
        }) `
        "Unused computer accounts may retain trust, permissions, certificates, and group membership." `
        "Confirm ownership, disable stale objects, monitor, and delete them after the retention period." `
        "Task 6 - Privileged Group and Stale Object Cleanup"
}

# Password and account-lockout policy
$policy = Get-ADDefaultDomainPasswordPolicy $DomainName

if ($policy.MinPasswordLength -lt 14) {
    Add-Finding "CRITICAL" "Password Policy" $DomainName `
        ([pscustomobject]@{
            summary = "Password policy minimum length: $($policy.MinPasswordLength)"
            current = $policy.MinPasswordLength; target = 14
        }) `
        "Short passwords are easier to guess, spray, and crack." `
        "Set the domain minimum password length to at least 14 and require MFA for privileged access." `
        "Task 2 - Password and Lockout Hardening"
}

if (-not $policy.ComplexityEnabled) {
    Add-Finding "HIGH" "Password Policy" $DomainName `
        ([pscustomobject]@{
            summary = "Password complexity: disabled"
            current = $false; target = $true
        }) `
        "Predictable passwords are easier to guess and reuse." `
        "Enable complexity and combine it with long passwords and blocked-password screening." `
        "Task 2 - Password and Lockout Hardening"
}

if ($policy.PasswordHistoryCount -lt 24) {
    Add-Finding "HIGH" "Password Policy" $DomainName `
        ([pscustomobject]@{
            summary = "Password history: $($policy.PasswordHistoryCount)"
            current = $policy.PasswordHistoryCount; target = 24
        }) `
        "A short history allows quick reuse of previous passwords." `
        "Set password history to 24 remembered passwords." `
        "Task 2 - Password and Lockout Hardening"
}

if ($policy.LockoutThreshold -eq 0 -or $policy.LockoutThreshold -gt 5) {
    $lockoutText = if ($policy.LockoutThreshold -eq 0) {
        "Account lockout: not configured"
    }
    else { "Account lockout threshold: $($policy.LockoutThreshold)" }

    Add-Finding "CRITICAL" "Account Lockout" $DomainName `
        ([pscustomobject]@{
            summary = $lockoutText
            current = $policy.LockoutThreshold; target = 5
        }) `
        "Attackers can repeatedly guess passwords with limited resistance." `
        "Set the threshold to 5 and configure tested duration and reset-counter values." `
        "Task 2 - Password and Lockout Hardening"
}

# Kerberos posture
$kerberosMask = 0
foreach ($dc in Get-ADDomainController -Filter * -Server $server) {
    $dcAccount = Get-ADComputer $dc.ComputerObjectDN -Server $server `
        -Properties msDS-SupportedEncryptionTypes

    if ($dcAccount.'msDS-SupportedEncryptionTypes') {
        $kerberosMask = $kerberosMask -bor
            [int]$dcAccount.'msDS-SupportedEncryptionTypes'
    }
}

$kerberosTypes = @(Get-KerberosTypes $kerberosMask)

if ($kerberosTypes -contains "DES" -or $kerberosTypes -contains "RC4") {
    Add-Finding "CRITICAL" "Kerberos" "Domain Controllers" `
        ([pscustomobject]@{
            summary = "Kerberos DES/RC4 enabled"
            encryption_types = $kerberosTypes
            raw_mask = $kerberosMask
        }) `
        "Legacy encryption increases exposure to credential cracking and downgrade attacks." `
        "Inventory dependencies, create AES keys, test, and disable DES and RC4." `
        "Task 4 - Kerberos Hardening"
}

# Audit, PowerShell, Sysmon, and GPO posture
$gpos = @(Get-GPO -All -Domain $DomainName -Server $server)
$gpoReports = @(
    foreach ($gpo in $gpos) {
        [string](Get-GPOReport -Guid $gpo.Id -ReportType Xml `
            -Domain $DomainName -Server $server)
    }
)
$gpoText = $gpoReports -join "`n"

$auditChecks = [ordered]@{
    process_creation = $gpoText -match "(?i)Audit Process Creation"
    special_logon = $gpoText -match "(?i)Audit Special Logon"
    account_management = $gpoText -match "(?i)Audit (User|Computer|Security Group) Account Management"
    object_access = $gpoText -match "(?i)Audit (File System|Registry|File Share|Other Object Access Events)"
    powershell_logging = $gpoText -match "(?i)EnableScriptBlockLogging|Script Block Logging"
    sysmon_readiness = (
        $gpoText -match "(?i)Sysmon" -or
        @($gpos | Where-Object DisplayName -match "(?i)Sysmon").Count -gt 0
    )
}

$missingVisibility = @(
    $auditChecks.GetEnumerator() |
    Where-Object { -not $_.Value } |
    Select-Object -ExpandProperty Key
)

if ($missingVisibility.Count) {
    Add-Finding "HIGH" "Audit and Detection" "Domain GPOs" `
        ([pscustomobject]@{
            summary = "Advanced Audit Policy: not fully configured"
            missing_controls = $missingVisibility
            detected_controls = $auditChecks
        }) `
        "Missing telemetry limits detection of processes, privileged logons, account changes, object access, and PowerShell activity." `
        "Deploy Advanced Audit Policy, command-line auditing, Script Block Logging, and a tested Sysmon configuration." `
        "Task 3 - Audit Policy and Endpoint Logging"
}

# Service-account risks
$privilegedNames = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")
$denyInteractive = (
    $gpoText -match "(?i)SeDenyInteractiveLogonRight|Deny log on locally" -and
    $gpoText -match "(?i)SeDenyRemoteInteractiveLogonRight|Deny log on through Remote Desktop"
)

$serviceAccounts = @(
    $users | Where-Object {
        $_.SamAccountName -match "(?i)svc" -or
        $_.DistinguishedName -match "(?i)OU=Service Accounts" -or
        @($_.ServicePrincipalName).Count -gt 0
    }
)

$serviceRisks = @(
    foreach ($account in $serviceAccounts) {
        $groups = @(Get-GroupNames $account)
        $risks = @()

        if (-not $denyInteractive) { $risks += "Interactive/RDP logon not explicitly denied" }
        if ($account.TrustedForDelegation) { $risks += "Unconstrained delegation" }
        if ($account.UseDESKeyOnly) { $risks += "DES-only Kerberos flag" }
        if ($groups | Where-Object { $_ -in $privilegedNames }) {
            $risks += "Privileged membership"
        }
        if (-not $account.PasswordLastSet -or
            $account.PasswordLastSet -lt $passwordCutoff) {
            $risks += "Stale or unknown password"
        }
        if (-not $account.LastLogonDate -or
            $account.LastLogonDate -lt $serviceLogonCutoff) {
            $risks += "Last logon older than 90 days or unknown"
        }

        if ($risks.Count) {
            [pscustomobject]@{
                account_name = $account.SamAccountName
                enabled = [bool]$account.Enabled
                password_last_set = $account.PasswordLastSet
                last_logon = $account.LastLogonDate
                group_memberships = $groups
                risks = $risks
            }
        }
    }
)

if ($serviceRisks.Count) {
    $delegationCount = @(
        $serviceRisks |
        Where-Object { $_.risks -contains "Unconstrained delegation" }
    ).Count

    $summary = if ($delegationCount) {
        "$delegationCount service accounts with unconstrained delegation"
    }
    else { "$($serviceRisks.Count) service accounts with security risks" }

    Add-Finding "HIGH" "Service Accounts" "$DomainName service accounts" `
        ([pscustomobject]@{
            summary = $summary
            accounts_with_risks = $serviceRisks.Count
            accounts = $serviceRisks
        }) `
        "Weak service accounts can enable persistence, Kerberoasting, delegation abuse, and privilege escalation." `
        "Use gMSAs, deny interactive logon, remove privilege, remove DES and unconstrained delegation, and rotate stale credentials." `
        "Task 5 - Service Account Control"
}

# Weak GPO security posture
$defaultGpos = @("Default Domain Policy", "Default Domain Controllers Policy")
$securityPattern = "(?i)MedDefense|Hardening|Security|Audit|Firewall|Sysmon|AppLocker|PowerShell|Defender|Baseline"
$customGpos = @($gpos | Where-Object DisplayName -notin $defaultGpos)
$hardeningGpos = @($gpos | Where-Object DisplayName -match $securityPattern)
$unclearGpos = @(
    $customGpos | Where-Object DisplayName -notmatch $securityPattern |
    Select-Object DisplayName, GpoStatus, Owner, ModificationTime
)

$gpoProblems = @()
if (-not $customGpos.Count) { $gpoProblems += "Default-only GPOs" }
if (-not $hardeningGpos.Count) { $gpoProblems += "No MedDefense hardening GPOs" }
if ($unclearGpos.Count) {
    $gpoProblems += "$($unclearGpos.Count) GPOs without clear security purpose"
}

if ($gpoProblems.Count) {
    Add-Finding "MEDIUM" "Group Policy" "Domain GPO inventory" `
        ([pscustomobject]@{
            summary = "No MedDefense hardening GPOs present"
            problems = $gpoProblems
            total_gpos = $gpos.Count
            hardening_gpos = @($hardeningGpos.DisplayName)
            unclear_gpos = $unclearGpos
        }) `
        "Weak GPO governance prevents consistent enforcement and can hide unsafe or abandoned policies." `
        "Create clearly named security GPOs, assign owners, review permissions and links, and deploy through a pilot OU." `
        "Task 7 - GPO Security Hardening"
}

# JSON report and console summary
$counts = [ordered]@{
    critical = @($findings | Where-Object severity -eq "CRITICAL").Count
    high = @($findings | Where-Object severity -eq "HIGH").Count
    medium = @($findings | Where-Object severity -eq "MEDIUM").Count
    low = @($findings | Where-Object severity -eq "LOW").Count
}

$report = [ordered]@{
    metadata = [ordered]@{
        script = "1-domain_findings.ps1"
        domain = $domain.DNSRoot
        generated_at = (Get-Date).ToString("o")
        stale_computer_days = $StaleComputerDays
        stale_service_password_days = $StaleServicePasswordDays
        note = "Interactive-logon and suspicious-last-logon checks are domain-level heuristics and should be validated with endpoint and event-log data."
    }
    summary = [ordered]@{
        findings = $findings.Count
        critical = $counts.critical
        high = $counts.high
        medium = $counts.medium
        low = $counts.low
    }
    findings = $findings
}

$report | ConvertTo-Json -Depth 10 |
    Set-Content $OutputFile -Encoding UTF8

Write-Host ""
$findings | ForEach-Object {
    Write-Host "[$($_.severity)] $($_.evidence.summary)"
}
Write-Host ""
Write-Host "Findings: $($findings.Count)"
Write-Host "Critical: $($counts.critical)"
Write-Host "High: $($counts.high)"
Write-Host "Medium: $($counts.medium)"
Write-Host "Low: $($counts.low)"
Write-Host "Report saved to: $OutputFile"
