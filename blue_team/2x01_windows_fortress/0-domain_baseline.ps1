<#
.SYNOPSIS
    Script Name: 0-domain_baseline.ps1
    Purpose: Collect a security baseline of the MedDefense Active Directory domain.
    Author: NS
    Date: 2026-08-05

.DESCRIPTION
    Collects domain, forest, domain controller, user, group, service-account,
    Group Policy, password, account-lockout, Kerberos, and privileged-account
    information.

    The script prints a short console summary and writes the complete structured
    report to JSON.

.REQUIREMENTS
    - Run in Windows PowerShell 5.1 or later.
    - Install the ActiveDirectory and GroupPolicy modules (RSAT).
    - Use a domain account with permission to read Active Directory and GPO data.

.OFFICIAL REFERENCES
    - Get-ADDomain / Get-ADForest / Get-ADDomainController
    - Get-ADDefaultDomainPasswordPolicy
    - Get-ADGroupMember
    - Get-GPInheritance
    - msDS-SupportedEncryptionTypes
#>

[CmdletBinding()]
param (
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath "domain_baseline_report.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-OptionalProperty {
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Convert-DateToIso {
    param (
        [AllowNull()]
        [object]$Date
    )

    if ($null -eq $Date) {
        return $null
    }

    return ([datetime]$Date).ToUniversalTime().ToString("o")
}

function Get-KerberosEncryptionTypes {
    param (
        [AllowNull()]
        [object]$Mask
    )

    if ($null -eq $Mask -or [int]$Mask -eq 0) {
        return @("NOT EXPLICITLY SET")
    }

    $value = [int]$Mask
    $types = New-Object System.Collections.Generic.List[string]

    # 0x01 and 0x02 are the two DES variants.
    if (($value -band 0x03) -ne 0) {
        $types.Add("DES")
    }

    if (($value -band 0x04) -ne 0) {
        $types.Add("RC4")
    }

    if (($value -band 0x08) -ne 0) {
        $types.Add("AES128")
    }

    if (($value -band 0x10) -ne 0) {
        $types.Add("AES256")
    }

    if (($value -band 0x200) -ne 0) {
        $types.Add("AES256-SK")
    }

    if ($types.Count -eq 0) {
        $types.Add("UNKNOWN MASK: $value")
    }

    return $types.ToArray()
}

function Add-Finding {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$FindingList,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium", "Low")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation
    )

    $FindingList.Add(
        [pscustomobject]@{
            Severity       = $Severity
            Title          = $Title
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    )
}

try {
    foreach ($moduleName in @("ActiveDirectory", "GroupPolicy")) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Required module '$moduleName' is not installed. Install the Windows RSAT tools."
        }

        Import-Module $moduleName
    }

    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath $OutputPath
    }

    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)

    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    Write-Host "Collecting Active Directory domain information..."

    $domain = Get-ADDomain
    $forest = Get-ADForest
    $pdcServer = $domain.PDCEmulator

    $adDomainControllers = @(
        Get-ADDomainController -Filter * -Server $domain.DNSRoot |
            Sort-Object -Property HostName
    )

    $domainControllers = @(
        foreach ($dc in $adDomainControllers) {
            [pscustomobject]@{
                HostName          = $dc.HostName
                Site              = $dc.Site
                IPv4Address       = $dc.IPv4Address
                IsGlobalCatalog   = $dc.IsGlobalCatalog
                IsReadOnly        = $dc.IsReadOnly
                OperatingSystem   = Get-OptionalProperty -InputObject $dc -Name "OperatingSystem"
                ComputerObjectDN  = Get-OptionalProperty -InputObject $dc -Name "ComputerObjectDN"
            }
        }
    )

    Write-Host "Collecting user accounts..."

    $userProperties = @(
        "Enabled",
        "LastLogonDate",
        "PasswordLastSet",
        "PasswordNeverExpires",
        "TrustedForDelegation",
        "UserPrincipalName",
        "ServicePrincipalName",
        "msDS-SupportedEncryptionTypes",
        "DistinguishedName"
    )

    $adUsers = @(
        Get-ADUser -Filter * -Properties $userProperties -Server $pdcServer |
            Sort-Object -Property SamAccountName
    )

    $users = @(
        foreach ($user in $adUsers) {
            $encryptionMask = Get-OptionalProperty -InputObject $user -Name "msDS-SupportedEncryptionTypes"

            [pscustomobject]@{
                Name                       = $user.Name
                SamAccountName             = $user.SamAccountName
                UserPrincipalName          = $user.UserPrincipalName
                Enabled                    = [bool]$user.Enabled
                LastLogon                  = Convert-DateToIso -Date $user.LastLogonDate
                LastLogonSource            = "LastLogonDate (replicated and approximate)"
                PasswordLastSet            = Convert-DateToIso -Date $user.PasswordLastSet
                PasswordNeverExpires       = [bool]$user.PasswordNeverExpires
                UnconstrainedDelegation    = [bool]$user.TrustedForDelegation
                ServicePrincipalNames      = @($user.ServicePrincipalName)
                KerberosEncryptionMask     = $encryptionMask
                KerberosEncryptionTypes    = @(Get-KerberosEncryptionTypes -Mask $encryptionMask)
                DistinguishedName          = $user.DistinguishedName
            }
        }
    )

    Write-Host "Collecting groups and direct members..."

    $adGroups = @(
        Get-ADGroup -Filter * -Properties GroupCategory, GroupScope, DistinguishedName -Server $pdcServer |
            Sort-Object -Property Name
    )

    $groups = @(
        foreach ($group in $adGroups) {
            $memberQueryError = $null
            $members = @()

            try {
                $rawMembers = @(
                    Get-ADGroupMember -Identity $group.DistinguishedName -Server $pdcServer
                )

                $members = @(
                    foreach ($member in $rawMembers) {
                        [pscustomobject]@{
                            Name              = $member.Name
                            SamAccountName    = Get-OptionalProperty -InputObject $member -Name "SamAccountName"
                            ObjectClass       = Get-OptionalProperty -InputObject $member -Name "ObjectClass"
                            DistinguishedName = $member.DistinguishedName
                        }
                    }
                )
            }
            catch {
                $memberQueryError = $_.Exception.Message
            }

            [pscustomobject]@{
                Name              = $group.Name
                SamAccountName    = $group.SamAccountName
                GroupCategory     = [string]$group.GroupCategory
                GroupScope        = [string]$group.GroupScope
                DistinguishedName = $group.DistinguishedName
                MemberCount       = $members.Count
                Members           = $members
                MemberQueryError  = $memberQueryError
            }
        }
    )

    Write-Host "Identifying service accounts..."

    $serviceAccountMap = @{}

    $userServiceAccounts = @(
        $adUsers | Where-Object {
            $_.Name -match "(?i)svc" -or
            $_.SamAccountName -match "(?i)svc" -or
            $_.DistinguishedName -match "(?i)(^|,)OU=Service Accounts(,|$)"
        }
    )

    foreach ($account in $userServiceAccounts) {
        $encryptionMask = Get-OptionalProperty -InputObject $account -Name "msDS-SupportedEncryptionTypes"

        $serviceAccountMap[$account.DistinguishedName] = [pscustomobject]@{
            AccountType              = "User-based service account"
            Name                     = $account.Name
            SamAccountName           = $account.SamAccountName
            Enabled                  = [bool]$account.Enabled
            PasswordLastSet          = Convert-DateToIso -Date $account.PasswordLastSet
            PasswordNeverExpires     = [bool]$account.PasswordNeverExpires
            UnconstrainedDelegation  = [bool]$account.TrustedForDelegation
            ServicePrincipalNames    = @($account.ServicePrincipalName)
            KerberosEncryptionMask   = $encryptionMask
            KerberosEncryptionTypes  = @(Get-KerberosEncryptionTypes -Mask $encryptionMask)
            DistinguishedName        = $account.DistinguishedName
        }
    }

    if (Get-Command -Name Get-ADServiceAccount -ErrorAction SilentlyContinue) {
        $managedServiceAccounts = @(
            Get-ADServiceAccount -Filter * -Properties @(
                "Enabled",
                "PasswordLastSet",
                "PasswordNeverExpires",
                "TrustedForDelegation",
                "ServicePrincipalName",
                "msDS-SupportedEncryptionTypes",
                "PrincipalsAllowedToRetrieveManagedPassword",
                "DistinguishedName",
                "ObjectClass"
            ) -Server $pdcServer
        )

        foreach ($account in $managedServiceAccounts) {
            $encryptionMask = Get-OptionalProperty -InputObject $account -Name "msDS-SupportedEncryptionTypes"
            $objectClass = Get-OptionalProperty -InputObject $account -Name "ObjectClass"

            $serviceAccountMap[$account.DistinguishedName] = [pscustomobject]@{
                AccountType              = [string]$objectClass
                Name                     = $account.Name
                SamAccountName           = $account.SamAccountName
                Enabled                  = [bool](Get-OptionalProperty -InputObject $account -Name "Enabled")
                PasswordLastSet          = Convert-DateToIso -Date (
                    Get-OptionalProperty -InputObject $account -Name "PasswordLastSet"
                )
                PasswordNeverExpires     = [bool](
                    Get-OptionalProperty -InputObject $account -Name "PasswordNeverExpires"
                )
                UnconstrainedDelegation  = [bool](
                    Get-OptionalProperty -InputObject $account -Name "TrustedForDelegation"
                )
                ServicePrincipalNames    = @(
                    Get-OptionalProperty -InputObject $account -Name "ServicePrincipalName"
                )
                PrincipalsAllowedToRetrieveManagedPassword = @(
                    Get-OptionalProperty -InputObject $account -Name "PrincipalsAllowedToRetrieveManagedPassword"
                )
                KerberosEncryptionMask   = $encryptionMask
                KerberosEncryptionTypes  = @(Get-KerberosEncryptionTypes -Mask $encryptionMask)
                DistinguishedName        = $account.DistinguishedName
            }
        }
    }

    $serviceAccounts = @(
        $serviceAccountMap.Values |
            Sort-Object -Property SamAccountName
    )

    Write-Host "Collecting linked GPOs from the domain and all OUs..."

    $organizationalUnits = @(
        Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName -Server $pdcServer |
            Sort-Object -Property DistinguishedName
    )

    $scopeTargets = New-Object System.Collections.Generic.List[object]
    $scopeTargets.Add(
        [pscustomobject]@{
            ScopeType        = "Domain"
            ScopeName        = $domain.DNSRoot
            DistinguishedName = $domain.DistinguishedName
        }
    )

    foreach ($ou in $organizationalUnits) {
        $scopeTargets.Add(
            [pscustomobject]@{
                ScopeType         = "OU"
                ScopeName         = $ou.Name
                DistinguishedName = $ou.DistinguishedName
            }
        )
    }

    $gpoScopes = New-Object System.Collections.Generic.List[object]
    $gpoLinks = New-Object System.Collections.Generic.List[object]
    $gpoCache = @{}

    foreach ($scope in $scopeTargets) {
        try {
            $inheritance = Get-GPInheritance `
                -Target $scope.DistinguishedName `
                -Domain $domain.DNSRoot `
                -Server $pdcServer

            $directLinks = @($inheritance.GpoLinks)

            $gpoScopes.Add(
                [pscustomobject]@{
                    ScopeType              = $scope.ScopeType
                    ScopeName              = $scope.ScopeName
                    DistinguishedName      = $scope.DistinguishedName
                    InheritanceBlocked     = [string]$inheritance.GpoInheritanceBlocked
                    DirectGpoLinkCount     = $directLinks.Count
                    QueryError             = $null
                }
            )

            foreach ($link in $directLinks) {
                $gpoIdValue = Get-OptionalProperty -InputObject $link -Name "GpoId"
                $gpoId = if ($null -eq $gpoIdValue) { $null } else { [string]$gpoIdValue }
                $gpoObject = $null
                $gpoQueryError = $null

                if ($null -ne $gpoId) {
                    if (-not $gpoCache.ContainsKey($gpoId)) {
                        try {
                            $gpoCache[$gpoId] = Get-GPO `
                                -Guid ([guid]$gpoId) `
                                -Domain $domain.DNSRoot `
                                -Server $pdcServer
                        }
                        catch {
                            $gpoCache[$gpoId] = $null
                            $gpoQueryError = $_.Exception.Message
                        }
                    }

                    $gpoObject = $gpoCache[$gpoId]
                }

                $displayName = Get-OptionalProperty -InputObject $link -Name "DisplayName"

                $gpoLinks.Add(
                    [pscustomobject]@{
                        ScopeType         = $scope.ScopeType
                        ScopeName         = $scope.ScopeName
                        ScopeDN           = $scope.DistinguishedName
                        DisplayName       = $displayName
                        GpoId             = $gpoId
                        LinkEnabled       = Get-OptionalProperty -InputObject $link -Name "Enabled"
                        Enforced          = Get-OptionalProperty -InputObject $link -Name "Enforced"
                        LinkOrder         = Get-OptionalProperty -InputObject $link -Name "Order"
                        Owner             = if ($null -eq $gpoObject) {
                            $null
                        }
                        else {
                            [string](Get-OptionalProperty -InputObject $gpoObject -Name "Owner")
                        }
                        GpoStatus         = if ($null -eq $gpoObject) {
                            $null
                        }
                        else {
                            [string](Get-OptionalProperty -InputObject $gpoObject -Name "GpoStatus")
                        }
                        CreationTime      = if ($null -eq $gpoObject) {
                            $null
                        }
                        else {
                            Convert-DateToIso -Date (
                                Get-OptionalProperty -InputObject $gpoObject -Name "CreationTime"
                            )
                        }
                        ModificationTime  = if ($null -eq $gpoObject) {
                            $null
                        }
                        else {
                            Convert-DateToIso -Date (
                                Get-OptionalProperty -InputObject $gpoObject -Name "ModificationTime"
                            )
                        }
                        GpoQueryError     = $gpoQueryError
                    }
                )
            }
        }
        catch {
            $gpoScopes.Add(
                [pscustomobject]@{
                    ScopeType          = $scope.ScopeType
                    ScopeName          = $scope.ScopeName
                    DistinguishedName  = $scope.DistinguishedName
                    InheritanceBlocked = $null
                    DirectGpoLinkCount = 0
                    QueryError         = $_.Exception.Message
                }
            )
        }
    }

    $gpoScopesArray = @($gpoScopes)
    $gpoLinksArray = @($gpoLinks)

    Write-Host "Collecting password and account-lockout policies..."

    $passwordPolicyRaw = Get-ADDefaultDomainPasswordPolicy `
        -Identity $domain.DNSRoot `
        -Server $pdcServer

    $lockoutConfigured = ([int]$passwordPolicyRaw.LockoutThreshold -gt 0)

    $passwordPolicy = [pscustomobject]@{
        MinimumPasswordLength       = [int]$passwordPolicyRaw.MinPasswordLength
        ComplexityEnabled           = [bool]$passwordPolicyRaw.ComplexityEnabled
        PasswordHistoryCount        = [int]$passwordPolicyRaw.PasswordHistoryCount
        MinimumPasswordAgeDays      = [math]::Round($passwordPolicyRaw.MinPasswordAge.TotalDays, 2)
        MaximumPasswordAgeDays      = [math]::Round($passwordPolicyRaw.MaxPasswordAge.TotalDays, 2)
        ReversibleEncryptionEnabled = [bool]$passwordPolicyRaw.ReversibleEncryptionEnabled
    }

    $accountLockoutPolicy = [pscustomobject]@{
        Configured                    = $lockoutConfigured
        Status                        = if ($lockoutConfigured) { "CONFIGURED" } else { "NOT CONFIGURED" }
        LockoutThreshold              = [int]$passwordPolicyRaw.LockoutThreshold
        LockoutDurationMinutes        = if ($lockoutConfigured) {
            [math]::Round($passwordPolicyRaw.LockoutDuration.TotalMinutes, 2)
        }
        else {
            $null
        }
        ObservationWindowMinutes      = if ($lockoutConfigured) {
            [math]::Round($passwordPolicyRaw.LockoutObservationWindow.TotalMinutes, 2)
        }
        else {
            $null
        }
    }

    Write-Host "Checking Kerberos encryption types on Domain Controller accounts..."

    $kerberosMasks = New-Object System.Collections.Generic.List[int]
    $kerberosSources = New-Object System.Collections.Generic.List[object]
    $kerberosQueryErrors = New-Object System.Collections.Generic.List[string]

    foreach ($dc in $adDomainControllers) {
        $computerObjectDN = Get-OptionalProperty -InputObject $dc -Name "ComputerObjectDN"

        if ($null -eq $computerObjectDN) {
            $kerberosQueryErrors.Add("No ComputerObjectDN was returned for $($dc.HostName).")
            continue
        }

        try {
            $dcComputer = Get-ADComputer `
                -Identity $computerObjectDN `
                -Properties "msDS-SupportedEncryptionTypes" `
                -Server $pdcServer

            $mask = Get-OptionalProperty -InputObject $dcComputer -Name "msDS-SupportedEncryptionTypes"

            if ($null -ne $mask) {
                $kerberosMasks.Add([int]$mask)
            }

            $kerberosSources.Add(
                [pscustomobject]@{
                    DomainController = $dc.HostName
                    Mask             = $mask
                    Types            = @(Get-KerberosEncryptionTypes -Mask $mask)
                }
            )
        }
        catch {
            $kerberosQueryErrors.Add(
                "Could not read Kerberos encryption types for $($dc.HostName): $($_.Exception.Message)"
            )
        }
    }

    $combinedKerberosMask = 0

    foreach ($mask in $kerberosMasks) {
        $combinedKerberosMask = $combinedKerberosMask -bor $mask
    }

    $domainKerberosTypes = @(
        Get-KerberosEncryptionTypes -Mask (
            if ($kerberosMasks.Count -eq 0) {
                $null
            }
            else {
                $combinedKerberosMask
            }
        )
    )

    $kerberos = [pscustomobject]@{
        CombinedDomainControllerMask = if ($kerberosMasks.Count -eq 0) {
            $null
        }
        else {
            $combinedKerberosMask
        }
        DomainControllerTypes        = $domainKerberosTypes
        DomainControllerDetails      = @($kerberosSources)
        QueryErrors                  = @($kerberosQueryErrors)
    }

    Write-Host "Collecting Domain Admin and Enterprise Admin membership..."

    $rootDomain = Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain

    $privilegedGroupDefinitions = @(
        [pscustomobject]@{
            GroupName = "Domain Admins"
            GroupSid  = "$($domain.DomainSID.Value)-512"
            Server    = $pdcServer
        },
        [pscustomobject]@{
            GroupName = "Enterprise Admins"
            GroupSid  = "$($rootDomain.DomainSID.Value)-519"
            Server    = $forest.RootDomain
        }
    )

    $privilegedAccounts = New-Object System.Collections.Generic.List[object]
    $privilegedQueryErrors = New-Object System.Collections.Generic.List[string]

    foreach ($definition in $privilegedGroupDefinitions) {
        try {
            $privilegedGroup = Get-ADGroup `
                -Identity $definition.GroupSid `
                -Server $definition.Server

            $members = @(
                Get-ADGroupMember `
                    -Identity $privilegedGroup.DistinguishedName `
                    -Recursive `
                    -Server $definition.Server
            )

            foreach ($member in $members) {
                $privilegedAccounts.Add(
                    [pscustomobject]@{
                        PrivilegeGroup    = $definition.GroupName
                        Name              = $member.Name
                        SamAccountName    = Get-OptionalProperty -InputObject $member -Name "SamAccountName"
                        ObjectClass       = Get-OptionalProperty -InputObject $member -Name "ObjectClass"
                        DistinguishedName = $member.DistinguishedName
                    }
                )
            }
        }
        catch {
            $privilegedQueryErrors.Add(
                "Could not query $($definition.GroupName): $($_.Exception.Message)"
            )
        }
    }

    $privilegedAccountsArray = @(
        $privilegedAccounts |
            Sort-Object -Property PrivilegeGroup, SamAccountName
    )

    Write-Host "Evaluating security findings..."

    $findings = New-Object System.Collections.Generic.List[object]

    $unconstrainedServiceAccounts = @(
        $serviceAccounts | Where-Object { $_.UnconstrainedDelegation }
    )

    foreach ($account in $unconstrainedServiceAccounts) {
        Add-Finding `
            -FindingList $findings `
            -Severity "Critical" `
            -Title "Service account allows unconstrained delegation" `
            -Evidence "$($account.SamAccountName) has TrustedForDelegation enabled." `
            -Recommendation "Remove unconstrained delegation and use constrained or resource-based constrained delegation where required."
    }

    if ($passwordPolicy.MinimumPasswordLength -lt 14) {
        Add-Finding `
            -FindingList $findings `
            -Severity "High" `
            -Title "Domain minimum password length is weak" `
            -Evidence "Minimum password length is $($passwordPolicy.MinimumPasswordLength)." `
            -Recommendation "Increase the domain minimum password length to the approved MedDefense baseline."
    }

    if (-not $passwordPolicy.ComplexityEnabled) {
        Add-Finding `
            -FindingList $findings `
            -Severity "High" `
            -Title "Password complexity is disabled" `
            -Evidence "ComplexityEnabled is False." `
            -Recommendation "Enable the approved password policy and combine it with long passwords, blocked-password screening, and MFA."
    }

    if (-not $accountLockoutPolicy.Configured) {
        Add-Finding `
            -FindingList $findings `
            -Severity "High" `
            -Title "Account lockout is not configured" `
            -Evidence "Lockout threshold is 0." `
            -Recommendation "Configure a tested lockout threshold, duration, observation window, and failed-logon monitoring."
    }

    if ($domainKerberosTypes -contains "DES" -or $domainKerberosTypes -contains "RC4") {
        Add-Finding `
            -FindingList $findings `
            -Severity "High" `
            -Title "Weak Kerberos encryption is supported" `
            -Evidence "Detected Kerberos types: $($domainKerberosTypes -join ', ')." `
            -Recommendation "Identify legacy dependencies, remove DES and RC4 support, and move accounts and services to AES."
    }

    $enabledPasswordNeverExpiresUsers = @(
        $users | Where-Object {
            $_.Enabled -and $_.PasswordNeverExpires
        }
    )

    if ($enabledPasswordNeverExpiresUsers.Count -gt 0) {
        Add-Finding `
            -FindingList $findings `
            -Severity "Medium" `
            -Title "Enabled accounts have passwords that never expire" `
            -Evidence "$($enabledPasswordNeverExpiresUsers.Count) enabled account(s) have PasswordNeverExpires enabled." `
            -Recommendation "Review each account, use managed service accounts where possible, and apply an approved credential-rotation process."
    }

    $linkedGpoNames = @(
        $gpoLinksArray |
            ForEach-Object { $_.DisplayName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    $defaultGpoNames = @(
        "Default Domain Policy",
        "Default Domain Controllers Policy"
    )

    $nonDefaultGpos = @(
        $linkedGpoNames | Where-Object {
            $_ -notin $defaultGpoNames
        }
    )

    $defaultOnly = (
        $linkedGpoNames.Count -gt 0 -and
        $nonDefaultGpos.Count -eq 0
    )

    if ($linkedGpoNames.Count -eq 0) {
        Add-Finding `
            -FindingList $findings `
            -Severity "Medium" `
            -Title "No linked GPOs were discovered" `
            -Evidence "No direct GPO links were found on the domain or OUs." `
            -Recommendation "Confirm GPO query access and deploy tested security-baseline GPOs."
    }
    elseif ($defaultOnly) {
        Add-Finding `
            -FindingList $findings `
            -Severity "Medium" `
            -Title "Only default GPOs are linked" `
            -Evidence "Linked GPOs: $($linkedGpoNames -join ', ')." `
            -Recommendation "Create separate, tested GPOs for endpoint hardening, auditing, firewall, PowerShell logging, Sysmon, and AppLocker."
    }

    $findingsArray = @($findings)
    $criticalCount = @($findingsArray | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($findingsArray | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($findingsArray | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($findingsArray | Where-Object { $_.Severity -eq "Low" }).Count

    $domainAdmins = @(
        $privilegedAccountsArray |
            Where-Object { $_.PrivilegeGroup -eq "Domain Admins" }
    )

    $enterpriseAdmins = @(
        $privilegedAccountsArray |
            Where-Object { $_.PrivilegeGroup -eq "Enterprise Admins" }
    )

    $summary = [pscustomobject]@{
        UserAccounts                          = $users.Count
        EnabledUsers                          = @($users | Where-Object { $_.Enabled }).Count
        DisabledUsers                         = @($users | Where-Object { -not $_.Enabled }).Count
        PasswordNeverExpires                  = @($users | Where-Object { $_.PasswordNeverExpires }).Count
        Groups                                = $groups.Count
        ServiceAccounts                       = $serviceAccounts.Count
        UnconstrainedDelegationServiceAccounts = $unconstrainedServiceAccounts.Count
        UniqueLinkedGpos                      = $linkedGpoNames.Count
        TotalDirectGpoLinks                   = $gpoLinksArray.Count
        DefaultGposOnly                       = $defaultOnly
        DomainAdmins                          = $domainAdmins.Count
        EnterpriseAdmins                      = $enterpriseAdmins.Count
        Findings                              = $findingsArray.Count
        CriticalFindings                      = $criticalCount
        HighFindings                          = $highCount
        MediumFindings                        = $mediumCount
        LowFindings                           = $lowCount
    }

    $report = [ordered]@{
        Metadata = [ordered]@{
            ScriptName       = "0-domain_baseline.ps1"
            GeneratedAtUtc   = (Get-Date).ToUniversalTime().ToString("o")
            GeneratedBy      = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            CollectorComputer = $env:COMPUTERNAME
            OutputPath       = $OutputPath
        }

        Summary = $summary

        Domain = [ordered]@{
            DomainName          = $domain.DNSRoot
            NetBIOSName         = $domain.NetBIOSName
            DistinguishedName   = $domain.DistinguishedName
            DomainMode          = [string]$domain.DomainMode
            ForestName          = $forest.Name
            ForestMode          = [string]$forest.ForestMode
            ForestRootDomain    = $forest.RootDomain
            PDCEmulator         = $domain.PDCEmulator
            RIDMaster           = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainControllers   = $domainControllers
        }

        Users                = $users
        Groups               = $groups
        ServiceAccounts      = $serviceAccounts
        GpoScopes            = $gpoScopesArray
        GpoLinks             = $gpoLinksArray
        PasswordPolicy       = $passwordPolicy
        AccountLockoutPolicy = $accountLockoutPolicy
        Kerberos             = $kerberos

        PrivilegedAccounts = [ordered]@{
            Accounts   = $privilegedAccountsArray
            QueryErrors = @($privilegedQueryErrors)
        }

        Findings = $findingsArray
    }

    $report |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $OutputPath -Encoding UTF8

    $dcNames = if ($domainControllers.Count -eq 0) {
        "None found"
    }
    else {
        ($domainControllers.HostName -join ", ")
    }

    $gpoStatusText = if ($linkedGpoNames.Count -eq 0) {
        "None found"
    }
    elseif ($defaultOnly) {
        "Default only"
    }
    else {
        "$($linkedGpoNames.Count) unique linked GPO(s)"
    }

    $domainAdminNames = if ($domainAdmins.Count -eq 0) {
        "None"
    }
    else {
        ($domainAdmins.SamAccountName -join ", ")
    }

    $enterpriseAdminNames = if ($enterpriseAdmins.Count -eq 0) {
        "None"
    }
    else {
        ($enterpriseAdmins.SamAccountName -join ", ")
    }

    $lockoutThresholdText = if ($accountLockoutPolicy.Configured) {
        [string]$accountLockoutPolicy.LockoutThreshold
    }
    else {
        "0 (NOT CONFIGURED)"
    }

    Write-Host ""
    Write-Host "Domain: $($domain.DNSRoot)"
    Write-Host "Forest Level: $($forest.ForestMode)"
    Write-Host "DC: $dcNames"
    Write-Host "User Accounts: $($users.Count)"
    Write-Host "  Password Never Expires: $(@($users | Where-Object { $_.PasswordNeverExpires }).Count)"
    Write-Host "Service Accounts: $($serviceAccounts.Count)"
    Write-Host "  Unconstrained delegation: $($unconstrainedServiceAccounts.Count)"
    Write-Host "Groups: $($groups.Count)"
    Write-Host "GPOs: $($linkedGpoNames.Count) ($gpoStatusText)"
    Write-Host "Password Minimum Length: $($passwordPolicy.MinimumPasswordLength)"
    Write-Host "Complexity: $(if ($passwordPolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })"
    Write-Host "Password History: $($passwordPolicy.PasswordHistoryCount)"
    Write-Host "Maximum Password Age: $($passwordPolicy.MaximumPasswordAgeDays) days"
    Write-Host "Lockout Threshold: $lockoutThresholdText"
    Write-Host "Kerberos: $($domainKerberosTypes -join ', ')"
    Write-Host "Domain Admins: $domainAdminNames"
    Write-Host "Enterprise Admins: $enterpriseAdminNames"
    Write-Host "Findings: $($findingsArray.Count) (Critical: $criticalCount, High: $highCount, Medium: $mediumCount, Low: $lowCount)"
    Write-Host "Report: $OutputPath"
}
catch {
    Write-Error "Domain baseline collection failed: $($_.Exception.Message)"
    exit 1
}

