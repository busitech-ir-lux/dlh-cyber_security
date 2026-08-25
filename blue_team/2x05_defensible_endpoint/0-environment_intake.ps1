#Requires -Version 5.1
<#
.SYNOPSIS
    Hawthorne capstone, Task 0 (Windows side): captures the raw, pre-hardening
    state of hawthorne-adm-01 as a single deterministic JSON intake record.

.DESCRIPTION
    Produces the Windows half of the Task 0 baseline. The record uses the same
    envelope, field names and directory layout as 0-environment_intake.sh so
    that both hosts can be ingested by one Module 3 parser.

    The script is read-only with respect to system state: it collects, it never
    configures. Idempotency therefore holds by construction - a second
    execution re-collects and atomically replaces the record at the same
    deterministic path, and can neither corrupt state nor re-apply a change.

.PARAMETER OutputRoot
    Root of the artifact tree. Defaults to .\artifacts, overridable with the
    INTAKE_OUTPUT_ROOT environment variable.

.PARAMETER AllowUnprivileged
    Permit a non-elevated run. The record is still written but is marked
    privileged=false and will be incomplete.

.OUTPUTS
    OutputRoot\intake\<hostname>\environment_intake.json
    OutputRoot\intake\<hostname>\environment_intake.json.sha256
    The full path of the record is written to the success stream; all logging
    goes to the verbose and warning streams.

.NOTES
    Exit codes:
      0  success - record written, every collector reported clean
      1  controlled failure - record written, one or more collectors degraded
         (listed in .collection_errors)
      2  environment error - not Windows, missing dependency, unwritable output

.EXAMPLE
    .\0-environment_intake.ps1 -OutputRoot 'C:\handoff\artifacts' -Verbose
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot,

    [Parameter()]
    [switch]$AllowUnprivileged
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptName = '0-environment_intake.ps1'
$ScriptVersion = '1.0.0'
$SchemaVersion = '1.0'
$RecordType = 'environment_intake'
$Phase = 'pre_hardening'

# Module 3 handoff layout. Keep these two constants aligned with the telemetry
# handoff from 2x02 and the network artifact package from 2x04 - they are the
# only place the layout is defined.
$ArtifactSubdir = 'intake'
$RecordBasename = 'environment_intake.json'

$ExitOk = 0
$ExitFail = 1
$ExitEnv = 2

$script:IntakeError = New-Object -TypeName 'System.Collections.Generic.List[string]'

function Add-CollectionError {
    <#
    .SYNOPSIS
        Records a degraded collector and mirrors it to the warning stream.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $script:IntakeError.Add($Message)
    Write-Warning $Message
}

function Test-ElevatedSession {
    <#
    .SYNOPSIS
        Returns $true when the current session holds the local Administrators role.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostIntake {
    <#
    .SYNOPSIS
        Hostname, OS build and patch level.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        hostname             = $env:COMPUTERNAME
        os_caption           = $null
        os_version           = $null
        os_build             = $null
        ubr                  = $null
        display_version      = $null
        product_type         = $null
        architecture         = $env:PROCESSOR_ARCHITECTURE
        install_date_utc     = $null
        last_boot_utc        = $null
        patch_level          = $null
        hotfix_count         = $null
        latest_hotfix_id     = $null
        latest_hotfix_date   = $null
    }

    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $record.os_caption = $osInfo.Caption
        $record.os_version = $osInfo.Version
        $record.os_build = $osInfo.BuildNumber
        $record.product_type = switch ($osInfo.ProductType) {
            1 { 'workstation' }
            2 { 'domain_controller' }
            3 { 'server' }
            default { 'unknown' }
        }
        $record.install_date_utc = $osInfo.InstallDate.ToUniversalTime().ToString('s') + 'Z'
        $record.last_boot_utc = $osInfo.LastBootUpTime.ToUniversalTime().ToString('s') + 'Z'
    }
    catch {
        Add-CollectionError -Message "host: Win32_OperatingSystem query failed - $($_.Exception.Message)"
    }

    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        if ($cv.PSObject.Properties.Name -contains 'UBR') { $record.ubr = $cv.UBR }
        if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $record.display_version = $cv.DisplayVersion }
        $record.patch_level = '{0}.{1}' -f $record.os_build, $record.ubr
    }
    catch {
        Add-CollectionError -Message "host: CurrentVersion registry read failed - $($_.Exception.Message)"
    }

    try {
        $hotfix = Get-HotFix | Sort-Object -Property InstalledOn -Descending
        $record.hotfix_count = @($hotfix).Count
        if (@($hotfix).Count -gt 0) {
            $record.latest_hotfix_id = $hotfix[0].HotFixID
            if ($null -ne $hotfix[0].InstalledOn) {
                $record.latest_hotfix_date = $hotfix[0].InstalledOn.ToString('yyyy-MM-dd')
            }
        }
    }
    catch {
        Add-CollectionError -Message "host: Get-HotFix failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-FeatureIntake {
    <#
    .SYNOPSIS
        Installed feature count, using the server or client cmdlet as appropriate.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductType
    )

    $record = [ordered]@{
        source            = $null
        installed_count   = $null
        available_count   = $null
        installed_names   = @()
    }

    try {
        if ($ProductType -ne 'workstation' -and (Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue)) {
            $record.source = 'Get-WindowsFeature'
            $feature = Get-WindowsFeature
            $installed = $feature | Where-Object { $_.Installed }
            $record.available_count = @($feature).Count
            $record.installed_count = @($installed).Count
            $record.installed_names = @($installed | Select-Object -ExpandProperty Name | Sort-Object)
        }
        elseif (Get-Command -Name 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue) {
            $record.source = 'Get-WindowsOptionalFeature -Online'
            $feature = Get-WindowsOptionalFeature -Online
            $enabled = $feature | Where-Object { $_.State -eq 'Enabled' }
            $record.available_count = @($feature).Count
            $record.installed_count = @($enabled).Count
            $record.installed_names = @($enabled | Select-Object -ExpandProperty FeatureName | Sort-Object)
        }
        else {
            Add-CollectionError -Message 'features: neither Get-WindowsFeature nor Get-WindowsOptionalFeature is available'
        }
    }
    catch {
        Add-CollectionError -Message "features: enumeration failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-ServiceIntake {
    <#
    .SYNOPSIS
        Service inventory with the running subset broken out.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        source          = 'Get-Service'
        total_count     = $null
        running_count   = $null
        stopped_count   = $null
        units           = @()
    }

    try {
        $svc = Get-Service | Sort-Object -Property Name
        $record.total_count = @($svc).Count
        $record.running_count = @($svc | Where-Object { $_.Status -eq 'Running' }).Count
        $record.stopped_count = @($svc | Where-Object { $_.Status -eq 'Stopped' }).Count
        $record.units = @(
            $svc | Where-Object { $_.Status -eq 'Running' } | ForEach-Object {
                [ordered]@{
                    unit         = $_.Name
                    display_name = $_.DisplayName
                    active       = $_.Status.ToString()
                    start_type   = if ($_.PSObject.Properties.Name -contains 'StartType') { $_.StartType.ToString() } else { $null }
                }
            }
        )
    }
    catch {
        Add-CollectionError -Message "services: Get-Service failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-LocalAccountIntake {
    <#
    .SYNOPSIS
        Local user accounts and their enabled or expired state.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        source          = 'Get-LocalUser'
        total_count     = $null
        enabled_count   = $null
        accounts        = @()
    }

    try {
        if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
            Add-CollectionError -Message 'local_users: Get-LocalUser is unavailable on this host'
            return $record
        }

        $user = Get-LocalUser | Sort-Object -Property Name
        $record.total_count = @($user).Count
        $record.enabled_count = @($user | Where-Object { $_.Enabled }).Count
        $record.accounts = @(
            $user | ForEach-Object {
                [ordered]@{
                    name                     = $_.Name
                    sid                      = $_.SID.Value
                    enabled                  = [bool]$_.Enabled
                    password_required        = [bool]$_.PasswordRequired
                    password_expires_utc     = if ($null -ne $_.PasswordExpires) { $_.PasswordExpires.ToUniversalTime().ToString('s') + 'Z' } else { $null }
                    password_last_set_utc    = if ($null -ne $_.PasswordLastSet) { $_.PasswordLastSet.ToUniversalTime().ToString('s') + 'Z' } else { $null }
                    last_logon_utc           = if ($null -ne $_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('s') + 'Z' } else { $null }
                    user_may_change_password = [bool]$_.UserMayChangePassword
                }
            }
        )
    }
    catch {
        Add-CollectionError -Message "local_users: enumeration failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-FirewallIntake {
    <#
    .SYNOPSIS
        Windows Firewall state for each profile.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        backend        = 'windows_firewall'
        source         = 'Get-NetFirewallProfile'
        active         = $false
        rule_count     = $null
        profiles       = @()
    }

    try {
        if (-not (Get-Command -Name 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue)) {
            Add-CollectionError -Message 'firewall: Get-NetFirewallProfile is unavailable on this host'
            return $record
        }

        $profileState = Get-NetFirewallProfile -PolicyStore ActiveStore
        $record.profiles = @(
            $profileState | ForEach-Object {
                [ordered]@{
                    name                  = $_.Name.ToString()
                    enabled               = [bool]$_.Enabled
                    default_inbound       = $_.DefaultInboundAction.ToString()
                    default_outbound      = $_.DefaultOutboundAction.ToString()
                    log_allowed           = $_.LogAllowed.ToString()
                    log_blocked           = $_.LogBlocked.ToString()
                    log_file_name         = $_.LogFileName
                    log_max_size_kb       = $_.LogMaxSizeKilobytes
                    notify_on_listen      = $_.NotifyOnListen.ToString()
                }
            }
        )
        $record.active = @($profileState | Where-Object { $_.Enabled }).Count -eq @($profileState).Count

        if (Get-Command -Name 'Get-NetFirewallRule' -ErrorAction SilentlyContinue) {
            $record.rule_count = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Enabled }).Count
        }
    }
    catch {
        Add-CollectionError -Message "firewall: state query failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-AuditPolicyIntake {
    <#
    .SYNOPSIS
        Audit policy summary from auditpol, parsed from its CSV output.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        source             = 'auditpol /get /category:* /r'
        subcategory_count  = $null
        configured_count   = $null
        no_auditing_count  = $null
        subcategories      = @()
    }

    try {
        $raw = & auditpol.exe /get '/category:*' /r 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            Add-CollectionError -Message 'audit_policy: auditpol returned no data (elevation required)'
            return $record
        }

        $parsed = $raw | ConvertFrom-Csv
        $record.subcategories = @(
            $parsed | Where-Object { $_.Subcategory } | ForEach-Object {
                [ordered]@{
                    subcategory      = $_.Subcategory
                    subcategory_guid = $_.'Subcategory GUID'
                    setting          = $_.'Inclusion Setting'
                }
            }
        )
        $record.subcategory_count = @($record.subcategories).Count
        $record.no_auditing_count = @($record.subcategories | Where-Object { $_.setting -eq 'No Auditing' }).Count
        $record.configured_count = $record.subcategory_count - $record.no_auditing_count
    }
    catch {
        Add-CollectionError -Message "audit_policy: auditpol parsing failed - $($_.Exception.Message)"
    }

    return $record
}

function Get-TelemetryIntake {
    <#
    .SYNOPSIS
        Sysmon presence, version and operational channel sizing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $sysmon = [ordered]@{
        present                = $false
        service_name           = $null
        running                = $false
        active_state           = $null
        start_type             = $null
        version                = $null
        image_path             = $null
        channel_name           = 'Microsoft-Windows-Sysmon/Operational'
        channel_present        = $false
        channel_max_size_bytes = $null
        channel_record_count   = $null
    }

    try {
        $svc = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $svc) {
            $sysmon.present = $true
            $sysmon.service_name = $svc.Name
            $sysmon.active_state = $svc.Status.ToString()
            $sysmon.running = ($svc.Status -eq 'Running')
            if ($svc.PSObject.Properties.Name -contains 'StartType') {
                $sysmon.start_type = $svc.StartType.ToString()
            }

            $svcCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            if ($null -ne $svcCim -and $svcCim.PathName) {
                $imagePath = $svcCim.PathName.Trim('"')
                $sysmon.image_path = $imagePath
                if (Test-Path -LiteralPath $imagePath) {
                    $sysmon.version = (Get-Item -LiteralPath $imagePath).VersionInfo.ProductVersion
                }
            }
        }
    }
    catch {
        Add-CollectionError -Message "telemetry: Sysmon service query failed - $($_.Exception.Message)"
    }

    try {
        $channel = Get-WinEvent -ListLog $sysmon.channel_name -ErrorAction SilentlyContinue
        if ($null -ne $channel) {
            $sysmon.channel_present = $true
            $sysmon.channel_max_size_bytes = $channel.MaximumSizeInBytes
            $sysmon.channel_record_count = $channel.RecordCount
        }
    }
    catch {
        Add-CollectionError -Message "telemetry: Sysmon event channel query failed - $($_.Exception.Message)"
    }

    if (-not $sysmon.present) {
        Add-CollectionError -Message 'telemetry: Sysmon is not installed on this host'
    }

    return [ordered]@{ sysmon = $sysmon }
}

function Get-PowerShellLoggingIntake {
    <#
    .SYNOPSIS
        Script block logging, module logging and transcription policy state.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $record = [ordered]@{
        source                              = $policyRoot
        script_block_logging_key_present    = $false
        script_block_logging_enabled        = $null
        script_block_invocation_logging     = $null
        module_logging_enabled              = $null
        transcription_enabled               = $null
        transcription_output_directory      = $null
    }

    $readValue = {
        param($Path, $Name)
        if (Test-Path -Path $Path) {
            $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($null -ne $item -and $item.PSObject.Properties.Name -contains $Name) {
                return $item.$Name
            }
        }
        return $null
    }

    try {
        $sbPath = Join-Path -Path $policyRoot -ChildPath 'ScriptBlockLogging'
        $record.script_block_logging_key_present = [bool](Test-Path -Path $sbPath)
        $record.script_block_logging_enabled = & $readValue $sbPath 'EnableScriptBlockLogging'
        $record.script_block_invocation_logging = & $readValue $sbPath 'EnableScriptBlockInvocationLogging'

        $mlPath = Join-Path -Path $policyRoot -ChildPath 'ModuleLogging'
        $record.module_logging_enabled = & $readValue $mlPath 'EnableModuleLogging'

        $trPath = Join-Path -Path $policyRoot -ChildPath 'Transcription'
        $record.transcription_enabled = & $readValue $trPath 'EnableTranscripting'
        $record.transcription_output_directory = & $readValue $trPath 'OutputDirectory'
    }
    catch {
        Add-CollectionError -Message "powershell_logging: registry read failed - $($_.Exception.Message)"
    }

    if ($record.script_block_logging_enabled -ne 1) {
        Add-CollectionError -Message 'powershell_logging: script block logging is not enabled'
    }

    return $record
}

function Get-AccountPolicyIntake {
    <#
    .SYNOPSIS
        Account lockout and password policy parsed from net accounts.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $record = [ordered]@{
        source   = 'net accounts'
        settings = [ordered]@{}
    }

    try {
        $raw = & net.exe accounts 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            Add-CollectionError -Message 'account_policy: net accounts returned no data'
            return $record
        }

        foreach ($line in $raw) {
            if ($line -match '^(?<key>[^:]+):\s{2,}(?<value>.*?)\s*$') {
                $key = $Matches['key'].Trim().ToLowerInvariant() -replace '[^a-z0-9]+', '_'
                $record.settings[$key.Trim('_')] = $Matches['value'].Trim()
            }
        }

        if (@($record.settings.Keys).Count -eq 0) {
            Add-CollectionError -Message 'account_policy: net accounts output could not be parsed'
        }
    }
    catch {
        Add-CollectionError -Message "account_policy: net accounts failed - $($_.Exception.Message)"
    }

    return $record
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$isWindowsPlatform = ($PSVersionTable.PSEdition -eq 'Desktop') -or
    ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

if (-not $isWindowsPlatform) {
    Write-Warning 'This intake collector only runs on Windows.'
    exit $ExitEnv
}

if (-not $PSBoundParameters.ContainsKey('OutputRoot')) {
    if ([string]::IsNullOrWhiteSpace($env:INTAKE_OUTPUT_ROOT)) {
        $OutputRoot = Join-Path -Path (Get-Location).Path -ChildPath 'artifacts'
    }
    else {
        $OutputRoot = $env:INTAKE_OUTPUT_ROOT
    }
}

foreach ($dependency in @('Get-CimInstance', 'Get-Service', 'Get-HotFix')) {
    if (-not (Get-Command -Name $dependency -ErrorAction SilentlyContinue)) {
        Write-Warning "Missing required dependency: $dependency"
        exit $ExitEnv
    }
}

$isElevated = Test-ElevatedSession
if (-not $isElevated) {
    if (-not $AllowUnprivileged.IsPresent) {
        Write-Warning 'Must run elevated. Re-run as Administrator, or pass -AllowUnprivileged to accept a degraded record.'
        exit $ExitEnv
    }
    Add-CollectionError -Message 'run is not elevated, record is a lower bound only'
}

Write-Verbose "Starting intake on $env:COMPUTERNAME (privileged=$isElevated)"

$hostIntake = Get-HostIntake
$productType = if ($null -ne $hostIntake.product_type) { $hostIntake.product_type } else { 'unknown' }

$record = [ordered]@{
    schema_version    = $SchemaVersion
    record_type       = $RecordType
    phase             = $Phase
    platform          = 'windows'
    collected_at_utc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    collector         = [ordered]@{
        script     = $ScriptName
        version    = $ScriptVersion
        privileged = $isElevated
    }
    host              = $hostIntake
    features          = Get-FeatureIntake -ProductType $productType
    services          = Get-ServiceIntake
    local_users       = Get-LocalAccountIntake
    firewall          = Get-FirewallIntake
    audit_policy      = Get-AuditPolicyIntake
    telemetry         = Get-TelemetryIntake
    powershell_logging = Get-PowerShellLoggingIntake
    account_policy    = Get-AccountPolicyIntake
    collection_errors = @($script:IntakeError)
}

$outDir = Join-Path -Path (Join-Path -Path $OutputRoot -ChildPath $ArtifactSubdir) -ChildPath $env:COMPUTERNAME
$outFile = Join-Path -Path $outDir -ChildPath $RecordBasename

try {
    if (-not (Test-Path -Path $outDir)) {
        $null = New-Item -Path $outDir -ItemType Directory -Force
    }
}
catch {
    Write-Warning "Cannot create output directory ${outDir}: $($_.Exception.Message)"
    exit $ExitEnv
}

try {
    # LF line endings and no BOM keep the digest stable across both hosts.
    $json = ($record | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
    $tempFile = Join-Path -Path $outDir -ChildPath ('.intake.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($tempFile, $json + "`n", $utf8NoBom)
    # Atomic replace: a repeated run never leaves a partial record behind.
    [System.IO.File]::Copy($tempFile, $outFile, $true)
    Remove-Item -Path $tempFile -Force
}
catch {
    Write-Warning "Cannot write intake record to ${outFile}: $($_.Exception.Message)"
    exit $ExitEnv
}

try {
    $digest = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $digestLine = '{0}  {1}' -f $digest, $RecordBasename
    [System.IO.File]::WriteAllText("$outFile.sha256", $digestLine + "`n", $utf8NoBom)
}
catch {
    Add-CollectionError -Message "integrity: SHA256 digest could not be written - $($_.Exception.Message)"
}

Write-Verbose "Intake record written to $outFile"
Write-Output $outFile

if ($script:IntakeError.Count -gt 0) {
    Write-Warning "$($script:IntakeError.Count) collector(s) degraded; see .collection_errors"
    exit $ExitFail
}

exit $ExitOk
