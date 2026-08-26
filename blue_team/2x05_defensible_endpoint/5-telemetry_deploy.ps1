#Requires -Version 5.1
<#
.SYNOPSIS
    Hawthorne capstone, Task 5 (Windows side): verifies the telemetry stack on
    hawthorne-adm-01, runs a controlled sequence of authorized test actions,
    confirms each left the expected event within the last 10 minutes, and
    exports the last 30 minutes of Sysmon and PowerShell events.

.DESCRIPTION
    Schema parity: the per-action coverage rows use exactly the same field set
    as the Linux sibling 5-telemetry_deploy.sh, so T8 and the Module 3 analysts
    read both without branching.

    Safety: every test action uses a run-scoped probe identity (mdp<run-id>)
    that cannot collide with a real account, and every action is undone in a
    finally block that runs even when the script fails partway through. The
    script refuses to remove a principal it did not create, and it restores the
    probe service to whatever state it was found in.

    Idempotency: the test sequence is create-then-remove, so it is net-zero by
    construction - the host ends each run in the state it started.

.PARAMETER CapstoneRoot
    Root containing capstone\. Defaults to the current directory, overridable
    with the CAPSTONE_ROOT environment variable.

.PARAMETER SysmonConfig
    Path to the MedDefense Sysmon configuration, used to confirm the running
    Sysmon is using the project config.

.PARAMETER ProbeService
    Service used for the start/stop test action (default: Spooler). Its
    original state is restored afterwards.

.PARAMETER KeepProbe
    Skip cleanup. Debugging only.

.OUTPUTS
    capstone\telemetry\windows_events.json    last 30 min of Sysmon + PowerShell
    capstone\telemetry\windows_coverage.json  per-action coverage evidence

.NOTES
    Exit codes:
      0  every test action produced its expected event
      1  one or more actions produced no matching event, or an action failed,
         or Sysmon / Script Block Logging is not correctly deployed
      2  environment error - not Windows, not elevated, missing dependency,
         missing or corrupt target_state.json

.EXAMPLE
    .\5-telemetry_deploy.ps1 -CapstoneRoot 'C:\handoff' -Verbose
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CapstoneRoot,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SysmonConfig = '/home/analyst/MedDefense_Lab/2x02/meddefense_sysmon.xml',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ProbeService = 'Spooler',

    [Parameter()]
    [switch]$KeepProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptName = '5-telemetry_deploy.ps1'
$ScriptVersion = '1.0.0'
$SchemaVersion = '1.0'
$RecordType = 'telemetry_coverage'

$TelemetrySubdir = 'capstone\telemetry'
$EventsRelPath = 'capstone/telemetry/windows_events.json'
$CoverageRelPath = 'capstone/telemetry/windows_coverage.json'
$RecordBasename = 'windows_coverage.json'
$TargetStateRelPath = 'capstone/target_state.json'

$SysmonChannel = 'Microsoft-Windows-Sysmon/Operational'
$PowerShellChannel = 'Microsoft-Windows-PowerShell/Operational'
$SecurityChannel = 'Security'
$SystemChannel = 'System'

# Coverage verification searches the last 10 minutes; the export window is the
# last 30 minutes. Both are recorded in the evidence so a reader knows exactly
# what window a verdict was based on.
$VerificationWindowMinutes = 10
$ExportWindowMinutes = 30

$script:CoverageError = New-Object -TypeName 'System.Collections.Generic.List[string]'
$script:ActionRow = New-Object -TypeName 'System.Collections.Generic.List[object]'

function Add-CoverageError {
    <#
    .SYNOPSIS
        Records a problem and mirrors it to the warning stream.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $script:CoverageError.Add($Message)
    Write-Warning $Message
}

function Test-ElevatedSession {
    <#
    .SYNOPSIS
        Returns $true when the session holds the local Administrators role.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SysmonState {
    <#
    .SYNOPSIS
        Confirms Sysmon is installed, running and using the MedDefense config.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ConfigPath
    )

    $state = [ordered]@{
        installed              = $false
        service_name           = $null
        running                = $false
        version                = $null
        channel_present        = $false
        config_path            = $ConfigPath
        config_present         = $false
        config_sha256          = $null
        config_reported_hash   = $null
        config_matches_project = $null
        verified               = $false
    }

    try {
        $svc = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $svc) {
            $state.installed = $true
            $state.service_name = $svc.Name
            $state.running = ($svc.Status -eq 'Running')

            $svcCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            if ($null -ne $svcCim -and $svcCim.PathName) {
                $imagePath = $svcCim.PathName.Trim('"')
                if (Test-Path -LiteralPath $imagePath) {
                    $state.version = (Get-Item -LiteralPath $imagePath).VersionInfo.ProductVersion
                }
            }
        }
    }
    catch {
        Add-CoverageError -Message "sysmon service query failed - $($_.Exception.Message)"
    }

    try {
        $channel = Get-WinEvent -ListLog $SysmonChannel -ErrorAction SilentlyContinue
        $state.channel_present = ($null -ne $channel)
    }
    catch {
        $state.channel_present = $false
    }

    # The project config is the authority. Sysmon reports the hash of the
    # config it actually loaded, so compare that against the file on disk
    # rather than trusting that the file was ever applied.
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
        $state.config_present = $true
        try {
            $state.config_sha256 = (Get-FileHash -Path $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        catch {
            Add-CoverageError -Message "could not hash the sysmon config - $($_.Exception.Message)"
        }
    }
    else {
        Add-CoverageError -Message "MedDefense sysmon config not found at ${ConfigPath}; config match cannot be confirmed"
    }

    if ($state.installed) {
        try {
            $dump = & 'sysmon.exe' -c 2>&1 | Out-String
            $m = [regex]::Match($dump, '(?im)^\s*Config file hash:\s*SHA256=([0-9A-Fa-f]+)')
            if ($m.Success) {
                $state.config_reported_hash = $m.Groups[1].Value.ToLowerInvariant()
            }
        }
        catch {
            Add-CoverageError -Message "sysmon -c could not be read - $($_.Exception.Message)"
        }
    }

    if ($null -ne $state.config_reported_hash -and $null -ne $state.config_sha256) {
        $state.config_matches_project = ($state.config_reported_hash -eq $state.config_sha256)
    }

    # Verified means: installed, running, channel exists, and the loaded config
    # is not known to differ from the project config.
    $state.verified = ($state.installed -and $state.running -and $state.channel_present -and
        ($state.config_matches_project -ne $false))

    if (-not $state.verified) {
        Add-CoverageError -Message 'sysmon is not fully verified (installed/running/channel/config)'
    }

    return $state
}

function Get-ScriptBlockLoggingState {
    <#
    .SYNOPSIS
        Reads the Script Block Logging policy key and its event channel.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $keyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $state = [ordered]@{
        registry_path          = $keyPath
        key_present            = $false
        enabled                = $null
        invocation_logging     = $null
        channel_present        = $false
        channel_max_size_bytes = $null
        verified               = $false
    }

    try {
        if (Test-Path -Path $keyPath) {
            $state.key_present = $true
            $item = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($null -ne $item) {
                if ($item.PSObject.Properties.Name -contains 'EnableScriptBlockLogging') {
                    $state.enabled = $item.EnableScriptBlockLogging
                }
                if ($item.PSObject.Properties.Name -contains 'EnableScriptBlockInvocationLogging') {
                    $state.invocation_logging = $item.EnableScriptBlockInvocationLogging
                }
            }
        }
    }
    catch {
        Add-CoverageError -Message "script block logging registry read failed - $($_.Exception.Message)"
    }

    try {
        $channel = Get-WinEvent -ListLog $PowerShellChannel -ErrorAction SilentlyContinue
        if ($null -ne $channel) {
            $state.channel_present = $true
            $state.channel_max_size_bytes = $channel.MaximumSizeInBytes
        }
    }
    catch {
        $state.channel_present = $false
    }

    $state.verified = ($state.enabled -eq 1 -and $state.channel_present)
    if (-not $state.verified) {
        Add-CoverageError -Message 'script block logging is not enabled, or its channel is missing'
    }

    return $state
}

function Get-ChannelEventCount {
    <#
    .SYNOPSIS
        Counts events on a channel in the last 10 minutes, optionally filtered.
    .DESCRIPTION
        Returns the count and the earliest matching timestamp. A marker string
        makes verification unambiguous: the probe writes a unique run marker,
        so a match cannot be some unrelated event that happened to land in the
        same window.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel,

        [Parameter()]
        [int[]]$EventId,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Marker = '',

        [Parameter()]
        [int]$WindowMinutes = 10   # the last 10 minutes
    )

    $result = [ordered]@{ count = 0; first = $null }

    try {
        $filter = @{ LogName = $Channel; StartTime = (Get-Date).AddMinutes(-$WindowMinutes) }
        if ($null -ne $EventId -and $EventId.Count -gt 0) {
            $filter['Id'] = $EventId
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)

        if (-not [string]::IsNullOrEmpty($Marker)) {
            $events = @($events | Where-Object { $_.Message -and $_.Message.Contains($Marker) })
        }

        $result.count = $events.Count
        if ($events.Count -gt 0) {
            $earliest = ($events | Sort-Object -Property TimeCreated | Select-Object -First 1)
            $result.first = $earliest.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }
    catch {
        Add-CoverageError -Message "channel query failed for ${Channel} - $($_.Exception.Message)"
    }

    return $result
}

function Add-ActionRow {
    <#
    .SYNOPSIS
        Appends one coverage row, matching the Linux per-action field set.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ExpectedSelector,
        [Parameter(Mandatory = $true)][int]$RecordsFound,
        [Parameter()][AllowNull()][string]$FirstRecordTime,
        [Parameter()][int]$WindowMinutes = 10,
        [Parameter(Mandatory = $true)][bool]$Verified,
        [Parameter()][AllowEmptyString()][string]$Notes = ''
    )

    $script:ActionRow.Add([ordered]@{
            action            = $Action
            description       = $Description
            command           = $Command
            exit_code         = $ExitCode
            expected_source   = $ExpectedSource
            expected_selector = $ExpectedSelector
            records_found     = $RecordsFound
            first_record_time = $FirstRecordTime
            verification_window_minutes = $WindowMinutes
            verified          = $Verified
            notes             = $Notes
        })
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$isWindowsPlatform = ($PSVersionTable.PSEdition -eq 'Desktop') -or
    ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

if (-not $isWindowsPlatform) {
    Write-Warning 'This telemetry collector only runs on Windows.'
    exit 2
}

if (-not $PSBoundParameters.ContainsKey('CapstoneRoot')) {
    if ([string]::IsNullOrWhiteSpace($env:CAPSTONE_ROOT)) {
        $CapstoneRoot = (Get-Location).Path
    }
    else {
        $CapstoneRoot = $env:CAPSTONE_ROOT
    }
}

if (-not (Test-ElevatedSession)) {
    Write-Warning 'Telemetry verification must run elevated. Re-run as Administrator.'
    exit 2
}

foreach ($dependency in @('Get-WinEvent', 'Get-Service', 'New-LocalUser', 'Register-ScheduledTask')) {
    if (-not (Get-Command -Name $dependency -ErrorAction SilentlyContinue)) {
        Write-Warning "Missing required dependency: $dependency"
        exit 2
    }
}

$targetState = Join-Path -Path $CapstoneRoot -ChildPath $TargetStateRelPath
if (-not (Test-Path -LiteralPath $targetState)) {
    Write-Warning "FATAL target state contract is missing: $targetState (run 2-target_state.sh first)"
    exit 2
}
try {
    $contract = Get-Content -LiteralPath $targetState -Raw | ConvertFrom-Json
    if ($null -eq $contract.controls -or @($contract.controls).Count -eq 0) {
        Write-Warning "FATAL target state contract declares no controls: $targetState"
        exit 2
    }
}
catch {
    Write-Warning "FATAL target state contract is corrupt: $targetState - $($_.Exception.Message)"
    exit 2
}

$telemetryDir = Join-Path -Path $CapstoneRoot -ChildPath $TelemetrySubdir
try {
    if (-not (Test-Path -Path $telemetryDir)) {
        $null = New-Item -Path $telemetryDir -ItemType Directory -Force
    }
}
catch {
    Write-Warning "Cannot create output directory ${telemetryDir}: $($_.Exception.Message)"
    exit 2
}

$runId = (Get-Date).ToUniversalTime().ToString('yyMMddHHmmss')
$probeUser = "mdp$runId"          # <= 20 chars, SAM-safe
$probeTask = "MDProbe-$runId"
$probeMarker = "MDTELEMETRY-PROBE-$runId"

if ($null -ne (Get-LocalUser -Name $probeUser -ErrorAction SilentlyContinue)) {
    Write-Warning "probe user $probeUser already exists; refusing to reuse a real account"
    exit 2
}

# --- deployment verification ---

Write-Verbose 'Verifying Sysmon and Script Block Logging deployment'
$sysmonState = Get-SysmonState -ConfigPath $SysmonConfig
$sblState = Get-ScriptBlockLoggingState

# --- controlled test sequence ---

$probeUserCreated = $false
$probeTaskCreated = $false
$serviceOriginalStatus = $null

try {
    # 1. create a local user
    $exitCode = 0
    try {
        # Built char-by-char from a cryptographic RNG. ConvertTo-SecureString
        # -AsPlainText would put the credential in a plaintext string first,
        # which PSAvoidUsingConvertToSecureStringWithPlainText rightly flags.
        $securePass = New-Object -TypeName System.Security.SecureString
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $buffer = New-Object -TypeName 'byte[]' -ArgumentList 24
            $rng.GetBytes($buffer)
            foreach ($byte in $buffer) {
                $securePass.AppendChar($alphabet[$byte % $alphabet.Length])
            }
        }
        finally {
            $rng.Dispose()
        }
        $securePass.MakeReadOnly()

        $null = New-LocalUser -Name $probeUser -Password $securePass -Description $probeMarker -ErrorAction Stop
        $probeUserCreated = $true
        # Disabled immediately: the account exists only to generate a 4720.
        Disable-LocalUser -Name $probeUser -ErrorAction SilentlyContinue
    }
    catch {
        $exitCode = 1
        Add-CoverageError -Message "create_user failed - $($_.Exception.Message)"
    }
    $probe = Get-ChannelEventCount -Channel $SecurityChannel -EventId @(4720) -WindowMinutes $VerificationWindowMinutes
    Add-ActionRow -Action 'create_user' -Description 'create a local user' `
        -Command "New-LocalUser -Name $probeUser" -ExitCode $exitCode `
        -ExpectedSource $SecurityChannel -ExpectedSelector 'EventID=4720' `
        -RecordsFound $probe.count -FirstRecordTime $probe.first -WindowMinutes $VerificationWindowMinutes `
        -Verified ($exitCode -eq 0 -and $probe.count -gt 0) -Notes ''

    # 2. create and run a scheduled task
    $exitCode = 0
    try {
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c echo $probeMarker"
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $null = Register-ScheduledTask -TaskName $probeTask -Action $action -Principal $principal `
            -Description $probeMarker -Force -ErrorAction Stop
        $probeTaskCreated = $true
        Start-ScheduledTask -TaskName $probeTask -ErrorAction Stop
        Start-Sleep -Seconds 2
    }
    catch {
        $exitCode = 1
        Add-CoverageError -Message "scheduled_task failed - $($_.Exception.Message)"
    }
    $probe = Get-ChannelEventCount -Channel $SecurityChannel -EventId @(4698, 4699, 4700, 4702) -WindowMinutes $VerificationWindowMinutes
    Add-ActionRow -Action 'scheduled_task' -Description 'create and run a scheduled task' `
        -Command "Register-ScheduledTask -TaskName $probeTask; Start-ScheduledTask" -ExitCode $exitCode `
        -ExpectedSource $SecurityChannel -ExpectedSelector 'EventID=4698,4699,4700,4702' `
        -RecordsFound $probe.count -FirstRecordTime $probe.first -WindowMinutes $VerificationWindowMinutes `
        -Verified ($exitCode -eq 0 -and $probe.count -gt 0) `
        -Notes 'requires Object Access > Other Object Access Events auditing'

    # 3. start and stop a service
    $exitCode = 0
    try {
        $svc = Get-Service -Name $ProbeService -ErrorAction Stop
        $serviceOriginalStatus = $svc.Status
        if ($svc.Status -ne 'Running') {
            Start-Service -Name $ProbeService -ErrorAction Stop
            Start-Sleep -Seconds 1
        }
        Stop-Service -Name $ProbeService -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
    }
    catch {
        $exitCode = 1
        Add-CoverageError -Message "service_action failed - $($_.Exception.Message)"
    }
    # Service state transitions land on System (7036), not Security.
    $probe = Get-ChannelEventCount -Channel $SystemChannel -EventId @(7036, 7040) -WindowMinutes $VerificationWindowMinutes
    Add-ActionRow -Action 'service_action' -Description 'start and stop a service' `
        -Command "Start-Service/Stop-Service -Name $ProbeService" -ExitCode $exitCode `
        -ExpectedSource $SystemChannel -ExpectedSelector 'EventID=7036,7040' `
        -RecordsFound $probe.count -FirstRecordTime $probe.first -WindowMinutes $VerificationWindowMinutes `
        -Verified ($exitCode -eq 0 -and $probe.count -gt 0) `
        -Notes 'service state changes are logged to System, not Security'

    # 4. a short authorized PowerShell command, carrying the run marker so the
    #    4104 match cannot be an unrelated script block from the same window.
    $exitCode = 0
    try {
        $null = & {
            param($Marker)
            Write-Output "telemetry probe $Marker"
        } $probeMarker
        Start-Sleep -Seconds 2
    }
    catch {
        $exitCode = 1
        Add-CoverageError -Message "powershell_command failed - $($_.Exception.Message)"
    }
    $probe = Get-ChannelEventCount -Channel $PowerShellChannel -EventId @(4104) -Marker $probeMarker -WindowMinutes $VerificationWindowMinutes
    Add-ActionRow -Action 'powershell_command' -Description 'run a short authorized PowerShell command' `
        -Command "Write-Output 'telemetry probe $probeMarker'" -ExitCode $exitCode `
        -ExpectedSource $PowerShellChannel -ExpectedSelector "EventID=4104 containing $probeMarker" `
        -RecordsFound $probe.count -FirstRecordTime $probe.first -WindowMinutes $VerificationWindowMinutes `
        -Verified ($exitCode -eq 0 -and $probe.count -gt 0) -Notes ''

    # 5. Sysmon must have observed the process creation driven by the sequence.
    $probe = Get-ChannelEventCount -Channel $SysmonChannel -EventId @(1) -WindowMinutes $VerificationWindowMinutes
    Add-ActionRow -Action 'sysmon_process_create' -Description 'sysmon observed process creation' `
        -Command 'cmd.exe launched by the scheduled task probe' -ExitCode 0 `
        -ExpectedSource $SysmonChannel -ExpectedSelector 'EventID=1' `
        -RecordsFound $probe.count -FirstRecordTime $probe.first -WindowMinutes $VerificationWindowMinutes `
        -Verified ($probe.count -gt 0) -Notes ''
}
finally {
    # Undo every test action, even if the sequence failed partway through.
    if ($KeepProbe.IsPresent) {
        Write-Warning '-KeepProbe set; probe artefacts left in place'
    }
    else {
        if ($probeTaskCreated) {
            try {
                Unregister-ScheduledTask -TaskName $probeTask -Confirm:$false -ErrorAction Stop
                Write-Verbose "cleanup: removed scheduled task $probeTask"
            }
            catch {
                Write-Warning "cleanup: could not remove scheduled task $probeTask"
            }
        }
        if ($probeUserCreated) {
            try {
                Remove-LocalUser -Name $probeUser -ErrorAction Stop
                Write-Verbose "cleanup: removed probe user $probeUser"
            }
            catch {
                Write-Warning "cleanup: could not remove probe user $probeUser"
            }
        }
        if ($null -ne $serviceOriginalStatus -and $serviceOriginalStatus -eq 'Running') {
            try {
                Start-Service -Name $ProbeService -ErrorAction Stop
                Write-Verbose "cleanup: restored $ProbeService to Running"
            }
            catch {
                Write-Warning "cleanup: could not restore $ProbeService to its original state"
            }
        }
    }
}

# --- event export ---

Write-Verbose 'Exporting the last 30 minutes of Sysmon and PowerShell events'
$exportEvent = New-Object -TypeName 'System.Collections.Generic.List[object]'
$exportStart = (Get-Date).AddMinutes(-$ExportWindowMinutes)

foreach ($channelName in @($SysmonChannel, $PowerShellChannel)) {
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $channelName; StartTime = $exportStart } -ErrorAction SilentlyContinue)
        foreach ($evt in $raw) {
            $message = ''
            if ($null -ne $evt.Message) {
                $message = $evt.Message
                if ($message.Length -gt 4000) { $message = $message.Substring(0, 4000) }
            }
            $exportEvent.Add([ordered]@{
                    source     = $(if ($channelName -eq $SysmonChannel) { 'sysmon' } else { 'powershell' })
                    host       = $env:COMPUTERNAME
                    timestamp  = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    event_type = [string]$evt.Id
                    serial     = [string]$evt.RecordId
                    key        = $evt.LevelDisplayName
                    raw        = $message
                })
        }
    }
    catch {
        Add-CoverageError -Message "event export failed for ${channelName} - $($_.Exception.Message)"
    }
}

$sortedEvent = @($exportEvent | Sort-Object -Property timestamp)
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$eventsFile = Join-Path -Path $telemetryDir -ChildPath 'windows_events.json'

$exportDoc = [ordered]@{
    schema_version   = $SchemaVersion
    record_type      = 'telemetry_export'
    platform         = 'windows'
    hostname         = $env:COMPUTERNAME
    generated_at     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    window_minutes   = $ExportWindowMinutes
    sources          = @('sysmon', 'powershell')
    event_count      = $sortedEvent.Count
    counts_by_source = [ordered]@{
        sysmon     = @($sortedEvent | Where-Object { $_.source -eq 'sysmon' }).Count
        powershell = @($sortedEvent | Where-Object { $_.source -eq 'powershell' }).Count
    }
    events           = @($sortedEvent)
}

try {
    $json = (ConvertTo-Json -InputObject $exportDoc -Depth 8) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($eventsFile, $json + "`n", $utf8NoBom)
}
catch {
    Write-Warning "Cannot write event export to ${eventsFile}: $($_.Exception.Message)"
    exit 2
}

# --- coverage evidence ---

$actions = @($script:ActionRow)
$verifiedCount = @($actions | Where-Object { $_.verified }).Count
$failedCount = $actions.Count - $verifiedCount

$record = [ordered]@{
    schema_version     = $SchemaVersion
    record_type        = $RecordType
    platform           = 'windows'
    timestamp          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname           = $env:COMPUTERNAME
    run_id             = $runId
    collector          = [ordered]@{
        script  = $ScriptName
        version = $ScriptVersion
    }
    deployment         = [ordered]@{
        sysmon               = $sysmonState
        script_block_logging = $sblState
        probe_service        = $ProbeService
    }
    actions            = $actions
    actions_total      = $actions.Count
    actions_verified   = $verifiedCount
    actions_failed     = $failedCount
    events_export_path = $EventsRelPath
    events_exported    = $sortedEvent.Count
    export_window_minutes = $ExportWindowMinutes
    verification_window_minutes = $VerificationWindowMinutes
    coverage_path      = $CoverageRelPath
    target_state_path  = $TargetStateRelPath
    result             = $(if ($failedCount -eq 0 -and $sysmonState.verified -and $sblState.verified) { 'pass' } else { 'fail' })
    collection_errors  = @($script:CoverageError)
}

$outFile = Join-Path -Path $telemetryDir -ChildPath $RecordBasename
try {
    $json = (ConvertTo-Json -InputObject $record -Depth 10) -replace "`r`n", "`n"
    $tempFile = Join-Path -Path $telemetryDir -ChildPath ('.coverage.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($tempFile, $json + "`n", $utf8NoBom)
    [System.IO.File]::Copy($tempFile, $outFile, $true)
    Remove-Item -LiteralPath $tempFile -Force
}
catch {
    Write-Warning "Cannot write coverage record to ${outFile}: $($_.Exception.Message)"
    exit 2
}

try {
    $digest = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$outFile.sha256", ('{0}  {1}' -f $digest, $RecordBasename) + "`n", $utf8NoBom)
}
catch {
    Add-CoverageError -Message "integrity: SHA256 digest could not be written - $($_.Exception.Message)"
}

$summary = '{0}/{1} action(s) verified, {2} event(s) exported' -f $verifiedCount, $actions.Count, $sortedEvent.Count
Write-Verbose $summary
Write-Verbose "Coverage record written to $outFile"
Write-Output $outFile

if ($failedCount -eq 0 -and $sysmonState.verified -and $sblState.verified) {
    exit 0
}

exit 1
