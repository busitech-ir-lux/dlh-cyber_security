#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$SysmonPath = "C:\Windows\System32\Sysmon64.exe",
    [string]$SysmonConfig = "C:\MedDefense\Sysmon\MedDefense.xml",
    [string]$OutputDir = "capstone\telemetry"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$EventsPath   = Join-Path $OutputDir "windows_events.json"
$CoveragePath = Join-Path $OutputDir "windows_coverage.json"

$Coverage = [System.Collections.Generic.List[object]]::new()
$OverallPass = $true

function Add-Coverage {
    param(
        [string]$Action,
        [string]$Channel,
        [int[]]$ExpectedEventIds,
        [bool]$Verified,
        [object]$Evidence
    )

    if (-not $Verified) {
        $script:OverallPass = $false
    }

    $script:Coverage.Add([ordered]@{
        action              = $Action
        channel             = $Channel
        expected_event_ids  = $ExpectedEventIds
        verified             = $Verified
        status               = if ($Verified) { "pass" } else { "fail" }
        evidence             = $Evidence
    })
}

function Get-RecentEvents {
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [int]$Minutes = 10
    )

    $StartTime = (Get-Date).AddMinutes(-$Minutes)

    $Filter = @{
        LogName   = $LogName
        StartTime = $StartTime
    }

    if ($EventIds.Count -gt 0) {
        $Filter.Id = $EventIds
    }

    @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
}

function Verify-Event {
    param(
        [string]$Action,
        [string]$Channel,
        [int[]]$ExpectedEventIds,
        [scriptblock]$Predicate
    )

    $Events = Get-RecentEvents `
        -LogName $Channel `
        -EventIds $ExpectedEventIds `
        -Minutes 10

    $Match = $null

    foreach ($Event in $Events) {
        try {
            if (& $Predicate $Event) {
                $Match = $Event
                break
            }
        }
        catch {
            # Ignore malformed/unparseable event records and continue. (expected record)
        }
    }

    if ($null -ne $Match) {
        Add-Coverage `
            -Action $Action `
            -Channel $Channel `
            -ExpectedEventIds $ExpectedEventIds `
            -Verified $true `
            -Evidence ([ordered]@{
                record_id       = $Match.RecordId
                event_id        = $Match.Id
                provider        = $Match.ProviderName
                time_created    = $Match.TimeCreated.ToString("o")
                message         = $Match.Message
            })
        return $true
    }

    Add-Coverage `
        -Action $Action `
        -Channel $Channel `
        -ExpectedEventIds $ExpectedEventIds `
        -Verified $false `
        -Evidence "No matching event found in the last 10 minutes"

    return $false
}

# ---------------------------------------------------------------------------
# 1. Sysmon installed, running, and configured
# ---------------------------------------------------------------------------

if (-not (Test-Path $SysmonPath)) {
    throw "Sysmon executable not found: $SysmonPath"
}

$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $SysmonService) {
    $SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($null -eq $SysmonService) {
    throw "Sysmon service is not installed"
}

if ($SysmonService.Status -ne "Running") {
    Start-Service -InputObject $SysmonService
    $SysmonService.WaitForStatus("Running", [TimeSpan]::FromSeconds(15))
}

if ($SysmonService.Status -ne "Running") {
    throw "Sysmon service is not running"
}

if (-not (Test-Path $SysmonConfig)) {
    throw "MedDefense Sysmon configuration not found: $SysmonConfig"
}

# Explicitly apply the project configuration so the test does not silently
# operate against an unrelated Sysmon configuration.
& $SysmonPath -c $SysmonConfig | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply MedDefense Sysmon configuration"
}

# Verify that Sysmon can report its active configuration.
$ConfigOutput = & $SysmonPath -c 2>&1 | Out-String

if ([string]::IsNullOrWhiteSpace($ConfigOutput)) {
    throw "Unable to verify active Sysmon configuration"
}

# ---------------------------------------------------------------------------
# 2. Verify Script Block Logging
# ---------------------------------------------------------------------------

$SblPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

$Sbl = Get-ItemProperty -Path $SblPath -ErrorAction SilentlyContinue

if ($null -eq $Sbl -or $Sbl.EnableScriptBlockLogging -ne 1) {
    throw "PowerShell Script Block Logging is not enabled"
}

# Make sure the relevant channels are available/enabled.
$SysmonChannel = "Microsoft-Windows-Sysmon/Operational"
$PowerShellChannel = "Microsoft-Windows-PowerShell/Operational"
$SecurityChannel = "Security"

foreach ($Channel in @($SysmonChannel, $PowerShellChannel, $SecurityChannel)) {
    $Log = Get-WinEvent -ListLog $Channel -ErrorAction SilentlyContinue

    if ($null -eq $Log) {
        throw "Required event channel is unavailable: $Channel"
    }

    if (-not $Log.IsEnabled) {
        throw "Required event channel is disabled: $Channel"
    }
}

# ---------------------------------------------------------------------------
# 3. Controlled test sequence
# ---------------------------------------------------------------------------

$TestUser = "MDTelemetry_$([int](Get-Random -Minimum 10000 -Maximum 99999))"
$TaskName = "\MedDefense-Telemetry-$([int](Get-Random -Minimum 10000 -Maximum 99999))"
$ServiceName = "Spooler"

try {
    # -----------------------------------------------------------------------
    # Create local user
    # Security 4720 = user account created
    # -----------------------------------------------------------------------

    $Password = ConvertTo-SecureString `
        "MedDefense-Temporary-42!" `
        -AsPlainText `
        -Force

    New-LocalUser `
        -Name $TestUser `
        -Password $Password `
        -Description "Temporary MedDefense telemetry coverage test" `
        -AccountNeverExpires | Out-Null

    Start-Sleep -Seconds 1

    Verify-Event `
        -Action "create_local_user" `
        -Channel $SecurityChannel `
        -ExpectedEventIds @(4720) `
        -Predicate {
            param($Event)
            $Event.Message -match [regex]::Escape($TestUser)
        } | Out-Null

    # -----------------------------------------------------------------------
    # Create and run scheduled task
    # Security 4698 = scheduled task created
    # Sysmon 1 = process creation, useful evidence for the task execution
    # -----------------------------------------------------------------------

    $Action = New-ScheduledTaskAction `
        -Execute "cmd.exe" `
        -Argument "/c exit 0"

    $Trigger = New-ScheduledTaskTrigger `
        -Once `
        -At ((Get-Date).AddMinutes(1))

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -User "SYSTEM" `
        -RunLevel Highest | Out-Null

    Start-Sleep -Seconds 1

    Verify-Event `
        -Action "create_scheduled_task" `
        -Channel $SecurityChannel `
        -ExpectedEventIds @(4698) `
        -Predicate {
            param($Event)
            $Event.Message -match [regex]::Escape($TaskName)
        } | Out-Null

    Start-ScheduledTask -TaskName $TaskName.TrimStart("\")
    Start-Sleep -Seconds 2

    Verify-Event `
        -Action "run_scheduled_task" `
        -Channel $SysmonChannel `
        -ExpectedEventIds @(1) `
        -Predicate {
            param($Event)
            $Event.Message -match "cmd.exe"
        } | Out-Null

    # -----------------------------------------------------------------------
    # Start and stop a service
    #
    # Use Spooler because it is a standard Windows service. Preserve its
    # original state and restore it in cleanup.
    # -----------------------------------------------------------------------

    $OriginalService = Get-Service -Name $ServiceName
    $OriginalServiceWasRunning = ($OriginalService.Status -eq "Running")

    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 1

    Verify-Event `
        -Action "start_service" `
        -Channel $SystemChannel `
        -ExpectedEventIds @(7036) `
        -Predicate {
            param($Event)
            $Event.Message -match "Print Spooler" -and
            $Event.Message -match "running"
        } | Out-Null

    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 1

    Verify-Event `
        -Action "stop_service" `
        -Channel $SystemChannel `
        -ExpectedEventIds @(7036) `
        -Predicate {
            param($Event)
            $Event.Message -match "Print Spooler" -and
            $Event.Message -match "stopped"
        } | Out-Null

    # -----------------------------------------------------------------------
    # Authorized PowerShell command
    #
    # Script Block Logging produces 4104 in the PowerShell Operational
    # channel.
    # -----------------------------------------------------------------------

    $Marker = "MedDefenseTelemetry_$([int](Get-Random -Minimum 10000 -Maximum 99999))"

    powershell.exe -NoProfile -NonInteractive -Command `
        "`$x = '$Marker'; Write-Output `$x" | Out-Null

    Start-Sleep -Seconds 2

    Verify-Event `
        -Action "authorized_powershell_command" `
        -Channel $PowerShellChannel `
        -ExpectedEventIds @(4104) `
        -Predicate {
            param($Event)
            $Event.Message -match [regex]::Escape($Marker)
        } | Out-Null
}
finally {
    # -----------------------------------------------------------------------
    # Restore/cleanup test state.
    # -----------------------------------------------------------------------

    Unregister-ScheduledTask `
        -TaskName $TaskName.TrimStart("\") `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

    $CurrentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -ne $CurrentService) {
        if ($OriginalServiceWasRunning) {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
    }

    Remove-LocalUser `
        -Name $TestUser `
        -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 4. Export last 30 minutes of Sysmon + PowerShell events
# ---------------------------------------------------------------------------

$ExportStart = (Get-Date).AddMinutes(-30)

$SysmonEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = $SysmonChannel
        StartTime = $ExportStart
    } -ErrorAction SilentlyContinue |
    ForEach-Object {
        [ordered]@{
            source       = "Sysmon"
            channel      = $_.LogName
            event_id     = $_.Id
            record_id    = $_.RecordId
            provider     = $_.ProviderName
            level        = $_.LevelDisplayName
            time_created = $_.TimeCreated.ToString("o")
            message      = $_.Message
        }
    }
)

$PowerShellEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = $PowerShellChannel
        StartTime = $ExportStart
    } -ErrorAction SilentlyContinue |
    ForEach-Object {
        [ordered]@{
            source       = "PowerShell"
            channel      = $_.LogName
            event_id     = $_.Id
            record_id    = $_.RecordId
            provider     = $_.ProviderName
            level        = $_.LevelDisplayName
            time_created = $_.TimeCreated.ToString("o")
            message      = $_.Message
        }
    }
)

$EventPayload = [ordered]@{
    schema_version = "1.0"
    platform       = "windows"
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToUniversalTime().ToString("o")
    window         = [ordered]@{
        start            = $ExportStart.ToUniversalTime().ToString("o")
        duration_minutes = 30
    }
    events = @($SysmonEvents + $PowerShellEvents)
}

$EventPayload |
    ConvertTo-Json -Depth 8 |
    Set-Content -Path $EventsPath -Encoding UTF8

# ---------------------------------------------------------------------------
# 5. Persist coverage evidence
# ---------------------------------------------------------------------------

$CoveragePayload = [ordered]@{
    schema_version      = "1.0"
    platform            = "windows"
    host                = $env:COMPUTERNAME
    generated_at        = (Get-Date).ToUniversalTime().ToString("o")
    all_actions_verified = $OverallPass
    actions             = @($Coverage)
}

$CoveragePayload |
    ConvertTo-Json -Depth 10 |
    Set-Content -Path $CoveragePath -Encoding UTF8

if (-not $OverallPass) {
    Write-Error "Windows telemetry coverage verification FAILED"
    Get-Content $CoveragePath
    exit 1
}

Write-Host "Windows telemetry deployment and coverage verification: PASS"
Write-Host "Events:   $EventsPath"
Write-Host "Coverage: $CoveragePath"
exit 0

