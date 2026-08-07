<#
name: 4-windows_telemetry_quality.ps1
purpose: Check the completeness and quality of exported Windows telemetry.
author: Mahdi Hamidi
#>

Set-StrictMode -Version Latest

$inputFile = Join-Path $PSScriptRoot "windows_events_export.json"
$outputFile = Join-Path $PSScriptRoot "windows_telemetry_quality.json"

$windowHours = 24
$gapThresholdMinutes = 30

Write-Host "[*] Analyzing windows_events_export.json..."

if (-not (Test-Path $inputFile)) {
    Write-Host "[ERROR] windows_events_export.json not found."
    exit 1
}

$events = @(Get-Content $inputFile -Raw | ConvertFrom-Json)
$totalEvents = $events.Count


# Get a field safely
function Get-EventValue {
    param($Event, [string]$Name)

    $property = $Event.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}


# Check if a field has useful data
function Test-FieldValue {
    param($Value)

    if ($null -eq $Value) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        return $false
    }

    if ([string]$Value -eq "-") {
        return $false
    }

    return $true
}


function Get-Percent {
    param([int]$Good, [int]$Total)

    if ($Total -eq 0) {
        return 100
    }

    return [math]::Round(($Good / $Total) * 100, 2)
}


# -------------------------------------------------
# Event Distribution
# -------------------------------------------------

$eventDistribution = @()

$groups = $events | Group-Object source_type, event_id

foreach ($group in $groups) {

    $sample = $group.Group[0]

    $eventDistribution += [PSCustomObject]@{
        source_type         = $sample.source_type
        event_id            = $sample.event_id
        count               = $group.Count
        percentage_of_total = Get-Percent $group.Count $totalEvents
    }
}


# -------------------------------------------------
# Channel distribution
# -------------------------------------------------

$channelDistribution = @()

foreach ($channel in @("Security", "Sysmon", "PowerShell")) {

    $count = @(
        $events | Where-Object { $_.source_type -eq $channel }
    ).Count

    $channelDistribution += [PSCustomObject]@{
        channel    = $channel
        count      = $count
        percentage = Get-Percent $count $totalEvents
    }
}


# -------------------------------------------------
# Time coverage - events per hour
# -------------------------------------------------

$endTime = (Get-Date).ToUniversalTime()
$startTime = $endTime.AddHours(-$windowHours)

$timedEvents = @()

foreach ($event in $events) {

    try {

        $time = [DateTimeOffset]::Parse($event.timestamp).UtcDateTime

        if ($time -ge $startTime -and $time -le $endTime) {

            $timedEvents += [PSCustomObject]@{
                time  = $time
                event = $event
            }
        }
    }
    catch {
        # Ignore invalid timestamp
    }
}


$eventsPerHour = @()

for ($i = 0; $i -lt $windowHours; $i++) {

    $hourStart = $startTime.AddHours($i)
    $hourEnd = $hourStart.AddHours(1)

    $count = @(
        $timedEvents | Where-Object {
            $_.time -ge $hourStart -and $_.time -lt $hourEnd
        }
    ).Count

    $eventsPerHour += [PSCustomObject]@{
        hour        = $hourStart.ToString("yyyy-MM-dd HH:00")
        event_count = $count
    }
}

$hoursWithEvents = @(
    $eventsPerHour | Where-Object { $_.event_count -gt 0 }
).Count

$hoursWithoutEvents = $windowHours - $hoursWithEvents


# -------------------------------------------------
# Gap detection - longer than 30 minutes
# -------------------------------------------------

$gaps = @()
$allGapMinutes = @()

$times = @(
    $timedEvents.time | Sort-Object
)

if ($times.Count -gt 0) {

    $firstGap = ($times[0] - $startTime).TotalMinutes
    $allGapMinutes += $firstGap

    if ($firstGap -gt $gapThresholdMinutes) {
        $gaps += [PSCustomObject]@{
            start   = $startTime.ToString("o")
            end     = $times[0].ToString("o")
            minutes = [math]::Round($firstGap, 2)
        }
    }


    for ($i = 1; $i -lt $times.Count; $i++) {

        $minutes = ($times[$i] - $times[$i - 1]).TotalMinutes
        $allGapMinutes += $minutes

        if ($minutes -gt $gapThresholdMinutes) {

            $gaps += [PSCustomObject]@{
                start   = $times[$i - 1].ToString("o")
                end     = $times[$i].ToString("o")
                minutes = [math]::Round($minutes, 2)
            }
        }
    }


    $lastGap = ($endTime - $times[-1]).TotalMinutes
    $allGapMinutes += $lastGap

    if ($lastGap -gt $gapThresholdMinutes) {

        $gaps += [PSCustomObject]@{
            start   = $times[-1].ToString("o")
            end     = $endTime.ToString("o")
            minutes = [math]::Round($lastGap, 2)
        }
    }
}
else {

    $allGapMinutes += ($windowHours * 60)

    $gaps += [PSCustomObject]@{
        start   = $startTime.ToString("o")
        end     = $endTime.ToString("o")
        minutes = ($windowHours * 60)
    }
}

$largestGap = [math]::Round(
    ($allGapMinutes | Measure-Object -Maximum).Maximum, 2
)


# -------------------------------------------------
# Field completeness
# -------------------------------------------------

$definitions = @(

    @{
        source = "Security"
        id = 4624
        fields = @("target_user", "logon_type", "source_ip", "workstation")
    },

    @{
        source = "Security"
        id = 4625
        fields = @("target_user", "failure_reason", "source_ip")
    },

    @{
        source = "Security"
        id = 4672
        fields = @("privileged_account")
    },

    @{
        source = "Security"
        id = 4688
        fields = @("process_name", "command_line", "parent_process")
    },

    @{
        source = "PowerShell"
        id = 4104
        fields = @("script_block_text")
    },

    @{
        source = "Sysmon"
        id = 1
        fields = @("image", "command_line", "parent_image", "hashes")
    },

    @{
        source = "Sysmon"
        id = 3
        fields = @("destination_ip", "destination_port", "process")
    },

    @{
        source = "Sysmon"
        id = 11
        fields = @("target_filename", "creating_process")
    },

    @{
        source = "Sysmon"
        id = 13
        fields = @("registry_key", "value_name")
    },

    @{
        source = "Sysmon"
        id = 22
        fields = @("query_name", "query_results")
    }
)


$fieldCompleteness = @()
$fieldScores = @()

foreach ($definition in $definitions) {

    $matchingEvents = @(
        $events | Where-Object {
            $_.source_type -eq $definition.source -and
            [int]$_.event_id -eq $definition.id
        }
    )

    $fieldResults = @()

    foreach ($field in $definition.fields) {

        $populated = 0

        foreach ($event in $matchingEvents) {

            $value = Get-EventValue $event $field

            if (Test-FieldValue $value) {
                $populated++
            }
        }

        $empty = $matchingEvents.Count - $populated
        $percent = Get-Percent $populated $matchingEvents.Count

        if ($matchingEvents.Count -gt 0) {
            $fieldScores += $percent
        }

        $fieldResults += [PSCustomObject]@{
            field            = $field
            populated        = $populated
            empty_or_null    = $empty
            completeness_pct = $percent
        }
    }

    $fieldCompleteness += [PSCustomObject]@{
        source_type = $definition.source
        event_id    = $definition.id
        event_count = $matchingEvents.Count
        fields      = $fieldResults
    }
}


# -------------------------------------------------
# Important completeness checks
# -------------------------------------------------

$processEvents = @(
    $events | Where-Object {
        ($_.source_type -eq "Security" -and [int]$_.event_id -eq 4688) -or
        ($_.source_type -eq "Sysmon" -and [int]$_.event_id -eq 1)
    }
)

$commandGood = @(
    $processEvents | Where-Object {
        Test-FieldValue (Get-EventValue $_ "command_line")
    }
).Count

$commandCompleteness = Get-Percent $commandGood $processEvents.Count


$logonEvents = @(
    $events | Where-Object {
        $_.source_type -eq "Security" -and
        ([int]$_.event_id -eq 4624 -or [int]$_.event_id -eq 4625)
    }
)

$ipGood = @(
    $logonEvents | Where-Object {
        Test-FieldValue (Get-EventValue $_ "source_ip")
    }
).Count

$sourceIpCompleteness = Get-Percent $ipGood $logonEvents.Count


$scriptEvents = @(
    $events | Where-Object {
        $_.source_type -eq "PowerShell" -and
        [int]$_.event_id -eq 4104
    }
)

$scriptGood = @(
    $scriptEvents | Where-Object {
        Test-FieldValue (Get-EventValue $_ "script_block_text")
    }
).Count

$scriptCompleteness = Get-Percent $scriptGood $scriptEvents.Count


# -------------------------------------------------
# Quality score 0-100
# -------------------------------------------------

if ($fieldScores.Count -gt 0) {
    $fieldScore = ($fieldScores | Measure-Object -Average).Average
}
else {
    $fieldScore = 0
}

$timeScore = ($hoursWithEvents / $windowHours) * 100

if ($largestGap -le 30) {
    $gapScore = 100
}
elseif ($largestGap -le 60) {
    $gapScore = 80
}
elseif ($largestGap -le 120) {
    $gapScore = 60
}
else {
    $gapScore = 30
}

$activeChannels = @(
    $channelDistribution | Where-Object { $_.count -gt 0 }
).Count

$channelScore = ($activeChannels / 3) * 100


# Weighted score
$qualityScore = (
    ($fieldScore * 0.40) +
    ($timeScore * 0.30) +
    ($gapScore * 0.20) +
    ($channelScore * 0.10)
)

$qualityScore = [math]::Round($qualityScore, 2)

if ($qualityScore -ge 90) {
    $assessment = "good"
}
elseif ($qualityScore -ge 70) {
    $assessment = "acceptable"
}
else {
    $assessment = "poor"
}


# -------------------------------------------------
# JSON report
# -------------------------------------------------

$report = [PSCustomObject]@{

    total_events = $totalEvents

    event_distribution = $eventDistribution

    channel_distribution = $channelDistribution

    time_coverage = @{
        window_hours         = $windowHours
        events_per_hour      = $eventsPerHour
        hours_with_events    = $hoursWithEvents
        hours_without_events = $hoursWithoutEvents
    }

    gap_detection = @{
        threshold_minutes   = $gapThresholdMinutes
        largest_gap_minutes = $largestGap
        gaps                = $gaps
    }

    field_completeness = @{
        by_event_type               = $fieldCompleteness
        command_line_completeness   = $commandCompleteness
        source_ip_completeness      = $sourceIpCompleteness
        script_block_completeness   = $scriptCompleteness
    }

    quality = @{
        score      = $qualityScore
        assessment = $assessment
    }
}

$report |
    ConvertTo-Json -Depth 10 |
    Set-Content $outputFile -Encoding UTF8


# Summary
Write-Host "Total events: $totalEvents"
Write-Host "Hours with events: $hoursWithEvents/$windowHours"
Write-Host "Largest gap: $largestGap minutes"
Write-Host "Command-line completeness: $commandCompleteness%"
Write-Host "Source IP completeness: $sourceIpCompleteness%"
Write-Host "Script block completeness: $scriptCompleteness%"
Write-Host "Quality score: $qualityScore% ($assessment)"
Write-Host "Report saved to: windows_telemetry_quality.json"