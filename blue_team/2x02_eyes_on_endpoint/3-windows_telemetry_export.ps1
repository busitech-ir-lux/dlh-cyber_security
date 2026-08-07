<#
name: 3-windows_telemetry_export.ps1
purpose: Export and normalize Windows Security, Sysmon and PowerShell telemetry.
author: Mahdi Hamidi
#>

Set-StrictMode -Version Latest

param(
    [int]$Hours = 24
)

$outputFile = Join-Path $PSScriptRoot "windows_events_export.json"
$EndTime = Get-Date
$StartTime = $EndTime.AddHours(-$Hours)

Write-Host "[*] Exporting Windows telemetry from last $Hours hours..."


# Read EventData fields from event XML
function Get-EventData {
    param($Event)

    $data = @{}
    [xml]$xml = $Event.ToXml()

    $nodes = $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")

    foreach ($node in $nodes) {

        $name = $node.GetAttribute("Name")

        if ($name) {
            $data[$name] = $node.InnerText
        }
    }

    return $data
}


# Safely get a field
function Get-Field {
    param(
        $Data,
        [string]$Name
    )

    if ($Data.ContainsKey($Name)) {
        return $Data[$Name]
    }

    return $null
}


# Create one normalized record
function Convert-WindowsEvent {
    param(
        $Event,
        [string]$SourceType
    )

    $data = Get-EventData $Event

    $category = "Other"

    # Common enriched fields
    $targetUser       = $null
    $logonType        = $null
    $sourceIp         = $null
    $workstation      = $null
    $failureReason    = $null
    $privilegedAccount = $null

    $processName      = $null
    $commandLine      = $null
    $parentProcess    = $null

    $scriptBlockText  = $null

    $image            = $null
    $parentImage      = $null
    $hashes           = $null

    $destinationIp    = $null
    $destinationPort  = $null
    $process          = $null

    $targetFilename   = $null
    $creatingProcess  = $null

    $registryKey      = $null
    $valueName        = $null

    $queryName        = $null
    $queryResults     = $null


    # Windows Security events
    if ($SourceType -eq "Security") {

        switch ($Event.Id) {

            4624 {
                $category    = "Successful Logon"
                $targetUser  = Get-Field $data "TargetUserName"
                $logonType   = Get-Field $data "LogonType"
                $sourceIp    = Get-Field $data "IpAddress"
                $workstation = Get-Field $data "WorkstationName"
            }

            4625 {
                $category      = "Failed Logon"
                $targetUser    = Get-Field $data "TargetUserName"
                $failureReason = Get-Field $data "FailureReason"
                $sourceIp      = Get-Field $data "IpAddress"
            }

            4672 {
                $category = "Privileged Logon"
                $privilegedAccount = Get-Field $data "SubjectUserName"
            }

            4688 {
                $category      = "Process Creation"
                $processName   = Get-Field $data "NewProcessName"
                $commandLine   = Get-Field $data "CommandLine"
                $parentProcess = Get-Field $data "ParentProcessName"

                if (-not $parentProcess) {
                    $parentProcess = Get-Field $data "CreatorProcessName"
                }
            }
        }
    }


    # PowerShell events
    if ($SourceType -eq "PowerShell") {

        if ($Event.Id -eq 4104) {
            $category = "PowerShell Script Block"
            $scriptBlockText = Get-Field $data "ScriptBlockText"
        }
    }


    # Sysmon events
    if ($SourceType -eq "Sysmon") {

        switch ($Event.Id) {

            1 {
                $category    = "Process Creation"
                $image       = Get-Field $data "Image"
                $commandLine = Get-Field $data "CommandLine"
                $parentImage = Get-Field $data "ParentImage"
                $hashes      = Get-Field $data "Hashes"
            }

            3 {
                $category        = "Network Connection"
                $destinationIp   = Get-Field $data "DestinationIp"
                $destinationPort = Get-Field $data "DestinationPort"
                $process         = Get-Field $data "Image"
            }

            11 {
                $category        = "File Creation"
                $targetFilename  = Get-Field $data "TargetFilename"
                $creatingProcess = Get-Field $data "Image"
            }

            13 {
                $category = "Registry Modification"

                $targetObject = Get-Field $data "TargetObject"

                if ($targetObject) {

                    $lastSlash = $targetObject.LastIndexOf("\")

                    if ($lastSlash -gt 0) {
                        $registryKey = $targetObject.Substring(0, $lastSlash)
                        $valueName = $targetObject.Substring($lastSlash + 1)
                    }
                    else {
                        $registryKey = $targetObject
                    }
                }
            }

            22 {
                $category     = "DNS Query"
                $queryName    = Get-Field $data "QueryName"
                $queryResults = Get-Field $data "QueryResults"
            }
        }
    }


    # Normalized output
    return [PSCustomObject]@{

        timestamp      = $Event.TimeCreated.ToUniversalTime().ToString("o")
        hostname       = $Event.MachineName
        platform       = "Windows"
        source_type    = $SourceType
        channel        = $Event.LogName
        event_id       = $Event.Id
        event_category = $category
        provider       = $Event.ProviderName
        raw_message    = $Event.Message

        target_user       = $targetUser
        logon_type        = $logonType
        source_ip         = $sourceIp
        workstation       = $workstation
        failure_reason    = $failureReason
        privileged_account = $privilegedAccount

        process_name   = $processName
        command_line   = $commandLine
        parent_process = $parentProcess

        script_block_text = $scriptBlockText

        image        = $image
        parent_image = $parentImage
        hashes       = $hashes

        destination_ip   = $destinationIp
        destination_port = $destinationPort
        process          = $process

        target_filename  = $targetFilename
        creating_process = $creatingProcess

        registry_key = $registryKey
        value_name   = $valueName

        query_name    = $queryName
        query_results = $queryResults
    }
}


# Read logs
$securityEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
)

$sysmonEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
)

$powerShellEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
)


# Normalize events
$events = @()

foreach ($event in $securityEvents) {
    $events += Convert-WindowsEvent $event "Security"
}

foreach ($event in $sysmonEvents) {
    $events += Convert-WindowsEvent $event "Sysmon"
}

foreach ($event in $powerShellEvents) {
    $events += Convert-WindowsEvent $event "PowerShell"
}


# Save JSON
$events |
    ConvertTo-Json -Depth 5 |
    Set-Content $outputFile -Encoding UTF8


# Find top Event IDs
$topIds = @(
    $events | ForEach-Object {

        if ($_.source_type -eq "Sysmon") {
            "Sysmon-$($_.event_id)"
        }
        else {
            "$($_.event_id)"
        }

    } | Group-Object |
        Sort-Object Count -Descending |
        Select-Object -First 4
)

$topText = ($topIds | ForEach-Object { $_.Name }) -join ", "


# Summary
Write-Host "Security events: $($securityEvents.Count)"
Write-Host "Sysmon events: $($sysmonEvents.Count)"
Write-Host "PowerShell events: $($powerShellEvents.Count)"
Write-Host "Total events: $($events.Count)"
Write-Host "Top Event IDs: $topText"
Write-Host "Output: windows_events_export.json"