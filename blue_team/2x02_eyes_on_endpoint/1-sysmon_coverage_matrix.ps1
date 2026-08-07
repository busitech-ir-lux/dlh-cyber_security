<#
name: 1-sysmon_coverage_matrix.ps1
purpose: Check Sysmon coverage against MITRE ATT&CK techniques.
author: Mahdi Hamidi
#>

Set-StrictMode -Version Latest

$configPath = Join-Path $PSScriptRoot "sysmonconfig.xml"
$outputPath = Join-Path $PSScriptRoot "sysmon_coverage_matrix.json"

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"

if (-not (Test-Path $configPath)) {
    Write-Host "[ERROR] sysmonconfig.xml not found."
    exit 1
}

[xml]$xml = Get-Content $configPath

# Sysmon event name -> Event ID
$eventMap = @{
    "ProcessCreate"         = @(1)
    "FileCreateTime"        = @(2)
    "NetworkConnect"        = @(3)
    "ImageLoad"             = @(7)
    "CreateRemoteThread"    = @(8)
    "ProcessAccess"         = @(10)
    "FileCreate"            = @(11)
    "RegistryEvent"         = @(12,13,14)
    "FileCreateStreamHash"  = @(15)
    "DNSQuery"              = @(22)
}

# Find enabled Event IDs
$enabledIds = @()

foreach ($eventName in $eventMap.Keys) {

    $nodes = $xml.SelectNodes("//$eventName")

    if ($nodes.Count -gt 0) {
        $enabledIds += $eventMap[$eventName]
    }
}

$enabledIds = @($enabledIds | Sort-Object -Unique)


# ATT&CK mappings
$techniques = @(

    @{
        technique_id = "T1059"
        technique_name = "Command and Scripting Interpreter"
        required_event_ids = @(1)
        events = @("ProcessCreate")
        evidence = @("Image", "CommandLine", "User", "ParentImage")
    },

    @{
        technique_id = "T1053"
        technique_name = "Scheduled Task/Job"
        required_event_ids = @(1)
        events = @("ProcessCreate")
        evidence = @("Image", "CommandLine", "ParentImage")
    },

    @{
        technique_id = "T1547"
        technique_name = "Boot or Logon Autostart Execution"
        required_event_ids = @(13)
        events = @("RegistryEvent")
        evidence = @("TargetObject", "Details", "Image")
    },

    @{
        technique_id = "T1055"
        technique_name = "Process Injection"
        required_event_ids = @(8,10)
        events = @("CreateRemoteThread","ProcessAccess")
        evidence = @("SourceImage", "TargetImage", "GrantedAccess")
    },

    @{
        technique_id = "T1071"
        technique_name = "Application Layer Protocol"
        required_event_ids = @(3,22)
        events = @("NetworkConnect","DNSQuery")
        evidence = @("Image", "DestinationIp", "DestinationPort", "QueryName")
    },

    @{
        technique_id = "T1574.002"
        technique_name = "DLL Side-Loading"
        required_event_ids = @(7)
        events = @("ImageLoad")
        evidence = @("Image", "ImageLoaded", "Hashes")
    },

    @{
        technique_id = "T1027"
        technique_name = "Obfuscated or Compressed Files"
        required_event_ids = @(11,15)
        events = @("FileCreate","FileCreateStreamHash")
        evidence = @("Image", "TargetFilename", "Hashes")
    }
)


$matrix = @()

foreach ($technique in $techniques) {

    $required = @($technique.required_event_ids)

    $enabled = @(
        $required | Where-Object { $enabledIds -contains $_ }
    )

    $conflicts = @()

    # Look for include/exclude filters
    foreach ($eventName in $technique.events) {

        $nodes = $xml.SelectNodes("//$eventName")

        foreach ($node in $nodes) {

            if ($null -ne $node.onmatch -and $node.ChildNodes.Count -gt 0) {

                $conflicts += "$eventName has $($node.onmatch) filtering"
            }
        }
    }


    # Decide coverage
    if ($enabled.Count -eq 0) {

        $status = "blind"
        $recommendation = "Enable required Sysmon Event IDs."

    }
    elseif ($enabled.Count -lt $required.Count) {

        $status = "partial"
        $recommendation = "Enable the missing Event IDs."

    }
    elseif ($conflicts.Count -gt 0) {

        $status = "partial"
        $recommendation = "Review include/exclude filters."

    }
    else {

        $status = "covered"
        $recommendation = "No tuning required."
    }


    $matrix += [PSCustomObject]@{

        technique_id             = $technique.technique_id
        technique_name           = $technique.technique_name
        required_event_ids       = $required
        enabled_event_ids        = $enabled
        filter_conflicts         = $conflicts
        coverage_status          = $status
        evidence_fields_expected = $technique.evidence
        recommendation           = $recommendation
    }
}


# Save JSON
$matrix | ConvertTo-Json -Depth 5 |
    Set-Content $outputPath


# Summary
$covered = @($matrix | Where-Object coverage_status -eq "covered").Count
$partial = @($matrix | Where-Object coverage_status -eq "partial").Count
$blind   = @($matrix | Where-Object coverage_status -eq "blind").Count

Write-Host "Enabled Event IDs: $($enabledIds -join ', ')"
Write-Host "Techniques assessed: $($matrix.Count)"
Write-Host "Covered: $covered"
Write-Host "Partial: $partial"
Write-Host "Blind: $blind"
Write-Host "Report saved to: sysmon_coverage_matrix.json"