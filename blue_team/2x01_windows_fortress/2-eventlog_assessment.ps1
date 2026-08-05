<#
Script Name: 2-eventlog_assessment.ps1
Purpose: Assess critical Windows Security event logging.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$OutputFile = "$PSScriptRoot\eventlog_assessment.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-AuditEnabled {
    param(
        [string]$Subcategory,
        [ValidateSet("Success", "Failure")]
        [string]$RequiredSetting
    )

    $result = (& auditpol.exe /get /subcategory:"$Subcategory" /r 2>&1) -join "`n"

    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for '$Subcategory': $result"
    }

    return $result -match $RequiredSetting
}

$events = @(
    [pscustomobject]@{
        EventId = 4624
        Description = "Successful Logon"
        Subcategory = "Logon"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4625
        Description = "Failed Logon"
        Subcategory = "Logon"
        RequiredSetting = "Failure"
    },
    [pscustomobject]@{
        EventId = 4648
        Description = "Explicit Credentials"
        Subcategory = "Logon"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4688
        Description = "Process Creation"
        Subcategory = "Process Creation"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4720
        Description = "Account Created"
        Subcategory = "User Account Management"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4726
        Description = "Account Deleted"
        Subcategory = "User Account Management"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4732
        Description = "Member Added to Group"
        Subcategory = "Security Group Management"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 4672
        Description = "Special Logon"
        Subcategory = "Special Logon"
        RequiredSetting = "Success"
    },
    [pscustomobject]@{
        EventId = 1102
        Description = "Audit Log Cleared"
        Subcategory = "Other System Events"
        RequiredSetting = "Success"
    }
)

Write-Host "Reading current audit policy..."

$auditPolicyText = (& auditpol.exe /get /category:* 2>&1) -join "`n"

if ($LASTEXITCODE -ne 0) {
    throw "Unable to read audit policy: $auditPolicyText"
}

$startTime = (Get-Date).AddHours(-$Hours)
$eventIds = @($events.EventId)

Write-Host "Checking Security events from the last $Hours hours..."

$generatedEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = $eventIds
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
)

$results = @(
    foreach ($item in $events) {
        $configured = Test-AuditEnabled `
            -Subcategory $item.Subcategory `
            -RequiredSetting $item.RequiredSetting

        $matchingEvents = @(
            $generatedEvents |
            Where-Object Id -eq $item.EventId
        )

        $status = if ($matchingEvents.Count -gt 0) {
            "[GENERATING]"
        }
        elseif ($configured) {
            "[CONFIGURED - NO EVENTS]"
        }
        else {
            "[NOT CONFIGURED]"
        }

        [pscustomobject]@{
            EventId          = $item.EventId
            Description      = $item.Description
            AuditSubcategory = $item.Subcategory
            RequiredAudit    = $item.RequiredSetting
            Configured       = $configured
            EventsLast24Hours = $matchingEvents.Count
            Status           = $status
        }
    }
)

Write-Host ""
$results |
    Select-Object `
        @{Name="Event ID"; Expression={$_.EventId}},
        Description,
        @{Name="Audit Subcategory"; Expression={$_.AuditSubcategory}},
        Status |
    Format-Table -AutoSize

$summary = [ordered]@{
    generating = @($results | Where-Object Status -eq "[GENERATING]").Count
    configured_no_events = @(
        $results |
        Where-Object Status -eq "[CONFIGURED - NO EVENTS]"
    ).Count
    not_configured = @(
        $results |
        Where-Object Status -eq "[NOT CONFIGURED]"
    ).Count
}

$report = [ordered]@{
    metadata = [ordered]@{
        script = "2-eventlog_assessment.ps1"
        computer = $env:COMPUTERNAME
        generated_at = (Get-Date).ToString("o")
        assessment_window_hours = $Hours
    }
    summary = $summary
    results = $results
    raw_audit_policy = $auditPolicyText
}

$report |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $OutputFile -Encoding UTF8

Write-Host "Generating: $($summary.generating)"
Write-Host "Configured but no events: $($summary.configured_no_events)"
Write-Host "Not configured: $($summary.not_configured)"
Write-Host "Report saved to: $OutputFile"
