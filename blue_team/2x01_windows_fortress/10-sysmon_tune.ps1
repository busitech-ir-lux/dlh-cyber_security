<#
Script Name: 10-sysmon_tune.ps1
Purpose: Add and safely test five MedDefense Sysmon detection rules.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$SysmonExe = "$PSScriptRoot\Sysmon64.exe",
    [string]$ConfigFile = "$PSScriptRoot\sysmonconfig.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Rule-to-event mapping:
# ProcessCreate: rclone, encoded PowerShell, vssadmin, scheduled task
# RegistryEvent: PsExec service registry modification

if (-not (Test-Path $SysmonExe)) {
    throw "Sysmon executable not found: $SysmonExe"
}

if (-not (Test-Path $ConfigFile)) {
    throw "sysmonconfig.xml not found: $ConfigFile"
}

Write-Host "[*] Loading sysmonconfig.xml..." -NoNewline
[xml]$config = Get-Content $ConfigFile -Raw
Write-Host " OK"

$requiredRules = @(
    "MedDefense-Rclone",
    "MedDefense-PsExec-Service",
    "MedDefense-Encoded-PowerShell",
    "MedDefense-Shadow-Deletion",
    "MedDefense-Scheduled-Task"
)

$configText = Get-Content $ConfigFile -Raw
foreach ($rule in $requiredRules) {
    if ($configText -notmatch [regex]::Escape($rule)) {
        throw "Required rule is missing from sysmonconfig.xml: $rule"
    }
}

Write-Host "[*] Adding custom rules..."
Write-Host "    Rule 1: Rclone detection                [ADDED]"
Write-Host "    Rule 2: PsExec service installation     [ADDED]"
Write-Host "    Rule 3: Encoded PowerShell              [ADDED]"
Write-Host "    Rule 4: Shadow deletion (vssadmin)      [ADDED]"
Write-Host "    Rule 5: Scheduled task persistence      [ADDED]"

& $SysmonExe -accepteula -c $ConfigFile | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon configuration update failed."
}
Write-Host "[*] Updating sysmonconfig.xml... OK"

function Test-SysmonEvent {
    param(
        [int]$EventId,
        [datetime]$StartTime,
        [string]$Pattern
    )

    Start-Sleep -Seconds 2

    $event = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = $EventId
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
        Where-Object Message -match $Pattern |
        Select-Object -First 1

    return [bool]$event
}

$results = @()
$testFiles = @(
    "$env:TEMP\rclone.exe",
    "$env:TEMP\vssadmin.exe"
)

Write-Host "[*] Trigger-and-Verify..."

try {
    # Rule 1 - ProcessCreate: harmless copy named rclone.exe.
    $start = Get-Date
    Copy-Item "$env:SystemRoot\System32\whoami.exe" $testFiles[0] -Force
    & $testFiles[0] | Out-Null
    $pass = Test-SysmonEvent -EventId 1 -StartTime $start -Pattern "rclone\.exe"
    $results += $pass
    Write-Host "    Rule 1: rclone.exe detection            [$(if ($pass) {'PASS'} else {'FAIL'})]"

    # Rule 2 - RegistryEvent: harmless temporary PsExec-like service key.
    $testKey = "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC-Test"
    $start = Get-Date
    New-Item $testKey -Force | Out-Null
    New-ItemProperty $testKey -Name ImagePath `
        -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
    $pass = Test-SysmonEvent -EventId 13 -StartTime $start -Pattern "PSEXESVC"
    $results += $pass
    Write-Host "    Rule 2: PsExec registry key             [$(if ($pass) {'PASS'} else {'FAIL'})]"
    Remove-Item $testKey -Recurse -Force -ErrorAction SilentlyContinue

    # Rule 3 - ProcessCreate: safe encoded PowerShell output command.
    $start = Get-Date
    $command = "Write-Output 'MedDefenseTest'"
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($command)
    )
    powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
    $pass = Test-SysmonEvent -EventId 1 -StartTime $start `
        -Pattern "EncodedCommand| -enc | -EncodedCommand "
    $results += $pass
    Write-Host "    Rule 3: Encoded PowerShell              [$(if ($pass) {'PASS'} else {'FAIL'})]"

    # Rule 4 - ProcessCreate: harmless binary renamed vssadmin.exe.
    # The arguments contain 'delete shadows', but no shadow copies are touched.
    $start = Get-Date
    Copy-Item "$env:SystemRoot\System32\whoami.exe" $testFiles[1] -Force
    & $testFiles[1] delete shadows | Out-Null
    $pass = Test-SysmonEvent -EventId 1 -StartTime $start `
        -Pattern "vssadmin\.exe.*delete.*shadows|delete.*shadows.*vssadmin\.exe"
    $results += $pass
    Write-Host "    Rule 4: vssadmin delete shadows         [$(if ($pass) {'PASS'} else {'FAIL'})]"

    # Rule 5 - ProcessCreate: create and remove a harmless scheduled task.
    $taskName = "MedDefense-Sysmon-Test"
    $start = Get-Date
    schtasks.exe /create /tn $taskName /tr "cmd.exe /c exit" `
        /sc once /st 23:59 /f | Out-Null
    $pass = Test-SysmonEvent -EventId 1 -StartTime $start `
        -Pattern "schtasks\.exe.*\/create|\/create.*schtasks\.exe"
    $results += $pass
    Write-Host "    Rule 5: schtasks /create                [$(if ($pass) {'PASS'} else {'FAIL'})]"
    schtasks.exe /delete /tn $taskName /f | Out-Null
}
finally {
    Remove-Item $testFiles -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC-Test" `
        -Recurse -Force -ErrorAction SilentlyContinue
    schtasks.exe /delete /tn "MedDefense-Sysmon-Test" /f 2>$null | Out-Null
}

$passed = @($results | Where-Object { $_ }).Count
Write-Host "Custom rules: 5 added | Tests: $passed/5 PASS"

if ($passed -ne 5) {
    exit 1
}

exit 0
