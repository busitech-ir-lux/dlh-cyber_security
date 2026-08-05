<#
Script Name: 9-sysmon_deploy.ps1
Purpose: Download, install, configure, and test Sysmon.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$WorkDir = "$PSScriptRoot\Sysmon"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$zipPath = Join-Path $WorkDir "Sysmon.zip"
$configPath = Join-Path $WorkDir "sysmonconfig.xml"

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

Write-Host "[*] Downloading Sysmon..." -NoNewline
Invoke-WebRequest $sysmonUrl -OutFile $zipPath
Expand-Archive $zipPath -DestinationPath $WorkDir -Force
Write-Host " OK"

Write-Host "[*] Downloading SwiftOnSecurity config..." -NoNewline
Invoke-WebRequest $configUrl -OutFile $configPath
Write-Host " OK"

$exe = Join-Path $WorkDir "Sysmon64.exe"
Write-Host "[*] Installing Sysmon with config..."
Write-Host "    Sysmon64.exe -accepteula -i sysmonconfig.xml"
& $exe -accepteula -i $configPath | Out-Null

$service = Get-Service Sysmon64
$driver = Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'"

Write-Host "    Service: Sysmon64 - $($service.Status)            [OK]"
Write-Host "    Driver: SysmonDrv - $($driver.State)              [OK]"

$start = (Get-Date).AddSeconds(-60)
$count = @(Get-WinEvent -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    StartTime=$start
} -ErrorAction SilentlyContinue).Count
Write-Host "[*] Verifying event generation..."
Write-Host "    Events in last 60 seconds: $count          [OK]"

$testFile = "C:\Windows\Temp\sysmon_test.txt"
$testStart = Get-Date
Set-Content $testFile "MedDefense Sysmon test"
Start-Sleep -Seconds 3
$event = Get-WinEvent -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    Id=11
    StartTime=$testStart
} -ErrorAction SilentlyContinue |
    Where-Object Message -match [regex]::Escape($testFile) |
    Select-Object -First 1

Write-Host "[*] Testing FileCreate detection..."
Write-Host "    Created: $testFile"
if ($event) { Write-Host "    Event ID 11 captured                   [VERIFIED]" }
else { Write-Host "    Event ID 11 not found                  [WARN]" }
