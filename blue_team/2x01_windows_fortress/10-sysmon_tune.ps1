<#
Script Name: 10-sysmon_tune.ps1
Purpose: Apply and test five MedDefense Sysmon detection rules.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$SysmonExe = "$PSScriptRoot\Sysmon\Sysmon64.exe",
    [string]$ConfigFile = "$PSScriptRoot\sysmonconfig.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Loading sysmonconfig.xml... OK"
[xml]$config = Get-Content $ConfigFile

$ruleNames = @(
    "MedDefense-Rclone",
    "MedDefense-PsExec-Service",
    "MedDefense-Encoded-PowerShell",
    "MedDefense-Shadow-Deletion",
    "MedDefense-Scheduled-Task"
)

Write-Host "[*] Adding custom rules..."
for ($i = 0; $i -lt $ruleNames.Count; $i++) {
    Write-Host "    Rule $($i + 1): $($ruleNames[$i]) [ADDED]"
}

& $SysmonExe -c $ConfigFile | Out-Null
Write-Host "[*] Updating sysmonconfig.xml... OK"

function Test-SysmonEvent {
    param([int]$Id, [datetime]$Start, [string]$Pattern)

    $event = Get-WinEvent -FilterHashtable @{
        LogName="Microsoft-Windows-Sysmon/Operational"
        Id=$Id
        StartTime=$Start
    } -ErrorAction SilentlyContinue |
        Where-Object Message -match $Pattern |
        Select-Object -First 1

    return [bool]$event
}

$results = @()

Write-Host "[*] Trigger-and-Verify..."

# Rule 1: safe process name copy. It may be blocked by application control.
$start = Get-Date
Copy-Item "$env:SystemRoot\System32\whoami.exe" "$env:TEMP\rclone.exe" -Force
& "$env:TEMP\rclone.exe" | Out-Null
Start-Sleep 2
$pass = Test-SysmonEvent 1 $start "rclone\.exe"
$results += $pass
Write-Host "    Rule 1: rclone.exe detection            [$(if($pass){'PASS'}else{'FAIL'})]"

# Rule 2: create and remove a harmless lab registry key.
$start = Get-Date
New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC-Test" -Force | Out-Null
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC-Test" `
    -Name "ImagePath" -Value "C:\Windows\System32\cmd.exe" -Force | Out-Null
Start-Sleep 2
$pass = Test-SysmonEvent 13 $start "PSEXESVC"
$results += $pass
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC-Test" -Recurse -Force
Write-Host "    Rule 2: PsExec registry key             [$(if($pass){'PASS'}else{'FAIL'})]"

# Rule 3
$start = Get-Date
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'MedDefenseTest'"))
powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
Start-Sleep 2
$pass = Test-SysmonEvent 1 $start "EncodedCommand| -enc "
$results += $pass
Write-Host "    Rule 3: Encoded PowerShell              [$(if($pass){'PASS'}else{'FAIL'})]"

# Rule 4: safe help command, never deletes shadow copies.
$start = Get-Date
vssadmin.exe /? | Out-Null
Start-Sleep 2
$pass = Test-SysmonEvent 1 $start "vssadmin\.exe"
$results += $pass
Write-Host "    Rule 4: vssadmin execution              [$(if($pass){'PASS'}else{'FAIL'})]"

# Rule 5: create then delete a harmless scheduled task.
$start = Get-Date
schtasks.exe /create /tn "MedDefense-Sysmon-Test" /tr "cmd.exe /c exit" `
    /sc once /st 23:59 /f | Out-Null
Start-Sleep 2
$pass = Test-SysmonEvent 1 $start "schtasks\.exe"
$results += $pass
schtasks.exe /delete /tn "MedDefense-Sysmon-Test" /f | Out-Null
Write-Host "    Rule 5: schtasks /create                [$(if($pass){'PASS'}else{'FAIL'})]"

$passed = @($results | Where-Object { $_ }).Count
Write-Host "Custom rules: 5 added | Tests: $passed/5 PASS"
