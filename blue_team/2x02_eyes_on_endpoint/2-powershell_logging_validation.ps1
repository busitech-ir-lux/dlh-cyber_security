<#
name: 1-sysmon_coverage_matrix.ps1
purpose: Check Sysmon coverage against MITRE ATT&CK techniques.
author: Mahdi Hamidi
#>


Set-StrictMode -Version Latest

$log = "Microsoft-Windows-PowerShell/Operational"
$transcriptPath = "C:\PSTranscripts"
$passed = 0

Write-Host "[*] Testing PowerShell logging coverage..."


# 1. Simple command
Write-Host "    [1/5] Simple command (Get-Process)..."

$time = Get-Date
powershell.exe -NoProfile -Command "Get-Process | Out-Null"
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName   = $log
    Id        = 4104
    StartTime = $time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*Get-Process*"
} | Select-Object -First 1

if ($event) {
    Write-Host '          EID 4104: "Get-Process" captured [CAPTURED: FULL] [PASS]'
    $passed++
}
else {
    Write-Host "          EID 4104: Get-Process [MISSED] [FAIL]"
}


# 2. Encoded command
Write-Host "    [2/5] Encoded command..."

$command = 'Write-Host "Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)

Write-Host "          Input: -enc $encoded"

$time = Get-Date
powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName   = $log
    Id        = 4104
    StartTime = $time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like '*Write-Host "Test"*'
} | Select-Object -First 1

if ($event) {
    Write-Host '          EID 4104: "Write-Host Test" decoded [CAPTURED: FULL] [PASS]'
    $passed++
}
else {
    Write-Host "          EID 4104: Decoded content [MISSED] [FAIL]"
}


# 3. Module Logging
Write-Host "    [3/5] Module import..."

$time = Get-Date
powershell.exe -NoProfile -Command "Import-Module ActiveDirectory" 2>$null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName   = $log
    Id        = 4103
    StartTime = $time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*ActiveDirectory*"
} | Select-Object -First 1

if ($event) {
    Write-Host '          EID 4103: "Import-Module ActiveDirectory" [CAPTURED: FULL] [PASS]'
    $passed++
}
else {
    Write-Host "          EID 4103: Module import [MISSED] [FAIL]"
}


# 4. Multi-line script block
Write-Host "    [4/5] Multi-line ScriptBlock..."

$multiLine = @'
Write-Output "PSLOG_LINE_01"
Write-Output "PSLOG_LINE_02"
Write-Output "PSLOG_LINE_03"
Write-Output "PSLOG_LINE_04"
Write-Output "PSLOG_LINE_05"
Write-Output "PSLOG_LINE_06"
Write-Output "PSLOG_LINE_07"
Write-Output "PSLOG_LINE_08"
Write-Output "PSLOG_LINE_09"
Write-Output "PSLOG_LINE_10"
Write-Output "PSLOG_LINE_11"
Write-Output "PSLOG_LINE_12"
'@

$time = Get-Date
powershell.exe -NoProfile -Command $multiLine | Out-Null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName   = $log
    Id        = 4104
    StartTime = $time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*PSLOG_LINE_01*" -and
    $_.Message -like "*PSLOG_LINE_12*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          EID 4104: Full block captured (12 lines) [CAPTURED: FULL] [PASS]"
    $passed++
}
else {
    Write-Host "          EID 4104: Full block not found [MISSED/PARTIAL] [FAIL]"
}


# 5. Transcription
Write-Host "    [5/5] Transcription file..."

$time = Get-Date
powershell.exe -NoProfile -Command "Write-Output 'TranscriptTest'" | Out-Null
Start-Sleep 2

$transcript = Get-ChildItem $transcriptPath -Filter "*.txt" -File -Recurse `
    -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -ge $time
    } | Select-Object -First 1

if ($transcript) {
    Write-Host "          C:\PSTranscripts\*.txt exists [CAPTURED: FULL] [PASS]"
    $passed++
}
else {
    Write-Host "          Transcription file [MISSED] [FAIL]"
}


$missed = 5 - $passed

Write-Host "Tests: 5 | Captured: $passed | Missed: $missed"