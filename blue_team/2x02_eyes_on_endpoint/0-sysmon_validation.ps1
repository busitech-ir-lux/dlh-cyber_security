# 0-sysmon_validation.ps1

$log = "Microsoft-Windows-Sysmon/Operational"
$purpose = "Sysmon telemetry validation"
$passed = 0

Write-Host "[*] Running Sysmon telemetry validation..."

# 1. Process Creation
Write-Host "    [1/5] Process creation (Event ID 1)..."
$time = Get-Date
cmd.exe /c whoami | Out-Null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName=$log
    Id=1
    StartTime=$time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*cmd.exe*" -and $_.Message -like "*whoami*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]"
    $passed++
} else {
    Write-Host "          Process creation not captured                               [FAIL]"
}


# 2. Network Connection
Write-Host "    [2/5] Network connection (Event ID 3)..."
$time = Get-Date
Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet | Out-Null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName=$log
    Id=3
    StartTime=$time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*1.1.1.1*" -and $_.Message -like "*443*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          Outbound TCP -> Sysmon EID 3 captured, dest IP/port present   [PASS]"
    $passed++
} else {
    Write-Host "          Network connection not captured                              [FAIL]"
}


# 3. File Creation
Write-Host "    [3/5] File creation (Event ID 11)..."
$file = "C:\Windows\Temp\test.txt"
$time = Get-Date
"Sysmon Test" | Out-File $file
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName=$log
    Id=11
    StartTime=$time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*$file*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          C:\Windows\Temp\test.txt -> Sysmon EID 11 captured            [PASS]"
    $passed++
} else {
    Write-Host "          File creation not captured                                   [FAIL]"
}


# 4. Registry Modification
Write-Host "    [4/5] Registry modification (Event ID 13)..."
$reg = "HKCU:\Software\SysmonTest"
$time = Get-Date

New-Item $reg -Force | Out-Null
$name = "TestValue"
Set-ItemProperty $reg -Name $name -Value "Hello"
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName=$log
    Id=13
    StartTime=$time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*SysmonTest*" -and $_.Message -like "*TestValue*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          HKCU\...\SysmonTest -> Sysmon EID 13 captured                 [PASS]"
    $passed++
} else {
    Write-Host "          Registry modification not captured                           [FAIL]"
}


# 5. DNS Query
Write-Host "    [5/5] DNS query (Event ID 22)..."
$time = Get-Date
Resolve-DnsName example.com | Out-Null
Start-Sleep 2

$event = Get-WinEvent -FilterHashtable @{
    LogName=$log
    Id=22
    StartTime=$time
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*example.com*"
} | Select-Object -First 1

if ($event) {
    Write-Host "          nslookup example.com -> Sysmon EID 22 captured                [PASS]"
    $passed++
} else {
    Write-Host "          DNS query not captured                                       [FAIL]"
}


# Cleanup
Write-Host "[*] Cleanup: removing test artifacts..."

Remove-Item $file -Force -ErrorAction SilentlyContinue
Remove-Item $reg -Recurse -Force -ErrorAction SilentlyContinue

$missed = 5 - $passed

Write-Host "Actions tested: 5 | Captured: $passed | Missed: $missed"
