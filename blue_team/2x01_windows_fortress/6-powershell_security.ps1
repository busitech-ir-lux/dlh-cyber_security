<#
Script Name: 6-powershell_security.ps1
Purpose: Configure PowerShell logging and verify Event ID 4104.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - PowerShell Security"
$domain = Get-ADDomain
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

Write-Host "[*] Creating GPO: `"$gpoName`"..." -NoNewline
if (-not $gpo) { $gpo = New-GPO $gpoName; Write-Host " CREATED" }
else { Write-Host " EXISTS" }

$psKey = "HKLM\Software\Policies\Microsoft\Windows\PowerShell"

Set-GPRegistryValue -Name $gpoName -Key "$psKey\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
Write-Host "[*] Configuring Script Block Logging..."
Write-Host "    EnableScriptBlockLogging = 1           [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"

Set-GPRegistryValue -Name $gpoName -Key "$psKey\ModuleLogging" `
    -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName -Key "$psKey\ModuleLogging\ModuleNames" `
    -ValueName "*" -Type String -Value "*" | Out-Null
Write-Host "[*] Configuring Module Logging..."
Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"

Set-GPRegistryValue -Name $gpoName -Key "$psKey\Transcription" `
    -ValueName "EnableTranscripting" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName -Key "$psKey\Transcription" `
    -ValueName "OutputDirectory" -Type String -Value "C:\PSTranscripts" | Out-Null
Set-GPRegistryValue -Name $gpoName -Key "$psKey\Transcription" `
    -ValueName "EnableInvocationHeader" -Type DWord -Value 1 | Out-Null
New-Item -ItemType Directory -Path "C:\PSTranscripts" -Force | Out-Null
Write-Host "[*] Configuring Transcription..."
Write-Host "    OutputDirectory = C:\PSTranscripts     [SET]"

$amsi = [type]::GetType("System.Management.Automation.AmsiUtils")
$amsiDll = Get-Process -Id $PID -Module -ErrorAction SilentlyContinue |
    Where-Object ModuleName -ieq "amsi.dll"
if ($amsi -or $amsiDll) {
    Write-Host "[*] Verifying AMSI... amsi.dll loaded [OK]"
}
else {
    Write-Warning "AMSI integration or amsi.dll was not detected in this host."
}

if (-not (Get-GPInheritance $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
gpupdate.exe /force | Out-Null
Write-Host "[*] Linking GPO and forcing update... COMPLETE"

$testText = "Write-Host 'Test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($testText))
$start = Get-Date
powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
Start-Sleep -Seconds 3

$event = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-PowerShell/Operational"
    Id = 4104
    StartTime = $start
} -ErrorAction SilentlyContinue | Where-Object Message -match "Write-Host" |
    Select-Object -First 1

Write-Host "[*] Testing encoded command..."
Write-Host "    Input: powershell -enc $encoded"
if ($event) { Write-Host "    Event ID 4104 found: `"Write-Host 'Test'`"  [VERIFIED]" }
else { Write-Host "    Event ID 4104 not found yet                [WARN]" }
