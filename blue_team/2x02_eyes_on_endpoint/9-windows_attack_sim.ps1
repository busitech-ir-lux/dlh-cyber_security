<#
name:
    Windows Attack Simulation - Telemetry Validation (Block 2, Task 9)

purpose and description:
    Executes a controlled, BENIGN sequence of attacker-like actions against the
    LOCAL hardened endpoint to validate detection instrumentation. Every action
    is timestamped (ISO-8601, ms precision) and mapped to its expected detection
    source and MITRE ATT&CK technique. All artifacts are removed after logging.

    >>> RUN ONLY ON A SYSTEM YOU OWN OR ARE AUTHORIZED TO TEST. <<<
    No real C2, no real malware. All payloads are inert placeholders.

NOTES
    Requires: Administrator privileges, PowerShell 5.1+
    Output:   ground_truth.json (kept as deliverable for Task 10)

author: Mahdi Hamidi
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------- Configuration ----------------------------------
$TargetUser      = 'support_update'
$TargetPassword  = ConvertTo-SecureString 'Sim-P@ss!2024xYz' -AsPlainText -Force
$TaskName        = 'SupportUpdateTask'
$StartupDir      = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile     = Join-Path $StartupDir 'support_update.bat'
$SafeIP          = '1.1.1.1'          # Cloudflare DNS – safe, well-known host
$SafePort        = 443

# Resolve script directory (fallback to CWD if run interactively)
$ScriptDir       = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$GroundTruthPath = Join-Path $ScriptDir 'ground_truth.json'

# Ordered collector for ground-truth records
$GroundTruth = [System.Collections.Generic.List[object]]::new()

function Record-Action {
    param(
        [int]$Number,
        [string]$Description,
        [string]$DetectionSource,
        [string]$MitreTechnique,
        [string]$MitreId
    )
    $ts = (Get-Date).ToString('o')   # ISO-8601 with milliseconds + UTC offset
    $GroundTruth.Add([ordered]@{
        action_number      = $Number
        description        = $Description
        timestamp          = $ts
        expected_detection = $DetectionSource
        mitre_technique    = $MitreTechnique
        mitre_id           = $MitreId
    })
    Write-Host ("[{0}] Action {1}: {2}" -f $ts, $Number, $Description) -ForegroundColor Cyan
}

Write-Host "=== Windows Attack Simulation START ===" -ForegroundColor Yellow
Write-Host ("Start time: {0}`n" -f (Get-Date).ToString('o'))

try {
    # === Action 1: Create local user ===================================
    New-LocalUser -Name $TargetUser -Password $TargetPassword -FullName 'Support Update' `
        -Description 'Simulation account - safe to delete' -AccountNeverExpires | Out-Null
    Record-Action -Number 1 `
        -Description "Created local user '$TargetUser'" `
        -DetectionSource "Security 4720 (user account created); Sysmon 1 (process create: net.exe/powershell)" `
        -MitreTechnique "Create Account: Local Account" `
        -MitreId "T1136.001"

    # === Action 2: Add to Administrators ===============================
    Add-LocalGroupMember -Group 'Administrators' -Member $TargetUser
    Record-Action -Number 2 `
        -Description "Added '$TargetUser' to the Administrators group" `
        -DetectionSource "Security 4732 (member added to security-enabled local group); Sysmon 1" `
        -MitreTechnique "Account Manipulation" `
        -MitreId "T1098"

    # === Action 3: Encoded PowerShell (harmless payload) ===============
    $payload = 'Write-Host "C2 beacon"'
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($payload)
    $encoded = [Convert]::ToBase64String($bytes)
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList "-NoProfile -enc $encoded" `
        -WindowStyle Hidden -Wait
    Record-Action -Number 3 `
        -Description "Ran encoded PowerShell (decoded payload: Write-Host 'C2 beacon')" `
        -DetectionSource "Sysmon 1 (cmdline contains -enc / -e / -EncodedCommand variants); PowerShell 4104 (Script Block Logging); Security 4688" `
        -MitreTechnique "Command and Scripting Interpreter: PowerShell; Obfuscated Files or Information" `
        -MitreId "T1059.001; T1027"

    # === Action 4: Scheduled task persistence ==========================
    schtasks /create /tn $TaskName `
        /tr "powershell.exe -NoProfile -Command `"Write-Host persistence`"" `
        /sc onlogon /rl highest /f | Out-Null
    Record-Action -Number 4 `
        -Description "Created scheduled task '$TaskName' (trigger: onlogon)" `
        -DetectionSource "Security 4698 (scheduled task created); Sysmon 1 (schtasks.exe)" `
        -MitreTechnique "Scheduled Task/Job: Scheduled Task" `
        -MitreId "T1053.005"

    # === Action 5: Outbound network connection =========================
    Test-NetConnection -ComputerName $SafeIP -Port $SafePort -InformationLevel Quiet | Out-Null
    Record-Action -Number 5 `
        -Description "Initiated outbound connection to $SafeIP`:$SafePort" `
        -DetectionSource "Sysmon Event ID 3 (network connection detected)" `
        -MitreTechnique "Application Layer Protocol (C2 proxy)" `
        -MitreId "T1071"

    # === Action 6: Startup folder file drop ============================
    "@echo off`r`necho simulation-artifact" | Out-File -FilePath $StartupFile -Encoding ASCII
    Record-Action -Number 6 `
        -Description "Dropped file in Startup folder: $StartupFile" `
        -DetectionSource "Sysmon 11 (file create); Security 4663 (if object-access auditing enabled)" `
        -MitreTechnique "Boot or Logon Autostart Execution: Startup Folder" `
        -MitreId "T1547.001"
}
finally {
    # === Write ground truth (runs even on partial failure) =============
    if ($GroundTruth.Count -gt 0) {
        $GroundTruth | ConvertTo-Json -Depth 4 | Out-File -FilePath $GroundTruthPath -Encoding UTF8
        Write-Host "`nGround truth written to: $GroundTruthPath" -ForegroundColor Green
    }

    # === Cleanup (always runs) =========================================
    Write-Host "`n=== Cleanup ===" -ForegroundColor Yellow

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    schtasks /delete /tn $TaskName /f 2>$null | Out-Null           # scheduled task
    if (Test-Path $StartupFile) { Remove-Item $StartupFile -Force }  # startup file
    if (Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TargetUser                          # user (+ group membership)
    }

    Write-Host "Cleanup complete. All simulation artifacts removed." -ForegroundColor Green
}

Write-Host "`n=== Simulation END ===" -ForegroundColor Yellow
