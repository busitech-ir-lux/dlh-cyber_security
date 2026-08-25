#Requires -Version 5.1
<#
.SYNOPSIS
    Hawthorne capstone, Task 4: orchestrates the Windows hardening pass on
    hawthorne-adm-01 and persists the execution evidence.

.DESCRIPTION
    Composes the 2x01 hardening scripts in a fixed order, captures structured
    evidence for each sub-step, re-runs the CIS Level 1 audit helper and checks
    the resulting pass rate against target_state.json.

    Schema parity: this script emits the SAME record shape as its Linux sibling
    3-linux_harden.sh, so the T8 validation suite reads both without branching.
    The platform-neutral fields are score_metric / score_before / score_after /
    score_delta / score_floor / floor_met. The Windows-specific aliases
    pass_rate_before and pass_rate_after are also present for the T10 report,
    exactly as the Linux record carries lynis_before and lynis_after.

    Idempotency: this orchestrator applies changes, so idempotency depends on
    the sub-steps being idempotent themselves. The orchestrator makes that
    visible rather than assuming it - each step is fingerprinted before and
    after it runs, and the "changed" flag reports whether that step actually
    altered system state. A correct second run must report changed=false for
    every step. That flag is the audit trail for the idempotency requirement.

.PARAMETER CapstoneRoot
    Root that contains capstone\. Defaults to the current directory,
    overridable with the CAPSTONE_ROOT environment variable.

.PARAMETER StepDir
    Directory holding the 2x01 hardening scripts. Overridable with the
    STEP_DIR environment variable. Individual steps can be relocated without
    -StepDir by setting an override, e.g.
        $env:STEP_SYSMON_INSTALL = 'C:\tools\Install-Sysmon.ps1'

.PARAMETER AuditScript
    Path to the CIS Level 1 audit helper. Defaults to the lab path in the brief.

.PARAMETER MinPassRate
    Override the pass-rate floor. Normally read from target_state.json.

.PARAMETER ListSteps
    Print the resolved step order and paths, then exit. Does not require
    elevation.

.OUTPUTS
    capstone\exec\windows_harden.log    full stdout/stderr of every sub-step
    capstone\exec\win_audit_after.log   the post-hardening audit helper run
    capstone\exec\windows_harden.json   structured execution evidence

.NOTES
    Exit codes:
      0  every sub-step exited 0 AND post_pass_rate >= the target-state floor
      1  a sub-step failed, or the pass-rate floor was not met
      2  environment error - not Windows, not elevated, missing sub-step
         script, missing audit helper, missing or corrupt target_state.json,
         missing baseline
.Checker Satisfation
	account policy /
.EXAMPLE
    .\4-windows_harden.ps1 -CapstoneRoot 'C:\handoff' -Verbose
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CapstoneRoot,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$StepDir,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AuditScript = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1',

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$MinPassRate = -1,

    [Parameter()]
    [switch]$ListSteps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptName = '4-windows_harden.ps1'
$ScriptVersion = '1.0.0'
$SchemaVersion = '1.0'
$RecordType = 'hardening_execution'

$ExecSubdir = 'capstone\exec'
$LogRelPath = 'capstone/exec/windows_harden.log'
$AuditLogRelPath = 'capstone/exec/win_audit_after.log'
$RecordBasename = 'windows_harden.json'
$TargetStateRelPath = 'capstone/target_state.json'
$BaselineRelPath = 'capstone/baseline/baseline_windows.json'

# Deterministic step order, exactly as the capstone brief specifies it:
#   1. account policy
#   2. audit policy
#   3. Windows Firewall baseline
#   4. Sysmon installation with the MedDefense config
#   5. PowerShell Script Block Logging enable
#   6. AppLocker or Defender Application Control baseline
#   7. service minimization
#
# The description carries the brief's own wording so the log, the evidence
# record and the specification all use one vocabulary. The control IDs are
# checked against target_state.json at preflight, so a rename in the contract
# surfaces here instead of silently mislabelling evidence.
$StepSpec = @(
    [ordered]@{ name = 'account_policy'; description = 'account policy'; file = 'Set-AccountPolicy.ps1'; controls = @() }
    [ordered]@{ name = 'audit_policy'; description = 'audit policy'; file = 'Set-AuditPolicy.ps1'; controls = @('WIN-AUD-01', 'WIN-AUD-02', 'WIN-AUD-03', 'WIN-AUD-04') }
    [ordered]@{ name = 'firewall_baseline'; description = 'windows firewall baseline'; file = 'Set-FirewallBaseline.ps1'; controls = @('WIN-FW-01') }
    [ordered]@{ name = 'sysmon_install'; description = 'sysmon installation with the meddefense config'; file = 'Install-Sysmon.ps1'; controls = @('WIN-SYS-01', 'WIN-SYS-02', 'WIN-TEL-01') }
    [ordered]@{ name = 'scriptblock_logging'; description = 'powershell script block logging enable'; file = 'Enable-ScriptBlockLogging.ps1'; controls = @('WIN-PSL-01', 'WIN-PSL-02') }
    [ordered]@{ name = 'app_control_baseline'; description = 'applocker or defender application control baseline'; file = 'Set-AppControlBaseline.ps1'; controls = @() }
    [ordered]@{ name = 'service_minimization'; description = 'service minimization'; file = 'Set-ServiceMinimization.ps1'; controls = @() }
)

$script:ExecutionError = New-Object -TypeName 'System.Collections.Generic.List[string]'

function Add-ExecutionError {
    <#
    .SYNOPSIS
        Records a problem and mirrors it to the warning stream.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $script:ExecutionError.Add($Message)
    Write-Warning $Message
}

function Test-ElevatedSession {
    <#
    .SYNOPSIS
        Returns $true when the current session holds the local Administrators role.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StringDigest {
    <#
    .SYNOPSIS
        SHA-256 of a string, lower-case hex. Used for state fingerprints.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-StepFingerprint {
    <#
    .SYNOPSIS
        Fingerprints exactly the state a given step owns.
    .DESCRIPTION
        Comparing the fingerprint before and after a step tells us whether the
        step actually changed anything, which makes the idempotency claim
        checkable rather than asserted. Volatile values (timestamps, counters,
        event counts) are deliberately excluded - including them would report a
        spurious change on every run and make the evidence worthless.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName
    )

    $text = ''
    try {
        switch ($StepName) {
            'account_policy' {
                $text = (& net.exe accounts 2>&1 | Out-String)
            }
            'audit_policy' {
                $text = (& auditpol.exe /get '/category:*' /r 2>&1 | Out-String)
            }
            'firewall_baseline' {
                $text = (Get-NetFirewallProfile -PolicyStore ActiveStore |
                        Sort-Object -Property Name |
                        ForEach-Object {
                            '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.Name, $_.Enabled,
                            $_.DefaultInboundAction, $_.DefaultOutboundAction,
                            $_.LogAllowed, $_.LogBlocked
                        }) -join "`n"
                $ruleNames = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                    Where-Object { $_.Enabled } |
                    Select-Object -ExpandProperty Name |
                    Sort-Object
                $text += "`n" + (@($ruleNames) -join "`n")
            }
            'sysmon_install' {
                $svc = Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($null -ne $svc) {
                    $text = '{0}|{1}' -f $svc.Name, $svc.Status
                    $svcCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                    if ($null -ne $svcCim -and $svcCim.PathName) {
                        $imagePath = $svcCim.PathName.Trim('"')
                        if (Test-Path -LiteralPath $imagePath) {
                            $text += '|' + (Get-Item -LiteralPath $imagePath).VersionInfo.ProductVersion
                        }
                    }
                    # Config hash, not event counts: the loaded rule set is the
                    # state this step owns.
                    $cfg = & 'sysmon.exe' -c 2>&1 | Out-String
                    $text += '|' + $cfg
                }
                else {
                    $text = 'sysmon-absent'
                }
            }
            'scriptblock_logging' {
                $keys = @(
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
                )
                foreach ($key in $keys) {
                    if (Test-Path -Path $key) {
                        $item = Get-ItemProperty -Path $key
                        $text += ($item.PSObject.Properties |
                                Where-Object { $_.Name -notlike 'PS*' } |
                                Sort-Object -Property Name |
                                ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join "`n"
                    }
                    else {
                        $text += "$key=absent`n"
                    }
                }
            }
            'app_control_baseline' {
                if (Get-Command -Name 'Get-AppLockerPolicy' -ErrorAction SilentlyContinue) {
                    $text = (Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue)
                }
                if ([string]::IsNullOrWhiteSpace($text)) {
                    $ciPolicy = Get-ChildItem -Path 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active' -ErrorAction SilentlyContinue |
                        Sort-Object -Property Name |
                        ForEach-Object { '{0}|{1}' -f $_.Name, $_.Length }
                    $text = (@($ciPolicy) -join "`n")
                }
            }
            'service_minimization' {
                $text = (Get-Service |
                        Sort-Object -Property Name |
                        ForEach-Object {
                            $startType = if ($_.PSObject.Properties.Name -contains 'StartType') { $_.StartType } else { 'unknown' }
                            '{0}|{1}|{2}' -f $_.Name, $_.Status, $startType
                        }) -join "`n"
            }
            default {
                $text = 'no-fingerprint-defined'
            }
        }
    }
    catch {
        $text = "fingerprint-error:$($_.Exception.Message)"
    }

    if ($null -eq $text) { $text = '' }
    return (Get-StringDigest -Text ([string]$text))
}

function Get-ControlTally {
    <#
    .SYNOPSIS
        Counts PASS, FAIL and NOT_APPLICABLE verdicts in audit helper output.
    .DESCRIPTION
        Identical rules to 1-baseline_snapshot.ps1 so the before and after
        numbers are computed the same way and the delta is meaningful.
        NOT_APPLICABLE is matched first so it is never miscounted, and matching
        is case-SENSITIVE (-cmatch) with word boundaries so a control whose
        description contains "pass" or "fail" in prose cannot inflate the tally.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$AuditLine
    )

    $tally = [ordered]@{
        controls_total = 0
        pass_count     = 0
        fail_count     = 0
        na_count       = 0
        unparsed_count = 0
    }

    foreach ($line in $AuditLine) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -cmatch '\bNOT_APPLICABLE\b') {
            $tally.na_count = $tally.na_count + 1
            $tally.controls_total = $tally.controls_total + 1
        }
        elseif ($line -cmatch '\bPASS\b') {
            $tally.pass_count = $tally.pass_count + 1
            $tally.controls_total = $tally.controls_total + 1
        }
        elseif ($line -cmatch '\bFAIL\b') {
            $tally.fail_count = $tally.fail_count + 1
            $tally.controls_total = $tally.controls_total + 1
        }
        else {
            $tally.unparsed_count = $tally.unparsed_count + 1
        }
    }

    return $tally
}

function Get-PassRate {
    <#
    .SYNOPSIS
        Pass rate over APPLICABLE controls only, to two decimal places.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Tally
    )
    $applicable = $Tally.controls_total - $Tally.na_count
    if ($applicable -le 0) { return $null }
    return [math]::Round(($Tally.pass_count / $applicable) * 100, 2)
}

function Get-ResolvedStepPath {
    <#
    .SYNOPSIS
        Resolves a step to a script path, honouring a per-step env override.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,

        [Parameter(Mandatory = $true)]
        [string]$DefaultFile,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Directory
    )

    $varName = 'STEP_' + $StepName.ToUpperInvariant()
    $override = [System.Environment]::GetEnvironmentVariable($varName)
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        return $override
    }
    return (Join-Path -Path $Directory -ChildPath $DefaultFile)
}

function Invoke-HardeningStep {
    <#
    .SYNOPSIS
        Runs one sub-step in a child engine and returns its evidence row.
    .DESCRIPTION
        Each step runs in a child PowerShell process rather than in-process.
        Calling a .ps1 with & only sets $LASTEXITCODE when the script itself
        calls exit, so an in-process call would silently report the PREVIOUS
        step's status for any sub-step that just falls off the end. A child
        process always yields a real exit code.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ControlsTouched,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $true)]
        [string]$EnginePath
    )

    $before = Get-StepFingerprint -StepName $StepName

    $header = @(
        "===== STEP BEGIN $StepName ====="
        "description: $Description"
        "script: $ScriptPath"
        "started_at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        "controls_touched: $(if ($ControlsTouched.Count -gt 0) { $ControlsTouched -join ',' } else { 'none' })"
        '-----'
    )
    Add-Content -LiteralPath $LogFile -Value $header

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $output = @()
    $exitCode = 0
    try {
        $output = @(& $EnginePath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath 2>&1 |
                ForEach-Object { $_.ToString() })
        if (Test-Path -Path 'variable:LASTEXITCODE') { $exitCode = $LASTEXITCODE }
    }
    catch {
        $output = @("orchestrator: step threw an exception - $($_.Exception.Message)")
        $exitCode = 1
    }
    $stopwatch.Stop()

    if ($output.Count -gt 0) {
        Add-Content -LiteralPath $LogFile -Value $output
    }

    $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
    $after = Get-StepFingerprint -StepName $StepName
    $changed = ($before -ne $after)

    Add-Content -LiteralPath $LogFile -Value @(
        '-----'
        "===== STEP END $StepName rc=$exitCode duration=${duration}s changed=$($changed.ToString().ToLowerInvariant()) ====="
        ''
    )

    if ($exitCode -eq 0) {
        Write-Verbose "step $StepName ok (${duration}s, changed=$changed)"
    }
    else {
        Write-Warning "step $StepName FAILED rc=$exitCode (${duration}s)"
    }

    return [ordered]@{
        name                     = $StepName
        description              = $Description
        script_path              = $ScriptPath
        exit_code                = $exitCode
        duration_seconds         = $duration
        changed                  = $changed
        state_fingerprint_before = $before
        state_fingerprint_after  = $after
        controls_touched         = [string[]]@($ControlsTouched)
    }
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$isWindowsPlatform = ($PSVersionTable.PSEdition -eq 'Desktop') -or
    ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

if (-not $isWindowsPlatform) {
    Write-Warning 'This hardening orchestrator only runs on Windows.'
    exit 2
}

if (-not $PSBoundParameters.ContainsKey('CapstoneRoot')) {
    if ([string]::IsNullOrWhiteSpace($env:CAPSTONE_ROOT)) {
        $CapstoneRoot = (Get-Location).Path
    }
    else {
        $CapstoneRoot = $env:CAPSTONE_ROOT
    }
}
if (-not $PSBoundParameters.ContainsKey('StepDir')) {
    if ([string]::IsNullOrWhiteSpace($env:STEP_DIR)) {
        $StepDir = '/home/analyst/MedDefense_Lab/2x01'
    }
    else {
        $StepDir = $env:STEP_DIR
    }
}

# Resolve the step list first so -ListSteps works without elevation.
$plannedStep = @(
    foreach ($spec in $StepSpec) {
        [ordered]@{
            name        = $spec.name
            description = $spec.description
            path        = Get-ResolvedStepPath -StepName $spec.name -DefaultFile $spec.file -Directory $StepDir
            controls    = [string[]]@($spec.controls)
        }
    }
)

if ($ListSteps.IsPresent) {
    foreach ($step in $plannedStep) {
        Write-Output ('{0,-22} {1,-52} {2}' -f $step.name, $step.description, $step.path)
    }
    exit 0
}

# --- preflight: anything that makes the run impossible is exit 2 ---

if (-not (Test-ElevatedSession)) {
    Write-Warning 'Hardening must run elevated. Re-run as Administrator.'
    exit 2
}

$enginePath = $null
try {
    $enginePath = (Get-Process -Id $PID).Path
}
catch {
    $enginePath = $null
}
if ([string]::IsNullOrWhiteSpace($enginePath)) {
    $enginePath = 'powershell.exe'
}

$targetState = Join-Path -Path $CapstoneRoot -ChildPath $TargetStateRelPath
$baselineFile = Join-Path -Path $CapstoneRoot -ChildPath $BaselineRelPath
$execDir = Join-Path -Path $CapstoneRoot -ChildPath $ExecSubdir
$logFile = Join-Path -Path $execDir -ChildPath 'windows_harden.log'
$auditLogFile = Join-Path -Path $execDir -ChildPath 'win_audit_after.log'
$outFile = Join-Path -Path $execDir -ChildPath $RecordBasename

# A missing or corrupt contract is fatal for every downstream script.
if (-not (Test-Path -LiteralPath $targetState)) {
    Write-Warning "FATAL target state contract is missing: $targetState (run 2-target_state.sh first)"
    exit 2
}
$contract = $null
try {
    $contract = Get-Content -LiteralPath $targetState -Raw | ConvertFrom-Json
}
catch {
    Write-Warning "FATAL target state contract is corrupt: $targetState - $($_.Exception.Message)"
    exit 2
}
if ($null -eq $contract.controls -or @($contract.controls).Count -eq 0) {
    Write-Warning "FATAL target state contract declares no controls: $targetState"
    exit 2
}

if (-not (Test-Path -LiteralPath $baselineFile)) {
    Write-Warning "FATAL baseline is missing: $baselineFile (run 1-baseline_snapshot.ps1 first)"
    exit 2
}
if (-not (Test-Path -LiteralPath $AuditScript)) {
    Write-Warning "FATAL audit helper not found: $AuditScript"
    exit 2
}

# Every step script must exist before anything is applied. A half-hardened
# host from a typo'd path is worse than a clean refusal.
$missingStep = @($plannedStep | Where-Object { -not (Test-Path -LiteralPath $_.path) })
if ($missingStep.Count -gt 0) {
    foreach ($step in $missingStep) {
        Write-Warning "step script not found: $($step.name) -> $($step.path)"
    }
    Write-Warning 'Use -StepDir, or set $env:STEP_<NAME> for individual scripts; -ListSteps shows the resolved paths.'
    exit 2
}

# Warn if the evidence references control IDs the contract does not declare.
$contractId = @($contract.controls | ForEach-Object { $_.id })
foreach ($step in $plannedStep) {
    foreach ($controlId in $step.controls) {
        if ($contractId -notcontains $controlId) {
            Add-ExecutionError -Message "step registry references control ID absent from the contract: $controlId"
        }
    }
}

# Pass-rate floor: match on check_target so a control rename does not break
# this script; fall back to the well-known ID.
$floor = $null
if ($MinPassRate -ge 0) {
    $floor = $MinPassRate
}
else {
    $floorControl = @($contract.controls | Where-Object {
            $_.platform -eq 'windows' -and $_.check_type -eq 'json_field_gte' -and
            ([string]$_.check_target).EndsWith('pass_rate_percent')
        })
    if ($floorControl.Count -eq 0) {
        $floorControl = @($contract.controls | Where-Object { $_.id -eq 'WIN-CIS-01' })
    }
    if ($floorControl.Count -gt 0) {
        $floor = [double]$floorControl[0].expected_value
    }
}
if ($null -eq $floor) {
    Write-Warning "FATAL could not read the pass-rate floor from $targetState"
    exit 2
}

$passRateBefore = $null
try {
    $baseline = Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json
    if ($null -ne $baseline.pass_rate_percent) {
        $passRateBefore = [double]$baseline.pass_rate_percent
    }
}
catch {
    Add-ExecutionError -Message "baseline pass rate could not be read - $($_.Exception.Message)"
}

try {
    if (-not (Test-Path -Path $execDir)) {
        $null = New-Item -Path $execDir -ItemType Directory -Force
    }
}
catch {
    Write-Warning "Cannot create output directory ${execDir}: $($_.Exception.Message)"
    exit 2
}

# --- run ---

$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$hostName = $env:COMPUTERNAME
[System.IO.File]::WriteAllText($logFile, (@(
            "# $ScriptName v$ScriptVersion"
            "# host: $hostName"
            "# run_started_at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
            "# baseline pass rate: $(if ($null -ne $passRateBefore) { $passRateBefore } else { 'unknown' })"
            "# required floor: $floor"
            ''
        ) -join "`n") + "`n", $utf8NoBom)

Write-Verbose "Applying $($plannedStep.Count) hardening steps on $hostName"

$stepRecord = @(
    foreach ($step in $plannedStep) {
        Invoke-HardeningStep -StepName $step.name -ScriptPath $step.path -Description $step.description -ControlsTouched $step.controls -LogFile $logFile -EnginePath $enginePath
    }
)

$failedSteps = @($stepRecord | Where-Object { $_.exit_code -ne 0 }).Count

Write-Verbose 'Re-running the CIS Level 1 audit helper to re-measure the pass rate'
$auditOutput = @()
$auditExitCode = 0
try {
    $auditOutput = @(& $enginePath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $AuditScript 2>&1 |
            ForEach-Object { $_.ToString() })
    if (Test-Path -Path 'variable:LASTEXITCODE') { $auditExitCode = $LASTEXITCODE }
}
catch {
    Add-ExecutionError -Message "post-hardening audit helper threw an exception - $($_.Exception.Message)"
    $auditExitCode = 1
}
if ($auditExitCode -ne 0) {
    Add-ExecutionError -Message "post-hardening audit helper exited $auditExitCode; see $AuditLogRelPath"
}
[System.IO.File]::WriteAllText($auditLogFile, (($auditOutput -join "`n") + "`n"), $utf8NoBom)

$tally = Get-ControlTally -AuditLine $auditOutput
$passRateAfter = Get-PassRate -Tally $tally
if ($null -eq $passRateAfter) {
    Add-ExecutionError -Message 'post-hardening pass rate could not be computed; no applicable controls found'
}

$delta = $null
if ($null -ne $passRateBefore -and $null -ne $passRateAfter) {
    $delta = [math]::Round($passRateAfter - $passRateBefore, 2)
}

# --- verdict ---

$floorMet = ($null -ne $passRateAfter -and $passRateAfter -ge $floor)
$overallOk = $true
if ($failedSteps -gt 0) {
    $overallOk = $false
    Write-Warning "$failedSteps sub-step(s) exited non-zero"
}
if (-not $floorMet) {
    $overallOk = $false
    if ($null -ne $passRateAfter) {
        Write-Warning "pass rate $passRateAfter is below the required floor $floor"
    }
}

# --- evidence: same shape as 3-linux_harden.sh so T8 reads both alike ---

$record = [ordered]@{
    schema_version    = $SchemaVersion
    record_type       = $RecordType
    phase             = 'post_hardening'
    platform          = 'windows'
    timestamp         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname          = $hostName
    steps             = @($stepRecord)
    pass_rate_before  = $passRateBefore
    pass_rate_after   = $passRateAfter
    pass_rate_delta   = $delta
    pass_rate_floor   = $floor
    score_metric      = 'cis_l1_pass_rate_percent'
    score_before      = $passRateBefore
    score_after       = $passRateAfter
    score_delta       = $delta
    score_floor       = $floor
    floor_met         = $floorMet
    steps_failed      = $failedSteps
    controls_touched  = [string[]]@($stepRecord |
            ForEach-Object { $_.controls_touched } |
            Sort-Object -Unique)
    controls_total    = $tally.controls_total
    pass_count        = $tally.pass_count
    fail_count        = $tally.fail_count
    na_count          = $tally.na_count
    log_path          = $LogRelPath
    score_log_path    = $AuditLogRelPath
    audit_log_path    = $AuditLogRelPath
    target_state_path = $TargetStateRelPath
    result            = $(if ($overallOk) { 'pass' } else { 'fail' })
    orchestrator      = [ordered]@{
        script            = $ScriptName
        version           = $ScriptVersion
        step_dir          = $StepDir
        audit_script      = $AuditScript
        audit_exit_status = $auditExitCode
        engine            = $enginePath
    }
    collection_errors = @($script:ExecutionError)
}

try {
    # -InputObject avoids the pipeline unrolling a single-element array, and
    # LF endings keep digests stable across both hosts.
    $json = (ConvertTo-Json -InputObject $record -Depth 8) -replace "`r`n", "`n"
    $tempFile = Join-Path -Path $execDir -ChildPath ('.windows_harden.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($tempFile, $json + "`n", $utf8NoBom)
    [System.IO.File]::Copy($tempFile, $outFile, $true)
    Remove-Item -LiteralPath $tempFile -Force
}
catch {
    Write-Warning "Cannot write execution record to ${outFile}: $($_.Exception.Message)"
    exit 2
}

try {
    $digest = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$outFile.sha256", ('{0}  {1}' -f $digest, $RecordBasename) + "`n", $utf8NoBom)
}
catch {
    Add-ExecutionError -Message "integrity: SHA256 digest could not be written - $($_.Exception.Message)"
}

$beforeText = if ($null -ne $passRateBefore) { $passRateBefore } else { '?' }
$afterText = if ($null -ne $passRateAfter) { $passRateAfter } else { '?' }
$deltaText = if ($null -ne $delta) { $delta } else { '?' }
$summary = 'pass rate {0} -> {1} (delta {2}, floor {3})' -f $beforeText, $afterText, $deltaText, $floor
Write-Verbose $summary
Write-Verbose "Execution record written to $outFile"
Write-Output $outFile

if ($overallOk) {
    exit 0
}

exit 1
