#Requires -Version 5.1
<#
.SYNOPSIS
    Hawthorne capstone, Task 1 (Windows side): runs the CIS Level 1 audit
    helper against hawthorne-adm-01 and persists the raw output plus the
    extracted pass rate.

.DESCRIPTION
    Invokes win_audit.ps1, which emits one line per control ending in PASS,
    FAIL or NOT_APPLICABLE. The pass rate derived here is the denominator for
    the delta reported at the end of the capstone.

    Idempotency: the baseline is a one-shot measurement of the UNHARDENED
    host. Re-running after a control has been applied would silently destroy
    the denominator, so an existing baseline is treated as state already in
    place - the script reports it and exits 0 without re-running the audit.
    Use -Force to deliberately recapture; the previous record is preserved
    as *.superseded.

.PARAMETER CapstoneRoot
    Root that contains capstone\. Defaults to the current directory,
    overridable with the CAPSTONE_ROOT environment variable.

.PARAMETER AuditScript
    Path to the audit helper. Defaults to the lab path given in the brief.

.PARAMETER Force
    Recapture even if a baseline already exists.

.PARAMETER AllowUnprivileged
    Permit a non-elevated run. Most CIS checks read privileged state, so the
    pass rate will be misleading and is marked as such in the record.

.OUTPUTS
    capstone\baseline\windows_baseline.log   full audit helper output
    capstone\baseline\baseline_windows.json  timestamp, hostname,
                                             controls_total, pass_count,
                                             fail_count, na_count,
                                             pass_rate_percent, log_path

.NOTES
    Exit codes:
      0  success - baseline captured, or already present and left untouched
      1  controlled failure - the audit ran but produced no parseable control
         lines, or the helper returned a non-zero status
      2  environment error - audit helper missing, not elevated, unwritable
         output tree

.EXAMPLE
    .\1-baseline_snapshot.ps1 -CapstoneRoot 'C:\handoff' -Verbose
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CapstoneRoot,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AuditScript = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1',

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$AllowUnprivileged
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptName = '1-baseline_snapshot.ps1'
$ScriptVersion = '1.0.0'
$SchemaVersion = '1.0'
$RecordType = 'baseline_snapshot'
$Phase = 'pre_hardening'

# Paths are fixed by the capstone brief. The relative form is what goes into
# the record so Module 3 can resolve it against whatever root they unpack into.
$BaselineSubdir = 'capstone\baseline'
$LogRelPath = 'capstone/baseline/windows_baseline.log'
$RecordBasename = 'baseline_windows.json'

$script:BaselineError = New-Object -TypeName 'System.Collections.Generic.List[string]'

function Add-CollectionError {
    <#
    .SYNOPSIS
        Records a degraded step and mirrors it to the warning stream.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $script:BaselineError.Add($Message)
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

function Get-ControlTally {
    <#
    .SYNOPSIS
        Counts PASS, FAIL and NOT_APPLICABLE verdicts in audit helper output.
    .DESCRIPTION
        NOT_APPLICABLE is matched first so it is never miscounted, and word
        matching is case-SENSITIVE (-cmatch, not -match) with word boundaries,
        so a control whose description contains the word "pass" or "fail" in
        prose cannot inflate the tally.
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
            # Banner or blank-ish line from the helper, not a control verdict.
            $tally.unparsed_count = $tally.unparsed_count + 1
        }
    }

    return $tally
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$isWindowsPlatform = ($PSVersionTable.PSEdition -eq 'Desktop') -or
    ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

if (-not $isWindowsPlatform) {
    Write-Warning 'This baseline collector only runs on Windows.'
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

if (-not (Test-Path -LiteralPath $AuditScript)) {
    Write-Warning "Audit helper not found: $AuditScript"
    Write-Warning 'Pass -AuditScript with the path to win_audit.ps1 on this host.'
    exit 2
}

$isElevated = Test-ElevatedSession
if (-not $isElevated) {
    if (-not $AllowUnprivileged.IsPresent) {
        Write-Warning 'Must run elevated. Re-run as Administrator, or pass -AllowUnprivileged to accept a degraded baseline.'
        exit 2
    }
    Add-CollectionError -Message 'run is not elevated, CIS control results are not comparable'
}

$baselineDir = Join-Path -Path $CapstoneRoot -ChildPath $BaselineSubdir
$logFile = Join-Path -Path $baselineDir -ChildPath 'windows_baseline.log'
$outFile = Join-Path -Path $baselineDir -ChildPath $RecordBasename

try {
    if (-not (Test-Path -Path $baselineDir)) {
        $null = New-Item -Path $baselineDir -ItemType Directory -Force
    }
}
catch {
    Write-Warning "Cannot create output directory ${baselineDir}: $($_.Exception.Message)"
    exit 2
}

# Idempotency gate: an existing baseline is state already in place.
if ((Test-Path -LiteralPath $outFile) -and -not $Force.IsPresent) {
    Write-Verbose "Baseline already present at $outFile; not re-running the audit (use -Force to recapture)."
    Write-Output $outFile
    exit 0
}
if ((Test-Path -LiteralPath $outFile) -and $Force.IsPresent) {
    Move-Item -LiteralPath $outFile -Destination "$outFile.superseded" -Force
    Write-Verbose "Previous baseline preserved as $outFile.superseded"
}

Write-Verbose "Running CIS Level 1 audit helper on $env:COMPUTERNAME"

$auditOutput = @()
$auditExitCode = 0
try {
    $auditOutput = @(& $AuditScript 2>&1 | ForEach-Object { $_.ToString() })
    if (Test-Path -Path 'variable:LASTEXITCODE') {
        $auditExitCode = $LASTEXITCODE
    }
}
catch {
    Add-CollectionError -Message "audit helper threw an exception - $($_.Exception.Message)"
    $auditExitCode = 1
}

if ($auditExitCode -ne 0) {
    Add-CollectionError -Message "audit helper exited with status $auditExitCode; see $LogRelPath"
}

$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
try {
    $logBody = ($auditOutput -join "`n")
    [System.IO.File]::WriteAllText($logFile, $logBody + "`n", $utf8NoBom)
}
catch {
    Write-Warning "Cannot write audit log to ${logFile}: $($_.Exception.Message)"
    exit 2
}

$tally = Get-ControlTally -AuditLine $auditOutput

# Pass rate is measured over APPLICABLE controls only: a NOT_APPLICABLE
# control is neither a win nor a gap, and counting it either way would
# distort the delta reported at the end of the capstone.
$applicable = $tally.controls_total - $tally.na_count
if ($applicable -gt 0) {
    $passRate = [math]::Round(($tally.pass_count / $applicable) * 100, 2)
}
else {
    $passRate = $null
    Add-CollectionError -Message 'no applicable controls found; pass rate cannot be computed'
}

if ($tally.controls_total -eq 0) {
    Add-CollectionError -Message 'audit helper produced no parseable control lines'
}

$record = [ordered]@{
    schema_version    = $SchemaVersion
    record_type       = $RecordType
    phase             = $Phase
    platform          = 'windows'
    timestamp         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname          = $env:COMPUTERNAME
    controls_total    = $tally.controls_total
    pass_count        = $tally.pass_count
    fail_count        = $tally.fail_count
    na_count          = $tally.na_count
    pass_rate_percent = $passRate
    pass_rate_basis   = 'pass_count / (controls_total - na_count)'
    log_path          = $LogRelPath
    collector         = [ordered]@{
        script         = $ScriptName
        version        = $ScriptVersion
        audit_script   = $AuditScript
        exit_status    = $auditExitCode
        unparsed_lines = $tally.unparsed_count
        privileged     = $isElevated
    }
    collection_errors = @($script:BaselineError)
}

try {
    $json = ($record | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
    $tempFile = Join-Path -Path $baselineDir -ChildPath ('.baseline.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($tempFile, $json + "`n", $utf8NoBom)
    # Atomic replace: a repeated or interrupted run never leaves a partial record.
    [System.IO.File]::Copy($tempFile, $outFile, $true)
    Remove-Item -LiteralPath $tempFile -Force
}
catch {
    Write-Warning "Cannot write baseline record to ${outFile}: $($_.Exception.Message)"
    exit 2
}

try {
    $digest = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$outFile.sha256", ('{0}  {1}' -f $digest, $RecordBasename) + "`n", $utf8NoBom)
}
catch {
    Add-CollectionError -Message "integrity: SHA256 digest could not be written - $($_.Exception.Message)"
}

$summary = "{0}/{1} applicable controls passed ({2}%), {3} not applicable" -f $tally.pass_count, $applicable, $passRate, $tally.na_count
Write-Verbose $summary
Write-Verbose "Baseline record written to $outFile"
Write-Output $outFile

if ($script:BaselineError.Count -gt 0) {
    Write-Warning "$($script:BaselineError.Count) issue(s) recorded; see .collection_errors"
    exit 1
}

exit 0
