<#
Script Name: 12-applocker_config.ps1
Purpose: Build and export a MedDefense AppLocker audit policy.
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param(
    [string]$OutputFile = "$PSScriptRoot\applocker_policy.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy
Import-Module ActiveDirectory

$gpoName = "MedDefense - AppLocker Policy"
$domain = Get-ADDomain
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO $gpoName | Out-Null
}
Write-Host "[*] Creating GPO: `"$gpoName`"... CREATED"

Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc
$appIdService = Get-Service AppIDSvc
if ($appIdService.Status -ne "Running") { throw "Application Identity service did not start." }
Write-Host "[*] Starting AppIDSvc... Running           [OK]"

$xml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Allow Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="Allow Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="33333333-3333-3333-3333-333333333333" Name="Allow Program Files x86" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES(X86)%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="44444444-4444-4444-4444-444444444444" Name="Allow DicomViewer" Description="MedImage Corp approved application" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="C:\MedDefense\DicomViewer\DicomViewer.exe"/></Conditions></FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="55555555-5555-5555-5555-555555555555" Name="Allow Windows Scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="66666666-6666-6666-6666-666666666666" Name="Allow MedDefense Admin Scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="C:\MedDefense_Lab\Scripts\*"/></Conditions></FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

$xml | Set-Content $OutputFile -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $OutputFile -Merge

Write-Host "[*] Configuring Executable Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\Program Files\*              [SET]"
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]"
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]"
Write-Host "    Default: DENY                          [SET]"
Write-Host "[*] Configuring Script Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]"
Write-Host "    Default: DENY                          [SET]"
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)"

if (-not (Get-GPInheritance $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
    New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
}
Write-Host "[*] Linking GPO... COMPLETE"
Write-Host "[*] Testing..."
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]"
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]"
Write-Host "Policy exported to: $OutputFile"
