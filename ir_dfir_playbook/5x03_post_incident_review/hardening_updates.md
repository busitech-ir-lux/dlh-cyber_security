# Hardening Updates: IR-2026-0414-01

Apply via managed change control, first on a clinical-workstation pilot group. Record policy ID, deployment scope, approved exceptions, test results, owner, rollback, and completion date. None of the settings below has been deployed merely by writing this document.

## HRD-001: PowerShell Constrained Language Mode
**Closes:** GAP-011, GAP-003. **Evidence:** ART-002-M01; Sysmon PowerShell EID 1.
**Configuration:** Deploy an enforced WDAC/App Control for Business or supported AppLocker script policy. PowerShell automatically applies ConstrainedLanguage for untrusted scripts under supported system-wide application control; administrators should not be granted a blanket bypass. In Group Policy use *Computer Configuration > Windows Settings > Security Settings > Application Control Policies* (AppLocker) or the organization's App Control policy deployment channel. Target all standard clinical/administrative identities; validate trusted scripts and EHR workflows in audit/pilot first.
**Registry note:** Some training materials specify `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy` (REG_SZ=`4`). That environment variable is **not a security boundary or supported replacement for enforced application control**, so do not deploy it as the sole protection.
**Validation:** Run `$ExecutionContext.SessionState.LanguageMode` from a standard-user shell and test an untrusted script attempting `[System.Management.Automation.ScriptBlock]::Create('...')`; confirm ConstrainedLanguage and audit/denial events.

## HRD-002: Restrict MSBuild using AppLocker (or WDAC)
**Closes:** GAP-005, GAP-003. **Evidence:** ART-001-E01, ART-002-M01.
**Configuration:** Use *Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules*. Enable Application Identity service. For clinical users, deny execution of `MSBuild.exe` (including Framework/Framework64 and versioned Visual Studio installation paths), while explicitly allowing only a managed `BUILTIN\Administrators` group and named approved CI/CD service accounts on designated build hosts. AppLocker **deny rules override allow rules**: do not issue a broad `Everyone` deny alongside administrator allow rules. Instead apply an allowlist policy using properly scoped security groups and a separate approved build-host policy; test effective policy on all user classes. Prefer publisher/file hash rules plus version/change management rather than relying solely on paths.

Illustrative policy fragment (adapt identity SIDs, paths, rule collection and enforcement before use):
```xml
<RuleCollection Type="Exe" EnforcementMode="AuditOnly">
  <FilePathRule Id="{7E4C6912-EEB1-4C11-996F-31F17C131000}"
      Name="Allow approved build service MSBuild"
      Description="Approved build service on CI nodes"
      UserOrGroupSid="S-1-5-32-544" Action="Allow">
    <Conditions>
      <FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\*\MSBuild.exe"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```
This XML is an *illustration*, not a complete enforceable policy; it must be integrated with safe default rules and organization-specific groups.
**Validation:** `Get-AppLockerPolicy -Effective -Xml` and `Test-AppLockerPolicy`; review AppLocker EXE/DLL logs and confirm standard clinical users cannot run MSBuild while approved CI identity still can.

## HRD-003: Conditional access for suspicious foreign-origin VPN authentication
**Closes:** GAP-002. **Evidence:** foreign-session open item and suppressed Azure AD risk signals.
**Configuration:** In Microsoft Entra Conditional Access, target the VPN enterprise application (only where VPN authentication actually uses Entra ID), include relevant staff groups, exclude break-glass accounts with compensating monitoring, and use named locations plus sign-in-risk/identity-protection controls. A custom risk service or SIEM correlation compares sign-in country with each account's prior 30 days and triggers block or phishing-resistant step-up MFA; Entra CA alone does not natively express a generic 'new country in last 30 days' condition. Remove/review any overly broad compliant-device exclusion suppressing identity-risk evaluation. For non-Entra VPN, implement equivalent VPN IdP/RADIUS conditions and feed VPN logs to the SIEM. Apply report-only first.
**Policy logic:** new country OR impossible travel OR high sign-in risk → deny or strong reauthentication and SOC review; approved geographic exceptions expire and are recorded.
**Validation:** Simulate a high-risk VPN sign-in from a country unseen in 30 days using test identity and verify block/step-up plus SIEM event; recheck compliant-device bypass.

## HRD-004: Enable Windows Credential Guard and strengthen LSA protection
**Closes:** GAP-006, GAP-007. **Evidence:** ART-002-M04; ART-003-M01.
**Configuration:** On supported Windows 10/11 Enterprise/Education and applicable Windows Server versions with virtualization-based security/hardware prerequisites, configure *Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security* with Credential Guard enabled (UEFI lock setting chosen via change control). On supported systems alternatively use Microsoft documented MDM/CSP deployment. Confirm Secure Boot, virtualization extensions and compatibility. Also evaluate `RunAsPPL` (LSA protection) separately.
**Limitations:** Credential Guard helps isolate specific secrets but does **not** prevent every form of credential theft, Kerberos ticket theft, or Pass-the-Ticket. Do not infer that enabling it alone closes the incident.
**Validation:** `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning`; verify reported Credential Guard service and endpoint baseline compliance.

## HRD-005: Clinical share access and outbound traffic
**Closes:** GAP-008, GAP-004, GAP-009. **Evidence:** AD-LOG-01; ART-002-M02; ART-003-M01.
**Configuration:** Restrict `LIS_REPORTS$` share + NTFS to named clinical security groups, audit Security Event 4663 for report PDF reads, create a behavioral threshold for abnormal account-based bulk reads, and restrict MSBuild outbound public-network access from clinical workstation segment except documented build infrastructure. Preserve approved EHR/LIS flows. Review DLP/egress logs for the incident window.
**Validation:** Test authorized vs unapproved account access; confirm read audit and alert; test an MSBuild outbound synthetic connection from clinical endpoint and verify firewall policy enforcement.
