# Hardening Updates — IR-2026-0420-01

These are **proposed changes**, not confirmed deployments. Pilot with clinical application owners before site-wide enforcement.

## GAP-01 — Office document launched a PowerShell downloader
- **Control:** Microsoft Defender Attack Surface Reduction (ASR), "Block all Office applications from creating child processes"; rule GUID `d4f940ab-401b-4efc-aadc-ad5f3c50688a`.
- **Configuration:** Intune Endpoint security > Attack surface reduction > Attack surface reduction rules > Block Office applications from creating child processes = **Block**. Alternatively Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack surface reduction rules; set the GUID to `1` (Block).
- **Scope:** Non-developer clinical workstations; first test application compatibility on pilot devices. Log approved exceptions.
- **Validation:** Run `Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids` and `Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions`; match the rule ID to action `1`. Safely execute an approved Office-to-child-process test in a lab and confirm a Defender ASR block event (1121). Do not use a real malicious document.
- **Evidence:** Sysmon sample: `WINWORD.EXE` -> `powershell.exe`, CS-WS-101 at 2026-04-17T14:22:14Z.

## GAP-02 — Network authentication protections need strengthening
- **Control:** Require SMB signing on clients and servers, reducing susceptibility to SMB relay. **Note:** Signing does not itself eliminate pass-the-hash or all NTLM lateral movement.
- **Configuration:** Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options:
  - `Microsoft network client: Digitally sign communications (always)` = **Enabled**.
  - `Microsoft network server: Digitally sign communications (always)` = **Enabled**.
- **Scope:** Domain-joined endpoints and file servers, after testing legacy clinical devices, SMB integrations and performance.
- **Validation:** On test clients use `Get-SmbClientConfiguration | Select RequireSecuritySignature`; on file server use `Get-SmbServerConfiguration | Select RequireSecuritySignature` (expect `True`). Attempt a controlled unsigned SMB session in a test environment (expect refusal). Confirm normal signed clinical file access still works.
- **Evidence:** Sysmon sample lateral service creation on CS-WS-104 using `MEDDEFENSE\jdoe`; precise credential-reuse mechanism requires full authentication logs.

## GAP-03 — PowerShell execution was not stopped before payload download
- **Control:** Enable PowerShell Script Block Logging and central collection, enabling detection of malicious downloaders even when process names change.
- **Configuration:** Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = **Enabled**. Forward Microsoft-Windows-PowerShell/Operational Event ID 4104 to the SIEM. Restrict reading these sensitive logs.
- **Scope:** All managed clinical Windows systems, including scheduling and file servers as appropriate.
- **Validation:** On a test endpoint run `Write-Output 'IR-test-4104'` in PowerShell; find Event ID 4104 with the test string locally and in the SIEM; verify alert rules and retention. No malicious command needed.
- **Evidence:** CS-WS-101 executed `powershell.exe -NoProfile -WindowStyle Hidden -ep bypass` with a web downloader in the Sysmon sample.

**Rollout gate:** Change approval, pilot test, application-owner sign-off, deployment record and post-change evidence for each control.
