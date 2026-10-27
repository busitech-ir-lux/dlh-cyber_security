# Credential Exposure Playbook Delta — IR-2026-0420-01

**Status:** Proposed changes. The original 5x00–5x04 credential-exposure playbook was not provided, so the **before** lines are illustrative summaries, not verbatim quotations. Compare and replace them with the actual current wording before approving the delta.

## DELTA-01 — Expand credential-exposure trigger
- **Section changed:** Activation / decision criteria.
- **Before (illustrative):** "Start credential response when password dumping is confirmed."
- **After:** "Start the credential-exposure playbook when EDR/Sysmon shows an unknown process accessing LSASS (Sysmon Event ID 10), or service creation on another host using the same account, even if hash theft is not yet confirmed. Record users, source/destination hosts and timestamps; classify exposure as suspected until forensic verification."
- **Why:** Sample Sysmon records show `svchost32.exe` accessing `lsass.exe` on CS-WS-101 and subsequent service creation using `MEDDEFENSE\jdoe` on CS-WS-104. These signals justify prompt triage, not an unsupported claim that credentials were extracted.
- **Verification:** Tabletop test with LSASS access plus remote service creation: playbook opens the credential-exposure workflow and records linked hosts.

## DELTA-02 — Sequence revocation with evidence and patient-care continuity
- **Section changed:** Containment / credential reset and verification.
- **Before (illustrative):** "Reset compromised account passwords and close the ticket."
- **After:** "(1) Preserve authentication logs and available host memory; (2) identify affected interactive, administrative, service and machine accounts over the full dwell window; (3) coordinate clinical service continuity and owner approval for disruptive service-account actions; (4) disable or restrict compromised accounts, rotate passwords/secrets, revoke sessions and invalidate applicable Kerberos tickets; (5) rotate affected machine-account credentials under domain-admin change control; (6) verify old credentials/sessions fail, new approved access works, and SIEM shows no continued unauthorized use; (7) attach evidence and timestamps before closure."
- **Why:** Samples show cross-host use of `MEDDEFENSE\jdoe` and file server access to lab results/clinical notes. The full set of affected accounts requires the complete 72-hour logs.
- **Verification:** In a supervised test, show that old sessions and passwords stop working while approved scheduling and clinical access is restored; record SIEM and identity-system results.

**Approval required:** IR lead, Identity/AD owner, clinical system owner and the existing playbook owner. Do not mark revised steps deployed without approval and test evidence.
