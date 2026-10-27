# HIPAA Breach Risk Assessment — IR-2026-0420-01

**Assessment status:** Preliminary; legal sign-off pending  
**Assessment date:** 2026-04-20 (exercise timeline, UTC)  
**Prepared by:** On-call IR analyst (student)  
**Final determination:** Helena Reyes, General Counsel, with MedDefense Privacy Officer / authorized covered-entity leadership  
**Review deadline:** Before the next-morning board briefing (exercise target 07:00 UTC); exact sign-off time **not verified**.

## Scope and evidentiary limits

The scenario describes **1,847 patient files** (lab results and clinical notes) accessed on `FILE-SVR-01`. The condensed `fileserver_access.sample.json` reports **1,847 Event ID 4663 ReadData events** between `2026-04-19T02:14:01Z` and `02:41:12Z`, attributed to `MEDDEFENSE\jdoe`, and supplies five representative rows. Event count alone **does not establish 1,847 unique files or 1,847 patients**. The full `fileserver_access.evtx` and the other original forensic artifacts have not been supplied. Under Task 4, samples are schema references, not evidence sufficient to confirm the full sequence. This assessment uses the sample only as an **explicitly provisional lead**; finding references below point to `forensic_findings.md`.

The HIPAA Breach Notification Rule presumes an impermissible use/disclosure of **unsecured** PHI to be a breach unless a low probability of compromise is demonstrated after evaluating at least four factors, subject to applicable exceptions. Confirm that the data is PHI subject to HIPAA and whether it was secured in a form meeting applicable standards. Reference: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html (45 CFR 164.402).

## Factor 1 — Nature and extent of PHI

- **Evidence:** FILE-001 and FILE-003. Sample access summary describes lab-results and clinical-notes PDFs in `D:\clinical\labs\` and `D:\clinical\notes\`; 1,847 read events are asserted but not independently counted from full EVTX. Identifiers, diagnoses, and unique patient count have not been inspected.
- **Conclusion:** Clinical records potentially contain sensitive identifiable health information; compromise impact could be high. File and patient counts and specific identifiers are **unverified**.
- **Confidence:** **Moderate** that sensitive categories are in scope; **low** for exact number of distinct files/patients and identifier details.

## Factor 2 — Unauthorized person who used/received the PHI

- **Evidence:** FILE-002 and FILE-003. The sample says `MEDDEFENSE\jdoe`, a scheduling coordinator without a legitimate clinical-document access need, authenticated from `10.30.12.101` via **Kerberos**; FILE-001 associates reads with a suspicious `svchost32.exe` path. SYSMON-002 and SYSMON-006 provide sample-only suspicious-process context. No known external recipient is established.
- **Conclusion:** Available leads are inconsistent with ordinary authorized clinical use and suggest attacker-controlled access. Identity of any external recipient remains **unknown**.
- **Confidence:** **Moderate** for suspected unauthorized access; **low** for recipient identity.

## Factor 3 — Whether PHI was actually acquired or viewed

- **Evidence:** FILE-001 sample summary reports 1,847 `4663` ReadData events during a 27-minute window; five rows are shown. PROXY-005 shows a potentially significant outbound exchange from the server, but its `bytes` field does not prove upload direction or data content. Original logs, unique-object count, endpoint traces and exfiltration evidence are missing.
- **Conclusion:** Sample suggests that documents were read, making acquisition or viewing plausible. **Exfiltration is not proven**, and actual reads must be confirmed from original events. Nonetheless, the available evidence does not support ruling out acquisition.
- **Confidence:** **Moderate** that access is indicated; **low** for the actual count, destinations and exfiltration.

## Factor 4 — Extent of mitigation

- **Evidence:** `containment_decision.md` and `containment_execution.md` document a containment **plan**, not verified firewall, EDR or credential-revocation results. The original 72-hour dwell and file access would precede the containment decision. No evidence shows recovered data, confirmed deletion, or a trusted recipient agreement.
- **Conclusion:** Risk-reducing steps are planned, but effective mitigation has **not been demonstrated**. Containment after access does not undo prior exposure.
- **Confidence:** **High** that the provided material lacks verified mitigation; **unknown** whether real-world actions succeeded.

## Preliminary determination and notification posture

**No evidence-based low-probability-of-compromise conclusion is supportable on this record.** Assuming MedDefense is a HIPAA covered entity and the potentially accessed records were unsecured PHI, the incident should be handled as a **presumptively notifiable breach**, subject to the authorized final determination, verification of applicability, the full forensic record, and any valid legal exception. **Do not certify “no notification required.”**

Helena Reyes (General Counsel), jointly with the designated Privacy Officer and authorized leadership, must document the final determination and its UTC timestamp. If notification is required, confirm unique affected individuals and the discovery date, then follow the applicable obligations to individuals, HHS, and potentially media; notices are generally required without unreasonable delay and no later than 60 days after discovery, with special rules for breaches affecting **500 or more individuals**. **1,847 read events are not 1,847 individuals.** Source: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html.

## Mandatory verification before sign-off

1. Parse and count *all* original Event ID 4663 records; identify unique files, patients and PHI elements, and corroborate `jdoe` authorization status.
2. Correlate original file-server, proxy, Sysmon and authentication events; establish whether records were obtained or transmitted outside MedDefense.
3. Record actual mitigation outputs (endpoint isolation, credential invalidation, C2 disconnection) and their times.
4. Verify HIPAA entity status, unsecured-PHI condition, exception analysis and notification deadlines with Legal/Privacy.
5. Record sign-off role, signer, UTC timestamp, final finding and evidence versions in the incident timeline.

**Evidence-ID references:** `5x05_task4/forensic_findings.md` (FILE-001, FILE-002, FILE-003, PROXY-005, SYSMON-002, SYSMON-006); these are currently sample-only leads marked *possible*, not validated full-artifact findings.
