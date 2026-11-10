# MedDefense Disaster Recovery Master Plan

**Version:** 1.1  
**Classification:** Confidential  
**Prepared:** 2026-11-10  
**Program owner:** Infrastructure Manager with IT Security  
**Status:** Proposed program; local LIS exercise completed, adoption pending

## Program scope

This plan coordinates technical recovery and continued clinical work when systems
supporting the 230-bed acute care hospital are unavailable. Its purpose is to
restore trustworthy records and usable clinical services within approved business
tolerances while staff protect patients and information during the interruption.
It covers the hospital's ED, ICU, inpatient care, laboratory, radiology, pharmacy,
central technical services, and their approved remote recovery providers. No extra
site names, provider capacity, or approved vendor commitments are assumed.

Covered scenarios include power/cooling failure, data-center loss, system/storage
failure, unrecoverable DC01 with healthy DC02, network loss, backup failure, and
destructive incidents. Suspected compromise requires containment and clean-point
selection alongside recovery.

The ten covered systems are Active Directory, Epic EHR, LIS, PACS/RIS, Pharmacy
Dispensing System, Medical Device Integration Gateway, Network Core, Email and
Secure Messaging, Backup and DR Infrastructure, and Security Operations Platform.
The BIA explains their dependencies and patient, regulatory, and financial impact.

## Explicit exclusions and current limitations

Evacuation, facilities repair, clinical treatment protocols, and full AD
forest-compromise rebuilds require separate plans. Vendor recovery needs verified
contracts and witnessed tests; the proposed architecture is not deployed evidence.
Only the five-row LIS fixture was restored locally. The prescribed SSH lab, full
application, analyzers/interfaces, production volumes, AD, and full-site recovery
were not tested. Clinical procedures require approval and drills. Full HIPAA
compliance is not established.

## Roles and responsibilities

| Role | Responsibility and decision authority |
| --- | --- |
| CISO, Dr. Morales | Approves plan, tolerances, material exceptions, and remediation priorities; presents unresolved exposure to the board. |
| Administrator on Call, 7000 | Authorizes hospital-wide downtime declaration and coordinates leadership decisions on sustained operations. |
| IT Incident Commander, 7200 | Leads technical response, maintains incident clock and decision log, coordinates containment, and recommends recovery release. |
| Nursing Supervisor, 7100 | Coordinates units, paper procedures, clinical escalations, and nursing acceptance. |
| Clinical Applications Lead, 7300 | Confirms Epic/LIS status, coordinates interfaces, and obtains application-owner acceptance. |
| Network Engineering Lead | Restores protected connectivity and confirms recovery-site routing and segmentation. |
| Systems Administrator | Maintains healthy DC02 and leads supported DC01 recovery or replacement; verifies identity and DNS. |
| Infrastructure Manager | Restores backup catalog, keys and storage; coordinates recovery capacity and evidence retention. |
| Laboratory Systems Lead and Chemistry Lead, 7510 | Restore and verify LIS records; coordinate specimen and critical-result reconciliation. |
| Pharmacy IT Lead and pharmacist, 7400 | Validate dispensing, cabinet state, medication records, and pharmacy reconciliation. |
| Radiology Systems Lead and Biomedical IT Lead | Validate imaging and gateway functions with their clinical users. |
| SOC Manager and IT Security | Assess clean recovery points, retain logs/evidence, monitor reduced-mode operations, and verify safeguards. |
| Privacy and Legal | Assess disclosure and reporting duties, approve provider safeguards and BAAs, and direct records holds. |
| Department data owners | Validate workflows and data completeness before clinical service acceptance. |

Role-to-person rosters, backup responders, and vendor contacts must be confirmed
before adoption. Supplied extension numbers are exercise material and must be
verified before deployment; they are not personal telephone numbers.

## Activation criteria

Start the incident clock at interruption or record the earliest defensible time.
An observer reports immediately; the Incident Commander assesses scope, while the
Administrator on Call authorizes hospital-wide downtime when needed. Activate the
applicable recovery branch when any of these triggerable conditions is confirmed:

1. Epic or LIS cannot perform an essential clinical workflow and immediate recovery is not
   confirmed; start local paper procedures at once.
2. Primary data-center power or cooling failure makes continued safe operation uncertain or disables
   multiple clinical systems.
3. Network or identity failure prevents new clinical authentication or access across a unit, or
   threatens the proposed dependency recovery budget.
4. DC01 is confirmed unrecoverable and DC02 health and available authentication have been checked.
5. Ransomware or suspected corruption makes clinical records or their integrity unsafe; isolate
   affected systems before selecting clean backups.
6. The newest verified recovery point exceeds a system's approved RPO, or the backup platform cannot
   provide a required restore.

An RPO breach can trigger an incident while production remains live. Do not wait
for RTO or MTD expiry. Record scope, time, accountable leads, affected systems,
and clinical fallback.

## Communication plan

Use the supplied laminated unit contact lists and protected paper logs if
normal messaging fails. Keep patient details out of broad incident messages.
The ordered notification sequence is:

1. Discovering staff notify the charge nurse or supervisor and the IT Incident Commander at 7200;
   urgent clinical escalation proceeds immediately in parallel.
2. The Incident Commander confirms impact with Clinical Applications at 7300, alerts the
   Administrator on Call at 7000, and notifies IT Security if compromise is suspected.
3. The Administrator authorizes hospital-wide downtime as needed; the Nursing Supervisor at 7100
   coordinates affected units and confirms receipt.
4. Unit leaders notify attending clinicians, pharmacy at 7400, laboratory accessioning at 7500,
   chemistry at 7510, and laboratory medical director at 7520 as relevant.
5. System owners notify approved service providers through the verified contact roster; CISO,
   Privacy, Legal, and executive leadership receive impact and reporting assessments.
6. The Incident Commander and clinical leaders issue a controlled restoration notice only after
   acceptance, then verify unit acknowledgment and reconciliation responsibilities.

Issue status updates every 15 minutes: affected services, verified facts, safe
workarounds, remaining checks, and next update. Record recipients, time, decisions,
and acknowledgment; do not promise unverified recovery times. Clinical critical
values retain their separate five- and ten-minute escalation rules.

## Recovery strategy and acceptance

Use the BIA's interruption-to-service targets: Network Core 5 minutes, AD 15,
backup capability 20, Epic core 25, LIS and gateway 30, pharmacy 45, and PACS,
messaging, and central security operations 120. These demanding targets require
warm failover, prepositioned equipment, and parallel staff; they are unapproved
business proposals, not demonstrated capabilities. The architecture budgets all
dependencies within those clocks rather than adding their RTOs together.

Begin with independent power/cooling confirmation, protected network bootstrap,
DNS/time reachability, identity, and backup catalog/key access. Restore Epic core
and clinical data in parallel where safe, then reconnect interfaces after verifying
both ends and reconciling queued work. Keep bedside observations, phone contact,
and paper workflows active until the responsible clinical leaders approve release.

Select an application-consistent recovery point from an independent copy, verify
its manifest and age, and preserve evidence before changes. Use supported AD
recovery; do not attach an arbitrarily rolled-back domain controller. For the
isolated LIS exercise, require five rows, both specified critical records,
integrity_check=ok, and explicit local-path validation. Production additionally
requires application access, service-account permissions, analyzer and interface
flows, clinical approval, and recovery-point age evidence.

Record actual completion, gaps, owners, and safeguards. Escalate threatened MTDs
before expiry; clinical leadership decides diversion or service restrictions.
Process startup or backup completion alone cannot establish recovery.

## Program document index

Dates below describe submitted versions, not approval of source materials.

| Document | Filename | Version | Last Updated | Last Tested |
| --- | --- | --- | --- | --- |
| Business Impact Analysis | [business_impact_analysis.md](business_impact_analysis.md) | 1.0 | 2026-11-10 | N/A; approval pending |
| Backup Architecture | [backup_architecture.md](backup_architecture.md) | 1.1 | 2026-11-10 | N/A; proposed |
| Recovery Runbooks | [recovery_runbooks.md](recovery_runbooks.md) | 1.1 | 2026-11-10 | 2026-11-10 LIS locally; AD not tested |
| Clinical Downtime Procedures | [clinical_downtime_procedures.md](clinical_downtime_procedures.md) | 1.0 | 2026-11-10 | N/A; drill pending |
| Recovery Test Record (LIS) | [recovery_test_record.md](recovery_test_record.md) | 1.1 | 2026-11-10 | 2026-11-10, limited local fixture |
| Gap Analysis | [gap_analysis.md](gap_analysis.md) | 1.1 | 2026-11-10 | N/A; revised workflow uses repeat evidence, production retest pending |

## HIPAA evidence alignment

The local `hipaa_164_308_a7_reference.md` supplies the evidence chain. The
[regulatory text](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308)
identifies backup, recovery, and emergency-mode plans as required; testing/revision
and criticality analysis are addressable. Document applicability decisions and
implementation rather than treating addressable specifications as optional.

| Specification | Submitted evidence | Remaining limitation |
| --- | --- | --- |
| 164.308(a)(7)(i) | This master plan and document index. | Approval and organizational adoption pending. |
| (ii)(A): Data backup | Backup architecture and successful fixture hash/import. | Current schedules do not meet proposed targets; production exact-copy retrievability not demonstrated. |
| (ii)(B): Disaster recovery | Runbooks, timer log, and LIS test record. | Only local sample restoration tested; other systems and full service unverified. |
| (ii)(C): Emergency mode | Two clinical quick references and escalation rules. | Clinical review, training, and witnessed night-shift drill pending. |
| (ii)(D): Testing and revision | Test record, gap analysis, revised LIS procedure, and schedule below. | Full revised workflow and production-scale exercise pending. |
| (ii)(E): Criticality analysis | Ten-system BIA with proposed impacts and tolerances. | Clinical, Finance, and CISO validation/signature pending. |

## Testing and revision schedule

Infrastructure reviews backup failures and verified recovery-point age daily;
IT Security reviews exceptions and access monthly. Each month perform a sampled
restore and catalog/key check; rotate critical systems so every Tier 1 service is
covered at least quarterly. Quarterly, exercise identity, network bootstrap,
geographic copy recovery, clinical communication, and end-to-end interface
validation under controlled conditions. Conduct a full-site scenario annually,
including a night-shift tabletop and downtime reconciliation drill.

By 2026-11-17 obtain BIA and clinical procedure review. By 2026-11-24 resolve the
LIS point-frequency design and conduct the first clinical drill. By 2026-12-08 run
a production-scale LIS test and foundation recovery exercise. These dates are
proposed commitments; the board must approve resources and accountable owners.

After each exercise or incident, record actual time, actual data age, deviations,
clinical acceptance, and corrective actions within five working days. Retest
material fixes before closing them. Review this plan annually and after major
application, vendor, site, or dependency changes. Retain approved versions,
execution logs, assessments, and review records for at least six years from
creation or last effective date, whichever is later; separate record-retention
requirements may apply to patient data and backups.

## CISO sign-off

I approve the program scope, assigned responsibilities, validated tolerances, and
funded remediation recorded with this plan. This signature does not certify tests
or operational controls beyond their documented scope.

**CISO name:** _________________________  
**Signature:** _________________________  
**Date:** _________________________  
**Approved version and effective date:** _________________________  
**Recorded exceptions and follow-up owners:** _________________________
