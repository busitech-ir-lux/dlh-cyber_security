# MedDefense audit evidence package

**Prepared:** 2026-11-10  
**Scope:** All eight requests in `compliance/ocr_audit_letter.md`  
**Overall readiness:** Not Ready

## How to use this package

Evidence status describes whether the supplied material answers the whole request.
Full means direct, sufficient evidence within the requested scope and period;
Partial means relevant evidence exists but the request is not fully supported;
None means the requested proof is unavailable. A file proving a gap does not count
as the missing control itself. Policy texts created here remain pending approval,
and proposed deadlines do not show completed remediation.

Original evidence filenames below are exact. They resolve to the local artifact
index at the end; generated filenames resolve within `tasks/`. Summaries are not
represented as underlying logs, complete playbooks, or signed records. The audit
letter does not provide an exact date; 2026-12-22 is the six-week planning target
from 2026-11-10. Owners must confirm the date and deadlines.

### Request 1: Security risk analysis

**HIPAA specification:** 164.308(a)(1)(ii)(A)  
**Evidence status:** Partial

**Evidence description:** `risk_register_updates.yaml` identifies current recorded risks;
`forensic_findings_summary.md` describes incident weaknesses; `gap_assessment.md` documents this
review method and baseline findings.

**Gap:** No comprehensive methodology and scope covering all ePHI locations, data flows, threats,
safeguards, likelihood, and impact is supplied. A framework gap matrix and incident findings are not
a complete HIPAA risk analysis. Risk IDs also conflict across sources.

**Remediation owner and timeline:** IT Security, with Infrastructure, Biomedical IT, and clinical
data owners: reconcile risk IDs by 2026-11-17 and complete a documented all-ePHI analysis with CISO
review by 2026-12-08.

### Request 2: Risk management plan

**HIPAA specification:** 164.308(a)(1)(ii)(B)  
**Evidence status:** Partial

**Evidence description:** `risk_treatment_plan.md` sets treatments, owners, targets, and success
criteria; `risk_register_updates.yaml` records open risks. `gap_assessment.md` and
`vendor_risk_assessment.md` add current review findings and proposed actions.

**Gap:** The treatment plan is unsigned and has not been presented to the Board Risk Committee. June
and July 2026 targets have passed without closure evidence. New assessment actions do not prove
execution.

**Remediation owner and timeline:** IT Security and CISO: reconcile and approve the plan by
2026-11-24, retain original targets and overdue status, record revised commitments, and review
evidence-backed progress weekly through 2026-12-22.

### Request 3: Workforce security awareness and training

**HIPAA specification:** 164.308(a)(5)  
**Evidence status:** Partial

**Evidence description:** `security_awareness_training_status.md` reports content and 1,460
completions from 2,000 workforce members for 2025-05-01 through 2026-04-30.
`acceptable_use_policy.md` adds proposed acknowledgment requirements.

**Gap:** The historical report leaves 540 incomplete and does not cover May through November 2026.
Individual dated attendance, current workforce reconciliation, role assignments, and phishing
metrics are absent. Signing the new policy is not training completion.

**Remediation owner and timeline:** IT Security with HR: refresh the rolling 12-month roster and
document overdue users and an interim remediation plan by 2026-12-15; provide the plan before the
2026-12-22 audit and track make-up completion weekly.

### Request 4: Audit controls and activity review

**HIPAA specification:** 164.312(b)  
**Evidence status:** Partial

**Evidence description:** `endpoint_hardening_baseline.md` describes Sysmon, auditd, sudo logging,
and partial forwarding; `sigma_detection_catalog.md` lists detections and informal weekly reviews;
`forensic_findings_summary.md` reports use of endpoint and proxy evidence.

**Gap:** Raw log exports, dated reviewer sign-offs, retention settings, and complete coverage are
not supplied. Sysmon reaches 198 of 280 clinical workstations, medical-device telemetry is absent,
and DR-region CloudTrail is missing.

**Remediation owner and timeline:** SOC Engineering and Cloud Security with Biomedical IT: validate
representative log ingestion and documented review by 2026-12-08, enable and test DR logging, and
record uncovered systems with owners and dated remediation plans by 2026-12-15.

### Request 5: Workforce security procedures

**HIPAA specification:** 164.308(a)(3)  
**Evidence status:** Partial

**Evidence description:** `endpoint_hardening_baseline.md` describes password and partial
local-admin controls; `forensic_findings_summary.md` identifies excessive service-account privilege;
`acceptable_use_policy.md` provides proposed individual-account and pre-access acknowledgment rules.

**Gap:** No approved provisioning, transfer, termination, or periodic access review procedure and no
completed review records are supplied. The crosswalk mentions earlier IAM work, but those artifacts
are absent. An AUP does not replace access lifecycle procedures.

**Remediation owner and timeline:** IAM lead with HR and IT Security: approve lifecycle and
quarterly review procedures by 2026-11-24, perform a privileged and clinical access review, verify
service-account remediation, and retain joiner/leaver samples by 2026-12-08.

### Request 6: CloudVault Business Associate Agreement

**HIPAA specification:** 164.308(b)  
**Evidence status:** None

**Evidence description:** None for an executed BAA or verified proof that no ePHI access has begun.
`baa_status_note.md` documents non-execution; `cloudvault_contract_summary.md` describes proposed
ePHI storage. `vendor_management_policy.md` and `vendor_risk_assessment.md` define gates but are not
a signed BAA.

**Gap:** No signed agreement exists in the materials and no access or transfer record proves the
alternative no-access condition in the actual OCR letter. Vendor willingness is not evidence of
execution. Current access state is unknown.

**Remediation owner and timeline:** Legal and Infrastructure with IT Security: verify and document
access/transfer state by 2026-11-11 and block new ePHI transfers immediately; obtain the signed
compliant BAA and close assessment gates by 2026-12-08. If access already occurred, escalate to
Privacy and Legal immediately.

### Request 7: Periodic technical evaluation

**HIPAA specification:** 164.308(a)(8)  
**Evidence status:** Partial

**Evidence description:** `endpoint_hardening_baseline.md` dated 2026-04-18 reports configuration
evaluation; `recovery_validation_summary.md` dated 2026-04-20 reports partial restoration testing;
`gap_assessment.md` provides a document-based evaluation.

**Gap:** These dates fall within 12 months of preparation, but evaluations omit important assets and
systems. Approved periodic evaluation scope, underlying test outputs, recurring review, and
remediation retests are absent. The LIS restore missed its target.

**Remediation owner and timeline:** IT Security and Infrastructure: establish an approved evaluation
schedule and scope, obtain underlying test records, retest LIS recovery, and evaluate excluded
clinical assets or document interim protections by 2026-12-15.

### Request 8: Incident procedures and testing

**HIPAA specification:** 164.308(a)(6)  
**Evidence status:** Partial

**Evidence description:** `ir_playbook_index.md` lists active procedures and reports April 2026
tabletop and live activation dates. `forensic_findings_summary.md` records the March 2026 incident
investigation and containment findings, within the requested 24 months.

**Gap:** The index summarizes procedures but individual playbook contents, exercise outputs, and
full activation records are not supplied. CISO sign-off is absent; cloud and vendor workflows are
draft and untested, and communication test evidence is incomplete.

**Remediation owner and timeline:** IR Lead with Cloud Security, Procurement, and CISO: obtain the
referenced playbooks and exercise records, approve outstanding workflows, and test vendor escalation
and communications by 2026-12-15.

## Readiness summary

- Full: 0.
- Partial: 7.
- None: 1.
- Overall audit readiness: **Not Ready**; no request is fully supported by the supplied package.

The largest overall gap is the absence of a comprehensive, documented risk analysis
covering all ePHI, which an auditor would need to assess the wider security program.
CloudVault's missing BAA is a separate immediate access gate and must not wait for
that broader analysis.

An auditor can evaluate the package's documented gaps and plans, but MedDefense
cannot claim full compliance from these records. Update evidence statuses only
after owners provide and reviewers verify the missing artifacts.

## Local artifact index

| Exact filename | Location |
| --- | --- |
| `ocr_audit_letter.md` | [OCR letter](../compliance/ocr_audit_letter.md) |
| `hipaa_security_rule_crosswalk.md` | [Project crosswalk](../compliance/hipaa_security_rule_crosswalk.md) |
| `risk_register_updates.yaml` | [Risk register](../risk_register/risk_register_updates.yaml) |
| `risk_treatment_plan.md` | [Treatment plan](../risk_register/risk_treatment_plan.md) |
| `endpoint_hardening_baseline.md` | [Endpoint baseline](../prior_controls/endpoint_hardening_baseline.md) |
| `sigma_detection_catalog.md` | [Detection catalog](../prior_controls/sigma_detection_catalog.md) |
| `ir_playbook_index.md` | [Playbook index](../prior_controls/ir_playbook_index.md) |
| `forensic_findings_summary.md` | [Forensic summary](../prior_controls/forensic_findings_summary.md) |
| `recovery_validation_summary.md` | [Recovery summary](../prior_controls/recovery_validation_summary.md) |
| `security_awareness_training_status.md` | [Training status](../prior_controls/security_awareness_training_status.md) |
| `baa_status_note.md` | [BAA status](../vendor/baa_status_note.md) |
| `cloudvault_contract_summary.md` | [Contract summary](../vendor/cloudvault_contract_summary.md) |
| `gap_assessment.md` | [Gap assessment](gap_assessment.md) |
| `acceptable_use_policy.md` | [AUP](acceptable_use_policy.md) |
| `data_classification_policy.md` | [Classification policy](data_classification_policy.md) |
| `vendor_management_policy.md` | [Vendor policy](vendor_management_policy.md) |
| `vendor_risk_assessment.md` | [Vendor assessment](vendor_risk_assessment.md) |
