# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-11-10  
**Assessor:** Project analyst; no individual name supplied  
**Framework version:** NIST CSF 2.0, using the supplied project interpretations  
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164

## Assessment method

This is a document review of the supplied baseline, not a live control test or a
complete HIPAA risk analysis. Implemented means the supplied artifact demonstrates
the specified outcome within its documented scope. Partial means some activity
exists but coverage, approval, or operating evidence is incomplete. Not Implemented
means the supplied evidence does not establish the outcome; it is not a claim about
unobserved systems.

Critical gaps block basic governance or leave major workforce exposure. High gaps
allow significant patient-data, access, monitoring, or recovery risk. Medium gaps
limit coverage or repeatability. Low denotes a minor evidence weakness; None means
no gap identified within the assessed scope. These are qualitative analyst judgments,
not measured probabilities or a legal compliance score.

There are 21 listed subcategories, not 22. See [scope notes](README.md) for source
errors, including RC.CO-01 and conflicting risk IDs. Titles below describe the
project interpretation, not verbatim official CSF text. Existing summaries support
only their stated findings; their referenced raw logs and scripts were not supplied.

## Gap Assessment Matrix

| CSF Function | Subcategory ID | Subcategory title | Implementation status | Evidence reference | Gap severity | Gap description |
| --- | --- | --- | --- | --- | --- | --- |
| GOVERN | GV.OC-01 | Organizational mission and risk context understood | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md` | High | Clinical risk priorities are visible, but an agreed mission and stakeholder risk context is not documented. |
| GOVERN | GV.PO-01 | Cybersecurity policies established and communicated organization-wide | Not Implemented | `risk_register_updates.yaml` | Critical | R-004 records three missing enforceable policies; approval and distribution evidence is absent. |
| GOVERN | GV.SC-04 | Suppliers inventoried and prioritized by criticality | Not Implemented | `risk_register_updates.yaml`; `forensic_findings_summary.md` | High | R-001 and the incident findings identify no formal vendor inventory or tiering process. |
| GOVERN | GV.SC-07 | Supplier risks assessed and managed continuously | Partial | `risk_register_updates.yaml`; `risk_treatment_plan.md`; `forensic_findings_summary.md` | High | R-001 records supplier risk, but vendor assessments, approvals, and ongoing monitoring are missing. |
| IDENTIFY | ID.AM-01 | Assets inventoried across the clinical environment | Partial | `endpoint_hardening_baseline.md`; `risk_register_updates.yaml` | Medium | Workstation and server counts exist, but medical devices are uncounted and the wider inventory is incomplete. |
| IDENTIFY | ID.RA-01 | Vulnerabilities and threats identified and recorded | Partial | `forensic_findings_summary.md`; `risk_register_updates.yaml` | High | Incident weaknesses are recorded, but organization-wide identification, validation, and consistent risk records are not evidenced. |
| IDENTIFY | ID.RA-06 | Risk responses prioritized and tracked consistently | Partial | `risk_treatment_plan.md`; `risk_register_updates.yaml` | High | Owners and targets exist, but approval, closure evidence, and recurring tracking are missing; targets have passed. |
| PROTECT | PR.AA-01 | User identities and credentials managed securely | Partial | `endpoint_hardening_baseline.md`; `ir_playbook_index.md` | High | Password and credential-response measures exist without documented end-to-end account lifecycle controls. |
| PROTECT | PR.AA-05 | Access permissions reviewed and privileges minimized | Partial | `endpoint_hardening_baseline.md`; `forensic_findings_summary.md` | High | Local admin restrictions are partial; service-account Domain Admin exposure has no documented closure or access review. |
| PROTECT | PR.AT-01 | Workforce receives security awareness and training | Partial | `security_awareness_training_status.md`; `risk_register_updates.yaml` | Critical | Only 73% completion is evidenced for the recorded period; role assignments and phishing metrics are missing. |
| PROTECT | PR.DS-01 | Stored data protected against unauthorized access | Partial | `endpoint_hardening_baseline.md` | High | BitLocker is confirmed on only 173 Windows endpoints; full ePHI storage protection is not demonstrated. |
| PROTECT | PR.PS-01 | Secure configuration baselines established and maintained | Partial | `endpoint_hardening_baseline.md` | High | Only 231 of 280 clinical workstations and 18 of 26 laptops are hardened; GPO conflicts persist. |
| PROTECT | PR.PS-04 | Security logs generated for continuing monitoring | Partial | `endpoint_hardening_baseline.md`; `sigma_detection_catalog.md`; `forensic_findings_summary.md` | High | Logging and forwarding are incomplete, DR CloudTrail is absent, and review records are informal. |
| DETECT | DE.CM-01 | Networks and endpoints monitored for threats | Partial | `sigma_detection_catalog.md`; `endpoint_hardening_baseline.md` | High | Sysmon reaches 198 of 280 clinical workstations; medical-device telemetry and complete network coverage are not evidenced. |
| DETECT | DE.CM-06 | External service provider activity monitored continuously | Partial | `sigma_detection_catalog.md`; `forensic_findings_summary.md` | High | Provider-related cloud detection is incomplete and the DR region lacks CloudTrail coverage. |
| DETECT | DE.AE-02 | Potentially adverse events analyzed for threats | Implemented | `forensic_findings_summary.md`; `sigma_detection_catalog.md` | None | The documented incident demonstrates event analysis; monitoring coverage limitations are captured in separate rows. |
| RESPOND | RS.MA-01 | Incident response procedures activated and executed | Partial | `ir_playbook_index.md`; `forensic_findings_summary.md` | High | Activation and containment are reported, but vendor and cloud workflows remain draft and CISO sign-off is absent. |
| RESPOND | RS.AN-03 | Incident analysis establishes cause and impact | Implemented | `forensic_findings_summary.md` | None | The documented incident analysis identifies vendor entry, credential activity, and privilege abuse within its stated limits. |
| RESPOND | RS.CO-02 | Incident stakeholders notified through tested procedures | Partial | `ir_playbook_index.md` | High | Communication testing evidence is incomplete and the vendor escalation workflow remains untested. |
| RECOVER | RC.RP-01 | Recovery plan executed for affected services | Partial | `recovery_validation_summary.md` | High | LIS exceeded its 30-minute RTO by 11 minutes; retest is pending and AD/EHR recovery is not fully tested. |
| RECOVER | RC.CO-01* | Recovery progress communicated to designated stakeholders | Not Implemented | `recovery_validation_summary.md` | High | Clinical notification language is missing and no performed recovery communication is evidenced. |

*RC.CO-01 is the supplied assignment label. Use RC.CO-03 for recovery progress
communication in an official CSF 2.0 profile. The summary's general claim of partial
communication support does not demonstrate that a notification was actually sent.

## Summary

**Implementation counts:** Implemented: 2; Partial: 16; Not Implemented: 3.
Total: 21. These counts describe evidence-supported outcomes, not a percentage of
HIPAA compliance. Current operation still requires confirmation.

**Top three pre-audit priorities:**

1. GV.PO-01, Critical: obtain CISO approval, distribution records, and acknowledgments for the three
   proposed policies.
2. PR.AT-01, Critical: reconcile current workforce records, address the 540 recorded missing
   completions, and document an interim training plan.
3. GV.SC-07, High: assess CloudVault and enforce the signed-BAA and vendor-evidence gates before any
   ePHI transfer.

**Connection to governance and resilience work:** The new policies define staff,
data, and vendor obligations, but approval and operating records are needed before
these gaps can close. The CloudVault assessment turns R-001 into specific access
gates. The audit package assigns evidence owners, while recovery work must retest
the LIS, test other critical systems, and document clinical communications. These
actions connect written governance to demonstrated protection and recovery.
