# Compliance Engine answers

These answers use the local MedDefense materials and the public references in the
project README. The original materials have not been changed.

| Source task | Answer file |
| --- | --- |
| 0: Pre-audit quiz | [Study notes](quiz_study_notes.md) |
| 1: Control mapping | [Gap assessment](gap_assessment.md) |
| 2: Acceptable use | [Acceptable Use Policy](acceptable_use_policy.md) |
| 3: Data classification | [Data Classification Policy](data_classification_policy.md) |
| 4: Vendor management | [Vendor Management Policy](vendor_management_policy.md) |
| 5: CloudVault assessment | [Vendor risk assessment](vendor_risk_assessment.md) |
| 6: Auditor evidence | [Audit evidence package](audit_evidence_package.md) |
| 7: Board communication | [CISO compliance brief](ciso_compliance_brief.md) |

The user calls the quiz Task 1; `tasks.md` labels it Task 0. Study notes replace quiz
answers, and all seven written deliverables are included. The learning objective
answers are in [LEARNING_OBJECTIVES.md](../LEARNING_OBJECTIVES.md).

## Dates and evidence boundaries

Preparation date is 2026-11-10. The source evidence mostly describes March and April
2026; it is not proof that controls remain unchanged today. For planning only, the
six-week audit window begins on the preparation date, giving a target audit date of
2026-12-22. No exact interview date is supplied. Owners must confirm that date and
adjust the proposed deadlines. June and July targets in `risk_register_updates.yaml`
are past due without closure evidence; this package does not silently replace them.

The three policies are complete proposed policy texts, pending CISO approval and
distribution. Their requirements are mandatory once adopted, but no signature,
workforce acknowledgment, implementation record, or executed BAA is invented here.
The gap matrix assesses the supplied baseline, before adoption of these policies.

## Source inconsistencies

The instructions say 22 subcategories but list 21. All 21 listed rows are assessed.
The introductory reference to 15 audit categories is unsupported by a supplied
15-item letter; `ocr_audit_letter.md` actually contains eight requests, all answered.

The local CSF reference simplifies several outcomes. The matrix follows those
project interpretations and identifies them as such. In official CSF 2.0, ID.AM-01
concerns hardware; software and services are covered separately. DE.CM-01 concerns
networks and network services, and PR.PS-04 concerns logs available for monitoring.
The requested RC.CO-01 is not a current CSF 2.0 subcategory; the recovery progress
communication outcome is RC.CO-03. The requested row is retained and labeled.
See the [official CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

The README's linked HIPAA crosswalk is a 2016 document for the older framework,
not a CSF 2.0 crosswalk despite its 2025 hosting path. The local
`hipaa_security_rule_crosswalk.md` provides project associations, not proof of legal
compliance. The README's original SP 800-161r1 PDF is archived; the
[November 2024 update](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final)
is the corrected supply-chain reference.

Risk IDs conflict between `forensic_findings_summary.md` and
`risk_register_updates.yaml`. Use the YAML register's IDs for current tracking:
R-001 vendor management, R-002 training, R-003 inventory, R-004 policies, and R-005
DR-region logging. Preserve the forensic document as historical evidence and
reconcile its different labels rather than merging unrelated risks.

A filename mentioned inside a summary does not establish that the underlying file
was supplied. For example, `recovery_test_record.md` and the individual incident
playbooks are not available here. They must be requested before claiming direct
inspection of those records.
