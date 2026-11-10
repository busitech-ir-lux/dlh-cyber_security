# Learning objectives: Compliance Engine

These answers explain each objective in the README using the MedDefense case.
The [task index](tasks/README.md) links to the complete deliverables and documents
source inconsistencies. Findings describe the supplied evidence as reviewed on
2026-11-10; new policies still require actual approval and adoption.

## Technical objectives

### Map deployed controls to CSF 2.0 subcategories using named evidence

Begin with the outcome being assessed, identify the exact artifact that supports
it, and check its scope and limitations before assigning a status. In
[gap_assessment.md](tasks/gap_assessment.md), `endpoint_hardening_baseline.md`
supports PR.PS-01 because it describes configuration baselines and deployment.
The result is Partial because only 231 of 280 clinical workstations and 18 of 26
administrative laptops are hardened, and conflicting settings remain.

`forensic_findings_summary.md` supports RS.AN-03 because it describes the attack
entry point, credential activity, and privilege abuse. That analysis demonstrates
the outcome for the reported incident, but does not prove that every incident has
been investigated or that all weaknesses were fixed. A source must support the
specific claim made; a relevant filename alone is insufficient.

The assignment contains 21 listed outcomes. Its RC.CO-01 label is retained for
traceability, but official CSF 2.0 uses RC.CO-03 for recovery progress communication.
Several local interpretations are broader than the official subcategories, so a
formal profile must use the official definitions. See
[NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

### Identify gaps across the security functions

A useful assessment records weaknesses as clearly as successes. MedDefense's
baseline has 2 Implemented, 16 Partial, and 3 Not Implemented outcomes under the
project interpretations. These counts are not a HIPAA compliance percentage.

| Function | Case finding | What is needed |
| --- | --- | --- |
| Govern | `risk_register_updates.yaml` R-004 records missing enforceable policies. | CISO approval, distribution, acknowledgment, and evidence that the policies operate. |
| Identify | `endpoint_hardening_baseline.md` excludes uncounted medical devices. | Complete owned asset records and include all ePHI environments in risk analysis. |
| Protect | `security_awareness_training_status.md` reports only 73% training completion. | Reconcile current workforce records, complete overdue training, and retain dated results. |
| Detect | `sigma_detection_catalog.md` reports absent DR-region logging and incomplete endpoint sources. | Validate collection, review activity, and retain evidence of coverage and follow-up. |
| Respond | `ir_playbook_index.md` reports draft vendor and cloud workflows and incomplete communication testing. | Obtain complete procedures, approve them, test them, and retain results. |
| Recover | `recovery_validation_summary.md` reports a 41-minute LIS restore against a 30-minute objective. | Retest after correction, validate restored data, and test other critical systems and clinical communications. |

Identify is included because the task explicitly requires it even though the
learning objective's abbreviated list omits it. Severity prioritizes work by likely
harm and urgency; an action becomes complete only when its success criterion is
verified, not merely when its owner receives a deadline.

### Evaluate a vendor using a structured risk method

First define the service, data, access, and business impact. Then assign a tier,
apply that tier's requirements, review each response against evidence, and identify
mandatory approval gates. Record the rationale, required evidence, verifier, and
final decision so another reviewer can repeat the assessment.

CloudVault is Tier A because `cloudvault_contract_summary.md` describes clinical
backups containing ePHI and support access to the management console. In
[vendor_risk_assessment.md](tasks/vendor_risk_assessment.md), all 15 questionnaire
items are assessed against [vendor_management_policy.md](tasks/vendor_management_policy.md).
The result is 0 Pass, 6 Acceptable, 5 Concern, and 4 Critical Concern ratings.
Acceptable describes a reported control without a stated policy conflict; it is
not independent verification.

The critical findings are outdated penetration testing, delayed incident notice,
delayed data removal, and the missing executed BAA. A current SOC 2 Type II report
is also needed: its reported age was already 11 months in April, and no refresh is
supplied for November. The absence of HITRUST alone is not a failure because the
policy accepts either current SOC 2 Type II or HITRUST assurance.

The recommendation is Approve with Conditions for planning and negotiation only.
No ePHI or clinical access is authorized until the evidence and contract gates are
verified. An EU subprocessor is not automatically prohibited; the unanswered data
flow, jurisdiction, access, and safeguard questions must be resolved. This approach
follows a supply-chain risk process rather than treating a certificate or a signed
contract as a complete security assessment. See the updated
[NIST supply-chain guidance](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final).

## Conceptual objectives

### Explain the relationship between CSF outcomes and HIPAA specifications

CSF provides an outcome structure for managing cybersecurity risk. HIPAA imposes
legal safeguards for regulated organizations and ePHI. A crosswalk helps find
related evidence, but one CSF outcome can support several HIPAA provisions, and a
single HIPAA requirement may need multiple controls. See the
[HHS Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

For example, endpoint logging and detections support the project's PR.PS-04 and
DE.CM-01 outcomes and help answer the 164.312(b) audit-control request. The
`hipaa_security_rule_crosswalk.md` connects risk records to
164.308(a)(1)(ii)(A), but the risk register and incident report alone do not establish
a comprehensive risk analysis. The missing scope and methodology still matter.

The README's public HIPAA crosswalk dates from 2016 and uses an older CSF version.
It must not be treated as a direct CSF 2.0 mapping simply because its web address
contains 2025. Neither a crosswalk nor this project's assessment is a certification
of legal compliance.

### Distinguish existence from documentation and supported evidence

A control may operate without enough records for an independent reviewer to verify
its scope or consistency. A written requirement may also exist without being
implemented. Audit readiness needs both an appropriate control and reliable proof
of its approval, coverage, operation, review, and correction where applicable.

| Evidence layer | MedDefense example | What it cannot establish alone |
| --- | --- | --- |
| Reported technical operation | The baseline says password settings are enforced through GPO. | Account provisioning, termination, or completed access reviews. |
| Summary of activity | The playbook index reports tabletop exercises. | The full procedures, exercise observations, or management approval. |
| Proposed written requirement | The new AUP requires annual signatures. | That users have signed or that access is blocked for nonresponders. |
| Documented absence | The BAA status note says the agreement is not executed. | That no ePHI has reached CloudVault. |

The evidence package therefore uses Full, Partial, and None for the requested
proof, rather than assuming the control is proven whenever its topic appears in a
file. Its present result is 0 Full, 7 Partial, and 1 None. Missing documentation
limits what can be substantiated; it does not justify inventing a control failure
or claiming a legal violation without the necessary facts.

### Explain why policy needs specificity and enforcement

A policy must tell a named person what action is required, when it is required,
how it is verified, and what happens if the rule is ignored. The instruction
“protect sensitive information” cannot tell staff which repository to use, who
may receive data, or how a violation will be handled.

The [Data Classification Policy](tasks/data_classification_policy.md) assigns four
tiers and defines storage, transfer protocols, recipients, and disposal. It uses
TLS 1.2 or higher with server certificate verification instead of the vague phrase
“secure transfer.” It also assigns classification authority, a 90-day exception
limit, and review duties. These requirements can be inspected and enforced after
approval; the policy text does not claim that the technical settings already exist.

The vendor policy makes the distinction practical: no executed BAA means no Tier A
onboarding, with no exception. A conditional assessment permits evidence collection
but cannot waive that gate. Contract requirements such as 24-hour incident notice
are MedDefense rules; they must not be misrepresented as universal HIPAA deadlines.

## Transversal objectives

### Write policies that people can read and follow

Plain language keeps the actor, action, and condition visible. “Do not share your
account” is easier to follow than an abstract statement about identity assurance.
Define unavoidable terms such as ePHI and BAA, keep related rules together, and
use tables where staff need to compare handling requirements.

The [AUP](tasks/acceptable_use_policy.md) names employees, contractors, temporary
clinical staff, and remote vendors. It lists prohibited actions, explains immediate
reporting through a ticket and phone call, and connects violations to the HR
process. It allows specifically authorized duties such as billing without creating
a general permission to browse patient records. The ticket URL and phone number
are not supplied, so IT Security must publish and test them before distribution.

A complete policy still needs an owner, approval, an effective date, a review cycle,
and adoption records. This project supplies the proposed text and leaves actual
approval and signatures pending rather than fabricating them.

### Package evidence for independent evaluation

Use the auditor's exact requests as the structure. For each request, provide the
applicable specification, evidence status, exact artifact names, their limits,
and a remediation owner and deadline when proof is incomplete. Link to the local
files and distinguish summaries from the underlying records they describe.

The [audit evidence package](tasks/audit_evidence_package.md) follows all eight
requests in `ocr_audit_letter.md`. Request 6 is None because neither an executed
CloudVault BAA nor verified proof that ePHI access has not begun is available.
`baa_status_note.md` explains the gap, but it is not a substitute for either
requested proof. Request 8 is Partial because the index reports exercises without
supplying the complete playbooks and test records.

Good packaging also checks time periods and conflicting records. The training
summary ends in April, so it does not describe the entire rolling year as of
November. The forensic summary's risk IDs differ from the YAML register and must
be reconciled. These limitations remain visible to the reviewer.

### Translate findings into clear executive decisions

Leadership needs to understand patient and business impact, the current evidence,
and the action it must authorize. Replace a code such as GV.SC-07 with a direct
statement: the proposed patient-backup provider cannot receive data until its
agreement, security evidence, and contract safeguards are verified. Keep technical
identifiers in the supporting assessment for traceability.

The [CISO brief](tasks/ciso_compliance_brief.md) rates readiness as Not Ready,
acknowledges completed hardening and incident work, and identifies policy adoption,
CloudVault clearance, and training evidence as priorities. It gives three actions
with owners and deadlines and requests a specific board decision. It also points
to the broader open risk-analysis, access, logging, and recovery work so the short
brief does not imply that three actions alone will establish compliance.

The dates are proposed planning dates based on a six-week window from preparation;
the actual audit date must be confirmed. Completion means verified evidence and
recorded decisions, not a promise that the organization will be compliant by a
particular date.
