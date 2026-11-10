# Pre-audit quiz study notes

This is study support for the quiz labeled Task 0 in `tasks.md`, which the user
calls Task 1. The materials include a scenario but no individual quiz questions.

## What the frameworks do

NIST CSF 2.0 organizes security outcomes into six functions: Govern sets direction
and accountability; Identify explains assets and risks; Protect reduces exposure;
Detect finds suspicious activity; Respond manages incidents; and Recover restores
services. It is a risk management framework, not a certificate of HIPAA compliance.
See [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

HIPAA's Security Rule requires administrative, physical, and technical safeguards
for electronic protected health information, called ePHI. Administrative safeguards
include risk analysis and training, physical safeguards include facility and media
protection, and technical safeguards include access and audit controls. Some
implementation specifications are required and others are addressable; addressable
does not mean optional, because the organization must assess suitability and
document its decision and any appropriate alternative. See the
[HHS Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

A crosswalk connects related requirements, but the relationship is not one-to-one.
For example, logging supports several security outcomes, while an audit-control
requirement needs evidence of actual coverage and operation. A framework mapping
helps locate evidence; it does not prove that the evidence is sufficient.

## What evidence can prove

A deployed control, an approved rule, and a record that the rule operates are
separate forms of evidence. `endpoint_hardening_baseline.md` reports configuration
work, but also incomplete coverage and missing monthly review sign-off. A new
policy can establish a clear requirement after approval; it cannot prove that all
staff already follow it. Missing records mean the control cannot be substantiated
from this package, even when someone says it exists.

MedDefense's technical work therefore cannot establish overall compliance.
`security_awareness_training_status.md` reports 1,460 completions out of 2,000
people, leaving 540 without completion evidence in that reporting period.
`baa_status_note.md` says CloudVault's agreement is not executed. These are specific
gaps that endpoint hardening cannot resolve.

## Risk analysis and risk treatment

Risk analysis identifies where ePHI exists, the threats and weaknesses that affect
it, the safeguards already present, and the likelihood and impact of harm. Risk
treatment chooses what to do, assigns an owner and date, and checks the result.
A post-incident report is useful input but does not cover every ePHI environment.
See [HHS risk analysis guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis/index.html).

At MedDefense, `risk_register_updates.yaml` records risks and
`risk_treatment_plan.md` assigns actions and owners. The plan explicitly lacks CISO
approval, and several risk IDs differ from the forensic summary. These issues limit
its reliability until the records are reconciled and approved.

## Vendor safeguards and incident decisions

A Business Associate Agreement, or BAA, sets obligations for a provider handling
PHI on MedDefense's behalf. Willingness to sign is not an executed agreement.
Encryption does not remove the project's BAA gate for clinical backup storage.
The Vendor Management Policy also requires recent testing, reviewed subprocessors,
and enforceable incident terms; a BAA alone cannot validate a vendor's security.
See the [HHS model BAA](https://www.hhs.gov/sites/default/files/model-business-associate-agreement.pdf).

The proposed policy requires vendor notice within 24 hours of a suspected or
confirmed incident affecting MedDefense data. This is a MedDefense contract
requirement, not a claim that HIPAA sets a universal 24-hour notification deadline.
Incident response and legal breach notification are related but distinct decisions.

For an impermissible PHI use or disclosure, the breach assessment considers the
information involved, the recipient, whether it was acquired or viewed, and the
mitigation. Presumed breach, exceptions, and notification duties require Privacy
and Legal review. MedDefense requires assessment of every unauthorized Tier 4
access; that internal rule does not mean every event legally requires notice.
See [HHS breach notification guidance](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

## Reading the case carefully

The LIS restore took 41 minutes against a 30-minute recovery time objective, an
11-minute miss. The one-hour recovery point objective describes acceptable data
loss measured in time; the summary does not establish that it was met. A successful
partial restore cannot prove that all critical clinical services can recover.

The supplied materials list 21 assessment rows and eight audit requests. Use the
actual lists rather than the conflicting introductory counts. The sample matrix
also contains filenames that are absent from this directory; those examples must
not be reused as if they were available evidence.
