# Data Classification Policy

**Policy number:** MD-DCP-001  
**Policy title:** Data Classification Policy  
**Effective date:** On recorded CISO approval; not yet effective  
**Review date:** Within 12 months of approval, then annually  
**Owner:** IT Security  
**Approved by:** CISO; approval pending  
**Classification:** Internal  
**Applies to:** All MedDefense data and all people or providers handling it

This is the complete proposed policy for approval. No approval or implementation
is represented as completed. The owner must record the actual effective date and
next annual review date when the CISO signs.

## Purpose and scope

This policy assigns protection rules according to the harm that disclosure,
alteration, or loss of data could cause. It applies to all data created, stored,
transmitted, or processed by or on behalf of MedDefense, including paper records,
backups, metadata, and vendor data flows. Employees, contractors, temporary staff,
and service providers must follow the rules for the highest tier present in a
record or dataset.

## Classification tiers

The examples below define how MedDefense operations must be classified; they do
not claim that each illustrative document exists in the supplied materials.

### Tier 1: Public

Public data has been approved in writing for release by its business owner and
Communications, with Privacy review when health information may be involved.
Examples are approved MedDefense clinic opening hours, published patient service
brochures, and approved public recruitment notices. A document is not Public merely
because someone uploaded it to a public location.

### Tier 2: Internal

Internal data is for employees and authorized contractors whose work requires it;
exposure would cause operational inconvenience without patient or regulatory harm.
Examples are a routine staff meeting agenda without patient or personnel details,
general service desk instructions without security configurations, and internal
training schedules without employee completion records. PHI, credentials, and
sensitive business details must never be classified as Internal.

### Tier 3: Confidential

Confidential data could cause financial, legal, or reputational harm if exposed.
Examples include employee personnel records, financial budgets, the CloudVault
contract and negotiation records, security configuration baselines, and incident
reports without patient identifiers. Employee health information must be reviewed
by Privacy because its legal status depends on the context; employment records
are not automatically HIPAA PHI.

### Tier 4: Restricted / ePHI

Restricted data includes patient-identifiable information and other data requiring
the highest protection. Examples are patient-linked laboratory results, Epic EHR
database exports, LIS backup archives, pharmacy backups, PACS/RIS metadata with
patient identifiers, and recovery logs that identify patients. CloudVault transfer
and analytics metadata must be Tier 4 whenever it identifies or can reasonably be
linked to a patient; encryption does not lower the source data's classification.

The Security Rule applies to ePHI; identifiable paper patient records remain
Restricted and subject to applicable privacy and breach rules. Every unauthorized
Tier 4 access must be reported immediately and triggers a documented four-factor
breach risk assessment by Privacy and Legal under this policy. Record the nature
and extent of PHI, the unauthorized recipient, whether it was acquired or viewed,
and the mitigation. Privacy and Legal document any statutory exception or other
basis affecting notification; staff must not declare an event nonreportable.
See [HHS breach notification guidance](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

## Handling matrix

AES-256 means encryption at rest using centrally managed keys with access separated
from ordinary data access. All TLS connections below require server certificate
verification; invalid or expired certificates must not be bypassed. Paper must be
locked away for Tiers 3 and 4 when not in use, and all tiers remain subject to
approved retention schedules and legal holds before disposal.

| Tier | Storage | Transmission | Internal sharing | External sharing | Disposal |
| --- | --- | --- | --- | --- | --- |
| 1: Public | Approved publication repository; restrict editing to designated publishers and retain a version history. | Publish through HTTPS using TLS 1.2 or higher with server certificate verification. | Approved public copy may be shared with all staff. | Release only the exact owner- and Communications-approved public version. | Delete obsolete electronic working copies and recycle public paper after retention review. |
| 2: Internal | Authenticated MedDefense document repository with staff and authorized contractor groups; no anonymous links. | HTTPS using TLS 1.2 or higher with server certificate verification, or SFTP using SSHv2 with host-key verification. | Share only with employees and authorized contractors who need the material for work. | Owner must authorize a named recipient; use an approved authenticated portal and confidentiality terms. | Delete electronic copies from active repositories and expire backups under the retention schedule; cross-cut shred paper. |
| 3: Confidential | MedDefense-approved repository and endpoints using AES-256 at rest, named access groups, and access logs; lock paper cabinets. | HTTPS using TLS 1.2 or higher with server certificate verification, or SFTP using SSHv2 with host-key verification; prohibit public links. | Owner-approved role groups only; review access quarterly and remove it when roles change. | Owner and IT Security approve named recipients, purpose, and confidentiality agreement; use an authenticated portal with MFA and expiring access. | Purge or destroy electronic media under an IT Security-approved sanitization process and retain the record; cross-cut shred paper. |
| 4: Restricted / ePHI | Approved clinical or backup platform with AES-256 at rest, separately managed keys, MFA for administration, role-based access, and audit logs; paper in locked controlled areas. | Approved clinical interface over TLS 1.2 or higher with server certificate verification, or SFTP using SSHv2 with host-key verification; IT Security must approve endpoints. | Assigned clinical or operational role only; log access, apply minimum necessary rules where applicable, and review permissions quarterly. | Data owner and Privacy authorize the purpose and recipient; service providers require an executed BAA and completed vendor gates before transfer, including metadata transfers. | Apply NIST SP 800-88 media sanitization or equivalent, selecting a method appropriate to the media and sensitivity; retain verification or destruction certificates and securely cross-cut shred paper. |

Tier 4 sharing with a provider for treatment must use an approved clinical channel;
a BAA is required for a business associate relationship, not automatically for
every legally permitted recipient. The unconditional Tier A vendor BAA gate in the
Vendor Management Policy still applies to MedDefense procurement.

## Classification responsibility

The creator assigns a tier when creating or receiving data and marks documents,
exports, and dataset metadata with that tier. The business data owner verifies the
classification and maintains it through copying, backup, export, and vendor use.
When unsure, use Tier 3 until reviewed; any known or suspected patient-identifiable
data must be Tier 4 immediately. Mixed datasets inherit their highest tier.

Only the data owner with written IT Security approval may reclassify data. Privacy
must also approve any lowering of Tier 4 patient information, including validation
that de-identification requirements are met. Removing a name alone is insufficient.
Record the old tier, new tier, reason, approvers, and date.

## Exceptions and enforcement

The CISO may approve a documented exception for at most 90 days, with Privacy and
Legal approval when PHI is involved. The request must identify the data, business
need, risk, compensating protection, responsible owner, and expiry date; IT Security
tracks it and re-reviews it before any renewal. Exceptions cannot waive legal
obligations, the BAA gate, or required incident reporting. When an exception expires,
normal rules apply unless a new approval has been recorded.

Managers correct handling violations with IT Security and HR under the disciplinary
process, up to termination or contract action. IT Security checks compliance through
quarterly access reviews and samples of storage, transfers, and disposal records;
data owners must correct findings by recorded deadlines.

## Review and source basis

IT Security reviews this policy annually and after any incident that reveals a
data-handling gap. Keep approved versions, exceptions, and review records for at
least six years from creation or last effective date, whichever is later; this does
not require keeping every underlying patient record for exactly six years.

`prior_policy_inventory.md` records the missing classification policy.
`forensic_findings_summary.md` identifies sensitive incident and configuration data;
`cloudvault_contract_summary.md` identifies the proposed backup and metadata flows.
The handling rules above are requirements created here, not evidence that the
current systems or vendor already meet them. See also the local
`hipaa_security_rule_crosswalk.md`.

## Acknowledgment

I acknowledge that I have read, understood and agree to comply with this policy.

**Employee name:** ____________________  
**Signature:** ____________________  
**Date:** ____________________
