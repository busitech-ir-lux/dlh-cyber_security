# Vendor Management Policy

**Policy number:** MD-VMP-001  
**Policy title:** Vendor Management Policy  
**Effective date:** On recorded CISO approval; not yet effective  
**Review date:** Within 12 months of approval, then annually  
**Owner:** IT Security and Procurement jointly  
**Approved by:** CISO; approval pending  
**Classification:** Internal  
**Applies to:** All third parties with access to MedDefense systems, networks, or data

This is the complete proposed policy for approval. No approval or implementation
is represented as completed. The owner must record the actual effective date and
next annual review date when the CISO signs.

## Purpose and scope

MedDefense must verify that suppliers protect patient care, systems, and data before
access begins and throughout the relationship. This policy covers SaaS providers,
managed service providers, cloud infrastructure providers, medical device vendors
with network-connected products, and staffing agencies with IT system access.
Procurement must register and classify every supplier before commitment, including
suppliers with no data access.

## Risk tiers and ownership

| Tier | Access and exposure | MedDefense examples |
| --- | --- | --- |
| A: Critical | Any access to ePHI or clinical systems, including storage of encrypted PHI or support access that may expose PHI. | Clinical scheduling platforms, imaging vendors, PHI backup providers such as proposed CloudVault, and Epic integration partners. |
| B: Standard | Access to internal systems or networks, with no ePHI or clinical system access. | Internal administrative software or support services proven not to access ePHI. |
| C: Low | No system, network, or data access. | Office suppliers, physical delivery vendors, and facilities contractors without such access. |

Use the highest applicable tier. If a facilities contractor receives data or system
access, it cannot remain Tier C. IT Security approves classification; Procurement
records vendor name, owner, service, tier, access, data types, locations,
subprocessors, review date, renewal date, and approval status. The business owner
confirms the actual service and data flows. Legal reviews contracts and BAAs, and
IT Security records vendor risks in the risk register with owners and closure dates.

## Pre-engagement requirements

| Tier | Requirements before access or engagement |
| --- | --- |
| A | Receive and review a SOC 2 Type II report or HITRUST CSF certification current within 12 months; a completed MedDefense security questionnaire; penetration test results within 12 months with critical findings and remediation status; all data-handling subprocessors and their jurisdictions; and an executed BAA. Obtain IT Security sign-off and Legal clearance before any ePHI, clinical access, or production transfer. |
| B | Complete the questionnaire, document data and network access, review access controls and incident terms, execute confidentiality and security terms, and obtain IT Security approval before access. Any potential incidental ePHI exposure invokes the BAA gate and Tier A reassessment. |
| C | Record no-access scope and business owner approval before purchase; include a prohibition on unapproved data or system access and reassess before scope changes. |

A questionnaire claim is not a substitute for the report or certification itself.
IT Security must verify the assurance scope, dates, exceptions, and coverage of the
proposed service. SOC 2 is an examination report, not a certification; HITRUST is
an alternative here, so a vendor does not need both. Obtain refreshed evidence if
it becomes older than 12 months before onboarding.

Tier A review must also verify AES-256 at rest, protected keys, TLS 1.2 or higher
with server certificate verification in transit, MFA for privileged access, staff
screening at hire, and annual PHI training supported by completion records. Verify
storage and DR locations, support access, and complete metadata flows. Foreign
processing is not automatically forbidden, but Privacy, Legal, and IT Security must
approve its jurisdiction, safeguards, and purpose in writing before access.

Critical vulnerabilities must be triaged within 24 hours and remediated within
15 calendar days of identification. Actively exploited critical vulnerabilities
require mitigation or access isolation within 24 hours and a dated remediation
plan. A vendor must provide evidence of closure of critical penetration-test
findings before onboarding; unresolved critical findings block approval.

## BAA and contract terms

An executed BAA is mandatory for every Tier A vendor and any vendor whose service
may incidentally expose ePHI. There are no exceptions to this onboarding gate.
Legal must retain the signed agreement before IT creates credentials or permits a
transfer; encryption or vendor willingness to sign cannot replace execution.

The BAA must state permitted uses and disclosures, safeguard and Security Rule
obligations, reporting of unauthorized uses and incidents, cooperation with access,
amendment and accounting duties as applicable, availability of records to HHS,
subcontractor restrictions and safeguards, return or destruction of PHI at
termination, and termination rights for material breach. If return or destruction
is infeasible, Legal must document that fact and require continuing protections
and restricted further use rather than accepting an unsupported deletion promise.
See the [HHS model BAA](https://www.hhs.gov/sites/default/files/model-business-associate-agreement.pdf).

All vendors with MedDefense data must notify MedDefense within 24 hours of discovery
of a suspected or confirmed security incident or breach affecting that data.
They must not wait for internal confirmation. The notice must identify discovery
time, known affected data and services, containment steps, and an investigation
contact; missing details must follow as they become available. Subprocessor
contracts must flow down these safeguards and allow timely notice to MedDefense.

MedDefense retains the right to investigate independently, obtain relevant logs
and evidence promptly, and coordinate notification decisions through Legal and
Privacy. Routine audits may have a reasonable scheduled notice period, but incident
investigation, regulator requests, and urgent evidence access must not be delayed
by a routine notice clause. The 24-hour period is a MedDefense requirement and
must not be described as HIPAA's universal notification deadline.

## Ongoing monitoring and material changes

IT Security and Procurement review Tier A vendors at least annually before the
approval expires, refresh evidence, and track corrective actions. Review Tier B
annually through access and scope confirmation and Tier C at renewal. Ownership
transfer, a new subprocessor, a data center relocation, or a significant security
incident triggers an immediate review before changed access or transfers proceed.
Contracts must require advance notice of planned material changes and prompt
notice of unplanned changes.

The vendor owner supplies current service and data-flow records. IT Security records
findings, severity, treatment, evidence, and a due date in the risk register.
Approval is not renewed while mandatory evidence is missing or critical findings
remain unresolved. IT Security must suspend affected access when continued use
creates an unacceptable immediate risk and coordinate safe clinical continuity.

## Assessment decisions and exceptions

Use Pass for an evidenced requirement met; Acceptable for a reported control with
no identified policy conflict but requiring normal verification; Concern for a gap
requiring correction or further evidence; and Critical Concern for a missing BAA,
a failed mandatory Tier A test gate, or a material contractual safeguard failure.
Use the highest risk where one item contains several issues. Review likelihood,
patient and regulatory impact, exposure, and available evidence; do not average
away a mandatory gate failure.

Approve means every mandatory gate is verified. Approve with Conditions permits
planning and contract corrections only, with a list of measurable gates; it grants
no clinical or ePHI access until IT Security verifies every condition and Legal
confirms execution. Do Not Approve applies when the vendor refuses required terms,
cannot close critical risks, or proposes access despite failed gates. The CISO
records the final decision and residual risks.

For nonmandatory process exceptions, the CISO may approve a documented request for
up to 90 days with an owner, reason, safeguards, and expiry. No exception may waive
the BAA, mandatory Tier A evidence, required incident terms, or legal obligations.

## Offboarding, records, and enforcement

The business owner notifies IT and Procurement of termination. IT revokes accounts,
API tokens, remote access, and integrations within 24 hours of contract termination
and records verification. The vendor must return data in an agreed usable format
or provide certified destruction within 30 days of termination, covering production,
backups, and subprocessors; return requires confirmed receipt and removal of
remaining vendor copies where feasible. Any legally required retention or infeasible
PHI destruction must be reviewed and documented by Legal with continuing safeguards.

Procurement retains assessments, signed contracts and BAAs, review records,
termination evidence, and exception decisions for at least six years from creation
or last effective date, whichever is later. IT Security monitors compliance;
unauthorized engagement or access triggers access suspension and HR or contract
enforcement. The owners review this policy annually and after a supplier incident;
the CISO approves revisions.

## Source basis

`prior_policy_inventory.md` identifies the missing written process.
`cloudvault_contract_summary.md`, `baa_status_note.md`, and
`cloudvault_subprocessor_list.md` identify the access, agreement, and data-flow gaps
that these gates address. `hipaa_security_rule_crosswalk.md` associates business
associate contracts with 164.308(b). These sources do not show that CloudVault has
already passed any gate.

## Acknowledgment

I acknowledge that I have read, understood and agree to comply with this policy.

**Employee name:** ____________________  
**Signature:** ____________________  
**Date:** ____________________
