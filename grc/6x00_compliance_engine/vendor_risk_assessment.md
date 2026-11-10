# CloudVault Medical vendor risk assessment

**Assessment date:** 2026-11-10  
**Reviewer:** Project analyst; IT Security and Legal sign-off pending  
**Decision:** Approve with Conditions; no production or ePHI access authorized

## Vendor overview and method

CloudVault Medical proposes clinical backup archive and disaster recovery storage
under a three-year contract. `cloudvault_contract_summary.md` identifies Epic EHR
exports, LIS backups, PACS/RIS metadata, pharmacy backups, and recovery logs that
may contain patient identifiers. Support staff may access the backup management
console. This is **Tier A: Critical** under [Vendor Management Policy](vendor_management_policy.md),
including encrypted ePHI storage and potentially identifying metadata.

This review applies the proposed policy as the project's decision standard; policy
adoption itself remains pending. Sources are `cloudvault_security_questionnaire.md`,
`cloudvault_contract_summary.md`, `cloudvault_subprocessor_list.md`, and
`baa_status_note.md`. Questionnaire responses were received on 2026-04-26. They are
vendor statements, not independently validated tests, and no actual SOC report,
penetration report, or signed agreement is supplied.

Pass means a requirement is verified by suitable evidence. Acceptable means a
reported control has no identified conflict, subject to routine verification.
Concern means missing evidence or a gap needs correction. Critical Concern means
a mandatory Tier A gate or material contractual safeguard fails. Ratings consider
potential patient and regulatory impact and the uncertainty in the evidence;
there is no numeric score that can cancel a failed gate.

## Findings table

| Item number | Finding | Risk rating | Gap description | Required action |
| --- | --- | --- | --- | --- |
| 1 | SOC 2 Type II report reportedly 11 months old when answered | Concern | Report is absent and its reported age is now beyond the 12-month window unless refreshed. | Obtain the current actual report, dated within 12 months at onboarding; review scope, exceptions, coverage period, and remediation. |
| 2 | No HITRUST certification | Acceptable | No policy conflict: current SOC 2 Type II or HITRUST is sufficient. | Use the SOC 2 route only after item 1 is satisfied; do not demand both. |
| 3 | AES-256 encryption at rest reported | Acceptable | No stated algorithm conflict; operation is unverified. | Verify backup and metadata coverage, key ownership, support access, and key-management evidence. |
| 4 | TLS 1.2 reported | Acceptable | Protocol meets the minimum; certificate validation and complete flow coverage are unverified. | Verify certificate checks and TLS coverage on primary, DR, support, and subprocessor transfer paths. |
| 5 | Penetration test 22 months old; no findings supplied | Critical Concern | Mandatory test recency and critical finding closure are not met. | Supply test results within 12 months at approval, critical findings, remediation status, and closure evidence. |
| 6 | US CDN and EU analytics provider disclosed | Concern | Data fields, precise locations, administrative access, and safeguard flow-down are unclear. | Identify all subprocessors and jurisdictions; supply field-level flows and contracts, and obtain Privacy, Legal, and IT Security approval. |
| 7 | US primary site; DR location undisclosed | Concern | Backup location, jurisdiction, and related access cannot be assessed. | Disclose DR countries and regions, replication routes, support locations, and applicable safeguards before transfer. |
| 8 | Notice 72 hours after internal breach confirmation | Critical Concern | Later and narrower than 24 hours from discovery of suspected or confirmed incidents affecting MedDefense data. | Execute amended incident and BAA terms with the required trigger, clock, scope, and subprocessor notice flow-down. |
| 9 | Deletion within 90 days of written request | Critical Concern | Fails the 30-day termination trigger and leaves backup and subprocessor copies unresolved. | Execute return or certified-destruction terms within 30 days of termination, with full copy coverage and Legal-reviewed infeasibility handling. |
| 10 | Background checks at hire, no recurring checks | Acceptable | At-hire checks meet this policy's stated screening baseline; recurring checks are not mandatory. | Verify screening scope for privileged and PHI staff, including contractors, and personnel change controls. |
| 11 | TOTP MFA for administrators and privileged accounts | Acceptable | No stated policy conflict; enforcement scope is unverified. | Provide configuration evidence covering support access, privileged accounts, and emergency-account controls. |
| 12 | Monthly scanning; quarterly critical remediation target | Concern | Quarterly remediation exceeds the policy's 15-day critical deadline and 24-hour exploited-critical mitigation. | Agree to policy deadlines and provide recent scan, triage, mitigation, and closure samples. |
| 13 | Audit allowed with 60 days' notice | Concern | Routine notice does not guarantee prompt incident, investigation, or regulator evidence access. | Amend terms to preserve independent investigation and urgent access without the 60-day delay. |
| 14 | Willing to execute BAA | Critical Concern | `baa_status_note.md` confirms no executed BAA; willingness does not satisfy the unconditional gate. | Legal must execute and retain a complete BAA before any ePHI access, including storage and metadata processing. |
| 15 | Annual PHI training module reported | Acceptable | Meets the reported cadence, but completion and content are unverified. | Obtain current completion records and curriculum for staff and contractors handling MedDefense PHI. |

**Rating counts:** Pass: 0; Acceptable: 6; Concern: 5; Critical Concern: 4.
No Pass ratings are assigned because the underlying assurance evidence is absent.
The current SOC report is also a mandatory access gate even though item 1 describes
an evidence gap rather than a confirmed failure of the vendor's control.

## Critical findings

**Item 5: Outdated penetration testing.** The supplied response describes a test
already 22 months old in April. MedDefense cannot evaluate present weaknesses or
confirm that critical weaknesses were fixed, which increases exposure for clinical
backups. Before approval, the vendor must provide an in-scope report within the
last 12 months and evidence closing all critical findings. This is a mandatory
MedDefense evidence gate, not a claim that HIPAA itself prescribes this test interval.

**Item 8: Delayed incident notification.** Waiting for internal confirmation and
then another 72 hours could prevent MedDefense from containing exposure promptly
or making timely notification decisions. Before approval, signed contract and BAA
terms must require notice within 24 hours of discovery of a suspected or confirmed
incident affecting MedDefense data, without waiting for a completed investigation.
This contractual clock supports, but does not replace, statutory reporting duties.

**Item 9: Delayed data removal.** A 90-day period that starts only after a written
request leaves clinical archives and identifiers with the vendor after termination.
MedDefense cannot demonstrate controlled exit under its proposed policy. Before
approval, signed terms must require return or certified destruction within 30 days
of termination, including backup and subprocessor copies, with documented Legal
review and continuing protection where destruction is infeasible.

**Item 14: No executed BAA.** CloudVault's proposed service maintains ePHI on
MedDefense's behalf; the signed agreement is a prerequisite, including for encrypted
archives. Beginning that service without the required agreement would create
business associate compliance exposure. Legal must supply an executed BAA covering
the policy's required terms before any transfer or access. The materials do not
establish whether ePHI transfer has already begun, so the reviewer must verify the
actual access state immediately.

## Recommendation and measurable conditions

**Approve with Conditions** permits continued negotiation and evidence collection
only. The proposed service may be usable, but four critical findings and unresolved
evidence prevent security sign-off for onboarding. If CloudVault refuses the terms
or cannot satisfy the gates, the final decision must be Do Not Approve. Procurement
must not treat this assessment as permission to activate the service.

| Condition before final approval | Evidence required | Verifier |
| --- | --- | --- |
| Current assurance | Actual SOC 2 Type II report or HITRUST certification within 12 months at onboarding, with scope and exceptions reviewed. | IT Security |
| Recent test and closure | In-scope penetration results within 12 months and verified closure of all critical findings. | IT Security |
| Complete data-flow review | Every subprocessor, jurisdiction, DR site, data field category, support access path, and safeguard flow-down approved in writing. | Privacy, Legal, IT Security |
| Correct contract safeguards | Signed 24-hour discovery-based incident notice, 30-day termination return/destruction, independent investigation, and urgent evidence access terms. | Legal |
| Executed BAA | Complete agreement signed by authorized parties and retained, including subprocessor obligations. | Legal |
| Verified operational safeguards | Encryption, certificate validation, privileged MFA, screening, training, and vulnerability closure evidence against policy requirements. | IT Security |
| Controlled activation | Evidence of disabled transfers and vendor access until all gates pass; then a dated CISO decision and access authorization. | Infrastructure, IT Security, CISO |

IT Security and Legal should close the review by 2026-12-08, two weeks before the
assumed 2026-12-22 audit. This is a proposed deadline, not a commitment or proof of
closure. If gates remain open, retain the transfer block and use an approved
continuity arrangement. The CISO must record residual risk and the final decision;
a conditional assessment alone cannot close R-001.
