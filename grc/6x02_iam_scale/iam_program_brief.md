# Identity Program Brief for Dr. Morales

## Identity Posture Summary

The 20-account audit identified 22 control failures across 10 accounts: six Critical, nine High, three Medium and four Low. Separate cloud review identified two Critical, four High and four Medium gaps across ten observations. These are finding counts, not numbers of compromised accounts. Remediation remains unverified.

## Connection to the Incident

The prior incident used a stolen service credential with broad domain authority to move between systems. IAM-015/016 show the same opportunity in svc_epic_int: domain-wide administration despite no identified current function and 1,156 days without recorded use. IAM-014 and IAM-017 document similarly broad service-account access. These current conditions reproduce the attack path; the inventory does not establish that all these accounts were used during the incident.

## What Has Been Completed

- Executed a repeatable audit and linked every finding to its source record, creating a verified action inventory.
- Authored three narrower cloud policies, including guarded emergency administration; deployment and access testing remain pending.
- Documented centralized sign-in configuration and its validation limits to support safer off-boarding design.
- Analyzed short-lived database credentials and the supplied successful revocation evidence to inform removal of persistent secrets.

These are completed assessment and design deliverables. No production access reduction or incident reduction is claimed.

## What Must Be Completed Before the Next Board Meeting

1. **IAM administrator and service owners, immediately; verify within seven days of authorization:** contain unnecessary domain-wide service rights and resolve departed/transferred access (IAM-007, IAM-014–017, IAM-021); preserve clinical function.
2. **Cloud lead with Privacy/Legal, immediately; report within seven days:** contain public clinical backups and secure root credentials, then investigate exposure (CLOUD-01, CLOUD-06).
3. **IT Director and HR, within 30 days:** enforce privileged verification, approve recurring access reviews and verify narrower cloud access and DR logging (IAM-002/006/020; CLOUD-02/05/07/09). Provide closure evidence at the next board meeting; its actual date is not supplied.

## What Requires Board Authorization or Budget

Authorize protected IAM/cloud engineering time, staged privileged-access and centralized-sign-in pilots, and Privacy/Legal investigation capacity. Obtain costed estimates before purchasing licenses; no price is supplied. Deferral leaves the documented stolen-credential path and public backup exposure unresolved.

## Board Resolution Requested

Authorize the IT Director to prioritize the Critical identity and cloud corrections, resource the scoped pilots and report verified closures, exceptions and cost proposals to the next Board Risk Committee meeting.

Evidence: [audit report](iam_audit_report.md), [findings](iam_findings.json), [cloud assessment](cloud_security_assessment.md), [policy analysis](iam_policy_analysis.md), [Vault analysis](vault_pam_lab.md); supplied [brief template](../opt/meddefense/materials/package/ciso_brief_template.md) and [evidence index](../opt/meddefense/materials/package/identity_program_evidence_index.md).
