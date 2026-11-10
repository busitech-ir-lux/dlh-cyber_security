# MedDefense Cloud Security Assessment

## Assessment Scope

Assessment covers all ten supplied observations and the authored Task 2 policies. No live AWS inspection or remediation occurred. The supplied `cis_aws_control_map.md` maps **control areas**, not numbered CIS v3.0 requirements. The table faithfully uses those areas; exact benchmark IDs and applicability require the licensed/versioned benchmark before a formal CIS attestation. In particular, absence of Organizations/SCPs is a supplied governance gap, not proof of failure against an invented numbered control. All ten observations have open gaps; status reflects source evidence, not verified deployment.

## Findings Table

| ID / observation | Supplied CIS control area | Severity | Status | Finding and exact proposed console action |
| --- | --- | --- | --- | --- |
| CLOUD-01 / 1 | Root MFA and root access key restrictions | Critical | Open gap; not remediated | Root credential takeover allows account-wide control. AWS console → account menu → Security credentials: register root MFA; inventory root-key dependencies, delete root access keys and verify no active keys remain. |
| CLOUD-02 / 2 | IAM user MFA | High | Open gap; not remediated | Three of seven console users lack MFA; four enrolled is 57.1%, not full coverage. IAM → Users → each affected user → Security credentials → Assign MFA device. Enforce verified sign-in/session policy and test access. |
| CLOUD-03 / 3 | Access key rotation | Medium | Open gap; not remediated | Two of four programmatic users have keys older than 22 months without rotation records. IAM → Users → Security credentials: identify key IDs, replace consumers with roles where possible; otherwise create replacement, validate use, deactivate old key, monitor and delete. |
| CLOUD-04 / 4 | IAM password policy | Medium | Open gap; not remediated | Eight-character minimum and no complexity weaken password controls; MFA is not an account password-policy setting. IAM → Account settings → Edit password policy: set approved stronger minimum and character rules, reuse protection and approved expiration settings; separately enforce console MFA. Exact organizational values require approval. |
| CLOUD-05 / 5 | CloudTrail in all regions | High | Open gap; not remediated | The DR region is outside the documented logging coverage, limiting reconstruction of backup access. CloudTrail → Trails → approved trail → Edit: enable multi-region coverage; verify delivery from us-east-2. Configure S3 object data events separately where required; management-event coverage alone does not record every object read. |
| CLOUD-06 / 6 | S3 public access restrictions | Critical | Open gap; not remediated | The clinical backup bucket permits public object reads and contains ePHI archives. S3 → meddefense-clinical-backup-2022 → Permissions: enable all four Block Public Access settings, remove public GetObject grant and verify policy status/access using approved checks; preserve existing evidence and notify incident/privacy leads. |
| CLOUD-07 / 7 | Least privilege/admin policy use | High | Open gap; not remediated | Three roles retain AdministratorAccess beyond an evidenced task scope. IAM → Roles → MedDefenseDevRole, MedDefenseLegacyRole, MedDefenseVendorAccess → Permissions: replace AdministratorAccess with reviewed workload policies, test and detach broad policy; inspect trust policies and vendor session limits. |
| CLOUD-08 / 8 | VPC Flow Logs | Medium | Open gap; not remediated | No VPC network-flow telemetry is configured. VPC → Your VPCs → each VPC → Flow logs → Create flow log: capture ALL traffic to approved protected destination with authorized delivery role; verify records and retention. |
| CLOUD-09 / 9 | Least privilege for backup role | High | Open gap; not remediated | Original s3:* on * can access or destroy unrelated backup/data buckets. IAM → Roles → MedDefenseEHRBackupRole → Permissions: review and attach corrected ehr_backup_policy.json, remove superseded broad grants, test allowed bucket/key and denied cross-bucket operations. |
| CLOUD-10 / 10 | AWS Organizations and SCPs | Medium | Open gap; not remediated | No organizational guardrails prevent account-level permission drift. Organizations console: authorize and create organization with all features; design and test SCPs on a nonproduction OU, then attach approved guardrails. SCPs limit permissions rather than granting them; preserve emergency paths. |

## Critical Findings

CLOUD-01 exposes unrestricted account control through root without MFA and persistent keys. CLOUD-06 exposes clinical backup archives: `Principal: "*"` means any principal, and `s3:GetObject` authorizes reading object contents. With the reported disabled public-access protections, that is a public-read exposure requiring urgent containment and investigation, not a conclusion that every object was actually downloaded.

Under 45 CFR 164.402, an impermissible use or disclosure of unsecured protected health information is generally presumed a breach unless an applicable exception or documented assessment establishes a low probability of compromise. Privacy/Legal must assess the information involved, recipients, whether it was actually acquired/viewed and mitigation, including whether encryption meets applicable guidance. Public configuration alone does not establish the complete notification determination. Preserve evidence, assess exposure and follow authorized notification procedures; do not state that no breach occurred merely because downloads are unconfirmed. See [HHS breach notification guidance](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

## Remediation Priority Order

Immediately contain public backup access and secure root credentials with tested recovery safeguards. Within seven days address console MFA, broad administrative roles, backup-role privilege and DR audit coverage. Within 30 days remediate keys, password controls, network logging and approved organization guardrails. These are proposed deadlines after authorization; clinical availability and evidence preservation govern execution.

## Estimated Effort

Planning estimates, not observed labor: root/MFA 1–2 administrator days; public bucket containment hours plus separately scoped investigation; policy/trust review and backup tests 2–4 days; DR/logging 1–3 days; key/consumer migration 2–5 days; organization/SCP design and staged testing 3–5 days. Work may overlap; unknown dependencies can increase effort. IAM/cloud engineers own configuration, workload owners validate function, and Privacy/Legal own breach analysis.

Sources: [observations](../opt/meddefense/materials/cloud_iam/aws_environment_observations.md), [supplied CIS area map](../opt/meddefense/materials/cloud_iam/cis_aws_control_map.md), [policy analysis](iam_policy_analysis.md) and corrected [policies](iam_policies/).
