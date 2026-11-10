# IAM Quiz Review: Supplied Questions


## Question 1: Least-Privilege S3 Reader

The MedDefense Lambda function that ingests SIEM logs from S3 currently uses the IAM statement `"Action": "s3:*", "Resource": "*"`. Which corrected statement satisfies least privilege for a read-only log ingestion function targeting a single bucket?

A. `"Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"` — restricts actions but not the resource scope.

B. `"Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::meddefense-siemlog-prod", "arn:aws:s3:::meddefense-siemlog-prod/*"]` — restricts both action set and resource to the specific bucket and its objects.

C. `"Action": "s3:*", "Resource": "arn:aws:s3:::meddefense-siemlog-prod/*"` — restricts resource but retains full S3 action scope.

D. `"Action": "s3:Read*", "Resource": "arn:aws:s3:::*"` — uses wildcard action prefix and global resource scope.

**Answer: B.** The function needs permission to list the named bucket and read its objects. `ListBucket` applies to the bucket ARN, while `GetObject` applies to object ARNs ending in `/*`. Including both resource types supports those two operations without granting modification or access to unrelated buckets. The submitted policy separates these into two statements for clarity; the combined choice expresses the same intended access. A remains globally scoped, C retains unnecessary operations and D does not specify the required API actions precisely.

Source: [policy analysis](iam_policy_analysis.md), [corrected SIEM policy](iam_policies/siem_reader_policy.json).

## Question 2: Console MFA and Programmatic Access

MedDefense enforces an AWS IAM policy requiring `"aws:MultiFactorAuthPresent": "true"` for console access. Which scenario bypasses this protection entirely?

A. An attacker intercepts the TOTP code using a browser extension before it expires.

B. An attacker social-engineers the user into approving a push notification for their MFA application.

C. An attacker uses a phishing page to capture the password and TOTP token simultaneously.

D. An attacker obtains a user's AWS access key ID and secret access key, then makes API calls programmatically.

**Answer: D, under the stated console-only protection.** Long-lived access keys provide a programmatic access path without a console sign-in. The other choices compromise or manipulate the MFA process itself. A requirement covering only console access leaves the API path unprotected unless other policies restrict it.

The condition key alone does not prove a policy is console-only: its effect depends on the complete policy and applicable grants. An explicit deny using `BoolIfExists` for missing or false MFA context can also block long-lived-key API requests. Therefore D is the intended answer, not a universal bypass of every policy using this key.

Source: [break-glass analysis and condition-key reference](iam_policy_analysis.md).

## Question 3: Dormant Account Priority

MedDefense Security Operations has identified 200 dormant accounts for remediation and must triage them by priority. Which account type should be placed highest in the queue?

A. A service account with Domain Admin membership, last authenticated 1,156 days ago and no documented operational function.

B. A helpdesk user account inactive since an internal role transfer within the IT department.

C. A shared facility access logging account inactive for six months.

D. A standard clinical user account for a nurse on extended medical leave with no privileged access.

**Answer: A.** Domain Admin membership gives the account broad authority even though it has not recently been used. Combined with no identified function, this creates an unjustified standing credential that could support domain takeover. The supplied severity model classifies Domain Admin service-account exposure as Critical; the other choices do not establish equivalent authority.

The question's 200 accounts are its scenario population. The actual supplied CSV contains 20 accounts, and the submitted script processes those 20 rather than inventing additional records.

Source: [severity model](../opt/meddefense/materials/iam_audit/severity_model.md), [static account risk](../opt/meddefense/materials/pam/svc_epic_int_static_account_risk.md).

## Question 4: AWS Shared Responsibility

MedDefense runs clinical workloads on AWS EC2 and stores ePHI backups in S3. Under the AWS shared responsibility model, which IAM-related controls are MedDefense's responsibility? Select all that apply.

A. Auditing and removing over-privileged IAM roles and inactive IAM users.

B. Configuring IAM policies that restrict who can read or write to the clinical backup S3 bucket.

C. Physical security of the AWS data center infrastructure.

D. Rotating IAM user access keys and auditing unused credentials.

E. Patching the underlying hypervisor that hosts EC2 instances.

F. Enforcing MFA for IAM users and roles with AWS console access.

**Answers: A, B, D and F.** MedDefense manages its identities, permissions, credentials and authentication requirements. AWS manages physical facilities and the underlying EC2 hypervisor. For F, roles do not enroll an MFA device like an IAM user; the customer enforces the appropriate MFA requirements on authentication and role access. This distinction does not change the intended selection.

Source context: [cloud observations](../opt/meddefense/materials/cloud_iam/aws_environment_observations.md) identify these customer configuration gaps; [AWS shared responsibility model](https://aws.amazon.com/compliance/shared-responsibility-model/) explains the infrastructure/customer boundary.

## Question 5: Federation Versus Credential Delegation

MedDefense is evaluating SAML 2.0 federation with Keycloak as the identity provider and Epic as the service provider. Sarah Park asks: “If Keycloak is the IdP and Epic is the SP, what is the fundamental security property that federation provides that a direct credential delegation model does not?” Which answer is most accurate?

A. Federation eliminates session management at the SP because all sessions are maintained by the IdP.

B. The IdP validates authorization decisions in real time on every request to the SP.

C. The SP never receives or stores the user's credential; the IdP authenticates the user and issues a signed assertion that the SP trusts, so credential exposure at the SP cannot occur.

D. Federation eliminates the need for MFA on the SP side, because the IdP handles all authentication factors.

**Answer: C is the intended best choice, with a wording correction.** In the described flow, Epic receives a signed assertion instead of the user's Keycloak password. It validates that assertion before establishing access. Epic still manages its application sessions and authorization, so A and B are incorrect. Federation alone does not establish that the required authentication strength has been met, making D too absolute.

C's final claim is also too absolute: assertions and session tokens can still be stolen. The precise benefit is that the user's **IdP password is not disclosed to the SP through this federation flow**, rather than that every form of credential exposure at the SP is impossible.

Source: [SAML reference](keycloak_saml_config.md), [flow notes](../opt/meddefense/materials/sso/saml_flow_notes.md).

## Question 6: SAML Assertion Elements

Robert Kim decodes a SAML response captured during an Epic SSO authentication. Which elements must be present in a valid SAML 2.0 assertion? Select all that apply.

A. Conditions including NotBefore and NotOnOrAfter validity timestamps.

B. A digital signature from the IdP over the assertion.

C. An Issuer element identifying the IdP that produced the assertion.

D. A NameID element identifying the authenticated subject.

E. A Kerberos ticket granting ticket for downstream authentication.

F. The user's plaintext password for SP-side re-verification.

**Intended lab answers: A, B, C and D.** The MedDefense configuration uses time constraints, intended assertion signing, issuer validation and an email NameID. The SP uses these to evaluate validity, integrity, origin and subject identity. Neither a Kerberos ticket nor the user's plaintext password belongs in this described authentication exchange.

The question generalizes beyond this configuration. SAML schema and profile requirements are not identical: Conditions and Signature are not universally mandatory assertion children, and NameID is not the only possible subject identifier. For this lab, select the four intended elements without treating the question as a universal schema definition. The supplied signature value is simulated and cannot demonstrate real signature validation.

Schema qualification: [OASIS SAML 2.0 assertion schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd).

Source: [decoded response reference](../opt/meddefense/materials/sso/decoded_saml_response_reference.md), [SAML configuration analysis](keycloak_saml_config.md).

## Question 7: Preventing Standing-Privilege Escalation

The post-incident review found that the attacker escalated to Domain Admin via `svc_epic_int`, a service account with Domain Admin rights unused for three years. Which control would most directly have prevented this specific escalation path?

A. Mandatory MFA on all service accounts.

B. Just-in-time privileged access: elevated rights are granted only for the duration of an authorized operation and automatically revoked.

C. EDR coverage on all servers.

D. Network segmentation between workstations and domain controllers.

**Answer: B.** Removing standing elevated rights prevents a dormant credential from continuously carrying Domain Admin authority. EDR and segmentation can provide valuable additional defenses, but do not directly correct the account's unjustified persistent privilege. Blanket interactive MFA is also not a suitable universal authentication design for unattended service workloads.

The scenario explicitly names `svc_epic_int` as the incident account. The local incident identity-path artifact describes the service-credential pattern and lists current accounts resembling it; the quiz wording should not be used as independent forensic proof about every account in that artifact. For the actual dormant account, dependency-aware containment and retirement may be preferable to preserving it through a JIT migration.

Source: [incident path](../opt/meddefense/materials/iam_audit/incident_identity_path.md), [Vault and migration analysis](vault_pam_lab.md).

## Question 8: Dynamic Credential Lifetime

Robert Kim configures HashiCorp Vault's database secrets engine against the LIS MariaDB. The dynamic credential role has a default TTL of one hour. A credential is issued at T+0 and stolen by an attacker. The attacker uses it at T+45 minutes and again at T+75 minutes. Which outcomes are correct? Select all that apply.

A. At T+45 minutes the credential is valid because the one-hour TTL has not elapsed.

B. At T+75 minutes the credential has expired and the database authentication attempt fails.

C. Vault requires MFA to issue replacement credentials, preventing the attacker from requesting a new lease.

D. Under the equivalent static service account model, the stolen credential would remain valid indefinitely without manual rotation.

E. Vault automatically alerts the security team when an expired credential is presented to the database.

**Intended answers: A, B and D.** Assuming no renewal, earlier revocation or other access change, the credential is within its issued lifetime at 45 minutes and beyond it at 75 minutes. Successful expiry-driven backend revocation should prevent a new database login after expiration. A static credential has no equivalent short lease and can remain reusable until changed, disabled or otherwise invalidated.

These outcomes depend on the stated assumptions. A renewable lease can have its lifetime extended within configured limits, and failed backend revocation can undermine the expected expiry protection. Existing database sessions are a separate question from new authentication. D assumes no other password-expiration or automatic rotation control; “indefinitely” is not a property of every static account.

C and E are not automatic properties of the database secrets engine. Issuance authentication and MFA depend on configured access controls, while failed database-login alerts require suitable database logging and monitoring. The local transcripts demonstrate manual read-write revocation, not a timed automatic-expiry test. The quiz calls the database MariaDB; the supplied transcript uses the MySQL plugin and client, so the response does not invent a separate MariaDB execution record.

Source: [Vault analysis](vault_pam_lab.md), [issuance transcript](../opt/meddefense/materials/pam/vault_database_secrets_transcript.md), [revocation transcript](../opt/meddefense/materials/pam/vault_lease_revoke_transcript.md).
