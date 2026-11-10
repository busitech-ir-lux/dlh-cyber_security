# Learning Objectives: Identity at Scale

This guide explains all eleven objectives from the [module README](../README.md) using the provided artifacts. It separates supplied evidence from operational recommendations; configuration examples and transcripts are not evidence of live deployment. The twelve questions below are original Security+ style scenarios, not official CompTIA questions or a claim of exact exam difficulty.

## 1. Analyze SAML SSO configuration

SAML federation lets an application trust an identity provider’s signed statement about a user. The portal redirects authentication to Keycloak; Keycloak returns a response, and the portal checks issuer, audience, recipient, time and signature before mapping MedDefenseRole to permissions. The realm separates this configuration from other realms, while the client defines the receiving application. Email NameID identifies the subject; it does not itself prove which permissions the person should receive.

The export sets a 30-minute idle SSO session, but the sample assertion expires at 09:20 UTC. These are different lifetimes. A valid signature protects integrity, not confidentiality, and an unexpired assertion still needs replay controls. The supplied simulated signature cannot support a claim of cryptographic validation.

Source: [sso/decoded_saml_response_reference.md](../opt/meddefense/materials/sso/decoded_saml_response_reference.md).

## 2. Find and correct AWS over-privilege

Least privilege means granting the operations and resources a workload actually needs. The SIEM reader needs to list one bucket and read its objects, not change every bucket. Bucket actions and object actions need the corresponding resource ARNs, so replacing a wildcard without checking resource types can break legitimate work.

The backup policy restricts both S3 resources and KMS operations. Emergency administration remains deliberately broad, but its MFA and network requirements must be enforced even if another policy grants access. Written policies need validation against actual workload calls, trust policies and resource policies before deployment.

Source: [cloud_iam/original_siem_reader_policy.json](../opt/meddefense/materials/cloud_iam/original_siem_reader_policy.json).

## 3. Explain Vault leases, TTLs and revocation

A dynamic credential is issued for a particular request with a lease that Vault tracks. The read-only example receives one hour, renewable within a four-hour maximum; the read-write example receives 15 minutes with a one-hour maximum. A lease ID identifies the issued secret for management, while the username identifies the database principal.

The revocation transcript provides stronger evidence than a command acknowledgment alone: connection fails after revocation and the user disappears from the database query. It does not prove established sessions were terminated or that automatic expiry was tested. Issuance, permitted renewal and successful revocation must all be considered when estimating stolen-secret lifetime.

Source: [pam/vault_lease_revoke_transcript.md](../opt/meddefense/materials/pam/vault_lease_revoke_transcript.md).

## 4. Write a reproducible inventory audit

A script applies the same explicit checks to each input row and writes structured findings that another reviewer can inspect. Exact group tokens avoid confusing Domain Admins with an unrelated group name, while case-insensitive keyword matching finds lifecycle descriptions such as Contract ended. Evidence should preserve the fields behind each result rather than merely print a severity.

The script processes the 20 supplied accounts, not the narrative’s illustrative 200. One account may trigger dormancy, missing MFA and lifecycle checks, so finding totals differ from distinct affected accounts. Row references and stable snapshot retention let a reader follow a finding back to its source.

Source: [iam_audit/accounts.csv](../opt/meddefense/materials/iam_audit/accounts.csv).

## 5. Distinguish federation from password delegation

With federation, the application relies on an assertion from the identity provider rather than receiving the user’s password from that provider. Trust therefore depends on validating the assertion and the issuer, not simply accepting a familiar-looking user name. This changes where authentication happens without eliminating the application’s responsibility to authorize access.

Central disabling can prevent new federated sign-ins, but existing application sessions, local fallback accounts and systems outside federation require separate handling. Treating SSO as automatic removal of every existing session would overstate the supplied off-boarding benefit.

Source: [sso/saml_flow_notes.md](../opt/meddefense/materials/sso/saml_flow_notes.md).

## 6. Distinguish IAM from PAM

Identity and access management covers who an identity is, what it can access and how that access changes through employment or workload lifecycles. Privileged access management concentrates on especially powerful access and credentials. Removing an ex-contractor’s account is a lifecycle task; replacing a standing administrative secret with scoped temporary access is a privileged-access control.

The service-account findings show why the distinction matters: a functioning ticket-routing account may still have unjustified Domain Admin rights. Confirming its owner does not make those rights appropriate, while rotating its password alone leaves the excessive authority intact.

Source: [pam/svc_epic_int_static_account_risk.md](../opt/meddefense/materials/pam/svc_epic_int_static_account_risk.md).

## 7. Explain JIT access and stolen-credential impact

Just-in-time access makes privileged access available when authorized work needs it instead of leaving it continuously available. Short-lived database credentials support that approach by reducing the time a stolen credential can be reused. The size of the damage also depends on permissions: a short-lived Domain Admin credential can still cause serious harm while valid.

A dynamic database account is not automatically a replacement for a Windows domain service account. First identify the business function and supported authentication method, then remove unnecessary authority and use an appropriate temporary or scoped access mechanism. Retirement is preferable when no function remains.

Source: [pam/pam_migration_candidates.csv](../opt/meddefense/materials/pam/pam_migration_candidates.csv).

## 8. Connect identity and cloud gaps to patient risk

Broad authority can turn one compromised credential into access across systems, as the supplied incident path shows. That can threaten patient-data confidentiality and the availability of clinical services. A public backup read grant creates a different route: data can become accessible without first compromising a workforce account.

An exposed configuration requires urgent containment and investigation, but does not by itself prove every archive was downloaded. Reporting should distinguish observed exposure, confirmed unauthorized activity and unresolved uncertainty; Privacy/Legal makes the notification assessment using the applicable evidence.

Source: [iam_audit/incident_identity_path.md](../opt/meddefense/materials/iam_audit/incident_identity_path.md).

## 9. Produce evidence-based findings and remediation

A useful finding states the account, the observed condition, why it matters and the exact corrective action. Severity follows the supplied model rather than a dramatic description: Domain Admin service access is Critical, while Server Admin service access is Medium. Lifecycle keywords trigger manual confirmation because descriptions can be incomplete or outdated.

A remediation plan needs an owner, deadline and success criterion. Removing svc_helpdesk from Domain Admins is only part of the work; its ticket-routing function must continue under approved narrower permissions, with the test recorded. That connects security correction with operational safety.

Source: [iam_audit/severity_model.md](../opt/meddefense/materials/iam_audit/severity_model.md).

## 10. Explain identity risk to executives

Executive reporting translates permissions into consequences and decisions. Instead of asking a board member to interpret group names alone, explain that an unattended account can administer the domain and reproduce the credential-theft path. Include the count of affected accounts as well as findings so overlapping checks do not exaggerate the scope.

Assessment and design completion are not production remediation. The brief can truthfully report an executed audit and authored policies, but cannot claim access was removed, MFA enforced or losses avoided without implementation evidence. Funding requests should identify the work and risk of delay without inventing a price.

Source: [package/ciso_brief_template.md](../opt/meddefense/materials/package/ciso_brief_template.md).

## 11. Preserve source-to-management traceability

Traceability creates a continuous evidence path from a source record to a named script check, its JSON finding and the report or executive decision. The CSV row and fields explain what was observed; the code explains the rule; the report explains the risk and required response. Retaining all of them makes the assessment reviewable.

Path accuracy is part of reproducibility. Here the materials live under 6x02_iam_scale/opt/meddefense/materials. From tasks, their relative path begins ../opt/meddefense/materials; from the module root it begins ./opt/meddefense/materials. Neither is the operating system’s /opt directory.

Source: [package/identity_program_evidence_index.md](../opt/meddefense/materials/package/identity_program_evidence_index.md).

## Practice Questions

Select the single BEST answer for each scenario. Answers follow all twelve questions so you can attempt them first.

### Question 1

A portal receives an assertion with the correct email and role, but its NotOnOrAfter time has passed. What is the BEST response?

A. Accept because the role matches the directory  
B. Reject the assertion and require a fresh authentication flow  
C. Extend its expiry locally  
D. Accept if the employee is still enabled  

### Question 2

An attacker changes MedDefenseRole in a captured assertion. Which control MOST directly detects the change?

A. Email-format NameID  
B. Thirty-minute idle timeout  
C. Validation of the trusted digital signature covering the assertion  
D. A longer password  

### Question 3

A SIEM reader must list and read one S3 bucket. Which permission set BEST meets that need?

A. ListBucket on the bucket ARN and GetObject on its object ARNs  
B. s3:* on the bucket  
C. GetObject on all resources  
D. AdministratorAccess with annual review  

### Question 4

A break-glass identity has an additional broad Allow policy. How should the required MFA and network restrictions remain effective?

A. Rely on the operator to choose the restricted policy  
B. Remove all emergency permissions  
C. Put both failure conditions into one combined deny  
D. Use separate explicit denies for missing MFA and missing or unapproved source IP  

### Question 5

A database password is stolen immediately after issuance with a 15-minute TTL. Which statement BEST describes the benefit?

A. The attacker cannot use it at all  
B. It can be reused indefinitely if copied  
C. Reuse is limited by its actual validity and permissions, assuming effective expiry/revocation  
D. It proves database encryption is enabled  

### Question 6

Vault reports revocation queued. Which additional evidence BEST supports successful backend revocation?

A. A role named readwrite exists  
B. The issued login fails and the database user is absent  
C. The operator closes the terminal  
D. The maximum TTL is increased  

### Question 7

A service account has been unused for 1,156 days, has Domain Admin rights and has no identified function. What is the BEST initial approach?

A. Confirm dependencies, contain the account and remove unnecessary privilege; retire it if unused  
B. Rotate its password and keep all rights permanently  
C. Migrate it immediately without identifying its function  
D. Ignore it because it is dormant  

### Question 8

A user transfers from IT to Finance but keeps Domain Admin membership. Which process MOST directly prevents recurrence?

A. Longer session timeout  
B. Public backup access checks  
C. Periodic password reminders alone  
D. Role-change notification linked to access review and removal  

### Question 9

An audit emits three findings for one account. How should this be presented to leadership?

A. As three compromised employees  
B. As one safe account because findings overlap  
C. As three control findings affecting one account  
D. Omit two findings to make the totals equal  

### Question 10

A clinical backup bucket permits Principal * to GetObject and public-access protections are disabled. What is the BEST response?

A. Assume encryption makes every exposure harmless  
B. Contain public access, preserve evidence and involve Security and Privacy/Legal in exposure assessment  
C. Delete audit evidence after changing the policy  
D. Wait until a patient reports misuse  

### Question 11

After disabling an IdP account, an employee still has an existing application session. Which explanation is MOST accurate?

A. Central disabling may block new federation while existing application sessions require separate termination  
B. SAML transmits the password to every application  
C. Every signed assertion is valid forever  
D. SSO necessarily disables all local fallback accounts  

### Question 12

A team has generated audit findings and written narrower policies but has not deployed them. Which CISO statement is MOST defensible?

A. All Critical issues have been eliminated  
B. No patient-data exposure is now possible  
C. The audit proves the exact financial loss avoided  
D. Assessment and policy design are complete; operational remediation and verification remain pending  

## Answers and Explanations

### Answer 1: B

Expiration is an acceptance boundary. A plausible subject or role does not authorize extending it; a fresh valid assertion is required.

### Answer 2: C

Signature validation detects modification of signed content. Identity format and session timeout do not establish integrity.

### Answer 3: A

Listing and reading are separate operations with different resource types. The first option scopes both required operations without unnecessary write or cross-bucket access.

### Answer 4: D

An explicit deny overrides an Allow. Separate denies block either failure; combining conditions would require both failures before denying.

### Answer 5: C

Short lifetime reduces reuse time but does not prevent use while valid or undo changes already made. Renewal and revocation behavior must also be considered.

### Answer 6: B

Backend access failure plus user removal corroborates completed revocation. Queue acknowledgment alone does not establish that the database action succeeded.

### Answer 7: A

Dormancy does not remove standing authority. Dependency-aware containment avoids disrupting an unknown workload while addressing the direct incident-like exposure.

### Answer 8: D

A transfer changes access justification. HR and IAM lifecycle coordination should remove prior-role rights; password measures do not fix authorization.

### Answer 9: C

Control findings and distinct affected accounts answer different questions. Preserve all checks while clearly separating counts; findings do not prove compromise.

### Answer 10: B

The source describes public ePHI exposure. Immediate containment and evidence-based breach analysis are appropriate; neither confirmed theft nor safety can be assumed from configuration alone.

### Answer 11: A

Federation centralizes new authentication, but does not automatically guarantee termination of every service session or local access path.

### Answer 12: D

Completed deliverables establish assessment progress, not deployed protection. The statement accurately separates design from verified risk reduction.
