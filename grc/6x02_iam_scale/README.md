# Identity at Scale

## Introduction

> "_Complexity is the enemy of security._" — **Bruce Schneier**

The Cobalt Strike attacker moved from a single compromised workstation to Domain Admin in under two hours. The path was not clever. It was short: extract credentials from memory, authenticate as a service account, and discover that the service account held Domain Admin because nobody remembered why it was granted three years ago. The perimeter held. The detection rules eventually fired. But the identity layer made the entire attack trivial.

Identity is where modern intrusions live. Access rights accumulate over years. Service accounts get created for migrations that finish, then sit dormant with excessive permissions. Contractors leave but accounts remain. Former employees transfer departments but old rights stay. Nobody audits the full list of privileged accounts until after the incident, and by then the damage is done.

### Why this matters

Identity is the most targeted layer in modern attacks. Every ransomware deployment, every data exfiltration chain and every lateral movement path starts with identity. The analyst who can configure federation, design least-privilege cloud IAM, implement JIT access and audit an organization's identity posture against real evidence is doing work that appears in every security architect, cloud security engineer and GRC role description in healthcare.

The IAM audit capability is particularly rare and particularly valued. Most professionals can describe what least privilege means. Few can look at a directory of 200 accounts, write a script to surface the findings and produce a professional assessment with severity ratings, evidence references and remediation actions that a CISO acts on before the next incident. This project builds that capability end to end.

---

## Context

The post-incident review following the Cobalt Strike breach produced one finding that James Chen returned to repeatedly in the debrief: the attacker needed fewer than two hours from initial compromise to Domain Admin access. The path was three hops: compromised workstation, extracted NTLM hash, service account with Domain Admin rights. None of that should have been possible.

Dr. Morales asked a direct question in the review meeting: _"How many accounts in this organization currently have more access than they need?"_ Nobody in the room could answer.

Robert Kim pulled a partial privileged account list the following morning. He found `svc_epic_int`: a Domain Admin service account whose last recorded authentication was over three years ago and whose description read "post-EHR-migration service account; no current function identified." He found `t.morrison`: a contractor whose engagement ended seven months ago, still enabled, still a Domain Admin. He found `svc_helpdesk`: granted Domain Admin during a vendor installation with the note "required per vendor; review later." Later had never come.

Helena Reyes flagged the cloud environment. Three IAM roles in the MedDefense AWS account carry `AdministratorAccess`. The S3 bucket used for clinical data backup has Block Public Access disabled. CloudTrail is not configured for the DR region. The IAM policy on the EHR backup automation role uses `"Action": "s3:*"` against `"Resource": "*"`.

Sarah Park confirmed that MedDefense has no SSO deployment, no formal PAM program and no documented process for IAM access review.

_"We need to know exactly where we stand,"_ James Chen said. _"Identity is how they got through us. Identity is how we close the gap."_

Your assignment has four components. Understand SSO federation by configuring it. Audit and correct the cloud IAM posture. Implement JIT credential controls using Vault to eliminate the `svc_epic_int` class of risk. Then audit the full account inventory, surface every finding and produce the assessment that answers Dr. Morales's question.

---

## Learning Objectives

**Technical**

- Analyze SAML 2.0 SSO configuration, including realm isolation, client settings, NameID, assertions, signatures and role attributes
- Identify AWS IAM over-privilege and write least-privilege policy corrections
- Explain Vault database secrets engine behavior using realistic command transcripts, leases, TTLs and revocation evidence
- Write a Python script that processes an account inventory and produces severity-scored JSON findings

**Conceptual**

- Explain how SAML federation differs from password delegation
- Distinguish IAM from PAM and explain standing privileged credential risk
- Explain how JIT access and TTL-based credentials reduce credential theft blast radius
- Connect IAM and cloud misconfigurations to ePHI exposure and patient-safety risk

**Transversal**

- Produce IAM audit findings with evidence, severity and remediation
- Write executive identity-risk language for a CISO and Board Risk Committee
- Preserve traceability from source artifact to script finding to management report

---

## Resources

**Identity standards and federation**

- [NIST SP 800-63B Digital Identity Guidelines, Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
    
- [SAML 2.0 Technical Overview, OASIS Standard](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
    
- [Keycloak documentation, SAML 2.0 Identity Provider](https://www.keycloak.org/docs/latest/server_admin/index.html#saml-v2-0-identity-providers)
    

**Cloud IAM**

- [AWS IAM Best Practices, IAM User Guide](docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
    
- [CIS Amazon Web Services Foundations Benchmark v3.0](https://www.cisecurity.org/benchmark/amazon_web_services)
    

**Privileged access management**

- [HashiCorp Vault Database Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/databases)
    
- [NIST SP 800-207 Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
    

**IAM audit methodology**

- [CISA Zero Trust Maturity Model v2.0, Identity Pillar](https://www.cisa.gov/zero-trust-maturity-model)

---

## Requirements

### General

- All work is performed inside the provided `6x02-identity-at-scale` lab container.
- Container base: `Ubuntu 22.04+`.
- Allowed editors: `vi`, `vim`, `emacs`, `nano`.
- A `README.md` at the root of the project directory is mandatory.
- Python 3.8+ is available; standard library only.
- Do not run Docker commands inside the lab.
- All source artifacts are staged in `/opt/meddefense/materials`.

### Python

- Use `python3`.
- Allowed modules include `csv`, `json`, `argparse`, `datetime`, `re`, `pathlib`, `collections`.
- Scripts must produce clean output.
- `audit_iam.py` must write `iam_findings.json`.

### Workflow

- Connect using SSH.
- Work inside `/home/student/6x02`.
- Use `/opt/meddefense/materials`.
- Submit required `.md`, `.py`, `.json` and `.xml` files from `/home/student/6x02`.

## Lab Materials

The materials includes all materials required to complete the project. You need to download [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/6/abad3724053f0de6778c49ab914080edfb90a7c2.zip).

Expected structure:

```text
/opt/meddefense/materials/
├── sso/
│   ├── keycloak_realm_export_meddefense.json
│   ├── saml_assertion_d_walsh.xml
│   ├── saml_assertion_r_kim.xml
│   ├── saml_flow_notes.md
│   └── decoded_saml_response_reference.md
├── cloud_iam/
│   ├── original_siem_reader_policy.json
│   ├── original_ehr_backup_policy.json
│   ├── original_break_glass_policy.json
│   ├── aws_environment_observations.md
│   └── cis_aws_control_map.md
├── pam/
│   ├── vault_database_secrets_transcript.md
│   ├── vault_lease_revoke_transcript.md
│   ├── svc_epic_int_static_account_risk.md
│   └── pam_migration_candidates.csv
├── iam_audit/
│   ├── accounts.csv
│   ├── severity_model.md
│   └── incident_identity_path.md
└── package/
    ├── ciso_brief_template.md
    └── identity_program_evidence_index.md
```