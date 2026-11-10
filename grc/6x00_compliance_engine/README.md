## Introduction

> "_Measure what is measurable, and make measurable what is not so._" — **Galileo Galilei**

You have spent fourteen weeks building security controls. Endpoint hardening baselines. Sigma detection rules. IR playbooks. Forensic runbooks. A post-incident risk register. If an auditor walked in tomorrow and asked you to prove MedDefense has an adequate security program, could you?

That is exactly what compliance is about. Not checkboxes. Not policy binders that exist to say they exist. Compliance is the discipline of measuring your actual controls against a recognized standard, finding where reality falls short, closing those gaps with enforceable policy, and producing evidence an independent party can evaluate without asking you to explain everything verbally.

In this project you run that entire process. You map every major control MedDefense has deployed against NIST CSF 2.0 and the HIPAA Security Rule. You find the gaps and there will be gaps. You write three policies that currently do not exist in enforceable form. You evaluate a critical vendor. You package the results for an audit that is six weeks away.

The output of this project is a compliance package that could be handed to an auditor without a single verbal explanation. That is the standard.

### Why this matters

Security work without governance documentation does not survive an audit. A risk register that exists in a shared drive without an approval signature, hardening baselines deployed without documented evidence of review, detection rules running without a formal change management record: these are controls that exist technically but cannot be proven to an auditor. Auditors do not operate on trust. They operate on evidence.

The analyst who can build a gap assessment, write enforceable policy, evaluate vendor risk, and brief leadership on compliance posture is not just a technician. In regulated sectors like healthcare, finance, public services, and critical infrastructure, the compliance layer is often the hardest part of the job and the one most visible to leadership. GRC analyst, security program manager, compliance officer, and eventually CISO functions all require exactly this capability. Building it now means arriving at those roles with something most candidates do not have: a record of having actually done it.

---

## Context

Four weeks after the incident, an email lands in Dr. Patricia Morales's inbox. MedDefense has been selected for an HHS Office for Civil Rights desk audit. The audit letter requests documentation of HIPAA Security Rule compliance across 15 categories. The interview is in six weeks.

James Chen sends you a one-line message: _"We have never done a formal compliance assessment against CSF or HIPAA. I need to know where we actually stand before they get here."_

Sarah Park confirms that three organization-wide security policies (Acceptable Use, Data Classification, and Vendor Management) either do not exist in writing or were last reviewed in 2021. Helena Reyes flags that the CloudVault Medical relationship, brought in to handle clinical data backup, has no current security assessment on file and no executed Business Associate Agreement.

You have the controls. You built most of them. Now you prove they exist and close what is missing.

---

## Learning Objectives

**Technical**

- Map deployed security controls to NIST CSF 2.0 subcategories using evidence references drawn from real MedDefense artifacts
    
- Identify compliance gaps across the Govern, Protect, Detect, Respond, and Recover functions
    
- Evaluate a vendor's security posture using a structured risk assessment methodology
    

**Conceptual**

- Understand the relationship between NIST CSF 2.0 subcategories and HIPAA Security Rule implementation specifications
    
- Distinguish between controls that exist and controls that are documented and evidence-supported
    
- Apply the principle that policy without specificity and enforcement mechanism is not policy
    

**Transversal**

- Write policies that are concise enough to be read and specific enough to be enforced
    
- Package compliance evidence in a format an auditor can independently evaluate
    
- Translate compliance findings into executive language without losing accuracy
    

---

## Resources

**Frameworks and standards**

- [NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) (full framework with subcategory reference)
    
- [NIST CSF 2.0 to HIPAA Security Rule Crosswalk](https://www.nist.gov/system/files/documents/2025/03/17/nist-csf-to-hipaa-security-rule-crosswalk-02-22-2016-final.pdf)
    

**HIPAA regulatory**

- [HHS HIPAA Security Rule, 45 CFR Part 164 Subpart C](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
    
- [HHS Guidance on Risk Analysis Requirements under the HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis/index.html)
    

**Vendor and supply chain risk**

- [NIST SP 800-161r1, Cybersecurity Supply Chain Risk Management Practices](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1.pdf)
    
- [HHS Model Business Associate Agreement](www.hhs.gov/sites/default/files/model-business-associate-agreement.pdf) (reference template)
    

---

## Requirements

### General

- A `Linux`, `macOS`, or Windows WSL environment is acceptable.
- Allowed editors: `vi`, `vim`, `emacs`, `nano`, VS Code, or any plain-text Markdown editor.
- A `README.md` file at the root of the project directory is mandatory.
- All submitted documents must be Markdown files unless a task explicitly requests another format.
- All Markdown files must pass `markdownlint` structure checks where possible.
- The student must preserve artifact names exactly when citing evidence from the material folder.
- No live internet research is required to complete the project. The provided material folder contains the local evidence artifacts needed for the audit package.
- Public standards linked in the Resources section may be used for conceptual reference, but submitted work must cite MedDefense artifacts by name when making evidence claims.

### Workflow Requirements

- Download the provided 6x00 materials from the platform.
- Create a local project directory named `6x00`.
- Place the extracted material folder inside the project directory or next to it.
- Work from local copies of the provided materials.
- Submit the requested `.md` files from the project root.
- Do not invent evidence artifacts. If a required evidence item does not exist in the materials, write `None` or identify the gap clearly.
- Do not claim that a policy, BAA, training record, vendor assessment, or audit artifact exists unless it is present in the provided materials or produced in this project.

### Critical Constraints

- The project assesses compliance evidence, not technical exploitation or system administration.
- Evidence must be specific and auditable. Generic phrases such as "security documentation" or "technical controls" are not sufficient evidence references.
- Every compliance claim must be traceable to a named artifact.
- Policies must read as enforceable MedDefense policies, not educational summaries.
- Vendor risk conclusions must follow the Vendor Management Policy created in this project.
- Audit readiness must be honest. If evidence is missing or partial, the submission must say so.

## Lab Materials

Download the complete 6x00 Compliance Engine material folder from the platform:

- Download the provided [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/5/4a9cf00f32cb80ee5e84eba85e7c83fd62fd2a80.zip)

Expected local structure:

```text
6x00/
├── prior_controls/
│   ├── endpoint_hardening_baseline.md
│   ├── sigma_detection_catalog.md
│   ├── ir_playbook_index.md
│   ├── forensic_findings_summary.md
│   ├── recovery_validation_summary.md
│   └── security_awareness_training_status.md
├── risk_register/
│   ├── risk_register_updates.yaml
│   └── risk_treatment_plan.md
├── compliance/
│   ├── nist_csf_2_0_subcategory_reference.md
│   ├── hipaa_security_rule_crosswalk.md
│   ├── ocr_audit_letter.md
│   └── prior_policy_inventory.md
├── vendor/
│   ├── cloudvault_security_questionnaire.md
│   ├── cloudvault_contract_summary.md
│   ├── cloudvault_subprocessor_list.md
│   └── baa_status_note.md
└── templates/
    ├── policy_header_template.md
    ├── audit_evidence_request_template.md
    └── ciso_brief_template.md
```