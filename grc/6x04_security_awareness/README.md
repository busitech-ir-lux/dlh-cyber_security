# Security Awareness & Human Defense

## Introduction

> "_The human factor is truly security's weakest link._" — **Kevin Mitnick**

You have spent weeks looking at phishing from the defender's side. In Module 4 you dissected a phishing kit, reconstructed a campaign from headers and payload, and mapped the attacker's infrastructure. You have triaged alerts that fired because someone clicked. You followed the forensic trail that began with a single phishing email and ended with an LSASS dump, a beacon, and a full incident response activation.

Now you design the program that catches the humans before the attacker does.

The post-incident review documented the fact that 23 of 41 phishing emails delivered to MedDefense employees were clicked. The SIEM detected the C2 beacon. The IR team contained the damage. But a click rate of 56% means every technical control downstream of the human layer was carrying weight that a behavior change program should have reduced. No detection rule catches a credential handed over willingly. No playbook contains a compromise that never happened.

This will builds the complete security awareness program for MedDefense: a phishing simulation campaign grounded in real attacker behavior, role-targeted guidance that clinical and administrative staff will actually read, vishing scenarios for live social engineering exercises, an insider threat awareness framework that protects the organization without creating a surveillance culture, an annual program calendar with budget justification, and the metrics infrastructure that tells leadership whether any of it is working.

The test for every artifact in this project is the same: would a nurse coming off a 12-hour shift read this and do something differently? Would a finance analyst hesitate before wiring money based on a phone call? If the answer is no, redesign it.

### Why this matters

Most security awareness programs fail for the same reason: they are designed to satisfy a compliance requirement rather than change behavior. Annual training courses generate completion certificates. Completion certificates satisfy auditors. Auditors leave. The click rate stays at 38%.

The organizations that actually move the needle run something different: continuous simulations calibrated to real attacker behavior, immediate post-failure interventions that teach rather than shame, content segmented by role and risk profile, and metrics that measure what employees do rather than what they know. The analyst who can design and run this kind of program is doing three jobs simultaneously: threat intelligence (what is the attacker actually doing?), operational security (how do we simulate it safely?) and organizational communication (how do we change what 1,200 people do under pressure?).

Security awareness program design appears in GRC analyst job descriptions, security program manager roles and CISO portfolios. Every skill in this project is transferable the day you walk into your first security role.

---

## Context

Three weeks after the IAM audit and the SOC automation rollout, Dr. Patricia Morales calls a meeting that nobody wanted to have. She puts a single number on the whiteboard: 23.

Twenty-three MedDefense employees clicked the phishing link that initiated the Cobalt Strike compromise documented in Module 5. Out of 41 phishing emails delivered, 23 were clicked. The SIEM caught the beacon within four minutes. The IR team contained the damage. But the humans failed first, and they failed at a rate that is not acceptable for a healthcare organization handling ePHI at scale.

James Chen speaks first: "We can automate enrichment. We can write playbooks. We cannot automate judgment. We need a program that changes behavior, not a training calendar that satisfies a checkbox."

Sarah Park flags the operational constraint: clinical staff at MedDefense are already carrying 14 mandatory training modules from regulatory and accreditation requirements. Any security content that lands on top of that stack must earn its place by being relevant, brief and actionable. "If it reads like a compliance document," she says, "it will not be read."

HR Director Maria Santos adds one firm boundary: simulation results are not to be used in performance reviews. The program's purpose is training, not accountability enforcement.

Dr. Morales assigns you the full build. Ninety days to first wave. The deliverable is a complete, operational security awareness program.

---

## Learning Objectives

**Technical**

- Design a phishing simulation campaign with targeting strategy, wave scheduling and behavioral metrics that measure actual behavior change
    
- Produce realistic social engineering lures calibrated to healthcare sector threat patterns and role-specific attack surfaces
    
- Build a vishing simulation framework with complete scenario scripts, assessment rubrics and debrief protocols
    

**Conceptual**

- Distinguish between phishing campaigns that measure behavior and campaigns that measure awareness
    
- Apply behavior change theory to security training design: spaced reinforcement, moment-of-failure intervention and role-targeted content delivery
    
- Analyze the ethical boundaries of security simulation: exclusion criteria, informed consent frameworks and post-simulation support obligations
    

**Transversal**

- Write security guidance that non-technical audiences will actually read and act on within their existing workflows
    
- Design insider threat awareness criteria that distinguish protective indicators from surveillance overreach
    
- Translate program metrics into executive language for budget justification and board reporting
    

---

## Resources

**Behavior change and learning design**

- [NIST SP 800-50r1, Building a Cybersecurity and Privacy Learning Program](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-50r1.pdf)
    
- [SANS Security Awareness Report](https://www.sans.org/for-organizations/workforce/resources/security-awareness-report) (annual, open access)
    

**Phishing simulation methodology**

- [MITRE ATT&CK Phishing Techniques](https://attack.mitre.org/techniques/T1566/) (T1566, T1566.001, T1566.002)
    
- [Anti-Phishing Working Group (APWG) Phishing Activity Trends Reports](https://apwg.org/trendsreports/)
    

**Insider threat**

- [CISA Insider Threat Mitigation Guide](https://www.cisa.gov/sites/default/files/publications/CISA_Insider_Threat_Mitigation_Guide_092018.pdf)

**Healthcare security communications**

- [Health-ISAC Threat Intelligence and Awareness Resources:](https://health-isac.org/resources-and-news/)

---

## Requirements

### General

- A `Linux`, `macOS`, or Windows WSL environment is acceptable.
- Allowed editors: `vi`, `vim`, `emacs`, `nano`, VS Code, or any plain-text Markdown editor.
- A `README.md` file at the root of the project directory is mandatory.
- All submitted documents must be Markdown files unless a task explicitly requests another format.
- All Markdown files must pass `markdownlint` structure checks where possible.
- The student must preserve artifact names exactly when citing evidence from the material folder.
- No live internet research is required to complete the project. The provided material folder contains the MedDefense-specific evidence and design inputs needed for the full awareness program.
- Public standards linked in the Resources section may be used for conceptual reference, but submitted work must be grounded in the provided MedDefense artifacts.
- Do not create deployable real-world phishing infrastructure, credential collection pages, real impersonation domains, or live attack tooling. Templates are written for controlled internal simulation only.

### Workflow Requirements

- Download the provided 6x04 materials from the platform.
- Create a local project directory named `6x04`.
- Place the extracted material folder inside the project directory or next to it.
- Work from local copies of the provided materials.
- Submit the requested `.md` files from the project root.
- Use the material references named in each task. If a relevant material is missing, identify the gap rather than inventing evidence.
- Treat employee privacy and HR boundaries as hard constraints throughout the project.
- Campaign, vishing and insider-threat artifacts must be usable by MedDefense program owners without verbal clarification.

### Critical Constraints

- The project assesses security awareness program design, not technical exploitation.
- Simulation content must train behavior and must not shame, punish, harass, or embarrass employees.
- Individual simulation results must not be used in performance reviews.
- Department managers receive aggregate team data only unless a documented second confirmed offense and formal HR escalation trigger apply.
- Templates must use placeholders such as `[SIMULATION_LINK]`; do not include real credential-harvesting URLs or instructions to collect passwords.
- Vishing scripts must be safe for controlled simulation and must include verification opportunities and debrief guidance.
- Insider threat content must distinguish protective indicators from surveillance overreach.
- Every program claim must be traceable to provided materials or to artifacts created earlier in this project.

## Lab Materials

Download the complete 6x04 Security Awareness & Human Defense material folder from the platform:

- Download the provided [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/5/47ce115327cafd3477cb9f93be61aa23704cee7c.zip)

Expected local structure:

```text
6x04/
├── threat_intel/
│   ├── phishing_kit_analysis_summary.md
│   ├── email_header_inspection_results.md
│   ├── campaign_reconstruction.md
│   ├── healthcare_social_engineering_patterns.md
│   └── lure_effectiveness_benchmarks.md
├── incident_context/
│   ├── module5_incident_summary.md
│   ├── post_incident_click_rate_review.md
│   ├── cobalt_strike_phishing_path.md
│   └── security_awareness_gap_notes.md
├── iam_context/
│   ├── role_inventory.csv
│   ├── privileged_account_findings.md
│   ├── employee_segments.csv
│   └── iam_audit_summary_6x02.md
├── campaign_design/
│   ├── hr_privacy_rules.md
│   ├── workforce_population_breakdown.csv
│   ├── clinical_schedule_constraints.md
│   └── simulation_ethics_guidelines.md
├── templates/
│   ├── phishing_template_constraints.md
│   ├── post_click_microtraining_reference.md
│   ├── role_based_guidance_style_guide.md
│   └── vishing_facilitator_notes.md
├── insider_threat/
│   ├── insider_threat_case_notes.md
│   ├── technical_indicators_reference.md
│   ├── reporting_and_triage_model.md
│   └── manager_reference_constraints.md
└── program_governance/
    ├── annual_calendar_constraints.md
    ├── budget_assumptions.md
    ├── metrics_baseline.csv
    ├── board_reporting_template.md
    └── program_governance_roles.md
```