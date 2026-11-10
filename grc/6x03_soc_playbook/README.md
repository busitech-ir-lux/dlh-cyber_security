# The SOC Playbook

## Introduction

> "_Automation applied to an inefficient operation will magnify the inefficiency._" — **Bill Gates**

During the Cobalt Strike incident, Mike Torres spent 45 minutes manually enriching a single IP address: checking the reputation against three separate browser tabs, reading WHOIS output, cross-referencing with known C2 infrastructure documented in a previous threat intel report. By the time he had a verdict, the attacker had moved laterally to two additional hosts. The enrichment was not wrong. It was not bad analysis. It was just 40 minutes too slow because it was done entirely by hand.

MedDefense processes between 120 and 180 SIEM alerts per day. The security team has two analysts on any given shift. At an average of 8 minutes per alert for manual triage, that is 18 hours of analyst time required daily for work that in large part involves looking things up, not thinking. Enrichment is not a skill. Enrichment is a query. Queries should be run by computers, not people.

This project builds the automation infrastructure that should have existed before the incident. You will write a modular IOC enrichment engine in Python that queries a threat intel feed, performs DNS and IP classification and produces a structured verdict. You will write a lightweight SQLite-backed case manager that serves as the output system for all automated decisions. Then you will write two executable automation playbooks: one for phishing triage and one for credential exposure alerts. Every script must run. Every playbook must produce output. The automation strategy document is last, because the professional who has built working automation writes better strategy than the one who plans it abstractly.

### Why this matters

Automation is the career differentiator between an analyst who handles 40 alerts and one who handles 200. Every mature SOC automates enrichment, deduplication and initial triage. The analyst who can write the enrichment script, design the playbook logic and wire up the case creation is doing the work of two analysts and producing a system that scales. That capability appears directly in SOC engineer, detection engineer and security automation engineer roles, and increasingly in senior analyst roles where scripting is expected.

The specific skills built here transfer directly to SOAR platforms: the playbook logic you write in Python maps cleanly to Palo Alto XSOAR, Splunk SOAR and Microsoft Sentinel playbooks. The concepts are the same. The syntax changes.

---

## Context

James Chen opened the team meeting with a number: _"Last month, our two analysts spent a combined 312 hours on alert triage. I pulled the data. 68 percent of that time was on enrichment activity: IP lookups, domain checks, URL analysis, hash lookups. Work a script should do."_

Dr. Morales asked the follow-up question: _"What is the risk of automating it?"_

Robert Kim answered honestly: _"If we automate on a bad rule, we auto-close malicious alerts. If we automate block actions on a high false-positive rule, we block legitimate traffic. The risk is not in automation. The risk is in automating without measuring the false positive rate first, and without building in a human checkpoint for any action that is destructive or irreversible."_

That is the design constraint this project operates under. Every playbook you write must distinguish between enrichment and classification (safe to automate) and actions like blocking, isolating or closing (require measured false-positive rates and override mechanisms). The phishing triage playbook creates cases and escalates findings. It does not block senders or quarantine mailboxes automatically. The credential exposure playbook flags hosts for isolation and writes to an isolation queue, but the queue is consumed by a human action, not an automated one.

Mike Torres, who has been building his own one-off `bash` scripts since the incident, summarized it best: _"Build it right once, and it helps every alert. Build it wrong once, and it hurts every alert."_

---

## Learning Objectives

**Technical**

- Write a Python IOC enrichment module that auto-detects IOC type, queries a local threat intel feed, performs DNS and IP classification using only the standard library and produces a structured verdict with scoring
    
- Design and implement a SQLite-backed case manager with a normalized schema supporting case creation, note appending, status tracking and IOC linkage
    
- Write two executable automation playbooks that import the enrichment and case manager modules, apply decision logic against enrichment verdicts and produce structured case output with a full audit log
    
- Run an end-to-end integration test against five provided alert scenarios and verify that each playbook produces the expected verdict, case severity and action
    

**Conceptual**

- Understand the distinction between enrichment actions (safe to automate) and response actions (require false-positive rate measurement and human override)
    
- Understand deduplication as a prerequisite for alert-to-ticket integration: why one-alert-to-one-ticket creates ticket storms at volume
    
- Understand TTL-based caching as the standard solution to API rate limiting in enrichment pipelines
    

**Transversal**

- Produce an automation strategy document that quantifies current manual effort, estimates automation ROI and explicitly names the risks of over-automation in a healthcare environment
    
- Write concisely: the strategy document is two to three pages, not twenty
    

---

## Resources

**SOC automation and SOAR**

- [NIST SP 800-61r2, Computer Security Incident Handling Guide, Section 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) (detection and analysis process)
    
- [IBM SOAR Playbook Standards](https://www.ibm.com/docs/en/sqsp/51.0.0?topic=guide-playbooks-planning-overview)
    

**Python standard library reference**

- [Python `sqlite3` module documentation](https://docs.python.org/3/library/sqlite3.html)
    
- [Python `ipaddress` module documentation](https://docs.python.org/3/library/ipaddress.html)
    
- [Python `socket` module documentation](https://docs.python.org/3/library/socket.html)
    

**Threat intelligence and enrichment**

- [AbuseIPDB API documentation](https://docs.abuseipdb.com/#introduction) (optional live API)
    
- [MITRE ATT&CK Technique T1003.001, OS Credential Dumping, LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
    

---

## Requirements

### General

- All work is performed inside the provided `6x03-soc-playbook` lab container.
- The container is based on `Ubuntu 22.04+`.
- Python 3.8 or later is available.
- Only Python standard-library modules may be used for core scripts: `json`, `sqlite3`, `socket`, `ipaddress`, `argparse`, `datetime`, `re`, `logging`, `pathlib`, `urllib.parse`, and `urllib.request`.
- Do not install external Python packages.
- Allowed editors: `vi`, `vim`, `emacs`, `nano`, or VS Code Remote SSH if available.
- A `README.md` file at the root of the project directory is mandatory.
- All Python scripts must run with `python3`.
- All scripts must produce clean output with no debug messages unless the task explicitly asks for audit or warning output.
- All Markdown files must pass `markdownlint` structure checks where possible.

### Critical Constraints

- The project assesses SOC automation logic, not internet OSINT collection.
- The lab uses local threat intelligence and local alert artifacts. Do not depend on live external API calls.
- Optional AbuseIPDB enrichment may be described in strategy, but checker execution must pass without internet access.
- Playbooks must distinguish safe automation from response actions that require human approval.
- The credential exposure playbook may write to `isolation_queue.json`, but it must not isolate a host or call an EDR API.
- The phishing triage playbook may close clearly benign simulated alerts, but the automation strategy must define false-positive gates before real production auto-close.
- Do not delete evidence files such as `playbook_audit.log`, `cases.db`, `isolation_queue.json`, or integration outputs unless the task explicitly tells you to reset the test.
- All source values, expected outcomes, privileged accounts, and test alerts must come from the provided materials or task instructions, not from invented assumptions.

### Workflow Requirements

- Connect to the lab using SSH.
- Work inside `/home/student/6x03`.
- Use the provided materials in `./opt/meddefense/materials`.
- Copy required input artifacts from `./opt/meddefense/materials` into the project root only when a task asks for a root-level file such as `ioc_feed.json` or `privileged_accounts.json`.
- Store alert test files under `alerts/`.
- Submit the requested `.py`, `.json`, `.db`, `.log`, and `.md` files from `/home/student/6x03`.
- The integration test must be run inside the lab container so the generated `cases.db`, `playbook_audit.log`, and `isolation_queue.json` reflect real execution.

## Lab Materials

The materials includes all materials required to complete the project. You need to download [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/6/2100289a7a233dd52fe05445a11b7805a1761ca4.zip).

Expected local structure:

```text
./opt/meddefense/materials/
├── threat_intel/
│   ├── ioc_feed.json
│   ├── enrichment_validation_set.csv
│   ├── ioc_scoring_reference.md
│   └── reverse_dns_expected_behavior.md
├── alerts/
│   ├── phishing/
│   │   ├── ALT-20260428-001.json
│   │   ├── ALT-20260428-002.json
│   │   └── ALT-20260428-003.json
│   └── credential/
│       ├── ALT-20260428-007.json
│       ├── ALT-20260428-008.json
│       └── ALT-20260428-009.json
├── iam/
│   ├── privileged_accounts.json
│   └── privileged_account_context.md
├── case_management/
│   ├── case_schema_reference.sql
│   ├── case_id_generation_notes.md
│   └── sample_case_output.json
├── playbooks/
│   ├── phishing_triage_decision_logic.md
│   ├── credential_exposure_decision_logic.md
│   ├── mitre_technique_reference.md
│   └── audit_log_format_reference.md
├── integration/
│   ├── expected_outcomes.csv
│   ├── integration_test_checklist.md
│   └── sample_stdout_outputs.md
└── strategy/
    ├── soc_volume_baseline.md
    ├── automation_candidate_matrix_seed.csv
    ├── false_positive_governance.md
    └── soc_brief_template.md
```