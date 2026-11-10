# When Everything Fails

## Introduction

> "_The time to repair the roof is when the sun is shining._" — **John F. Kennedy**

At 2:47 AM on a Tuesday in February, MedDefense's primary data center loses power. The generator starts. The UPS holds. Then the cooling system fails. By 3:15 AM, three critical servers are offline. Epic EHR is unreachable. Lab results from the overnight shift cannot be accessed. The charge nurse in the ICU is on hold with the help desk. A physician needs medication history for a patient who is deteriorating.

This is not a hypothetical. Healthcare organizations that have never tested their recovery procedures often discover that the difference between written plans and real recovery is measured in clinical risk, not only in minutes.

This project closes that gap before a real crisis opens it. You will build a Business Impact Analysis that prioritizes systems by patient safety consequence, design a backup architecture that can actually satisfy stated recovery objectives, write command-level recovery runbooks, execute a timed LIS recovery test inside the provided lab container, and convert the recovery gap into a board-ready remediation package.

The answer to disaster recovery is almost never "the plan worked exactly as written." The professional answer is: what did the plan promise, what did the test prove, what changed afterward, and what evidence supports that claim?

## Context

The HHS OCR desk audit preparation surfaced a gap more operationally dangerous than any missing policy: MedDefense has never tested its disaster recovery plan. The existing DR documentation predates the Epic EHR migration, does not account for the Laboratory Information System modernization completed last year, and references backup infrastructure that was decommissioned eighteen months ago.

James Chen escalated this to Dr. Morales immediately. Her response was direct: _"I am not going to tell an auditor we have a DR plan and then have them ask when we last tested it and have no answer. Fix it."_

Sarah Park pulled the existing documentation. It was 47 pages. It referenced a physical tape library in the basement that was replaced with cloud backup in 2024. The RTO for Epic EHR was listed as four hours, with no evidence that anyone had ever attempted to verify that number.

Robert Kim ran a check against the backup logs. In three cases, the declared RPO was shorter than the backup frequency. On paper, MedDefense was promising to recover data that the backup schedule mathematically could not preserve. A plan that fails arithmetic is not a plan.

Your assignment covers three things: build a defensible BIA, write a DR plan that reflects current infrastructure, and run a real recovery test against the Laboratory Information System using the provided containerized lab artifacts. The LIS was chosen as the test target because it has a clean backup chain and is critical enough to be meaningful without requiring students to manage Docker, MariaDB, or cloud infrastructure during the exercise.

The results will be presented to Dr. Morales and the Board Risk Committee next month. You are not being asked to produce documents only. You are being asked to produce evidence.

## Learning Objectives

### Technical

- Conduct a Business Impact Analysis using patient safety, regulatory, revenue and operational impact criteria across a clinical environment
- Design a backup architecture that satisfies declared RTO and RPO values with documented verification procedures per system
- Write command-level recovery runbooks with explicit expected outputs, checkpoints and deviation handling
- Execute a timed recovery test against a simulated LIS failure, measuring wall-clock time per step and documenting deviations in real time

### Conceptual

- Distinguish RTO, RPO and MTD as distinct business decisions with different clinical implications
- Understand how system dependency chains determine restoration sequencing in a multi-system outage
- Connect the gap between declared and actual recovery time to specific runbook deficiencies, not general unpreparedness

### Transversal

- Write clinical downtime procedures in language a nurse on a first night shift can follow without IT involvement
- Translate a failed recovery test into a gap analysis a CISO can present to a Board Risk Committee
- Produce a DR program package that satisfies HIPAA 164.308(a)(7) without requiring verbal explanation

---

## Resources

**Business continuity planning**

- [NIST SP 800-34 Rev.1, Contingency Planning Guide for Federal Information Systems](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-34r1.pdf)
    
- [FEMA Business Continuity Planning Suite](https://intranet.hbtn.io/rltoken/TpWieJyP2IAau2mzA9wcOg)
    

**Disaster recovery design**

- [CIS Controls v8, Control 11: Data Recovery](https://www.cisecurity.org/controls/data-recovery)
    
- [AWS Disaster Recovery Workloads on AWS Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-workloads-on-aws.html)
    

**Healthcare regulatory**

- [HIPAA Security Rule Contingency Plan Requirements, 164.308(a)(7), HHS Guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)

---

## Requirements

### General

- All work is performed inside the provided `6x01-when-everything-fails` lab container.
- The container is based on `Ubuntu 22.04+`.
- Allowed editors: `vi`, `vim`, `emacs`, `nano`.
- A `README.md` file at the root of the project directory is mandatory.
- All markdown files must pass `markdownlint` structure checks.
- Do not install extra packages unless the task explicitly tells you to.
- Do not use Docker commands inside the lab. The recovery environment is already prepared for you.
- Do not use internet resources during the recovery test. The test must reflect what is available during downtime.

### Bash Scripting

- Bash scripts must be executable with `chmod +x`.
- The first line of bash scripts must be exactly `#!/bin/bash`.
- Scripts must produce clean output with no debug messages unless specified.
- Scripts must be idempotent where reasonable: running a validation or setup command more than once must not destroy evidence.
- The recovery timer must write completed step logs as the test progresses, not only at the end.

### Critical Constraints

- The project assesses disaster recovery thinking, not Docker administration.
- Recovery artifacts are already staged inside the lab container.
- Service names, paths and expected values must come from the provided lab files, not from hardcoded assumptions.
- Recovery test findings must be honest. If the declared RTO is missed, the record must say so.
- Evidence must be copied exactly where the task asks for real command output.

### Workflow Requirements

- Connect to the lab using SSH.
- Work inside `/home/student/6x01`.
- Use the provided materials in `/opt/meddefense/materials`.
- Use `/tmp/meddefense-dr-test` only for the recovery test workspace.
- Submit the requested `.md`, `.sh` and evidence files from `/home/student/6x01`.

## Lab Materials

The materials includes all materials required to complete the project. You need to download [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/6/02fc9e72bfe2f8d49ff40244d2609e512e53b807.zip).

Expected local structure:

```text
./opt/meddefense/materials/
├── bia/
│   ├── meddefense_system_inventory.csv
│   ├── downtime_impact_notes.md
│   └── regulatory_reference_map.md
├── backup_architecture/
│   ├── current_backup_schedule.csv
│   ├── backup_log_review_findings.md
│   └── dependency_map_seed.md
├── runbooks/
│   ├── old_lis_recovery_runbook.md
│   ├── old_ad_recovery_notes.md
│   └── command_output_examples.md
├── downtime/
│   ├── nursing_station_locations.md
│   ├── paper_forms_inventory.md
│   └── clinical_escalation_contacts.md
├── recovery_test/
│   ├── lab_config.env
│   ├── app_config.env
│   ├── expected_lis_records.txt
│   ├── condition_cards.md
│   └── README.md
└── package/
    ├── hipaa_164_308_a7_reference.md
    └── board_brief_template.md
```

The recovery test workspace is created by the lab setup script and has this expected structure:

```text
./tmp/meddefense-dr-test/
├── backup/
│   └── lis/
│       └── 2026-04-21/
│           ├── lis_backup.sql.gz
│           └── backup_manifest.sha256
├── config/
│   └── app_config.env
├── recovery/
└── validation/
```

Download it [here](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/6/54147cb0ec2c636f0d5a09d658242bbcdfb47555.zip). The simulated LIS backup is SQLite-compatible SQL.