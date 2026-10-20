# Lessons Learned


## Introduction

> "_Learning is not compulsory… neither is survival._" — **W. Edwards Deming**

The incident is over. The forensic report is delivered. Most organizations stop here. The ones that do not are the ones that are harder to breach the next time.

In this project you close the loop on the incident. You audit every control that should have fired and assess why some did not. You identify the exact gaps. You write detection rules that target the observed TTPs, then test them against real and clean data to confirm they work without flooding the queue. You enrich the incident IOCs with open-source threat intelligence to understand who you were dealing with and what they typically do next. You update the hardening baseline, the risk register, and the IR playbooks with specific, evidence-driven changes. You deliver an implementation package another engineer can execute.

The output is not a list of recommendations. It is a set of artifacts that actually change the organization's posture.

### Why this matters

Post-incident improvement is where most organizations fail. The PIR happens, a slide deck is presented, a few action items are assigned with no owners or deadlines, and six months later the same gaps exist. The next incident finds exactly the same holes.

The professionals who build durable defenses know how to close this loop. They write the detection rule, test it before it goes to production, and verify it fires on the next real event. They update the playbook before the next incident, not during it. They use threat intelligence to anticipate the next move instead of reacting to the last one. They put numbers and owners and deadlines on improvements and then verify those improvements worked.

This is the work that compounding returns in defense are built on. One incident, handled well, makes the organization measurably harder to compromise. That is the professional difference between maintaining a SOC and building one.

---

## Context

The forensic report is in Helena Reyes's inbox. Dr. Patricia Morales has briefed the board. James Chen has opened the post-incident review and assigned it to you.

The question is no longer what happened. The question is: why did this get as far as it did, and what specifically changes now?

Chen's guidance: "Give me things we can actually deploy. Not slides. Not awareness posters. Rules that run, configs that change, playbook text that is better than it was."

---

## Learning Objectives

**Technical**

- Audit control effectiveness against an actual incident timeline
    
- Write Sigma detection rules targeting observed TTPs
    
- Test detection rules against positive and negative samples to measure false positive rate
    
- Enrich IOCs and TTPs with open-source threat intelligence
    
- Produce hardening specifications driven by specific incident findings
    

**Conceptual**

- The gap between controls in place and controls that work
    
- Detection engineering as a lifecycle: write, test, tune, deploy
    
- Threat intelligence as a forward-looking discipline, not just retrospective analysis
    
- Risk register as a living document, updated by operational evidence
    

**Transversal**

- Every improvement must have an owner, a deadline, and a validation method
    
- Bound conclusions to evidence; bound recommendations to findings
    
- Write artifacts other engineers can execute without asking questions
    

---

## Resources

**Post-incident review methodology**

- [NIST SP 800-61r2, Section 3.4, Post-Incident Activity](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
    
- [CISA Post-Incident Review Guide](https://www.cisa.gov/sites/default/files/publications/Incident-Response-Plan-Basics_508c.pdf)
    

**Detection engineering**

- [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification)
    
- [MITRE ATT&CK technique T1127.001, Trusted Developer Utilities, MSBuild](https://attack.mitre.org/techniques/T1127/001/)
    
- [MITRE ATT&CK technique T1550.003, Use Alternate Authentication Material, Pass-the-Ticket](https://attack.mitre.org/techniques/T1550/003/)
    

**Threat intelligence**

- [MITRE ATT&CK Groups (actor TTP mapping)](https://attack.mitre.org/groups/)
    
- [AlienVault OTX open threat intelligence](https://otx.alienvault.com/)
    
- [AbuseIPDB](https://www.abuseipdb.com/)
    

**Hardening references**

- [Microsoft Attack Surface Reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
    
- [CIS Benchmark for Windows 10/11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
    

---

## Requirements

- A `Linux` workstation with `bash`, `yamllint`, and `sigma-cli` (or `sigmac`) for rule syntax validation
    
- Provided sample logs: `incident_sysmon.jsonl` (Sysmon events from the incident window) and `clean_sysmon.jsonl` (30-day baseline from the same host class)
    
- Access to open threat intelligence sources (VirusTotal, OTX, AbuseIPDB)
    
- The correlated timeline and forensic findings from the investigation phase
    

### Lab Materials

Download the complete 5x03 lessons learned material folder from the platform:

- Download the provided [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/5/ada1cb926fb3b1a07c60fad104757282a663519c.zip)

Expected local structure:

```text
5x03/
├── clean_sysmon.jsonl
├── forensic_findings_summary.md
├── incident_sysmon.jsonl
└── ioc_enrichment_snapshot
    ├── abuseipdb
    │   ├── 185.220.101.47.json
    │   └── 91.234.99.107.json
    ├── otx
    │   ├── pulse_185.220.101.47.json
    │   └── pulse_91.234.99.107.json
    ├── urlhaus
    │   └── ms0365-support.login-verification.click.json
    └── virustotal
        ├── domain_ms0365-support.login-verification.click.json
        ├── hash_update_xml.json
        ├── ip_185.220.101.47.json
        └── ip_91.234.99.107.json
```