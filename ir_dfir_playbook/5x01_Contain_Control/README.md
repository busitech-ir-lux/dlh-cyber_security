
# Contain and Control

## Introduction

> "_Everybody has a plan until they get punched in the mouth._" — **Mike Tyson**

The alarm is going off. A process is talking to an IP it should not. A clinical workstation is executing code a clinical workstation should never run. You are on call. Nobody is coming to help you for the first thirty minutes.

In this project you run a live incident from the first alert to a clean handoff. You open the authoritative timeline, preserve the evidence that would disappear the moment you act, weigh containment options with their real costs, execute the chosen option, reassess when the scope expands on you, plan eradication as a checklist with verification, validate recovery with proof, and package the incident so another analyst can own it without asking a single question.

The outcome is not a narrative report. It is the paper trail of an incident, written in the order it happened, with the decisions and trade-offs captured on the page as they were made.

### Why this matters

Detection buys the first thirty seconds. Everything after that is response, and response is where careers are made or damaged.

Analysts who handle incidents well share a few habits. They open a timeline the moment they declare an incident. They preserve what they will need later before they touch anything. They pick containment actions deliberately, knowing what they gain and what they lose. They write down the decision the moment it is made, not after. They treat eradication as a list with verification, not a feeling. They validate recovery with evidence, not relief.

Those habits transfer across every environment, hospital, bank, SaaS, factory, public sector. They are what senior analysts grade on in hiring loops. They are what separates someone who "has handled incidents" from someone who handles them well.

Regulated environments raise the bar. When the incident touches patient data, payment data, or public services, the written record becomes the legal record. The artifacts you build here are the kind that survive that scrutiny and the kind that keep a real response from falling apart at the moment it matters.

---

## Context

It is 02:47 Z on a Tuesday morning. A monitoring rule fires on a MedDefense clinical workstation. An endpoint alert backs it up. The on-call pager goes off in your hand.

James Chen sends one message to the incident channel: _"You own this. Contain it. Document everything."_

The account showing activity belongs to Daniel Marsh, a laboratory technician at the West Campus. The host is `WST-WS-031`, a clinical workstation with access to the Laboratory Information System. No other analyst is online. Dr. Patricia Morales and Helena Reyes will wake up in the next two hours, and the first thing they will read is whatever you write between now and then.

---

## Learning Objectives

**Technical**

- Perform initial triage on progressively revealed alert and log evidence
    
- Preserve volatile and non-volatile evidence before any containment action
    
- Select containment strategies against explicit operational trade-offs
    
- Execute eradication steps with verification across Windows persistence surfaces
    
- Validate service recovery with proof instead of assumption
    

**Conceptual**

- Order of operations between evidence preservation and containment
    
- Severity reassessment on scope change
    
- Eradication completeness across process, credential, and network persistence
    
- Handoff quality as a measurable outcome, not a courtesy
    

**Transversal**

- Maintain a timeline under pressure
    
- Justify every decision on the page at the moment it is taken
    
- Separate what is known from what is assumed
    

---

## Resources

**Incident response standards**

- [NIST SP 800-61r2, Computer Security Incident Handling Guide (Sections 3.3 and 3.4)](https://intranet.hbtn.io/rltoken/GL9OadF9y8-x1V24Lx4RUQ)
    
- [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://intranet.hbtn.io/rltoken/_xp3dmqAvT9K3l_DCuWg3Q)
    
- [SANS Incident Handler's Handbook](https://intranet.hbtn.io/rltoken/3L3r9YyQXxN95J2tNtegcg)
    

**Containment and eradication guidance**

- [CISA Federal Government Cybersecurity Incident Response Playbook](https://intranet.hbtn.io/rltoken/MxYlDoPsvJgmJV2e20GbFA)
    
- [Microsoft Incident Response Playbooks](https://intranet.hbtn.io/rltoken/BRaqvyuVM21yNjR-KWeTfg)
    
- [CISA Alert AA22-277A, Impacket and Remote Services abuse](https://intranet.hbtn.io/rltoken/NYeuBiwjwLRIGRzHIY89cQ)
    

**Adversary TTPs**

- [MITRE ATT&CK, Tactic Lateral Movement](https://intranet.hbtn.io/rltoken/IbBHs4dMpgdFB5pJgbhUGw)
    
- [LOLBAS Project, msbuild.exe abuse](https://intranet.hbtn.io/rltoken/Fvu-KkdUtMLTiIE2hQ5i6g)
    

---

## Requirements

- **Format:** Answers must be precise. Avoid "fluff".
    
- **Tools:** Analysis is done on the text/logs provided in the tasks.
    

### Lab Materials

Download the complete 5x01 containment and control material folder from the platform:

- Download the provided [materials](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/5/18413c1a55fbdaf53e83530b8161d959889de1de.zip)

Expected local structure:

```text
5x01/
├── alert_A-20260414-9841.json
├── auth_24h_dmarsh.json
├── auth_expansion_0334Z.log
├── edr_wst_ws_031_24h.jsonl
├── evidence_store_init.sh
├── proxy_24h_dmarsh.log
└── mock_validation_api
    ├── README.md
    ├── endpoint
    │   ├── persistence
    │   └── processtree
    ├── service
    │   ├── epic-api
    │   └── lis-api
    └── siem
        ├── netflow.json
        └── detection
```
