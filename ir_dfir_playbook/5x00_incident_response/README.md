
# When the Alarm Sounds

## Introduction

> "_Plans are nothing; planning is everything._" — **Dwight D. Eisenhower**

An incident will happen. Not if. When. The only thing you control is whether your organization is ready to respond or has to improvise.

In this project you build the incident response capability for a regional healthcare organization. You produce the severity model, the team structure, the playbooks an on-call analyst will follow at 3 AM, and the communication templates that will land on the CEO's phone and the regulator's desk. You ship the artifacts. Real ones. The kind that end up in the folder titled "IR" on a team's shared drive.

### Why this matters

Your first week on a SOC or IR team, someone hands you a wiki. Inside are playbooks, severity levels, contact trees, and communication templates. They exist because someone before you sat down and wrote them. Those documents are the only thing standing between a tired analyst and a bad decision at 2 AM. As you grow in this field, you will start writing them yourself. New threats, new regulations, new business units, new tooling: the playbooks have to keep up. The people who lead IR functions are the ones who can turn messy operational reality into a repeatable process that anyone on the team can follow under pressure.

In regulated industries the stakes are higher. When a healthcare, finance, or utilities organization is breached, the first thing auditors and regulators ask for is the IR plan. If it does not exist, or reads like a theory paper, the fines arrive fast. The artifacts you build here are the kind that survive that scrutiny, and the kind that keep a real response from falling apart.

---

## Context

MedDefense Health Systems runs three hospital sites, employs 2,000 staff, and holds the clinical records of patients who cannot unshare their data. Detection capability has been improving. Response capability has not. When something breaks, people call people. Decisions happen in hallways. Almost nothing gets written down.

Dr. Patricia Morales, Chief Information Security Officer, has authorized a formal incident response capability and funded it out of the operational risk budget. James Chen, SOC Lead, owns the delivery and has handed you the build. His brief: _"Executive review is in three weeks. I do not want a theory paper. I want artifacts the on-call analyst opens at 2 AM and follows without calling me."_

You will work with:

- Sarah Park, **IT Director**
    
- Robert Kim, **Infrastructure Lead**
    
- Mike Torres, **Network Engineer**
    
- Helena Reyes, **General Counsel**
    
- Marcus Webb, **Communications Director**
    

What you ship in this project becomes the baseline IR capability for the organization. It is what the next real alert will be handled against.

---

## Learning Objectives

**Technical**

- Translate the incident response lifecycle into organizational artifacts
    
- Define severity classification tied to operational and patient impact
    
- Design playbooks that an on-call analyst can execute under pressure
    
- Produce communication templates tuned to distinct audiences
    

**Conceptual**

- Align IR structure with healthcare regulatory obligations
    
- Distinguish decision authority across incident severity levels
    
- Reason about trade-offs between evidence preservation and operational continuity
    

**Transversal**

- Write for operators, not readers
    
- Standardize before you scale
    
- Validate a design by running it, not by reviewing it
    

---

## Resources

**Incident response standards**

- [NIST SP 800-61r2, Computer Security Incident Handling Guide](https://intranet.hbtn.io/rltoken/C2xA2pYbdsAGGEwkwVA8jg)
    
- [NIST SP 800-184, Guide for Cybersecurity Event Recovery](https://intranet.hbtn.io/rltoken/bV9OyoUeXRLiXsNYzHCOSA)
    
- [ISO/IEC 27035-1:2023, Information security incident management](https://intranet.hbtn.io/rltoken/MQ6c8K06DPZj8oWgn3V6jw)
    

**Healthcare regulatory**

- [HHS HIPAA Breach Notification Rule, 45 CFR 164.400 to 414](https://intranet.hbtn.io/rltoken/-dRZyaMN3Vt5bI8pRAIPOg)
    
- [HHS Health Industry Cybersecurity Practices (HICP)](https://intranet.hbtn.io/rltoken/Ncx9YSYugJmNNvLclYAstg)
    

**Operational playbooks and team design**

- [CISA Federal Government Cybersecurity Incident Response Playbooks](https://intranet.hbtn.io/rltoken/8jVvD_AKLOaM-GQBy22urQ)
    
- [FIRST CSIRT Services Framework v2.1](https://intranet.hbtn.io/rltoken/hoJ-8tyYS8TViy3RhvVewA)
    
- [ENISA Good Practice Guide for Incident Management](https://intranet.hbtn.io/rltoken/nFEH0UwYQFK52ZsLVXSGyg)
    

---

## Requirements

- **Format:** Answers must be precise. Avoid "fluff".
    
- **Tools:** Analysis is done on the text/logs provided in the tasks.
    

### Lab Materials

Download the shared Module 5 organization profile from the platform:

- Download the provided [MedDefense profile](https://s3.eu-west-3.amazonaws.com/hbtn.intranet/uploads/misc/2026/5/a342050dc0314b9497a408a1798285e90829227b.zip)

Expected local structure:

```text
5x00_shared/
└── meddefense_profile.md
```



