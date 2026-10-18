
# The Evidence Trail

## Introduction

> "_Every contact leaves a trace._" — **Edmond Locard**

Containment answered whether the threat was stopped. Forensics answers what actually happened: how the attacker got in, what they did, what they accessed, and how to prove it.

**Helena Reyes**, MedDefense's General Counsel, has placed a litigation hold on all evidence from the incident. Dr. Patricia Morales needs a report she can present to the board. The findings will drive the HIPAA breach notification assessment. Depending on what you uncover, this report may end up cited in a regulatory proceeding.

From this point forward, every artifact you analyze must be verified before you touch it, every action recorded in the chain of custody, and every conclusion tied to a specific evidence reference. The standard is not "probably happened." The standard is "supported by documented evidence."

In this project you work through a full forensic investigation: you verify artifact integrity, hunt the filesystem for attacker footprints, extract persistence mechanisms from the registry, analyze memory with Volatility 3, correlate the full attack timeline, assess the regulatory impact, and deliver a forensic report with two audiences — technical and executive.

### Why this matters

**Digital forensics** is the bridge between "the incident happened" and "we can prove exactly what happened." In healthcare, finance, legal, and regulated industries, the forensic report is what drives breach notifications, insurance claims, regulatory responses, and sometimes criminal referrals. Getting it wrong has direct consequences: facts asserted without evidence, chains of custody that cannot be defended, breach scope underestimated, all of these create organizational and legal exposure far beyond the incident itself.

**Analysts** who can read a disk image, extract and interpret memory artifacts, correlate a multi-source timeline, and write a report that survives external scrutiny are rare. Most security teams can detect. Fewer can prove. This capability leads to senior IR positions, forensic specialist roles, and the kind of trust that comes with being the person leadership calls when something serious has happened.

It is also the skill that keeps well-meaning analysts from becoming the problem by touching evidence without a plan, losing chain of custody, or drawing conclusions the evidence cannot support.

---

## Context

The incident on `WST-WS-031` is contained. The active threat has been remediated. Now the harder question begins: what exactly happened, and how far did it go?

Helena Reyes has issued a formal litigation hold referencing case number `LH-2026-0414-01`. James Chen has authorized the forensic phase and assigned it to you. Three artifacts were acquired during the response: a disk image from `WST-WS-031` and memory dumps from `WST-WS-031` and `WST-WS-017`. All three are waiting in the evidence store, unanalyzed.

Dr. Morales's deadline for the board briefing is 72 hours. The forensic report must be complete, referenced, and defensible. If you cannot tie a finding to an artifact, it does not go in the report.

---

## Learning Objectives

**Technical**

- Verify forensic artifact integrity before and after analysis
    
- Perform filesystem timeline analysis using The Sleuth Kit
    
- Extract and interpret Windows persistence artifacts from a disk image
    
- Analyze a Windows memory dump using Volatility 3
    
- Correlate evidence across artifact types into a single incident timeline
    

**Conceptual**

- Chain of custody as a continuous discipline, not a one-time form
    
- Order of volatility and its impact on what evidence survives
    
- Distinction between confirmed findings, probable findings, and possible findings
    
- HIPAA breach scope determination from forensic evidence
    

**Transversal**

- Write for two audiences in the same document
    
- Tie every assertion to an evidence reference
    
- Bound your conclusions to what the evidence supports
    

---

## Resources

**Digital forensics standards**

- [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://intranet.hbtn.io/rltoken/xIJsBo9qxXs4TNHckEgNEA)
    
- [RFC 3227, Guidelines for Evidence Collection and Archiving](https://intranet.hbtn.io/rltoken/o1dpySbWnAoy7HBQBNgQUA)
    

**Tooling and methodology**

- [Volatility 3 documentation and plugin reference](https://intranet.hbtn.io/rltoken/1EfnV5m3qAx3ZxGIuy0MGw)
    
- [The Sleuth Kit (TSK) documentation](https://intranet.hbtn.io/rltoken/zXzNfPc_ITEbtq0d68G44A)
    
- [Plaso log2timeline documentation](https://intranet.hbtn.io/rltoken/343ddI8IIV_EXA6yVwU8nw)
    

**Healthcare regulatory**

- [HHS HIPAA Breach Notification Rule, 45 CFR 164.400 to 414](https://intranet.hbtn.io/rltoken/4Z7JJ4d0Roqr6pacvbdsMQ)
    
- [HHS OCR Guidance on Risk Assessment under the Breach Notification Rule](https://intranet.hbtn.io/rltoken/oR0TZiIX5dqBW6Gg6ztfow)