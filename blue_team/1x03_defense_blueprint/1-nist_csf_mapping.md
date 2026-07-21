# NIST CSF Current Profile

## 1. Govern

**Current Level:** Partial

**Evidence:** MedDefense has a deputy CISO, a security analyst, an IT Director and Board involvement. However, Project 1x00 found no formal security framework, complete policy structure, risk appetite or documented security strategy.

**Key Gap:** Security decisions are informal and responsibilities are not fully documented.

**Target Level:** Managed

Within six months, MedDefense should have approved policies, assigned roles, a risk register and regular Board reporting. Optimized is not realistic yet because the security team is small.

---

## 2. Identify

**Current Level:** Partial

**Evidence:** Projects 1x00, 1x01 and 1x02 created an asset inventory, data map, threat analysis and vulnerability assessment. These activities did not exist as a complete and repeatable process before the projects.

**Key Gap:** There is no permanent process for updating assets, vulnerabilities and risks.

**Target Level:** Managed

MedDefense should maintain an updated asset inventory and formal Risk Register, with named owners and regular risk reviews.

---

## 3. Protect

**Current Level:** Partial

**Evidence:** Project 1x00 found no MFA on the VPN and EHR, shared PACS accounts, a flat network, exposed medical devices and backups stored on the production network. Project 1x02 also found unpatched and outdated systems.

**Key Gap:** Critical systems are not protected by strong access control, segmentation and secure configuration.

**Target Level:** Managed

Within six months, MedDefense should implement MFA, remove shared accounts, patch critical systems, isolate backups and segment important clinical systems.

---

## 4. Detect

**Current Level:** Not Implemented

**Evidence:** MedDefense has no SIEM, centralized logging, intrusion detection or automated alerting. The crypto-miner operated for at least two weeks without detection, and the ransomware incident was discovered only when files became unavailable.

**Key Gap:** MedDefense cannot quickly detect or investigate attacks.

**Target Level:** Managed

MedDefense should centralize logs from critical systems, deploy endpoint and network monitoring, create alerts and establish a documented alert-review process.

---

## 5. Respond

**Current Level:** Partial

**Evidence:** MedDefense reacted to the ransomware and crypto-mining incidents, but Project 1x00 found no documented or tested incident response plan. Communication, escalation and breach-notification responsibilities are unclear.

**Key Gap:** There is no repeatable process for containing and managing incidents.

**Target Level:** Managed

MedDefense should create an incident response plan, define roles, prepare ransomware and phishing playbooks, and complete at least one tabletop exercise.

---

## 6. Recover

**Current Level:** Partial

**Evidence:** Backups exist, but Project 1x00 found that they are connected to the same network as production systems. There is no evidence of regular restoration testing, defined recovery times or a complete business continuity plan.

**Key Gap:** MedDefense cannot prove that systems and patient services can be restored safely after an attack.

**Target Level:** Managed

MedDefense should isolate backups, test restoration regularly, define recovery time objectives and document a recovery plan for critical clinical systems.

---

## Overall Current Profile

|Function|Current Level|Six-Month Target|
|---|---|---|
|Govern|Partial|Managed|
|Identify|Partial|Managed|
|Protect|Partial|Managed|
|Detect|Not Implemented|Managed|
|Respond|Partial|Managed|
|Recover|Partial|Managed|

The most urgent weakness is **Detect**, because MedDefense currently has almost no ability to discover attacks before they cause serious damage.
