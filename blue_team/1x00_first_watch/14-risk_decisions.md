# The Risk Decisions

The estimated costs below are planning estimates, not vendor quotations.

---

## 1. GAP-001 — No Internal Network Segmentation

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
The flat network allows attackers to move between workstations, servers and medical devices. Avoiding the risk is impossible because MedDefense needs the network, and accepting it would expose several Critical assets.

**Proposed Controls:**

* Create separate VLANs for servers, clinical workstations, administrative devices, medical devices, guest Wi-Fi and management systems.
* Apply firewall rules between the VLANs.
* Allow only required systems and ports.
* Block unnecessary communication between sites.

**Category and Function:**
Technical Preventive and Compensating

**Estimated Cost:** $30,000 — **$10–50K**

**Implementation Effort:** Long-term — more than one month

**Expected Risk Reduction:**
High. Segmentation would not prevent every compromise, but it would strongly limit lateral movement and reduce the number of systems affected by one infected device.

**Trade-offs:**
The project may interrupt services if rules are incorrect. IT must document required connections before blocking traffic.

---

## 2. GAP-002 — Medical Devices Exposed to the Wider Network

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
Patient monitors, infusion pumps and the MRI support direct patient care. They cannot simply be disconnected, and some devices cannot be patched, so MedDefense must use compensating controls.

**Proposed Controls:**

* Place Medical IoT devices in isolated network segments.
* Allow only approved communication with PACS, management servers and clinical systems.
* Change default credentials where supported.
* Monitor medical-device traffic for unusual connections.
* Create an approved vendor-access process.

**Category and Function:**
Technical Preventive, Technical Detective and Administrative Compensating

**Estimated Cost:** $15,000 — **$10–50K**

**Implementation Effort:** Long-term — more than one month

**Expected Risk Reduction:**
High. The controls would reduce direct access to medical devices and limit the ability to use them as entry points into the wider hospital network.

**Trade-offs:**
Some older devices may not support modern authentication. Changes must be tested with Radiology, Pharmacy, Nursing and biomedical engineering to avoid affecting patient care.

---

## 3. GAP-004 — Backups Are Not Isolated or Offsite

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
The existing backups are stored in the same room and network as production systems. Ransomware, fire or flooding could destroy both copies. Accepting this risk would leave MedDefense unable to restore major clinical systems.

**Proposed Controls:**

* Replicate backups to an offsite cloud-storage location.
* Use immutable or write-protected backup storage where possible.
* Restrict backup administration accounts.
* Test restoration regularly.

**Category and Function:**
Technical Corrective and Compensating

**Estimated Cost:** $14,400 per year — **$10–50K**

**Implementation Effort:** Short-term — less than one month

**Expected Risk Reduction:**
High. An isolated copy would give MedDefense a recovery option even if ransomware encrypts the local NAS and production servers.

**Trade-offs:**
The organization must pay an annual cost. Upload speed, storage growth and recovery time from the cloud must also be considered.

---

## 4. GAP-005 — No Centralized Security Monitoring

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
MedDefense creates logs but does not centrally review or alert on them. A full enterprise SIEM may consume most of the budget, so a lower-cost monitoring solution is more realistic.

**Proposed Controls:**

* Deploy a lower-cost centralized logging platform such as the Wazuh system Marcus had considered.
* Collect logs from the FortiGate, Active Directory, EHR, Linux servers and important Windows servers.
* Create alerts for unusual logins, privilege changes, malware, scanning and outbound connections.
* Assign responsibility for reviewing alerts.

**Category and Function:**
Technical Detective

**Estimated Cost:** $22,000 — **$10–50K**

**Implementation Effort:** Long-term — more than one month

**Expected Risk Reduction:**
High. Central alerts would reduce attacker dwell time and help MedDefense detect lateral movement, credential abuse and malware communication earlier.

**Trade-offs:**
The system requires tuning and staff time. Poorly configured alerts could create too many false positives.

---

## 5. GAP-006 — No Formal Incident Response or Disaster Recovery Plan

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
MedDefense previously improvised its ransomware response for four days. Written and tested plans are relatively inexpensive compared with the financial and clinical impact of a poorly managed incident.

**Proposed Controls:**

* Create an incident-response plan.
* Develop ransomware, data-breach and medical-device incident playbooks.
* Create a disaster-recovery plan with system recovery priorities.
* Define clinical downtime procedures.
* Conduct one tabletop exercise and one technical recovery test.

**Category and Function:**
Administrative Corrective and Technical Corrective

**Estimated Cost:** $12,000 — **$10–50K**

**Implementation Effort:** Short-term — less than one month for the first version; testing continues afterward

**Expected Risk Reduction:**
Medium to High. The plans will not prevent attacks, but they will reduce confusion, recovery time and regulatory mistakes.

**Trade-offs:**
Staff must spend time participating in planning and exercises. Plans will become ineffective if they are not updated and tested.

---

## 6. GAP-007 — Weak Protection of Privileged and Remote Accounts

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
Real healthcare breaches show that a valid password can be enough to access thousands of patient records. MedDefense cannot avoid remote access, but it can require stronger authentication.

**Proposed Controls:**

* Require MFA for VPN, O365, EHR administrators and privileged accounts.
* Remove shared accounts where individual accounts are possible.
* Review privileged accounts regularly.
* Require key-based SSH access on all Linux servers.

**Category and Function:**
Technical Preventive and Administrative Preventive

**Estimated Cost:** $17,000 — **$10–50K**

**Implementation Effort:** Short-term — less than one month for VPN and privileged accounts

**Expected Risk Reduction:**
High. MFA would greatly reduce the likelihood that stolen passwords alone result in unauthorized access.

**Trade-offs:**
Users may initially resist the extra login step. Some legacy applications may not support MFA and will need gateway-based compensating controls.

---

## 7. GAP-015 — No Formal Perimeter Patch Management

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
Internet-facing systems such as the FortiGate, VPN and patient portal are likely entry points. A formal process is less expensive than replacing systems after a ransomware incident.

**Proposed Controls:**

* Assign owners for the firewall, VPN and public-facing servers.
* Monitor vendor security advisories.
* Define emergency patch deadlines for Critical vulnerabilities.
* Scan internet-facing systems regularly.
* Document exceptions when patching must be delayed.
* Apply temporary restrictions when an immediate patch is impossible.

**Category and Function:**
Administrative Preventive and Technical Preventive

**Estimated Cost:** $8,000 — **$1–10K**

**Implementation Effort:** Quick Win — less than one week to establish the process; scanning continues regularly

**Expected Risk Reduction:**
High for perimeter compromise. The control reduces the period during which known internet-facing vulnerabilities remain exploitable.

**Trade-offs:**
Emergency patching may require downtime. Some updates must be tested before deployment to avoid service interruption.

---

# Budget Summary

| Priority | Treatment                                        | Estimated Annual Cost |
| -------: | ------------------------------------------------ | --------------------: |
|        1 | Internal network segmentation                    |               $30,000 |
|        2 | Medical-device isolation and monitoring          |               $15,000 |
|        3 | Offsite and isolated backups                     |               $14,400 |
|        4 | Centralized security monitoring                  |               $22,000 |
|        5 | Incident response and disaster recovery planning |               $12,000 |
|        6 | MFA and privileged-account improvements          |               $17,000 |
|        7 | Perimeter patch-management program               |                $8,000 |
|          | **Total**                                        |          **$118,400** |
|          | **Remaining budget**                             |            **$1,600** |

The proposed treatments fit within the **$120,000 annual budget**, leaving approximately **$1,600** for small unexpected expenses.

## Recommended Spending Order

The first spending should be:

1. Perimeter patch management
2. MFA
3. Offsite backups
4. Incident-response planning
5. Network segmentation
6. Medical-device isolation
7. Centralized monitoring

The first four can begin quickly and reduce immediate risk while the larger network projects are planned.

## Deferred Gaps

The following important gaps would need to move to the next fiscal year:

* Full server endpoint protection
* DLP and sensitive-data export monitoring
* Automated HR account offboarding
* Physical-security camera expansion
* Replacement of unsupported systems
* Full security-awareness program improvement
* Shadow IT discovery and network-access control

These items remain important, but the selected seven treatments provide broader protection for MedDefense’s most Critical assets and reduce the likelihood and impact of the most common healthcare attacks.

