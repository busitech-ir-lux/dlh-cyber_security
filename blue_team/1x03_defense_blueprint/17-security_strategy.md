# MedDefense Health Systems

# Security Strategy Document

**Document Owner:** Deputy CISO
**Version:** 1.0
**Planning Period:** Six months
**Security Budget:** $120,000

---

# 1. Executive Summary

MedDefense currently has a **High to Critical cybersecurity risk posture**. The most serious weaknesses include a flat network, missing MFA, unsupported systems, exposed medical devices, connected backups and almost no centralized security monitoring.

MedDefense should adopt **NIST CSF 2.0 as its strategic framework**, use **CIS Controls IG1 as its technical baseline**, and gradually align its governance and evidence with **ISO/IEC 27001**. Quantitative risk analysis using AV, EF, SLE, ARO and ALE was used to connect security spending to expected financial loss.

The requested investment is **$120,000**. Across the five main risk scenarios, the controls reduce modeled annualized exposure by approximately **$5.05 million**, although the VPN and EHR scenarios overlap and must not be treated as completely separate savings.

The three highest priorities are:

1. Enable MFA for VPN and administrative accounts.
2. Segment the flat network and protect critical systems.
3. Deploy Wazuh centralized monitoring and security alerting.

The strategy also funds EDR, immutable offsite backups and a managed firewall for Westside Clinic.

---

# 2. Governance Framework

## 2.1 Framework Selection

MedDefense should use three complementary frameworks:

* **NIST CSF 2.0** provides the strategic structure.
* **CIS Controls** provide practical security actions.
* **ISO/IEC 27001** provides governance, documentation and audit evidence.

NIST CSF should be the main framework because MedDefense is a regional hospital, not a federal agency, and needs a flexible, risk-based approach. CIS IG1 should be the first implementation target because MedDefense has limited staff and lacks basic cyber hygiene. ISO 27001 certification should not be attempted immediately, but its management principles should guide policies, evidence and continuous improvement.

## 2.2 NIST CSF Current and Target Profile

| NIST Function | Current Level   | Six-Month Target | Main Improvement                                                 |
| ------------- | --------------- | ---------------- | ---------------------------------------------------------------- |
| Govern        | Partial         | Managed          | Policies, ownership, risk register and Board reporting           |
| Identify      | Partial         | Managed          | Updated asset, software and risk inventories                     |
| Protect       | Partial         | Managed          | MFA, segmentation, patching, EDR and protected backups           |
| Detect        | Not Implemented | Managed          | Centralized logs, Wazuh alerts and investigation process         |
| Respond       | Partial         | Managed          | Documented incident plan and tabletop exercise                   |
| Recover       | Partial         | Managed          | Isolated backups, recovery tests and defined recovery objectives |

The largest current weakness is **Detect** because MedDefense cannot reliably discover or investigate attacks.

## 2.3 CIS Controls Maturity

| Status          | Number of Controls |
| --------------- | -----------------: |
| Implemented     |                  0 |
| Partial         |                 12 |
| Not Implemented |                  6 |
| **Total**       |             **18** |

MedDefense should fully implement **CIS IG1** and begin selected IG2 safeguards for network monitoring, segmentation and architecture management.

The five highest-priority CIS Controls are:

1. Control 6 — Access Control Management
2. Control 7 — Continuous Vulnerability Management
3. Control 11 — Data Recovery
4. Control 12 — Network Infrastructure Management
5. Control 13 — Network Monitoring and Defense

## 2.4 Governance Structure

### Main Roles

| Role                   | Assigned Position       | Responsibility                                                   |
| ---------------------- | ----------------------- | ---------------------------------------------------------------- |
| Executive Sponsor      | CEO                     | Approves budget, policy and major risk acceptance                |
| Security Program Owner | Deputy CISO, James Chen | Accountable for strategy, risk and incident management           |
| Technical Owner        | IT Director, Sarah Park | Implements and maintains technical controls                      |
| Business/Data Owners   | Dept Heads              | Approve business access and data requirements                    |
| Security Operations    | Security Analyst        | Assessments, monitoring, reporting and risk-register maintenance |

### Data Roles

* **Data Owner:** Department heads decide who requires access to departmental information.
* **Data Controller:** MedDefense decides why and how patient and employee data is processed.
* **Data Processor:** External providers process data under MedDefense’s instructions.
* **Data Custodian:** The IT team stores, backs up and technically protects information.

### Key RACI Assignments

| Activity                  | Accountable | Responsible                      |
| ------------------------- | ----------- | -------------------------------- |
| Security budget           | CEO         | Deputy CISO                      |
| Vulnerability remediation | IT Director | Security Analyst and IT          |
| Incident response         | Deputy CISO | IT Director and Security Analyst |
| Security policy           | CEO         | Deputy CISO                      |
| Risk acceptance           | CEO         | Deputy CISO                      |
| Vendor risk assessment    | Deputy CISO | Security Analyst                 |
| Audit coordination        | Deputy CISO | Security Analyst                 |

The vacant CISO position creates an authority and oversight gap. MedDefense should use a **vCISO during the first year**, allowing the organization to obtain senior expertise without using most of the security budget for one salary.

---

# 3. Quantitative Risk Analysis

## 3.1 Top Five Risks by ALE

| Rank | Risk                                   | ALE Before Controls | Estimated ALE After Controls |
| ---: | -------------------------------------- | ------------------: | ---------------------------: |
|    1 | EHR patient-data breach                |          $3,025,000 |                     $726,000 |
|    2 | VPN compromise and full network access |          $2,864,400 |                     $477,400 |
|    3 | Negligent insider data exposure        |            $300,000 |                      $96,000 |
|    4 | Billing-server ransomware              |            $135,278 |                      $18,920 |
|    5 | Medical-device patient-safety event    |             $60,000 |                      $15,000 |

The combined modeled reduction is:

```text
ALE before = $6,384,678
ALE after  = $1,333,320

Modeled reduction = $5,051,358
```

The VPN and EHR scenarios overlap because a VPN compromise may lead to an EHR breach. The values are therefore useful for prioritization but should not be added as guaranteed financial savings.

## 3.2 Risk Register Summary

| Risk ID  | Risk                                     | Inherent Risk | Treatment                                |
| -------- | ---------------------------------------- | ------------- | ---------------------------------------- |
| RISK-001 | EHR patient-data breach                  | Critical      | Mitigate                                 |
| RISK-002 | VPN compromise                           | Critical      | Mitigate                                 |
| RISK-003 | Billing ransomware and backup loss       | High          | Mitigate                                 |
| RISK-004 | Attacks remain undetected                | Critical      | Mitigate                                 |
| RISK-005 | Lateral movement across flat network     | Critical      | Mitigate                                 |
| RISK-006 | Negligent insider disclosure             | High          | Mitigate                                 |
| RISK-007 | Medical-device compromise                | High          | Mitigate and accept residual risk        |
| RISK-008 | Westside Clinic compromise               | High          | Mitigate                                 |
| RISK-009 | Unsupported systems exploited            | High          | Mitigate and temporarily accept MRI risk |
| RISK-010 | Shared PACS accounts and exposed traffic | High          | Mitigate                                 |

The Security Analyst maintains the register. It is reviewed monthly and after major incidents, vulnerabilities, system changes, audit findings or regulatory changes.

## 3.3 Risk Appetite Statement

MedDefense has a **low risk appetite** for risks affecting patient safety, patient data, clinical availability or regulatory compliance. Risks that may cause serious patient harm or prevent recovery of critical services must be reduced as far as reasonably possible. Limited financial and operational risks may be accepted when the cost of treatment is greater than the expected benefit. High and Critical risks may only be accepted temporarily by the CEO with Board approval and documented compensating controls.

---

# 4. Control Strategy

## 4.1 Cost-Benefit Results

| Rank | Control                        | Annual Cost | Estimated ALE Reduction |  Net Value | Decision  |
| ---: | ------------------------------ | ----------: | ----------------------: | ---------: | --------- |
|    1 | MFA                            |     $12,000 |              $2,387,000 | $2,375,000 | Implement |
|    2 | Network segmentation           |     $35,000 |              $2,299,000 | $2,264,000 | Implement |
|    3 | Wazuh SIEM                     |     $26,000 |                $349,847 |   $323,847 | Implement |
|    4 | EDR upgrade                    |     $24,000 |                $254,619 |   $230,619 | Implement |
|    5 | Westside firewall              |      $9,000 |                $190,960 |   $181,960 | Implement |
|    6 | Offsite backups                |     $14,000 |                 $74,403 |    $60,403 | Implement |
|    7 | Outsourced 24/7 SOC            |    $110,000 |                $150,000 |    $40,000 | Defer     |
|    8 | Full medical-device monitoring |     $60,000 |                 $48,000 |   -$12,000 | Reject    |

## 4.2 Approved Budget Allocation

| Funded Control                  |         Cost |
| ------------------------------- | -----------: |
| MFA for VPN and administrators  |      $12,000 |
| Network segmentation            |      $35,000 |
| Wazuh SIEM                      |      $26,000 |
| Endpoint Detection and Response |      $24,000 |
| Westside managed firewall       |       $9,000 |
| Immutable offsite backups       |      $14,000 |
| **Total**                       | **$120,000** |
| **Budget Remaining**            |       **$0** |

The managed SOC is deferred because it consumes almost the entire budget and overlaps with the first-year Wazuh deployment. The full medical-device monitoring platform is rejected because its expected risk reduction is lower than its cost.

## 4.3 Framework Mapping

| Control              | Main Risks                   | CIS Mapping             | NIST CSF Mapping |
| -------------------- | ---------------------------- | ----------------------- | ---------------- |
| MFA                  | RISK-001, RISK-002           | CIS 6.4 and 6.5         | PR.AA            |
| Network segmentation | RISK-001, RISK-005, RISK-007 | CIS 12.2                | PR.IR            |
| Wazuh SIEM           | RISK-004                     | CIS 8.1–8.3 and 13.1    | DE.CM, DE.AE     |
| EDR                  | RISK-003, RISK-009           | CIS 10.1–10.2           | PR.PS, DE.CM     |
| Westside firewall    | RISK-008                     | CIS 12.1, 12.2 and 12.7 | PR.PS, PR.IR     |
| Offsite backups      | RISK-003                     | CIS 11.2–11.4           | RC.RP            |

## 4.4 Immediate Quick Wins

Within the first two weeks, MedDefense should:

1. Enable MFA for VPN and administrator accounts.
2. Disable dormant, default and unnecessary shared accounts.
3. Patch the FortiGate, billing server and other critical systems.
4. Test backups and create a temporary offline copy.
5. Launch a simple phishing and incident-reporting process.

These activities require little or no additional budget and demonstrate immediate progress.

---

# 5. Architecture Recommendations

## 5.1 Segmentation Design

The current flat `10.10.0.0/16` network should be divided into controlled security zones.

| Zone                | Proposed Range  | Main Systems                                   |
| ------------------- | --------------- | ---------------------------------------------- |
| Server Zone         | `10.10.10.0/24` | EHR, billing, file server, AD and PACS servers |
| Clinical Zone       | `10.10.20.0/23` | Nurse, physician and radiology workstations    |
| Medical Device Zone | `10.10.30.0/24` | Pumps, monitors, MRI and imaging devices       |
| Management Zone     | `10.10.40.0/24` | Admin workstations, Wazuh and security tools   |
| Guest/IoT Zone      | `10.10.50.0/23` | Visitor Wi-Fi and non-clinical devices         |
| Backup Zone         | `10.10.60.0/24` | Backup NAS and recovery systems                |

Traffic between zones should follow a **default-deny** model. Only documented clinical, administrative and backup traffic should be permitted.

Important restrictions include:

* Guest devices must not access internal networks.
* Clinical workstations must not directly manage medical devices.
* Medical devices must not access the internet unless specifically required.
* Only the Management Zone may administer servers.
* Only approved servers may reach the Backup Zone.

## 5.2 Kill Chain Disruption

In the ransomware kill chain, segmentation may not prevent the initial phishing email or stolen credential. However, it disrupts:

* network discovery
* lateral movement
* access to administrative systems
* ransomware deployment across multiple zones
* destruction of connected backups

The architecture is estimated to strongly disrupt **four of the five main kill chains**, or approximately **80%**, by limiting attacker movement and impact.

---

# 6. Policy Foundation

## 6.1 Acceptable Use Policy

The MedDefense AUP establishes enforceable rules for:

* authorized use of systems
* individual user accounts
* password and MFA responsibilities
* personal devices
* USB and removable media
* shadow IT
* patient and financial data handling
* incident reporting
* system monitoring
* policy exceptions and disciplinary action

The policy prohibits shared credentials, unauthorized software, personal cloud storage, unapproved USB devices and attempts to bypass security controls.

## 6.2 Policy Roadmap

| Policy                                    | Target Completion |
| ----------------------------------------- | ----------------- |
| Acceptable Use Policy                     | Month 1           |
| Access Control and Authentication Policy  | Month 1           |
| Vulnerability and Patch Management Policy | Month 2           |
| Incident Response Policy                  | Month 2           |
| Backup and Recovery Policy                | Month 2           |
| Data Classification and Handling Policy   | Month 3           |
| Remote Access Policy                      | Month 3           |
| Third-Party Risk Management Policy        | Month 4           |
| Medical Device Security Policy            | Month 4           |
| Business Continuity Policy                | Month 5           |

All policies should include ownership, scope, enforcement, exception handling and annual review requirements.

---

# 7. Residual Risk Assessment

## 7.1 Red-Team Findings

Even after the funded controls are implemented, phishing-led ransomware remains possible. An attacker may:

1. Target a billing or clinical employee.
2. Steal a session token or convince the user to approve MFA.
3. Use permitted application access to collect information.
4. Operate outside normal working hours.
5. Encrypt accessible information or threaten publication.

Segmentation and EDR would reduce the attack’s reach, but the lack of 24/7 monitoring could delay investigation.

Negligent insiders also remain a significant risk because legitimate users may email data incorrectly, use unauthorized cloud services or photograph clinical information with personal devices.

## 7.2 Accepted Risks

### Windows XP MRI Workstation

The risk is accepted temporarily because immediate replacement may affect a $2.1 million scanner lease. The workstation must be isolated, denied internet access, strictly monitored and replaced when the lease ends.

### Lack of 24/7 Human Monitoring

The outsourced SOC is deferred because its $110,000 annual cost would consume nearly the full first-year budget. Wazuh, daily log reviews and an on-call escalation process will act as compensating measures.

### Medical-Device Residual Risk

The full monitoring platform is not financially justified. MedDefense accepts the remaining risk after VLAN isolation, password changes, traffic restrictions and Wazuh monitoring.

## 7.3 Year 2 Priorities

The highest priority for Year 2 is an **outsourced managed SOC or equivalent 24/7 monitoring service**.

Additional priorities are:

1. Replace the unsupported MRI workstation.
2. Expand DLP and removable-media controls.
3. Improve medical-device monitoring.
4. Conduct external penetration testing.
5. Expand security-awareness exercises.
6. Perform an ISO 27001 readiness assessment.

---

# 8. Implementation Roadmap

## Phase 1 — Months 1–2: Quick Wins and Preparation

### Activities

* Approve governance roles and the AUP.
* Enable MFA for VPN and administrator accounts.
* Remove dormant, shared and default accounts.
* Patch critical systems and reduce exposed services.
* Test backups and create an offline copy.
* Complete asset, software and account inventories.
* Finalize network diagrams and segmentation rules.
* Procure the firewall, EDR and backup services.

### Dependencies

Inventories and network diagrams must be completed before reliable segmentation, patching and monitoring can be implemented.

### Success Metrics

* 100% of VPN and administrator accounts protected by MFA.
* 100% of default medical-device passwords changed.
* No Critical vulnerability open for more than 14 days.
* Successful restoration of one EHR and one billing backup.
* AUP approved and acknowledged by employees.

## Phase 2 — Months 3–4: Core Control Deployment

### Activities

* Create network VLANs and firewall rules.
* Deploy the Westside managed firewall.
* Install EDR on endpoints and servers.
* Deploy Wazuh and connect critical log sources.
* Configure encrypted offsite backup replication.
* Isolate the MRI workstation and medical devices.
* Create incident-response procedures.

### Dependencies

* Network segmentation must exist before full medical-device isolation.
* Log sources and storage must exist before Wazuh alerting.
* Automated backups must exist before offsite replication and recovery testing.

### Success Metrics

* Critical assets assigned to the correct network zone.
* Guest systems have no access to internal networks.
* At least 95% of managed endpoints report to EDR.
* Firewall, AD, EHR and billing logs report to Wazuh.
* Offsite backup replication completes successfully.
* Critical alerts have assigned owners and escalation times.

## Phase 3 — Months 5–6: Validation and Optimization

### Activities

* Test firewall rules and segmentation.
* Conduct a ransomware tabletop exercise.
* Perform vulnerability rescanning.
* Test recovery from immutable backups.
* Review access to EHR, PACS and administrative systems.
* Update the NIST Current and Target Profiles.
* Review the Risk Register and residual risks.
* Present results to the Board.

### Success Metrics

* At least 90% of IG1 safeguards implemented or formally planned.
* Critical security alerts reviewed within the defined response time.
* Successful recovery of critical data within approved objectives.
* No active shared PACS accounts.
* All High and Critical risks have an owner and treatment plan.
* Measurable movement from Partial to Managed across all six NIST functions.

---

# 9. Next Steps

Project 1x04, **Cryptographic Foundation**, should build on this strategy by defining how MedDefense protects information through encryption and key management. Priority areas include encryption of EHR and backup data, secure DICOM communication, VPN cryptography, certificate management, password storage and protection of administrative credentials.

The next stage is implementation. Each funded control should become a tracked project with an owner, deadline, acceptance criteria and evidence of completion. Technical deployment must be supported by approved policies, staff training, testing and risk-register updates.

The strategy is complete only when the controls are operational, measured and reviewed. MedDefense should therefore move from:

```text
Assessment
    ↓
Risk prioritization
    ↓
Control funding
    ↓
Implementation
    ↓
Testing
    ↓
Continuous improvement
```

The Board should approve the $120,000 allocation, the six-month roadmap and the documented temporary risk acceptances. Progress should be reported monthly to management and quarterly to the Board.

