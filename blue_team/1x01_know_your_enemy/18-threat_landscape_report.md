# MedDefense Health Systems

## Threat Landscape Report

**Prepared for:** Board of Directors and Security Leadership
**Report date:** 14 July 2026
**Classification:** Internal
**Companion document:** Project 1x00 — Security Posture Assessment

---

# 1. Executive Summary

MedDefense operates in a healthcare threat environment where ransomware, credential theft, insider misuse and automated exploitation are common. The organization is especially exposed because critical clinical systems, user workstations, medical devices and backups are connected through a flat network with limited monitoring and no multi-factor authentication.

The single most dangerous threat is a **BlackReef-style ransomware campaign**. An attacker could enter through the FortiGate VPN, phishing or stolen credentials, move across the flat network, compromise Active Directory, steal patient data, delete accessible backups and encrypt clinical systems. Healthcare accounted for 25% of reported ransomware incidents across critical infrastructure in the intelligence dossier, and 73% of healthcare ransomware incidents included data theft before encryption.

The three highest-priority recommendations are:

1. **Segment the network** so workstations, servers, medical devices, backups, remote users and vendors can reach only the systems they require.
2. **Deploy centralized monitoring and endpoint detection** so MedDefense can identify credential theft, internal scanning, unusual EHR access, data transfers and backup deletion before operational impact occurs.
3. **Require MFA** for VPN, administrative, vendor, cloud and EHR access to reduce the risk from stolen passwords.

MedDefense should also isolate its backups, patch public-facing systems rapidly and improve controls over USB devices, vendor access and employee offboarding. These actions are necessary because the current weaknesses do not exist independently. They combine into complete and realistic attack paths.

---

# 2. Scope and Methodology

## 2.1 Scope

This report evaluates threats to MedDefense Health Systems across:

* MedDefense Central Hospital
* Westside Clinic
* Corporate HQ
* Internet-facing systems
* Internal servers and workstations
* Medical IoT devices
* Cloud services
* Employees, contractors and vendors

The assessment focuses on MedDefense’s most important assets:

* EHR application and database
* Active Directory
* PACS and medical imaging
* Medical IoT and clinical devices
* Network and VPN infrastructure
* Billing systems
* Backup infrastructure

MedDefense operates a 350-bed central hospital, an outpatient clinic and a corporate office, with approximately 2,000 employees. Its infrastructure includes `ehr-srv-01`, `ehr-db-01`, `pacs-srv-01`, two domain controllers, medical devices, the FortiGate perimeter firewall and site-to-site VPN connections.

## 2.2 Intelligence Sources

The following sources were used:

* CISA healthcare ransomware advisory extracts
* HC3 healthcare threat actor analysis
* HHS healthcare breach statistics
* A comparable regional hospital ransomware case
* Healthcare ransomware economic analysis
* BlackReef Ransomware-as-a-Service profile
* MedDefense onboarding documentation
* Asset Registry and Data Map
* Network Scan Summary
* Security Control Matrix and source artifacts
* First Watch Gap Analysis
* Internal incident and vendor records

The intelligence dossier provided sector statistics, actor behavior and healthcare-specific targeting logic. The BlackReef profile provided a realistic ransomware lifecycle and observable pre-encryption indicators.

## 2.3 Analytical Frameworks

The report applies:

* **Threat actor profiling** to assess motivation, capability and likely behavior
* **Attack surface analysis** across external, internal and human dimensions
* **Vector-to-asset mapping** to identify which attack methods can reach critical assets
* **Kill chain analysis** to trace attacks from initial entry to business impact
* **MITRE ATT&CK** to map attacker actions to standard tactics and techniques
* **STRIDE** to identify spoofing, tampering, repudiation, information disclosure, denial of service and elevation-of-privilege threats
* **Gap-threat correlation** to update the priorities from the internal posture assessment

## 2.4 Connection to the Security Posture Assessment

The Security Posture Assessment identified MedDefense’s internal weaknesses. This report evaluates who is likely to exploit those weaknesses, how they would do so and what the resulting impact would be.

For example, the posture assessment identified the flat network as **M-01: Critical**. Threat analysis shows that this gap appears in every major ransomware, insider, vendor and opportunistic attack path. The internal posture and external threat landscape therefore support the same conclusion: network segmentation is the most important structural improvement for MedDefense.

## 2.5 Limitations

This report is based on the provided intelligence collection and MedDefense artifacts. It is not a live threat intelligence feed or a vulnerability scan. Technical weaknesses and software versions should be validated during Project 1x02.

---

# 3. Healthcare Sector Threat Overview

## 3.1 Why Healthcare Is Targeted

### Clinical urgency

Hospitals cannot tolerate long system outages. Loss of EHR, imaging, communication or medication systems can delay procedures, force ambulance diversions and create patient-safety risks.

Ransomware groups understand this pressure. They expect hospital leaders to consider payment when system availability affects clinical care.

### Valuable patient information

Healthcare records contain:

* Names and addresses
* Dates of birth
* Government identifiers
* Insurance details
* Diagnoses and medical histories
* Prescription information

This data can support identity theft, insurance fraud and prescription fraud. It also cannot be cancelled as quickly as a stolen payment card.

### Legacy and specialized technology

Healthcare organizations often depend on older operating systems and medical devices that are difficult to patch or replace. MedDefense’s environment includes a Windows XP MRI workstation, Windows Server 2012 R2 and medical devices with accessible web interfaces.

These systems provide attackers with weaker entry points and internal footholds.

### Limited security capacity

Regional hospitals may operate hundreds of systems and clinical devices with a small security team. MedDefense has a 12-person IT department but only one dedicated security analyst position under an acting security leader.

### Regulatory and reputational pressure

Stolen patient information creates reporting, legal and reputational consequences even when systems can be restored. Double extortion uses this pressure by combining encryption with a threat to publish patient data.

## 3.2 Sector Statistics

The intelligence dossier reports that:

* Healthcare accounted for **25% of reported ransomware incidents** across 16 critical infrastructure sectors.
* Data was stolen before encryption in **73% of healthcare ransomware incidents**.
* Initial access was linked to public-facing applications in **38%**, phishing in **31%**, valid credentials in **22%** and remote services in **9%**.
* Average hospital downtime after ransomware was **18 days**.
* Hacking and IT incidents represented **78%** of reported large healthcare breaches.
* Network servers were involved in **43%** of reported breaches, while electronic medical records were involved in **16%**.

These figures are directly relevant to MedDefense because it has internet-facing services, no MFA, exposed internal databases, weak monitoring and critical data stored on network servers.

## 3.3 Current Trends

### Double extortion is becoming normal

Attackers increasingly steal information before encryption. A hospital may therefore face a reportable breach even if it can restore its systems without paying.

### Attacks are industrialized

Ransomware is no longer performed only by one technical group. Developers create ransomware, Initial Access Brokers sell access, affiliates conduct attacks and negotiators manage payment demands.

BlackReef affiliates can buy hospital VPN access for approximately $3,000–$8,000, then keep 70–80% of the ransom payment.

### Valid credentials are increasingly important

Attackers use phishing, password reuse, credential stuffing and access brokers to obtain legitimate accounts. Without MFA, these logins may appear normal.

### Low-skill attacks are becoming more effective

Automated scanners and AI-assisted phishing reduce the skills required to attack exposed systems. The previous crypto-miner on `billing-srv-01` demonstrates that MedDefense is already visible to opportunistic attackers.

### Vendors are part of the attack surface

Cloud providers, EHR support companies, endpoint vendors, medical-device manufacturers and building managers all have some form of trusted access. A compromise of these organizations can bypass MedDefense’s perimeter.

---

# 4. MedDefense Threat Actor Profiles

## 4.1 Threat Actor Ranking

| Priority | Actor Type                           | Likelihood | Capability                    | Main Motivation                                  |
| -------: | ------------------------------------ | ---------- | ----------------------------- | ------------------------------------------------ |
|        1 | Ransomware groups / organized crime  | Critical   | Medium to High                | Financial gain and blackmail                     |
|        2 | Negligent insiders                   | High       | Low                           | Convenience, mistakes or poor security awareness |
|        3 | Unskilled or opportunistic attackers | High       | Low                           | Financial gain, curiosity or resource theft      |
|        4 | Malicious insiders                   | Medium     | Medium through trusted access | Financial gain, revenge, curiosity or sabotage   |
|        5 | Hacktivists                          | Low        | Low to Medium                 | Political or philosophical beliefs               |
|        6 | Nation-state APT actors              | Low        | Very High                     | Espionage and strategic intelligence             |

The dossier independently reached a similar order: ransomware first, negligent insiders second, opportunistic attackers third, malicious insiders fourth, hacktivists fifth and nation-state actors sixth.

## 4.2 Priority 1: Ransomware Groups

Ransomware groups represent the highest combined likelihood and impact.

MedDefense fits their preferred target profile:

* Regional hospital
* 350 beds
* Approximately 2,000 staff
* Valuable regulated patient data
* Limited security staffing
* Legacy technology
* Weak monitoring
* Accessible backup infrastructure

BlackReef’s typical attack begins through a VPN exploit, phishing or purchased credentials. Affiliates then map the network, steal administrative credentials, exfiltrate data, destroy backups and deploy ransomware through Active Directory.

A comparable 280-bed hospital was compromised through an unpatched VPN, after which attackers crossed a flat network, reached the Domain Controller, stole 42 GB of data and encrypted 23 servers and approximately 400 workstations. The incident caused 11 days of downtime and approximately $5 million in recovery and lost revenue.

## 4.3 Priority 2: Negligent Insiders

Negligent insiders do not intend to cause harm, but their actions can expose patient data or create an entry point for an external attacker.

Relevant MedDefense examples include:

* Shared Radiology credentials
* Personal NAS devices
* Unmanaged physician iPads
* Unrestricted USB storage
* Passwords stored in files or scripts
* Delayed account offboarding
* Employees responding to false IT requests

Clinical staff need broad and rapid access to patient information. This makes healthcare workflows difficult to secure using restrictions alone.

Training completion is only 71% at Central and 58% at Westside. No phishing simulations, role-specific training or digital PHI handling training have been conducted.

## 4.4 Priority 3: Opportunistic Attackers

Opportunistic attackers use automated scanners and public tools. They target vulnerable services rather than specific organizations.

MedDefense is highly exposed because:

* `billing-srv-01` runs Ubuntu 18.04 and Apache 2.4.29.
* A crypto-miner was already installed on the billing server.
* The Windows XP MRI workstation is unsupported.
* The print server runs unsupported Windows Server 2012 R2.
* Medical-device interfaces are reachable internally.
* Unknown Linux devices are present on the network.

The network scan confirmed that these systems are reachable within the same flat environment.

## 4.5 Malicious Insiders

A malicious insider may steal data, access high-profile patient records, create hidden accounts or sabotage systems.

MedDefense has no DLP, USB restrictions or continuous EHR behavioral monitoring. Shared credentials and delayed offboarding further reduce accountability.

Likelihood is Medium, but impact can be High because the attacker begins with legitimate access and knowledge of internal processes.

## 4.6 Hacktivists

Hacktivists are currently Low likelihood because MedDefense has no major political or public controversy.

Likely techniques include:

* DDoS
* Website defacement
* Data leaks
* Public portal attacks
* Brand impersonation

The risk would increase following a controversial policy, public data breach or geopolitical event.

## 4.7 Nation-State APT Actors

Nation-state actors have very high capability but Low likelihood for MedDefense because the organization has no clinical research or pharmaceutical program.

The risk would increase significantly if MedDefense started clinical trials, stored proprietary research or connected to high-value research institutions.

---

# 5. Attack Surface Analysis

## 5.1 External Surface

| Exposure                          | Asset                               | Current Protection                     | Main Weakness                                                                   |
| --------------------------------- | ----------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------- |
| Public website and patient portal | `web-srv-01`                        | FortiGate, DMZ, HTTPS                  | TLS 1.0 remains enabled; no MFA on portal administration; no central monitoring |
| VPN                               | FortiGate 100F and internal network | Firewall authentication and local logs | No MFA; patching risk; broad internal reach                                     |
| Microsoft 365                     | Email, SharePoint and OneDrive      | Microsoft cloud controls               | No MFA; no independent backup; phishing and BEC exposure                        |
| Westside VPN                      | Westside and Central systems        | IPSec tunnel                           | Consumer router and broad server access                                         |
| HQ VPN                            | Corporate HQ and Central systems    | Building VLAN and encrypted tunnel     | Landlord-managed infrastructure and permissive access                           |
| Billing web service               | `billing-srv-01`                    | FortiGate perimeter                    | Old Apache and Ubuntu; confirmed previous compromise                            |
| DNS and domains                   | Public web and email identity       | Basic DNS service                      | Registrar security and typo-domain monitoring are undocumented                  |

The firewall does include a default deny rule, but the Westside and HQ VPN rules allow all services toward the internal server subnet. Outbound access is also unrestricted.

## 5.2 Internal Surface

The internal surface presents the greatest structural risk.

The scan confirmed that all subnets were reachable from Sarah Park’s HQ workstation. There are no VLANs or internal firewalls between workstations, servers and medical devices.

Important exposures include:

* MySQL port 3306 on `billing-srv-01`, reachable network-wide
* PostgreSQL port 5432 on `ehr-db-01`, reachable network-wide
* RDP port 3389 on reception and administrative workstations
* NAS management ports 5000/5001, reachable network-wide
* PACS ports 4242 and 11112
* Active Directory services including Kerberos, LDAP and SMB
* Medical-device management pages on ports 80 and 443
* Windows XP MRI workstation with SMB and RPC services
* Windows Server 2012 R2 print server
* Unknown Linux devices inside Central and Westside

A compromise of one workstation, vendor connection or unmanaged device can therefore become a route to critical assets.

## 5.3 Human Surface

### Clinical staff

Clinical staff can access EHR, PACS, medication and monitoring systems. They work under time pressure and may respond to urgent phishing, vishing or impersonation attempts.

Risk is increased by low training completion and the absence of healthcare-specific exercises.

### Reception and administrative employees

Reception staff are the first contact for phone calls and visitors. They can be targeted through vishing, pretexting, impersonation and physical tailgating.

### IT staff

IT administrators have access to servers, backups, Active Directory, VPNs and network controls. A successful spearphishing attack against one administrator can have organization-wide impact.

The small team and heavy workload increase the risk of shortcuts, excessive permissions and unreviewed changes.

### Executives and finance staff

Executives and finance employees are attractive targets for BEC, confidential data theft and fraudulent payment instructions.

### Vendors and contractors

Vendor access may be trusted but is partly outside MedDefense’s control. MedTech Solutions, Microsoft, Sophos, Siemens and Greenfield all create different supply-chain pathways.

---

# 6. Critical Attack Paths

## 6.1 Kill Chain Summary

| Kill Chain                       | Sequence                                                                                                                    | Main Target                                     | Key Break Points                                                             |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------- |
| 1. VPN to ransomware             | VPN exploit → persistence → network discovery → credential theft → Domain Admin → data theft → backup deletion → encryption | Active Directory, EHR and backups               | Patch VPN; MFA; segmentation; SIEM/EDR; immutable backups                    |
| 2. Phishing to domain compromise | Phishing → malicious workstation execution → credential dumping → AD compromise → EHR theft and encryption                  | EHR and Active Directory                        | Email filtering; training; MFA; EDR; segmentation                            |
| 3. Public server to medical IoT  | Apache exploit → server foothold → internal scanning → default device credentials → device compromise                       | Infusion pumps, monitors and nurse call systems | Server patching; server EDR; IoT VLAN; unique credentials                    |
| 4. Shadow IT to EHR exposure     | Unauthorized device → external compromise → internal scanning → stolen account → EHR data theft                             | EHR and patient records                         | Network Access Control; MDM; segmentation; DLP                               |
| 5. Vendor to EHR compromise      | MedTech account theft → trusted maintenance session → persistence → database access → data theft or tampering               | EHR application and database                    | Vendor MFA; jump host; time-limited access; session recording; database ACLs |

## 6.2 Most Connected Assets

### PACS and medical imaging

PACS was reachable through all eight vectors assessed in the Vector-to-Asset Matrix. Shared credentials, the Windows XP MRI workstation, physical access and the flat network create several possible routes.

### Medical IoT

Medical IoT was also reachable through all eight assessed vectors. Accessible web interfaces, possible default credentials and no isolation make these devices easy to reach after an internal compromise.

### EHR

The EHR was reachable through seven of the eight assessed vectors. It is the most important target because it combines high-value patient information with direct clinical dependence.

## 6.3 Most Versatile Vectors

### VPN exploitation

A successful VPN compromise provides an external attacker with an internal position and access to nearly all critical systems.

### Phishing and spearphishing

Phishing can target clinical, administrative, financial or IT users. The absence of MFA makes stolen credentials more useful.

### Supply-chain compromise

Vendor access can bypass normal assumptions about untrusted external traffic. A compromised EHR, endpoint or network vendor may enter through approved channels.

## 6.4 Overall Break-Point Assessment

The controls that interrupt the greatest number of attack paths are:

* MFA
* Network segmentation
* SIEM and EDR
* Immutable backups
* Rapid public-facing patch management
* DLP and removable-device controls
* Controlled vendor access

BlackReef’s own defensive recommendations identify the same priorities: critical patching, segmentation, MFA, backup isolation, EDR/SIEM, incident response and least privilege.

---

# 7. STRIDE Analysis Summary

## 7.1 EHR System

The EHR analysis identified 12 threats across all six STRIDE categories.

### Spoofing

* Stolen clinician credentials
* Compromised MedTech vendor identity

### Tampering

* Unauthorized changes to medication, allergy or diagnosis records
* Modification of the EHR application or database

### Repudiation

* Employees denying unauthorized patient access
* Administrators clearing local evidence

### Information Disclosure

* Direct access to PostgreSQL from a compromised internal device
* Patient data copied to USB, cloud storage or unmanaged devices

### Denial of Service

* Ransomware encryption
* Application or database resource exhaustion

### Elevation of Privilege

* Clinical workstation compromise leading to administrator access
* EHR application exploitation leading to server or database control

**The greatest EHR STRIDE risk is Tampering.** A modified medical record may remain available and appear legitimate. Incorrect allergy, medication or diagnosis information could therefore lead to an unsafe clinical decision.

## 7.2 PACS and Medical Imaging

The most dangerous PACS threat is also **Tampering**. Malware on the unsupported MRI workstation could alter images or metadata before clinicians use them.

Other major risks include:

* Shared-account spoofing
* Lack of user accountability
* Image disclosure
* Ransomware or imaging outage
* Exploitation of Windows XP

## 7.3 Active Directory

The most dangerous Active Directory threat is **Elevation of Privilege**.

Domain Admin access would allow an attacker to:

* Create or modify accounts
* Change Group Policy
* Disable controls
* Access other servers
* Deploy ransomware
* Hide activity

Because Active Directory controls authentication across the organization, its compromise can turn one account takeover into an enterprise incident.

## 7.4 Network Infrastructure

The main network threat is also **Elevation of Privilege**.

Administrative control of the FortiGate, core network or VPN would allow an attacker to change routes and firewall rules, create persistent access and reach critical systems.

The danger is increased because the FortiGate is MedDefense’s main perimeter control and there is no internal segmentation behind it.

---

# 8. Threat Scenarios

## 8.1 Scenario 1: BlackReef Ransomware Campaign

A BlackReef affiliate exploits the FortiGate or uses stolen VPN credentials. The affiliate enters the flat network, identifies the domain controllers and EHR, steals Domain Admin credentials, exports patient data, deletes backups and deploys ransomware through Group Policy.

### Business Impact

* EHR and workstation outage
* Ambulance diversion
* Cancelled procedures
* Patient-data breach
* Ransom and recovery costs
* Regulatory investigation
* Public loss of confidence

### Main Gaps

* M-01: Network Segmentation
* M-02: Backup Isolation
* M-04: Monitoring and Detection
* M-05: No MFA
* Unnumbered patch-management weakness

## 8.2 Scenario 2: Malicious Insider Data Theft

A billing employee uses legitimate EHR and billing access to export patient records. The data is copied to a USB drive. Before leaving MedDefense, the employee also copies database credentials from a configuration file. Delayed offboarding leaves the VPN account active, allowing further access after employment ends.

### Business Impact

* Exposure of medical and insurance data
* Patient notification
* Regulatory investigation
* Legal expenses
* Reputational damage

### Main Gaps

* M-04: Monitoring and Detection
* M-05: No MFA
* No DLP
* No USB restriction
* Delayed manual offboarding
* Excessive export permissions

## 8.3 Scenario 3: MedTech Supply-Chain Compromise

An attacker steals a MedTech technician’s credentials and uses the trusted maintenance pathway to reach `ehr-srv-01`. The attacker creates persistence, accesses the EHR database, exports patient data and modifies the application or logs.

### Business Impact

* EHR data theft
* Possible medical-record tampering
* Clinical loss of confidence in EHR accuracy
* Vendor and regulatory investigation
* Extortion or ransomware
* Damage to MedDefense and MedTech reputation

### Main Gaps

* M-01: Network Segmentation
* M-04: Monitoring and Detection
* M-05: No MFA
* Weak third-party session controls
* No DLP
* Excessive vendor or service-account permissions

---

# 9. Gap-Threat Correlation

## 9.1 Updated Gap Priorities

| Rank | Gap                                 | Original Risk | Threat-Informed Risk | Change    |
| ---: | ----------------------------------- | ------------- | -------------------- | --------- |
|    1 | M-01 — Network Segmentation         | Critical      | Critical             | No change |
|    2 | M-04 — Monitoring and Detection     | High          | Critical             | Upgraded  |
|    3 | M-05 — No MFA                       | High          | Critical             | Upgraded  |
|    4 | M-02 — Backup Isolation             | Critical      | Critical             | No change |
|    5 | M-03 — Medical IoT Exposure         | High          | Critical             | Upgraded  |
|    6 | M-06 — Westside Security            | High          | High                 | No change |
|    7 | M-07 — Shared Radiology Credentials | Medium        | High                 | Upgraded  |
|    8 | M-08 — Print Server End of Life     | Low           | Low                  | No change |

The original findings and ratings are documented in the First Watch Gap Analysis.

## 9.2 The Critical Three

### M-01 — Network Segmentation

M-01 appears in all five critical kill chains and all three major scenarios. It allows a compromise of one user, workstation, vendor or server to become an organization-wide event.

### M-04 — Monitoring and Detection

M-04 also appears across all critical paths. Without monitoring, MedDefense may not identify an attack during initial access, discovery, credential theft, collection, exfiltration or backup deletion.

The crypto-miner on `billing-srv-01` operated for at least two weeks before performance problems revealed it.

### M-05 — No MFA

M-05 allows stolen employee, administrator and vendor credentials to provide direct access. It is especially important for VPN, EHR, cloud and privileged accounts.

## 9.3 The Surprise

**M-07 — Shared Radiology Credentials** was originally Medium but should be treated as High.

The original assessment reduced the rating because PACS access was considered on-site. Threat analysis showed that the shared account can still be used by:

* Malicious employees
* Unattended workstation users
* Physical intruders
* Attackers who compromise the MRI workstation
* Attackers who obtain the shared password

The account also prevents MedDefense from proving who accessed or changed medical images. This creates both privacy and clinical integrity risks.

M-03 also increased from High to Critical because compromise of medical devices could affect patient monitoring or medication delivery, not only information security.

---

# 10. Prioritized Recommendations

## 10.1 Top Five Threats

| Rank | Threat                                    | Likelihood | Impact   | Key Gap              | Recommended Action                                                                                 |
| ---: | ----------------------------------------- | ---------- | -------- | -------------------- | -------------------------------------------------------------------------------------------------- |
|    1 | Ransomware with data theft and encryption | Critical   | Critical | M-01                 | Segment user, server, IoT, backup, VPN and vendor zones — **Long-term**                            |
|    2 | Negligent insider exposure                | High       | High     | DLP/USB gap          | Block unapproved USB storage and deploy DLP to high-risk departments — **Short-term**              |
|    3 | Opportunistic exploitation                | High       | High     | Patch-management gap | Patch or replace exposed and unsupported systems; set a 48-hour critical-patch SLA — **Quick Win** |
|    4 | Vendor-based EHR compromise               | Medium     | Critical | M-05                 | Require vendor MFA, jump-host access, approval and session recording — **Short-term**              |
|    5 | Malicious insider data theft              | Medium     | High     | M-04                 | Monitor EHR exports, VPN activity and privileged-account use — **Short-term**                      |

## 10.2 Recommended Action Plan

### Immediate: 0–30 days

* Enable MFA for VPN, administrative, cloud and vendor accounts.
* Patch or replace `billing-srv-01`.
* Review FortiGate firmware and exposed management services.
* Disable unused accounts and complete an access review.
* Restrict vendor access to named accounts.
* Create alerts for backup deletion and unusual VPN logins.
* Begin sending FortiGate, Active Directory and EHR events to a central log platform.

### Short term: 1–3 months

* Deploy SIEM and EDR to critical servers and administrator workstations.
* Implement immutable cloud or offline backup replication.
* Restrict USB storage and introduce DLP.
* Automate employee and contractor offboarding.
* Establish a critical-vulnerability patching SLA.
* Route vendor access through a controlled jump server.
* Start healthcare-specific phishing and BEC simulations.
* Create and test a ransomware incident-response plan.

### Long term: 3–12 months

* Segment the network into dedicated security zones.
* Isolate medical IoT and prevent unnecessary internet access.
* Restrict EHR database access to approved application servers.
* Replace unsupported Windows systems.
* Upgrade Westside to a managed firewall and secure network equipment.
* Replace shared PACS accounts with badge-based individual access.
* Perform full disaster-recovery exercises.
* Establish a formal third-party risk management program.

## 10.3 Strategic Two-Initiative Recommendation

If MedDefense can fund only two major initiatives next quarter, it should select:

### 1. Network Segmentation

Segmentation would reduce the impact of ransomware, compromised vendors, shadow IT, malicious insiders and opportunistic attackers. It prevents a single compromised device from reaching every critical system.

### 2. Centralized Detection and Response

A SIEM combined with EDR would allow MedDefense to detect unusual VPN activity, scheduled tasks, credential dumping, internal scans, EHR exports, large cloud uploads and backup deletion.

These initiatives address M-01 and M-04, the two gaps that appear in the greatest number of attack paths. MFA should still be enabled as an immediate operational action because the existing licensing may reduce cost and deployment time.

## 10.4 Connection to Project 1x02

Project 1x02 should convert the threat conclusions in this report into a technical vulnerability assessment.

The next phase should:

* Confirm the exact exposure and patch status of the FortiGate.
* Identify vulnerabilities on `billing-srv-01`, `web-srv-01` and other public-facing systems.
* Assess Apache 2.4.29 and Ubuntu 18.04.
* Test access controls on MySQL 3306 and PostgreSQL 5432.
* Review Active Directory permissions, service accounts and stored credentials.
* Assess the Windows XP MRI workstation and Windows Server 2012 R2.
* Validate medical-device firmware and default credentials.
* Test VPN, RDP and remote vendor access.
* Review web portal TLS and authentication.
* Verify backup permissions and immutability.
* Assess unknown network devices and unmanaged endpoints.

Vulnerability findings should not be prioritized only by CVSS. Priority should also consider:

* Whether the vulnerability is externally reachable
* Whether it is actively exploited
* Whether it appears in a critical kill chain
* Whether it provides access to Active Directory or EHR
* Whether the affected asset supports clinical care
* Whether compensating controls exist

---

# Conclusion

MedDefense’s threat landscape is defined by the interaction between common healthcare attackers and a small number of high-impact internal weaknesses.

Ransomware groups are the most immediate danger, but negligent insiders, opportunistic exploitation, malicious insiders and vendor compromise also represent realistic paths to patient data and clinical systems. The flat network, absence of centralized monitoring and lack of MFA allow these different threats to follow similar routes.

MedDefense does not need a separate defensive product for every possible attacker. It needs controls that interrupt several attack paths at once. Network segmentation, centralized monitoring, MFA, isolated backups and strong access governance provide the greatest reduction in overall risk.

---

# Evidence Register

1. **Marcus Webb Threat Intelligence Collection** — sector trends, actor categories, breach statistics and ransomware case evidence.
2. **BlackReef Threat Actor Profile** — RaaS structure, attack lifecycle, healthcare targeting and indicators.
3. **MedDefense Internal Documentation Package** — organization, systems, vendors and architecture.
4. **Network Scan Summary** — systems, ports, unsupported technology, flat network and medical-device exposure.
5. **Security Controls Source Artifacts** — firewall rules, password policy, endpoint protection, backups, training and logging.
6. **First Watch Gap Analysis** — M-01 through M-08 and unnumbered findings.

