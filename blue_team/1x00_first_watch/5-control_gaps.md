# The Missing Pieces

## G-001

**Gap Description:**
There is no centralized log management or SIEM. Logs remain on individual systems and are checked mainly when something breaks.

**Category x Function Missing:**
Technical Detective

**Affected Asset(s) or Zone:**
EHR, billing server, Active Directory, Linux servers, Windows servers, firewall and web server

**Risk if Unaddressed:**
Attackers may remain unnoticed after gaining access. This could lead to unauthorized data access, system changes and longer outages, affecting Confidentiality, Integrity and Availability.

**Evidence:**
The artifacts state that no centralized log management or automated security alerting exists. Local logs are stored separately and reviewed manually.

---

## G-002

**Gap Description:**
Sophos endpoint protection does not cover Windows servers, Linux servers, mobile devices or iPads.

**Category x Function Missing:**
Technical Preventive and Technical Detective

**Affected Asset(s) or Zone:**
EHR server, billing server, database server, web server, other Linux servers, Windows servers and physician iPads

**Risk if Unaddressed:**
Malware may execute on critical systems without being blocked or detected. This could expose sensitive information, change data or interrupt important services.

**Evidence:**
Sophos protects managed Windows workstations, but Windows servers, Linux servers and mobile devices are not covered.

---

## G-003

**Gap Description:**
There is no offsite, cloud or isolated backup copy. The backup NAS is in the same room, rack area and network as the production servers.

**Category x Function Missing:**
Technical Corrective

**Affected Asset(s) or Zone:**
EHR, billing, file shares, domain services, website and other backed-up Central systems

**Risk if Unaddressed:**
Ransomware, fire, flooding or physical damage could destroy both the production systems and the backups. MedDefense may be unable to restore critical services, causing a major Availability impact.

**Evidence:**
The backup configuration states that all backups are stored on a local NAS and that no offsite or cloud backup exists.

---

## G-004

**Gap Description:**
There is no tested disaster recovery process. Only one partial server restore was tested, and no full disaster recovery test has ever been completed.

**Category x Function Missing:**
Administrative Corrective

**Affected Asset(s) or Zone:**
All critical Central systems, including EHR, billing, Active Directory and file services

**Risk if Unaddressed:**
During a serious incident, staff may not know how to restore systems in the correct order or within an acceptable time. Critical services may remain unavailable for longer than expected.

**Evidence:**
The last test was a partial restore eight months ago, and a full disaster recovery test has never been performed.

---

## G-005

**Gap Description:**
VPN access from Westside and Corporate HQ allows all services to the server subnet instead of only the ports that are required.

**Category x Function Missing:**
Technical Preventive

**Affected Asset(s) or Zone:**
Central server subnet and all servers reachable through the VPN

**Risk if Unaddressed:**
If a device or router at Westside or HQ is compromised, an attacker may gain broad access to Central systems. This could lead to data exposure, unauthorized changes and service disruption.

**Evidence:**
Firewall rules 2 and 3 allow `ALL` services from both VPN connections, and Marcus identified the rules as too permissive.

---

## G-006

**Gap Description:**
There is no outbound traffic filtering. Internal systems can connect to any external destination and port.

**Category x Function Missing:**
Technical Preventive

**Affected Asset(s) or Zone:**
Internal network, servers and infected endpoints

**Risk if Unaddressed:**
Malware can communicate with command-and-control servers, mining pools or data-exfiltration destinations. This may affect Confidentiality, Integrity and Availability.

**Evidence:**
Firewall rule 4 permits all outbound services, and the notes state that this allowed the crypto-miner to communicate with mining pools.

---

## G-007

**Gap Description:**
There is no mandatory MFA for remote access or normal privileged access.

**Category x Function Missing:**
Technical Preventive

**Affected Asset(s) or Zone:**
Remote access, user accounts, administrative accounts and systems using Active Directory

**Risk if Unaddressed:**
A stolen or guessed password may be enough for an attacker to access MedDefense systems. This could expose confidential data or allow unauthorized changes.

**Evidence:**
The password policy says MFA is recommended for remote access but is not required.

---

## G-008

**Gap Description:**
Physical monitoring does not cover the server room, network closets or administrative wing.

**Category x Function Missing:**
Physical Detective

**Affected Asset(s) or Zone:**
Server room, network equipment, IT offices and security offices

**Risk if Unaddressed:**
Unauthorized physical access, equipment tampering or theft may not be detected or recorded. This could affect Confidentiality, Integrity and Availability.

**Evidence:**
The camera system covers only selected entrances and the parking garage. No cameras cover server-room areas, network closets or the administrative wing.

---

## G-009

**Gap Description:**
Security awareness training is incomplete and not healthcare-specific. Completion is low at Central and Westside.

**Category x Function Missing:**
Administrative Preventive

**Affected Asset(s) or Zone:**
Employees, patient data, email accounts, clinical systems and medical devices

**Risk if Unaddressed:**
Staff may fail to recognize phishing, mishandle protected health information or respond incorrectly to healthcare-specific security events. This may lead to data exposure or system compromise.

**Evidence:**
Completion is 71% at Central and 58% at Westside. The training does not cover digital PHI handling, medical-device security or role-specific risks.

---

## G-010

**Gap Description:**
There are no documented compensating controls for systems that cannot be fully protected, such as unsupported servers, uncovered Linux systems or medical devices.

**Category x Function Missing:**
Technical Compensating and Administrative Compensating

**Affected Asset(s) or Zone:**
Legacy systems, Linux servers, medical devices and systems without endpoint protection

**Risk if Unaddressed:**
Known weaknesses may remain exposed without alternative protection such as isolation, strict access control or extra monitoring. This increases the chance of unauthorized access, data changes or service outages.

**Evidence:**
The control matrix contains no compensating controls, while several systems are not covered by antivirus and some existing controls are incomplete.

---

## Overall Pattern

MedDefense is more **prevention-oriented** than detection-oriented. It has firewalls, password rules, antivirus on some workstations and basic physical access controls, but limited centralized monitoring, alerting and investigation capability.

If an attacker bypasses the preventive controls, MedDefense may not detect the incident quickly. This could allow the attacker to remain in the environment longer, access more data and cause greater damage before the organization responds.

