# STRIDE Across the MedDefense Architecture

**Severity:** C = Critical, H = High, M = Medium, L = Low

## System 1: PACS / Medical Imaging

**Architecture Notes:**
The imaging environment includes `pacs-srv-01` on Windows Server 2016, Radiology workstations and the Siemens MRI workstation running Windows XP. Staff use the shared `raduser/radiology1` account. The systems operate on the flat `10.10.0.0/16` network, and PACS data is not included in the nightly backup.

| STRIDE | Threat                                                                                                                                           | Impact                                                                                 | Severity |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | -------- |
| **S**  | An attacker or unauthorized employee uses the shared `raduser` account and appears to be a legitimate Radiology technician.                      | Unauthorized access to patient images cannot be connected to a specific person.        | H        |
| **T**  | Malware on the Windows XP MRI workstation modifies images or patient metadata before they reach `pacs-srv-01`.                                   | Clinicians may make diagnostic decisions using altered or incorrect images.            | C        |
| **R**  | A technician accesses or exports patient images and later denies doing so because multiple people use the same account.                          | MedDefense cannot establish individual accountability during a privacy investigation.  | H        |
| **I**  | A compromised workstation uses the flat network to access PACS services and copy unencrypted medical images.                                     | Patient images and identifying information are exposed.                                | H        |
| **D**  | Ransomware encrypts `pacs-srv-01` or disables the MRI workstation. PACS is not included in the normal backup system.                             | Imaging and diagnosis are delayed, and some historical images may be permanently lost. | C        |
| **E**  | An attacker exploits Windows XP or an exposed imaging service to gain administrative access and move from Radiology into other internal systems. | A legacy clinical workstation becomes a path toward servers and Active Directory.      | H        |

**Top Threat:** **Tampering** is the most dangerous threat because modified images may still appear valid. A clinician could unknowingly use false information when diagnosing or treating a patient.

---

## System 2: Active Directory

**Architecture Notes:**
`ad-dc-01` and `ad-dc-02` run Windows Server 2019 and control authentication for users, workstations and services. Active Directory uses an eight-character minimum password policy, but administrative accounts have no MFA. Both domain controllers are reachable from other devices through the flat network. AD logs exist locally but are not centrally monitored. Only `ad-dc-01` is included in the nightly backup.

| STRIDE | Threat                                                                                                        | Impact                                                                                    | Severity |
| ------ | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------- |
| **S**  | An attacker uses stolen administrator credentials to authenticate as a legitimate domain administrator.       | The attacker appears trusted and can access systems across the organization.              | C        |
| **T**  | A compromised administrator changes Group Policy, account permissions or security settings.                   | Malware can be deployed to many computers, and security controls can be disabled.         | C        |
| **R**  | An attacker creates accounts or changes permissions and then clears local Windows event logs.                 | MedDefense may be unable to identify who made the changes or reconstruct the incident.    | H        |
| **I**  | An attacker extracts password hashes, Kerberos tickets or the Active Directory database.                      | Credentials for employees, administrators and service accounts may be exposed.            | C        |
| **D**  | Ransomware encrypts both domain controllers or damages Active Directory services.                             | Staff may be unable to log in to workstations, clinical applications or network services. | C        |
| **E**  | An attacker compromises a normal workstation account, steals privileged credentials and becomes Domain Admin. | The attacker gains control over nearly every Windows system and account.                  | C        |

**Top Threat:** **Elevation of Privilege** is the most dangerous threat. Domain Admin access would allow an attacker to control identities, disable defenses, distribute ransomware and reach nearly every critical asset.

---

## System 3: Network Infrastructure

**Architecture Notes:**
The FortiGate 100F is MedDefense’s main perimeter defense and connects the internet, DMZ, Central network and site-to-site VPNs. The core switch has no VLAN segmentation. Westside uses a consumer Netgear router, while the Westside and HQ VPN rules allow all services toward the Central server subnet. Firewall logs are stored locally with no SIEM or automated alerting.

| STRIDE | Threat                                                                                                                                                    | Impact                                                                                      | Severity |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------- |
| **S**  | An attacker uses stolen VPN or firewall administrator credentials to appear as an authorized employee or network technician.                              | The attacker gains trusted access to the internal network without MFA.                      | C        |
| **T**  | An attacker changes firewall rules, VPN policies or switch configurations to create hidden access paths.                                                  | Security boundaries are weakened, and malicious traffic may be redirected or permitted.     | C        |
| **R**  | A privileged user makes unauthorized configuration changes and denies responsibility because there is no formal change management or centralized logging. | MedDefense cannot reliably prove who changed the network or when it occurred.               | H        |
| **I**  | A compromised Westside router or core network device captures or redirects traffic passing between users and servers.                                     | Credentials, patient information and administrative traffic may be exposed.                 | H        |
| **D**  | A DDoS attack, firewall failure or malicious configuration makes the FortiGate or VPN tunnels unavailable.                                                | Patient portal, remote access and communication between MedDefense locations may stop.      | C        |
| **E**  | An attacker exploits the FortiGate or Westside router and gains network-administrator access.                                                             | The attacker can enter the server subnet and reach EHR, PACS, backups and Active Directory. | C        |

**Top Threat:** **Elevation of Privilege** is the most dangerous threat because the FortiGate is the only major perimeter control. Administrative control of the firewall or VPN would give an attacker broad access to the flat internal network.

