# MedDefense Vector-to-Asset Matrix

The matrix includes direct and indirect attack paths. Indirect paths are especially important because **M-01: Network Segmentation** confirms that one compromised device can communicate with nearly every other MedDefense system. The scan also shows network-wide access to databases, management interfaces, medical devices and domain controllers.

| Attack Vector                    | EHR System                                                                              | PACS and Imaging                                                                      | Billing System                                                                                   | Backup Infrastructure                                                                                | Network Core and VPN                                                                           | Medical IoT                                                                                   | Active Directory                                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Phishing / Spear Phishing**    | Phishing → clinician credentials → no MFA → access `ehr-srv-01` and patient records.    | Phishing → radiology technician account → PACS workstation → imaging records.         | Phishing → billing employee workstation → flat network → MySQL 3306 on `billing-srv-01`.         | Spear phishing IT staff → privileged credentials → NAS management ports 5000/5001 → backup deletion. | Spear phishing network administrator → stolen account → FortiGate or VPN configuration access. | Phishing → compromised clinical workstation → flat network → pump and monitor web interfaces. | Phishing → stolen administrator credentials → LDAP/SMB access → domain compromise.                          |
| **VPN Exploit**                  | FortiGate exploit → internal network → PostgreSQL 5432 → `ehr-db-01`.                   | FortiGate exploit → flat network → PACS ports 4242/11112 → imaging system.            | VPN exploit → internal access → MySQL 3306 → billing database.                                   | VPN exploit → internal reconnaissance → NAS-01 → backups encrypted or deleted.                       | FortiGate vulnerability → VPN appliance control → trusted access to internal networks.         | VPN exploit → flat network → medical-device ports 80/443 → pump or monitor access.            | VPN exploit → internal network → Kerberos, LDAP and SMB → domain controller attack.                         |
| **Default / Shared Credentials** |                                                                                         | Shared `raduser/radiology1` account → PACS access without individual accountability.  |                                                                                                  |                                                                                                      |                                                                                                | Default device credentials → medical-device web interface → configuration changes.            |                                                                                                             |
| **Vulnerable Software Exploit**  | Exploit vulnerable internal server → flat network → reach EHR application and database. | Exploit Windows XP MRI workstation → SMB movement → `pacs-srv-01`.                    | Apache 2.4.29 exploit → remote code execution directly on `billing-srv-01`.                      | Compromise `billing-srv-01` or another server → flat network → NAS management interface.             | Exploit unpatched FortiGate or Westside router → control a trusted network entry point.        | Exploit vulnerable BD Alaris firmware or web interface → access clinical devices.             | Exploit an old server or workstation → credential theft → attack `ad-dc-01` or `ad-dc-02`.                  |
| **Supply Chain Compromise**      | Compromised MedTech account → trusted maintenance access → `ehr-srv-01`.                | Compromised Siemens technician device or update → Windows XP MRI workstation → PACS.  | Compromised Sophos update → billing workstation → flat network → `billing-srv-01`.               | Compromised Veeam account or update → backup server and NAS access.                                  | Compromised Fortinet or Greenfield infrastructure → FortiGate, HQ VLAN or VPN access.          | Compromised medical-device vendor update → malicious firmware delivered to pumps or monitors. | Compromised Microsoft or Sophos administration → endpoints or identities → Active Directory access.         |
| **Insider — Malicious**          | Authorized employee → unnecessary EHR searches → patient-record theft or modification.  | Radiology employee → shared PACS login → imaging-data theft without attribution.      | Billing employee → legitimate access → claims and financial data copied to USB or cloud storage. | Privileged administrator → disables backup jobs or deletes NAS recovery data.                        | IT insider → changes firewall or VPN rules → creates hidden remote access.                     | Biomedical employee → changes device settings or introduces unauthorized equipment.           | Administrator → creates hidden account or changes privileges → persistent domain access.                    |
| **Insider — Negligent**          | Clinician → patient files copied to personal NAS or sent to the wrong recipient.        | Technician leaves shared PACS session open → another person accesses patient imaging. | Administrator stores credentials insecurely → attacker gains billing-system access.              | Overworked administrator makes an untested change → backup job fails without detection.              | IT employee misconfigures firewall or VPN rules → unnecessary external or internal access.     | Employee connects unauthorized Raspberry Pi → external attacker pivots to nurse call devices. | Administrator stores domain credentials in plaintext → credentials exposed through email or desktop access. |
| **Physical Access**              | Intruder enters a clinical area → uses an unlocked workstation → opens EHR records.     | Intruder enters Radiology → uses a logged-in PACS or Windows XP workstation.          | Intruder accesses an administrative workstation → reaches billing applications and data.         | Server-room access → attacker connects directly to or removes NAS backup equipment.                  | Network-closet or server-room access → attacker connects to switches or the FortiGate.         | Physical access to a pump or monitor → device tampering or unauthorized network connection.   | Access to an unlocked IT workstation or server room → steal an admin session or reach domain controllers.   |

The asset inventory confirms that the EHR, PACS, billing, backup, network, medical-device and Active Directory systems are connected through the same environment. It also documents the Windows XP MRI workstation, consumer-grade Westside router, unmanaged physician devices and incomplete asset records.

## Most Connected Assets

### 1. PACS and Imaging — 8 vectors

PACS is reachable through every assessed vector because it combines shared credentials, an unsupported Windows XP workstation, internal network exposure and physical access in Radiology.

### 2. Medical IoT — 8 vectors

Medical IoT is reachable through every vector because devices use accessible web interfaces, may have default credentials and are not separated from workstations or servers under **M-03**.

### 3. EHR System — 7 vectors

The EHR is tied with several other assets at seven vectors, but it is the highest-priority intersection because it contains critical patient information and supports hospital care.

## Most Versatile Vectors

Several vectors can reach all seven assets because the network is flat. The three highest-priority vectors among this tie are:

### 1. VPN Exploit — 7 assets

A successful VPN appliance exploit gives an external attacker an internal position from which the EHR, PACS, databases, backups, medical devices and Active Directory are reachable.

### 2. Phishing / Spear Phishing — 7 assets

Phishing can compromise clinical, billing or IT staff, and the lack of MFA under **M-05** allows stolen credentials to become access to critical systems.

### 3. Supply Chain Compromise — 7 assets

A compromised trusted vendor may enter through approved software, maintenance accounts or infrastructure, allowing the attack to bypass normal perimeter assumptions.

## Priority Intersection

The highest-risk intersection is **VPN or phishing access leading to Active Directory**. Once Active Directory is compromised, an attacker can distribute malware, change permissions and control systems across the flat network. Closing **M-01: Network Segmentation**, **M-04: Absence of Monitoring** and **M-05: No MFA** would break many of the attack paths shown in this matrix.

