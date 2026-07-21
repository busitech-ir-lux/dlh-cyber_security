# 14. The Segmentation Architecture

## Part 1 — Zone Definition

### Zone 1: Server Zone

**VLAN:** 10
**IP Range:** `10.10.10.0/24`

**Systems included:**

* EHR application and database servers
* Billing server
* File server
* Active Directory and DNS servers
* PACS application server

**Allowed outbound connections:**

* Backup traffic to the Backup Zone
* Security logs to Wazuh
* Approved updates to the internet

**Allowed inbound connections:**

* HTTPS access from clinical workstations
* Authentication requests from approved systems
* DICOM traffic from approved medical devices
* Administrative access from the Management Zone

---

### Zone 2: Clinical Workstation Zone

**VLAN:** 20
**IP Range:** `10.10.20.0/23`

**Systems included:**

* Nurse-station computers
* Physician workstations
* Radiology workstations
* Approved clinical laptops

**Allowed outbound connections:**

* EHR, PACS and billing applications
* Active Directory, DNS and NTP
* Approved internet and email services

**Allowed inbound connections:**

* Management traffic from authorized IT workstations
* Required responses to connections started by clinical workstations

Clinical workstations cannot directly initiate connections to medical devices, databases or backup systems.

---

### Zone 3: Medical Device Zone

**VLAN:** 30
**IP Range:** `10.10.30.0/24`

**Systems included:**

* Infusion pumps
* Patient monitors
* MRI workstation
* PACS imaging devices
* Other connected clinical equipment

**Allowed outbound connections:**

* DICOM traffic to the PACS server
* Required clinical data to approved servers
* DNS and time synchronization
* Security logs where supported

**Allowed inbound connections:**

* Approved management traffic from the Management Zone
* Required responses from clinical servers

Medical devices cannot directly access workstations, the internet or backup systems.

---

### Zone 4: Management Zone

**VLAN:** 40
**IP Range:** `10.10.40.0/24`

**Systems included:**

* IT administrator workstations
* Security analyst workstation
* Wazuh server
* Vulnerability scanner
* Network management tools

**Allowed outbound connections:**

* Approved administrative traffic to all managed zones
* Patch and security-update services
* Log collection and vulnerability scanning

**Allowed inbound connections:**

* Security logs from managed systems
* VPN access from authorized administrators using MFA

Only authorized IT and security personnel may access this zone.

---

### Zone 5: Guest and Non-Clinical IoT Zone

**VLAN:** 50
**IP Range:** `10.10.50.0/23`

**Systems included:**

* Visitor Wi-Fi devices
* Personal phones
* Smart televisions
* Printers without clinical functions
* Building and non-clinical IoT devices

**Allowed outbound connections:**

* Internet access through the firewall
* Approved DNS services

**Allowed inbound connections:**

* None from internal MedDefense zones

This zone has no access to patient systems, servers or medical devices.

---

### Zone 6: Backup Zone

**VLAN:** 60
**IP Range:** `10.10.60.0/24`

**Systems included:**

* Backup NAS
* Backup management server
* Local recovery repository
* Offsite backup gateway

**Allowed outbound connections:**

* Encrypted replication to immutable cloud storage
* Security logs to Wazuh

**Allowed inbound connections:**

* Backup traffic from approved servers
* Administrative access from dedicated Management Zone systems

Clinical workstations, medical devices and guest systems cannot access this zone.

---

## Part 2 — Critical Firewall Rules

|  # | Firewall Rule                                                                | Purpose                                                                         |
| -: | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
|  1 | `Clinical → Server : TCP 443 : ALLOW`                                        | Allows staff to use approved EHR, PACS and billing applications.                |
|  2 | `Clinical → Active Directory : TCP/UDP 53, 88, 389/636 : ALLOW`              | Allows DNS, authentication and directory services.                              |
|  3 | `Medical Device → PACS Server : TCP 104/11112 : ALLOW`                       | Allows approved DICOM image transfers.                                          |
|  4 | `Medical Device → Approved DNS/NTP : UDP 53, 123 : ALLOW`                    | Allows name resolution and correct device time.                                 |
|  5 | `Management → Internal Zones : SSH/RDP/HTTPS/WinRM/SNMP : ALLOW`             | Allows authorized administration from dedicated management systems.             |
|  6 | `Server → Backup : Approved backup ports : ALLOW`                            | Allows servers to send backup data to the protected repository.                 |
|  7 | `Guest/IoT → Internet : TCP 80/443 and approved DNS : ALLOW`                 | Gives guests internet access without internal network access.                   |
|  8 | `Guest/IoT → Internal Zones : ANY : DENY`                                    | Prevents personal or IoT devices from reaching clinical systems and servers.    |
|  9 | `Clinical → Medical Device : ANY : DENY`                                     | Prevents malware on a user workstation from directly attacking medical devices. |
| 10 | `Medical Device → Server/Clinical/Backup : ANY except approved rules : DENY` | Stops compromised medical devices from moving laterally or reaching backups.    |

All other traffic should follow a **default-deny rule** unless it is specifically approved and documented.

## Part 3 — Kill Chain Impact

### Kill Chain #1: Ransomware Attack

#### Step 1 — Initial Access

The attacker sends a phishing email, steals a password or compromises the VPN.

**Segmentation impact:** Segmentation may not stop the original phishing or credential theft. MFA and email protections are still required.

#### Step 2 — Workstation Compromise

The attacker installs malware on a clinical or administrative workstation.

**Segmentation impact:** The infected workstation remains contained inside its assigned zone.

#### Step 3 — Network Discovery

On the flat network, the attacker could scan the entire `10.10.0.0/16` environment.

**Segmentation impact:** Firewall rules prevent the attacker from discovering most servers, medical devices and backup systems.

#### Step 4 — Lateral Movement

The attacker attempts to connect to Active Directory, EHR, billing and medical devices using RDP, SMB or SSH.

**Segmentation impact:** This step is strongly disrupted because clinical workstations can only reach specific approved services.

#### Step 5 — Privilege Escalation

The attacker attempts to reach administrator systems and obtain higher privileges.

**Segmentation impact:** Administrative access is restricted to the Management Zone, which prevents normal workstations from directly managing servers.

#### Step 6 — Ransomware Deployment

The attacker attempts to deploy ransomware across servers, workstations and medical devices.

**Segmentation impact:** Firewall boundaries prevent one compromised zone from automatically spreading ransomware to every other zone.

#### Step 7 — Backup Destruction

The attacker attempts to encrypt or delete the backup NAS.

**Segmentation impact:** The Backup Zone is inaccessible from clinical workstations and medical devices, protecting recovery data.

## Estimated Kill Chain Reduction

Segmentation would strongly disrupt approximately **4 of MedDefense’s top 5 kill chains, or 80%**. It would reduce lateral movement and impact in all five chains, but it would not fully prevent phishing, stolen credentials or malicious insider activity.

The main breakpoints are:

```text
Initial compromise
        |
        v
Compromised workstation
        |
        X  Firewall blocks unrestricted discovery
        |
        X  Firewall blocks lateral movement
        |
        X  Management Zone protects administrative access
        |
        X  Backup Zone protects recovery data
```

Segmentation does not eliminate every attack, but it changes one compromised device from an organization-wide incident into a smaller and more manageable event.

