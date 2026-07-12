# Complete Control Matrix

**Effectiveness scale**

* **Strong:** Correctly configured, maintained and covering the required scope.
* **Adequate:** Implemented but has some limitations.
* **Weak:** Poor coverage, outdated, easily bypassed or not yet implemented.

Controls C-024 to C-028 are **proposed MRI compensating controls**. They are rated Weak because they have not yet been implemented.

## Part 1: Updated Control Registry

| ID    | Control Name                                | Category       | Function     | Asset(s) Protected                                  | Effectiveness | Evidence / Source                                                                                         |
| ----- | ------------------------------------------- | -------------- | ------------ | --------------------------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------- |
| C-001 | Inbound Web Filtering                       | Technical      | Preventive   | `web-srv-01`, patient portal, DMZ                   | Adequate      | FortiGate permits only HTTP/HTTPS inbound, but the DMZ design has not been fully verified.                |
| C-002 | Default Deny Firewall Rule                  | Technical      | Preventive   | Central network and DMZ                             | Strong        | FortiGate denies and logs traffic not permitted by another rule.                                          |
| C-003 | Firewall Traffic Logging                    | Technical      | Detective    | Firewall, VPNs and network traffic                  | Weak          | Logs are stored locally for 30 days with no SIEM or automated alerts.                                     |
| C-004 | Site-to-Site VPN Encryption                 | Technical      | Preventive   | Westside, HQ and Central communications             | Adequate      | VPN tunnels protect inter-site traffic, but both VPN rules permit all services.                           |
| C-005 | SSH Key Authentication                      | Technical      | Preventive   | `ehr-srv-01`                                        | Strong        | Password authentication is disabled on this server.                                                       |
| C-006 | SSH Root Login Disabled                     | Technical      | Preventive   | `ehr-srv-01`                                        | Strong        | Direct root login is disabled.                                                                            |
| C-007 | SSH Authentication Limits                   | Technical      | Preventive   | `ehr-srv-01`                                        | Adequate      | Three login attempts and a 60-second login period are configured.                                         |
| C-008 | Verbose SSH Logging                         | Technical      | Detective    | `ehr-srv-01`                                        | Adequate      | Authentication events are logged, but logs are not centralized.                                           |
| C-009 | Password Requirements Policy                | Administrative | Preventive   | Employee, contractor and vendor accounts            | Weak          | Policy exists but is outdated, uses an eight-character minimum and is not consistently enforced on Linux. |
| C-010 | Account Lockout                             | Technical      | Preventive   | Active Directory accounts                           | Adequate      | Accounts lock for 30 minutes after five failed attempts.                                                  |
| C-011 | Password History                            | Technical      | Preventive   | Active Directory accounts                           | Adequate      | The previous five passwords cannot be immediately reused.                                                 |
| C-012 | Sophos Endpoint Protection                  | Technical      | Preventive   | Managed Windows workstations                        | Adequate      | Covers 372 workstations, but not servers, Linux, iPads or mobile devices.                                 |
| C-013 | Malware Detection and Quarantine            | Technical      | Detective    | Managed Windows workstations                        | Strong        | Sophos has blocked or quarantined malware, miners and malicious URLs.                                     |
| C-014 | Nightly Veeam Backups                       | Technical      | Corrective   | Selected EHR, billing, domain, file and web servers | Adequate      | Daily backups exist, but are local, incomplete and stored beside production systems.                      |
| C-015 | Backup Restore Testing                      | Administrative | Detective    | Backup and recovery process                         | Weak          | Only one partial restore was tested eight months ago; no full DR test exists.                             |
| C-016 | Visitor Registration and Badge Verification | Physical       | Preventive   | Central Hospital main entrance                      | Adequate      | Guard checks visitors on weekdays during business hours only.                                             |
| C-017 | Uniformed Guard Presence                    | Physical       | Deterrent    | Central Hospital main entrance                      | Adequate      | Visible guard presence discourages unauthorized entry, but coverage is limited.                           |
| C-018 | Security Cameras                            | Physical       | Detective    | Selected Central and Westside entrances             | Weak          | Cameras do not cover server rooms, network closets or administrative areas.                               |
| C-019 | CCTV Recording Retention                    | Technical      | Detective    | Physical security evidence                          | Adequate      | Central footage is retained for 30 days, but monitoring is informal.                                      |
| C-020 | Annual Security Awareness Training          | Administrative | Preventive   | Staff, systems and information                      | Weak          | Completion is only 71% at Central and 58% at Westside; training is generic.                               |
| C-021 | Suspicious Activity Reporting Training      | Administrative | Detective    | Organization-wide systems and facilities            | Weak          | Staff are told to report suspicious activity, but no formal reporting process is shown.                   |
| C-022 | Local System and Application Logging        | Technical      | Detective    | Servers, EHR, Active Directory and applications     | Weak          | Logs exist but are separated, manually reviewed and have no integrity protection.                         |
| C-023 | HID Badge Access System                     | Physical       | Preventive   | Selected doors and server room                      | Weak          | Badge readers exist, but the server room uses a generic badge available to most employees.                |
| C-024 | Dedicated MRI VLAN and Firewall Rules       | Technical      | Compensating | MRI workstation, PACS and hospital network          | Weak          | Proposed control; would allow only required MRI-to-PACS traffic but is not implemented.                   |
| C-025 | MRI Network Monitoring                      | Technical      | Detective    | MRI workstation and medical-device traffic          | Weak          | Proposed monitoring and alerting control; no evidence of implementation.                                  |
| C-026 | MRI Access and Support Procedure            | Administrative | Compensating | MRI workstation and vendor access                   | Weak          | Proposed approved-user and vendor-access process; not implemented.                                        |
| C-027 | Restricted MRI Control Area                 | Physical       | Preventive   | MRI control workstation                             | Weak          | Proposed locked access, visitor log and removable-media restrictions; not implemented.                    |
| C-028 | MRI Incident and Continuity Procedure       | Administrative | Corrective   | MRI and Radiology operations                        | Weak          | Proposed isolation, escalation and clinical-continuity procedure; not implemented.                        |

## The implemented controls are supported by the firewall, SSH, password, antivirus, backup, physical-security, training and logging artifacts. The asset and network findings show the systems covered and the remaining weaknesses.

# Part 2: Updated Control Summary Matrix

For calculating average effectiveness:

* Strong = 3
* Adequate = 2
* Weak = 1

| Category           | Preventive                       | Detective                        | Corrective                      | Compensating                | Deterrent                       |
| ------------------ | -------------------------------- | -------------------------------- | ------------------------------- | --------------------------- | ------------------------------- |
| **Technical**      | **9 controls** — 2.3/3, Adequate | **6 controls** — 1.7/3, Adequate | **1 control** — 2.0/3, Adequate | **1 control** — 1.0/3, Weak | **0 controls**                  |
| **Administrative** | **2 controls** — 1.0/3, Weak     | **2 controls** — 1.0/3, Weak     | **1 control** — 1.0/3, Weak     | **1 control** — 1.0/3, Weak | **0 controls**                  |
| **Physical**       | **3 controls** — 1.3/3, Weak     | **1 control** — 1.0/3, Weak      | **0 controls**                  | **0 controls**              | **1 control** — 2.0/3, Adequate |

## Control IDs by Cell

| Category           | Preventive                                                    | Detective                                | Corrective | Compensating | Deterrent |
| ------------------ | ------------------------------------------------------------- | ---------------------------------------- | ---------- | ------------ | --------- |
| **Technical**      | C-001, C-002, C-004, C-005, C-006, C-007, C-010, C-011, C-012 | C-003, C-008, C-013, C-019, C-022, C-025 | C-014      | C-024        | —         |
| **Administrative** | C-009, C-020                                                  | C-015, C-021                             | C-028      | C-026        | —         |
| **Physical**       | C-016, C-023, C-027                                           | C-018                                    | —          | —            | C-017     |

The matrix shows that most controls are **technical and preventive**. Administrative, corrective, compensating and physical-detective controls are limited or weak.

---

# Part 3: Control Coverage Map

## Top 5 Critical Assets

| Critical Asset                         | Preventive Controls                                           | Detective Controls         | Corrective Controls            | Compensating Controls                                                             | Coverage Assessment     |
| -------------------------------------- | ------------------------------------------------------------- | -------------------------- | ------------------------------ | --------------------------------------------------------------------------------- | ----------------------- |
| **EHR System**                         | C-001, C-002, C-005, C-006, C-007, C-009, C-010, C-011, C-012 | C-003, C-008, C-022        | C-014                          | None                                                                              | **Partially Protected** |
| **Medical IoT and Clinical Devices**   | C-002, C-009, C-016, C-023                                    | C-003, C-018, C-022        | None                           | C-024, C-025, C-026, C-027, C-028 apply mainly to the MRI and are not implemented | **Under-Protected**     |
| **Network Core and Connectivity**      | C-002, C-004, C-016, C-023                                    | C-003, C-018, C-019, C-022 | None                           | None                                                                              | **Partially Protected** |
| **Identity and Access Infrastructure** | C-002, C-009, C-010, C-011, C-023                             | C-022                      | C-014 protects only `ad-dc-01` | None                                                                              | **Partially Protected** |
| **PACS and Imaging Infrastructure**    | C-002, C-009, C-010, C-011, C-016, C-023                      | C-003, C-018, C-022        | None—PACS is not backed up     | C-024 to C-028 are proposed for the MRI but not implemented                       | **Under-Protected**     |

## Coverage Details

### EHR System — Partially Protected

The EHR has several authentication, firewall, SSH, logging and backup controls. However, the PostgreSQL database is reachable from the wider internal network, monitoring is not centralized, MFA is absent and endpoint protection does not cover the Linux servers. It therefore has reasonable preventive coverage but weak detection and response.

### Medical IoT — Under-Protected

Patient monitors and infusion pumps are connected to the same reachable network as servers and workstations. They lack endpoint protection, effective segmentation, dedicated monitoring and tested recovery procedures. The MRI controls are only proposals and therefore do not yet reduce the real risk.

### Network Core — Partially Protected

The FortiGate, VPNs and default-deny rule provide basic perimeter protection. However, the internal network is flat, VPN access permits all services, outbound traffic is unrestricted and no centralized monitoring exists. There is also no documented corrective control for a core network failure or compromise.

### Identity and Access Infrastructure — Partially Protected

Active Directory benefits from password requirements, lockout and backup of the primary domain controller. However, MFA is not required, shared accounts exist, access reviews are not documented and the secondary domain controller is not backed up. Detection is limited to local logs without alerts.

### PACS and Imaging — Under-Protected

PACS supports critical diagnostic imaging but is excluded from backups because of its size. The MRI workstation runs Windows XP and shares the wider network, while Radiology uses a shared PACS account. There is no effective corrective control if PACS data is lost and the proposed MRI compensating controls have not been implemented.

