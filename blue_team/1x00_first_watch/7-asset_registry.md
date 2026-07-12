# MedDefense Asset Registry

## Asset Registry

| Asset ID | Name                                | Type                    | Location                                                        | Owner (Dept)                            | OS / Platform                    | Critical Services                                    | Network Segment                       | Status     | Notes                                                                                                      |
| -------- | ----------------------------------- | ----------------------- | --------------------------------------------------------------- | --------------------------------------- | -------------------------------- | ---------------------------------------------------- | ------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------- |
| A-001    | `ehr-srv-01`                        | Server                  | Central Hospital server room                                    | Clinical IT / EHR                       | Ubuntu 20.04                     | EHR application                                      | `10.10.2.0/24`                        | Active     | IP `10.10.2.10`; ports 22, 443 and 8080; SSH key authentication enabled.                                   |
| A-002    | `ehr-db-01`                         | Data Store              | Central Hospital server room                                    | Clinical IT / DBA                       | Ubuntu 20.04, PostgreSQL         | Stores EHR data                                      | `10.10.2.0/24`                        | Active     | IP `10.10.2.11`; PostgreSQL port 5432 is reachable from the whole internal network.                        |
| A-003    | `pacs-srv-01`                       | Server                  | Central Hospital server room                                    | Radiology                               | Windows Server 2016              | Medical image storage and transfer                   | `10.10.2.0/24`                        | Active     | IP `10.10.2.12`; not included in Veeam backups because of its size.                                        |
| A-004    | `billing-srv-01`                    | Server                  | Central Hospital server room                                    | Finance / Billing                       | Ubuntu 18.04                     | Billing and insurance claims                         | `10.10.2.0/24`                        | Deprecated | IP `10.10.2.15`; affected by ransomware and later a crypto-miner; MySQL and Apache are exposed internally. |
| A-005    | `ad-dc-01`                          | Server                  | Central Hospital server room                                    | IT                                      | Windows Server 2019              | Primary domain controller, DNS and authentication    | `10.10.2.0/24`                        | Active     | IP `10.10.2.20`; included in backups.                                                                      |
| A-006    | `ad-dc-02`                          | Server                  | Central Hospital server room                                    | IT                                      | Windows Server 2019              | Secondary domain controller                          | `10.10.2.0/24`                        | Active     | IP `10.10.2.21`; not included in backups.                                                                  |
| A-007    | `file-srv-01`                       | Server                  | Central Hospital server room                                    | IT / All Departments                    | Windows Server 2016              | Department file shares                               | `10.10.2.0/24`                        | Active     | IP `10.10.2.30`; contains shared departmental and security files.                                          |
| A-008    | `print-srv-01`                      | Server                  | Central Hospital server room                                    | IT                                      | Windows Server 2012 R2           | Printing services                                    | `10.10.2.0/24`                        | Deprecated | IP `10.10.2.31`; previously marked unverified but found in the scan; operating system is end-of-life.      |
| A-009    | `backup-srv-01`                     | Server                  | Central Hospital server room                                    | IT                                      | Ubuntu 22.04 / Veeam             | Nightly backups                                      | `10.10.2.0/24`                        | Active     | IP `10.10.2.40`; backs up selected servers to NAS-01.                                                      |
| A-010    | `NAS-01`                            | Data Store              | Central Hospital server room                                    | IT                                      | Synology DSM 7, RAID 5           | Backup storage                                       | `10.10.2.0/24`                        | Active     | IP `10.10.2.41`; management interface is reachable from the whole internal network.                        |
| A-011    | `web-srv-01`                        | Server                  | Central Hospital DMZ                                            | IT / Marketing / Patient Services       | Ubuntu 20.04                     | Public website and patient portal                    | DMZ / `10.10.2.0/24`                  | Active     | IP `10.10.2.50`; website was previously defaced; hosts patient-facing services.                            |
| A-012    | `ws-srv-01`                         | Server                  | Westside server closet                                          | Westside Clinic / IT                    | Windows Server 2016              | Local files and scheduling                           | `10.10.10.0/24`                       | Active     | IP `10.10.10.10`; not included in Central backups.                                                         |
| A-013    | `UNKNOWN-01`                        | Server                  | Central Hospital                                                | Unknown                                 | Linux 4.x                        | Unknown web services                                 | `10.10.2.0/24`                        | Shadow IT  | IP `10.10.2.99`; ports 22, 8888 and 9090; absent from all documentation.                                   |
| A-014    | Westside unknown Linux device       | Server                  | Westside Clinic                                                 | Unknown                                 | Linux 5.x                        | Unknown; possibly monitoring or Node.js service      | `10.10.10.0/24`                       | Shadow IT  | IP `10.10.10.200`; ports 22, 80 and 3000; not documented.                                                  |
| A-015    | FortiGate 100F                      | Network Device          | Central Hospital                                                | IT / Network Team                       | FortiOS                          | Firewall, DMZ and VPN connectivity                   | Perimeter                             | Active     | Allows Westside and HQ VPN traffic; VPN and outbound rules are too permissive.                             |
| A-016    | Central Cisco core switch           | Network Device          | Central Hospital                                                | IT / Network Team                       | Cisco, model unknown             | Core network switching                               | `10.10.0.0/16`                        | Active     | The scan confirms that network separation is not enforced.                                                 |
| A-017    | Central access switches             | Network Device          | Central Hospital floors                                         | IT / Network Team                       | Cisco, models unknown            | Connect workstations, APs and medical devices        | `10.10.0.0/16`                        | Active     | Approximately two per floor; one unlocked network closet exposes switches and credentials.                 |
| A-018    | Central UniFi access points         | Network Device          | Central Hospital                                                | IT / Network Team                       | Ubiquiti UniFi                   | Staff and guest Wi-Fi                                | `10.10.1.0/24`                        | Active     | 12 APs detected; guest Wi-Fi isolation has not been confirmed.                                             |
| A-019    | Westside Netgear Nighthawk          | Network Device          | Westside Clinic                                                 | Westside / IT                           | Netgear firmware                 | Internet access and IPSec VPN                        | `10.10.10.0/24`                       | Active     | IP `10.10.10.1`; consumer-grade router and no dedicated firewall.                                          |
| A-020    | Westside unmanaged switch           | Network Device          | Westside Clinic                                                 | Westside / IT                           | Unknown                          | Local network connectivity                           | `10.10.10.0/24`                       | Unknown    | Mentioned in documentation but not separately identified in the scan.                                      |
| A-021    | Central Windows workstations        | Endpoint                | Central Hospital                                                | Clinical and Administrative Departments | Windows 10                       | EHR, administration, pharmacy, lab and clinical work | `10.10.1.0/24`                        | Active     | About 320 documented; scan found about 290 additional systems plus named examples. Some have RDP enabled.  |
| A-022    | Central thin clients                | Endpoint                | Central Hospital clinical areas                                 | Clinical Departments / IT               | Linux thin client                | Clinical access                                      | `10.10.1.0/24`                        | Active     | About 60 documented; only four appeared in the scan summary.                                               |
| A-023    | Westside workstations               | Endpoint                | Westside Clinic                                                 | Westside Clinic                         | Windows 10                       | Scheduling, clinical and office work                 | `10.10.10.0/24`                       | Active     | Documentation says about 45; scan shows 36 named systems in the included range.                            |
| A-024    | HQ workstations                     | Endpoint                | Corporate HQ                                                    | Corporate Departments                   | Windows 10 and 11                | Finance, HR, Legal, Marketing and IT work            | `10.10.20.0/24`                       | Active     | Around 120 documented; scan found approximately 121.                                                       |
| A-025    | HQ laptops                          | Endpoint                | Corporate HQ / Remote                                           | Corporate Departments                   | Windows 11                       | Remote-capable corporate work                        | `10.10.20.0/24` when on-site          | Active     | Documentation says about 30; only about 25 were online during the scan.                                    |
| A-026    | Physician iPads                     | Endpoint                | Central Hospital                                                | Clinical Departments                    | Apple iPadOS                     | Physician rounds and patient care                    | Wireless, exact segment unknown       | Unknown    | About 25 devices; not managed by MDM and not visible in the scan summary.                                  |
| A-027    | `WS-RAD-01` MRI control workstation | IoT Medical             | Central Hospital Radiology                                      | Radiology                               | Windows XP Embedded / SP3        | Controls MRI scanner and sends studies to PACS       | `10.10.1.0/24`                        | Deprecated | IP `10.10.1.70`; cannot be patched or upgraded without affecting certification; currently not isolated.    |
| A-028    | Siemens MAGNETOM MRI scanner        | IoT Medical             | Central Hospital Radiology                                      | Radiology                               | Vendor medical platform          | MRI studies                                          | Connected through control workstation | Active     | Processes about 45 studies per day; expected operational life is 12 years.                                 |
| A-029    | GE Revolution CT scanner            | IoT Medical             | Central Hospital Radiology                                      | Radiology                               | Unknown                          | CT imaging                                           | Unknown                               | Active     | Mentioned in documentation but not clearly identified in the scan.                                         |
| A-030    | Philips IntelliVue monitors         | IoT Medical             | Central Hospital                                                | Clinical Departments                    | Philips IntelliVue               | Patient monitoring                                   | `10.10.3.0/24`                        | Active     | Around 80 documented; scan found listed examples plus about 65 additional units.                           |
| A-031    | BD Alaris infusion pumps            | IoT Medical             | Central Hospital                                                | Pharmacy / Nursing                      | Firmware 12.1.2                  | Medication delivery and dosage updates               | `10.10.3.0/24`                        | Active     | Around 120 documented; management interfaces are reachable across the internal network.                    |
| A-032    | `MON-VITALS-3F-01`                  | IoT Medical             | Central Hospital, third floor                                   | Nursing / Clinical                      | Firmware v2.1.3, vendor unclear  | Vital-sign monitoring                                | `10.10.3.0/24`                        | Active     | IP `10.10.3.47`; observed during the walk-through; last updated in 2019.                                   |
| A-033    | Nurse call system                   | IoT Medical             | Central Hospital                                                | Nursing / Facilities                    | IP-based / SIP                   | Patient-to-nurse communication                       | `10.10.3.0/24`                        | Active     | Two units detected at `10.10.3.50-51`; integrated with the phone system.                                   |
| A-034    | HID badge access system             | Physical Infrastructure | Central Hospital                                                | Facilities / Security / IT              | HID Global                       | Controls access to selected doors                    | `10.10.3.0/24`                        | Active     | Readers detected at main entrance, server room and ER; generic badges give overly broad access.            |
| A-035    | Central server room                 | Physical Infrastructure | Central Hospital ground floor / basement documentation conflict | IT                                      | Physical facility                | Hosts critical servers, storage and network systems  | Not applicable                        | Active     | Uses generic employee badges; no dedicated camera or visitor log.                                          |
| A-036    | Second-floor network closet         | Physical Infrastructure | Central Hospital second floor                                   | IT / Network Team                       | Physical facility                | Houses switches and patch panels                     | Not applicable                        | Active     | Unlocked, door ajar and switch credentials displayed on the wall.                                          |
| A-037    | EHR application                     | Application             | Central Hospital / Organization-wide                            | Clinical IT                             | Vendor EHR platform              | Electronic patient records                           | Depends on A-001 and A-002            | Active     | Used by physicians, nurses and clinical staff; audit logs are vendor-managed.                              |
| A-038    | PACS application                    | Application             | Central Hospital / Radiology                                    | Radiology                               | PACS platform                    | Stores and transfers medical images                  | Depends on A-003                      | Active     | Receives MRI and other imaging studies.                                                                    |
| A-039    | Billing application                 | Application             | Central Hospital / Finance                                      | Finance                                 | Apache / MySQL-based application | Billing and insurance claims                         | Depends on A-004                      | Active     | Experienced ransomware, crypto-mining and repeated performance degradation.                                |
| A-040    | Patient portal                      | Application             | Public-facing                                                   | Patient Services / IT                   | Hosted on `web-srv-01`           | Patient access to health information                 | DMZ                                   | Active     | Previously had broken access control that exposed other patients’ lab results.                             |
| A-041    | Microsoft O365 E3                   | Application             | Cloud / Organization-wide                                       | IT / All Departments                    | Microsoft cloud service          | Email, SharePoint and OneDrive                       | Cloud                                 | Active     | Main known cloud service; no separate O365 backup is documented.                                           |
| A-042    | Sophos Endpoint Protection          | Application             | Organization-wide endpoints                                     | IT / Security                           | Sophos Central                   | Malware prevention and detection                     | Managed endpoints                     | Active     | Covers 372 Windows endpoints; does not cover servers, Linux systems, iPads or other mobile devices.        |

The registry consolidates the onboarding packet, incident records, walk-through observations, control artifacts, MRI information and network scan.

# Reconciliation Notes

## 1. Assets found in the network scan but missing from documentation

### `10.10.2.99 – UNKNOWN-01`

* Linux 4.x device on the Central server subnet.
* Runs SSH and two web services on ports 8888 and 9090.
* It has no DNS hostname and no documented owner or purpose.
* It should be treated as **Shadow IT** until identified.

### `10.10.10.200 – Unknown Westside device`

* Linux 5.x device with ports 22, 80 and 3000 open.
* It may be an unofficial monitoring, Grafana or Node.js system.
* It has no documented owner or approved purpose.
* It should be treated as **Shadow IT**.

### `WS-WC-XRAY`

* Vendor-specific X-ray workstation at Westside.
* The clinic’s imaging service was documented, but this workstation was not included in the original asset list.
* Its OS is unknown.

### Individual network assets

The scan identifies individual access points, badge readers, nurse-call devices, patient monitors and pumps that were previously documented only as approximate totals.

---

## 2. Assets in documentation but not clearly found in the scan

### GE Revolution CT scanner

The CT scanner is documented, but no device is clearly identified as the CT scanner in the scan.

Possible reasons include:

* it was powered off;
* it is on another network;
* it does not respond to Nmap;
* it communicates through a separate control workstation.

### Physician iPads

Approximately 25 iPads are documented but do not appear in the scan summary.

Possible reasons include:

* they were not connected during the scan;
* they use a wireless network outside the scanned range;
* they do not respond to the scan;
* device management is incomplete.

### Westside unmanaged switch

The switch is documented but does not appear as a managed IP device. This is expected if it is truly unmanaged.

### Some Central thin clients

Approximately 60 thin clients are documented, but only four are shown in the scan summary. The scan output may have omitted them, or some may have been offline.

### Some Westside workstations

Documentation estimates around 45 workstations, while the scan shows approximately 36 in the listed range. Some devices may have been powered off or removed.

### Some HQ laptops

Documentation lists around 30 laptops, while approximately 25 were detected. Mobile laptops may have been off-site during the scan.

### Medical-device configurations

The onboarding packet mentions medical-device configurations and management needs, but no dedicated medical-device management server was identified.

---

## 3. Discrepancies and contradictions

### Flat network versus subnet names

The scan uses separate IP ranges for workstations, servers and medical devices. However, the scan confirms that these are only addressing conventions.

There is no actual VLAN or firewall separation, and a device on one subnet can reach the others.

### MRI operating-system description

The documentation describes the MRI control software as Windows XP Embedded. The scan identifies `WS-RAD-01` as Windows XP SP3.

These descriptions are related but not identical. The exact edition should be confirmed from the device itself or the vendor documentation.

### Central workstation count

The onboarding packet estimates approximately 320 workstations. The scan lists named devices and states that about 290 additional workstations were detected.

The exact total is still unclear because the scan summary omits many individual entries.

### HQ workstation count

The documentation lists approximately 120 HQ workstations. The scan reports systems up to `WS-HQ-121`, suggesting approximately 121.

This may be normal estimation, but the inventory should be updated.

### Westside workstation count

The documentation lists approximately 45 workstations. The scan shows 36 standard workstations plus one X-ray workstation.

The missing systems may have been offline, removed or outside the scanned list.

### `print-srv-01` verification

The onboarding asset list marked `print-srv-01` as unverified. The scan confirms that it is active at `10.10.2.31`.

### Server-room location

The HR guide describes a basement server room, while the walk-through describes the server room as being on the ground floor near the cafeteria corridor.

This may mean:

* two different IT rooms exist;
* the HR guide is outdated;
* the location was described incorrectly.

The physical location must be confirmed.

### DMZ description

The network diagram places `web-srv-01` in a DMZ. The scan identifies it in the `10.10.2.0/24` server range.

This does not prove that it is not logically separated, but the real DMZ design and firewall interfaces should be verified.

### Database exposure

The scan confirms that:

* PostgreSQL on `ehr-db-01` is reachable internally.
* MySQL on `billing-srv-01` is reachable internally.

The scan note says MySQL should be restricted to `ehr-srv-01`, but the billing application may be the correct client. The required connection path must be confirmed before changing the rule.

### Medical-device totals

The original documentation estimates:

* about 80 patient monitors;
* about 120 infusion pumps.

The scan lists examples and additional grouped devices, which broadly supports these estimates but does not provide an exact count.

### Backup environment

The onboarding packet refers to a local NAS without a name. The controls artifact and network scan identify it as `NAS-01`, a Synology DS1621+ at `10.10.2.41`.

### Unsupported systems

The scan confirms three important legacy systems:

* MRI workstation: Windows XP.
* `print-srv-01`: Windows Server 2012 R2.
* `billing-srv-01`: Ubuntu 18.04 without activated Extended Security Maintenance.

These systems should remain marked as **Deprecated**, even though they are still active.

