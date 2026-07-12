# Asset Criticality Assessment

The overall rating is the highest rating across Confidentiality, Integrity and Availability.

## Asset Criticality Matrix

| Asset Category                                                                                                    | Confidentiality | Integrity | Availability | Overall Criticality | Justification                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------- | --------------- | --------- | ------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EHR System** (`ehr-srv-01`, `ehr-db-01`, EHR application)                                                       | Critical        | Critical  | Critical     | **Critical**        | The EHR supports physicians and nurses across a 350-bed hospital. Exposure of patient records could create a serious privacy and regulatory incident; incorrect allergies, diagnoses or medication information could directly harm patients; and a long outage would force clinical staff to work with incomplete paper records. |
| **PACS and Imaging** (`pacs-srv-01`, MRI, CT and imaging workstations)                                            | High            | Critical  | Critical     | **Critical**        | Radiology depends on PACS to store and retrieve diagnostic images. Altered or missing images could lead to incorrect diagnosis, while an outage would delay imaging across departments; the MRI alone performs about 45 studies per day and its PACS server is not currently backed up.                                          |
| **Medical IoT and Clinical Devices** (patient monitors, infusion pumps and nurse call system)                     | High            | Critical  | Critical     | **Critical**        | MedDefense operates about 80 patient monitors and 120 network-connected infusion pumps. Incorrect readings or dosage information could directly affect treatment, and device outages could prevent staff from monitoring patients or delivering medication safely.                                                               |
| **Identity and Access Infrastructure** (`ad-dc-01`, `ad-dc-02` and badge integration)                             | Critical        | Critical  | Critical     | **Critical**        | Active Directory controls staff access to systems and some physical doors. A compromise could expose accounts, allow attackers to change permissions or impersonate staff, and prevent users from accessing EHR, files and other clinical systems.                                                                               |
| **Network Core and Connectivity** (FortiGate, switches, Wi-Fi and VPNs)                                           | High            | Critical  | Critical     | **Critical**        | Nearly all hospital systems depend on the same flat network. A failure or unauthorized network change could interrupt communication between clinical workstations, servers and medical devices across Central, Westside and HQ, while weak segmentation could allow an attacker to move between them.                            |
| **Backup and Recovery Infrastructure** (`backup-srv-01`, `NAS-01` and Veeam)                                      | High            | Critical  | Critical     | **Critical**        | Backups are needed to restore the EHR, billing, domain controller, file server and patient portal after ransomware or system failure. The server and NAS are in the same room and network, there is no offsite copy, and a complete disaster-recovery test has never been performed.                                             |
| **Clinical Endpoints** (nurse, pharmacy, laboratory and radiology workstations, thin clients and physician iPads) | Critical        | Critical  | High         | **Critical**        | These devices give staff direct access to patient records and clinical systems. An unattended or infected workstation could expose patient information or allow records and medication information to be changed; loss of many endpoints would slow clinical work even if central servers remained available.                    |
| **Billing and Financial Infrastructure** (`billing-srv-01` and billing application)                               | High            | High      | High         | **High**            | The billing server processes insurance claims and supports hospital revenue. Its ransomware incident stopped claims processing for four days, and later compromise by a crypto-miner showed that unauthorized access and modification were still possible.                                                                       |
| **Administrative Endpoints and Cloud Services** (HQ workstations, laptops, O365, HR and finance files)            | High            | High      | Medium       | **High**            | These systems contain employee, HR, legal, financial and executive information. A breach could expose sensitive workforce or business data and support phishing or fraud, but most direct clinical care could continue for a limited time without them.                                                                          |
| **Physical Security Infrastructure** (server room, network closets, badge readers, cameras and guards)            | High            | High      | High         | **High**            | Weak physical controls could allow someone to enter the server room, access switches, steal equipment or disrupt power and network connections. Current weaknesses include generic server-room badges, an unlocked network closet and no cameras near critical IT areas.                                                         |

The ratings are based on MedDefense’s actual asset inventory, 350-bed hospital operations, flat network, medical-device exposure, backup limitations and prior incidents.

# Top 5 Most Critical Assets

## 1. EHR System

The EHR system is the most critical asset because it supports daily clinical decisions across the hospital. Physicians and nurses depend on it for patient history, diagnoses, allergies, medication information and treatment records. A confidentiality breach could expose a large amount of protected health information, an integrity failure could cause unsafe treatment, and an outage could leave staff working with incomplete paper records.

## 2. Medical IoT and Clinical Devices

Patient monitors and infusion pumps directly support patient care. MedDefense has approximately 80 connected monitors and 120 network-connected pumps, and they are reachable through the same flat network as normal workstations. Incorrect readings, altered dosage settings or widespread device failure could create immediate patient-safety consequences.

## 3. Network Core and Connectivity

The FortiGate, core switch, access switches and VPN connections support communication between almost every important asset. The scan confirmed that workstations, servers and medical devices can reach each other without effective segmentation. A network-core failure or compromise could therefore affect the EHR, PACS, medical devices, Westside Clinic and Corporate HQ at the same time.

## 4. Identity and Access Infrastructure

The two Active Directory domain controllers manage user authentication and access to systems, and Active Directory is also connected to some physical badge readers. If an attacker compromises the domain, they could create accounts, change permissions, access sensitive systems and impersonate staff. If the service becomes unavailable, employees may be unable to log in to the systems needed for clinical and administrative work.

## 5. PACS and Imaging Infrastructure

PACS stores and transfers diagnostic images from systems such as the MRI and CT scanner. The MRI performs about 45 studies per day, so downtime would quickly delay diagnosis and treatment. The PACS server is also not included in current backups, which increases the effect of data loss, ransomware or hardware failure.

