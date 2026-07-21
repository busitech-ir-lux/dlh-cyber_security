# 10. MedDefense Risk Register

## Scoring Method

### Likelihood

| Score | Meaning                                |
| ----: | -------------------------------------- |
|     1 | Rare: less than once every 10 years    |
|     2 | Unlikely: once every 5–10 years        |
|     3 | Possible: once every 2–5 years         |
|     4 | Likely: about once per year            |
|     5 | Almost certain: several times per year |

### Impact

| Score | Meaning                |
| ----: | ---------------------- |
|     1 | Minor                  |
|     2 | Limited                |
|     3 | Significant            |
|     4 | Major                  |
|     5 | Severe or catastrophic |

### Risk Levels

| Score | Level    |
| ----: | -------- |
|   1–4 | Low      |
|   5–9 | Medium   |
| 10–16 | High     |
| 17–25 | Critical |

## Risk Assessment

| Risk ID  | Risk Description                                                                             | Category    | Threat Source                                | Vulnerability                      | Affected Assets                                    | Likelihood | Impact | Inherent Score |                               ALE |
| -------- | -------------------------------------------------------------------------------------------- | ----------- | -------------------------------------------- | ---------------------------------- | -------------------------------------------------- | ---------: | -----: | -------------: | --------------------------------: |
| RISK-001 | An attacker steals all EHR patient records.                                                  | Compliance  | External attacker or malicious insider       | F003, F031                         | `ehr-srv-01`, `ehr-db-01`                          |          4 |      5 |  20 — Critical |                        $3,025,000 |
| RISK-002 | A VPN compromise gives an attacker access to the full internal network.                      | Operational | RaaS group or credential thief               | F009, F019                         | FortiGate VPN, AD, EHR, billing and backups        |          4 |      5 |  20 — Critical |                        $2,864,400 |
| RISK-003 | Ransomware encrypts the billing server and connected backups.                                | Financial   | BlackReef-style RaaS group                   | F001, F002, F015                   | `billing-srv-01`, financial records and backup NAS |          3 |      5 |      15 — High |                          $135,278 |
| RISK-004 | Attacker activity remains undetected because MedDefense has no central monitoring.           | Operational | RaaS or opportunistic attacker               | F001, F002 and monitoring gap M-04 | All critical systems                               |          5 |      4 |  20 — Critical |  Included in RISK-001 to RISK-003 |
| RISK-005 | The flat network allows an attacker to move between user, server and medical-device systems. | Strategic   | Organized cybercrime group                   | F003, F007, F010, F016, F031       | Entire `10.10.0.0/16` network                      |          5 |      5 |  25 — Critical | Included in RISK-001 and RISK-002 |
| RISK-006 | An employee accidentally exposes patient information.                                        | Compliance  | Negligent insider                            | F024                               | Clinical workstations, EHR and PACS                |          5 |      3 |      15 — High |                          $300,000 |
| RISK-007 | An attacker compromises infusion pumps or patient-monitoring devices.                        | Operational | Opportunistic attacker                       | F010, F016                         | Seven infusion pumps and medical-device network    |          2 |      5 |      10 — High |                           $85,000 |
| RISK-008 | An attacker enters the Central network through the weak Westside Clinic connection.          | Operational | External attacker or compromised third party | F014, F029                         | Westside router, VPN and Central network           |          3 |      5 |      15 — High |                          $286,440 |
| RISK-009 | Unsupported or unpatched systems are exploited to gain initial access.                       | Operational | Opportunistic attacker or RaaS group         | F004, F008, F011                   | MRI workstation, print server and billing server   |          4 |      4 |      16 — High | Included in RISK-002 and RISK-003 |
| RISK-010 | Shared PACS accounts and unencrypted traffic expose medical images and patient data.         | Compliance  | Malicious or negligent insider               | F024                               | PACS and radiology workstations                    |          4 |      4 |      16 — High |              Included in RISK-006 |

ALE values that overlap should not be added together as independent losses.

## Treatment and Monitoring

| Risk ID  | Risk Owner                | Treatment | Justification                                                                          | Planned Controls                                                         | Residual Risk                     | KRI                                                                    | Review Date        |
| -------- | ------------------------- | --------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------- | ---------------------------------------------------------------------- | ------------------ |
| RISK-001 | Deputy CISO, James Chen   | Mitigate  | The financial and regulatory exposure is too high to accept.                           | EHR segmentation, restricted database access, MFA and Wazuh monitoring   | 10 — High; estimated ALE $726,000 | Any unauthorized EHR database connection or EHR accounts without MFA   | August 31, 2026    |
| RISK-002 | IT Director, Sarah Park   | Mitigate  | The VPN is a direct entry point to nearly every MedDefense asset.                      | VPN MFA, FortiGate patching, restricted VPN access and segmentation      | 10 — High; estimated ALE $477,400 | Any external or administrator account without MFA                      | August 31, 2026    |
| RISK-003 | IT Director, Sarah Park   | Mitigate  | Ransomware could stop billing and destroy connected recovery data.                     | Patch billing server, deploy EDR and create immutable offsite backups    | 6 — Medium; estimated ALE $18,920 | Failed backup test or critical billing vulnerability open over 14 days | August 31, 2026    |
| RISK-004 | Deputy CISO, James Chen   | Mitigate  | MedDefense cannot respond quickly to attacks it cannot detect.                         | Wazuh SIEM, centralized logging, alerts and investigation procedures     | 8 — Medium                        | Critical log source offline for over 24 hours                          | August 31, 2026    |
| RISK-005 | IT Director, Sarah Park   | Mitigate  | Segmentation limits lateral movement and reduces the impact of one compromised device. | VLANs for users, servers, medical devices, backups and guests            | 8 — Medium                        | Any unrestricted traffic rule between security zones                   | August 31, 2026    |
| RISK-006 | Deputy CISO, James Chen   | Mitigate  | Staff mistakes are frequent and can create regulatory exposure.                        | Individual accounts, USB restrictions, DLP and awareness training        | 9 — Medium; estimated ALE $96,000 | More than two data-handling incidents in one quarter                   | September 30, 2026 |
| RISK-007 | IT Director, Sarah Park   | Mitigate  | The event is unlikely but could affect patient safety.                                 | Medical-device VLAN, password changes and restricted network traffic     | 5 — Medium; estimated ALE $15,000 | Any medical device using default credentials                           | September 30, 2026 |
| RISK-008 | IT Director, Sarah Park   | Mitigate  | The consumer router creates a weak route into the Central network.                     | Dedicated Westside firewall, restricted VPN rules and managed DNS        | 8 — Medium; estimated ALE $95,480 | Unmanaged Westside device or unauthorized VPN connection               | August 31, 2026    |
| RISK-009 | IT Director, Sarah Park   | Mitigate  | Known vulnerabilities provide an easy and preventable attack path.                     | Monthly scanning, patch deadlines and replacement of unsupported systems | 8 — Medium                        | Critical vulnerability open for more than 14 days                      | September 30, 2026 |
| RISK-010 | Radiology Department Head | Mitigate  | Shared accounts remove accountability and increase patient-data risk.                  | Individual PACS accounts, access reviews and encrypted DICOM traffic     | 6 — Medium                        | Any active shared PACS account or unencrypted DICOM connection         | September 30, 2026 |

## Risk Register Governance Note

The Security Analyst maintains the Risk Register, while Deputy CISO James Chen is accountable for its accuracy and use. It should be reviewed monthly with the IT Director and relevant department heads, and summarized for the CEO and Board each quarter. An out-of-cycle review is required after a security incident, critical vulnerability, major system change, audit finding, new regulatory requirement or important supplier change. When a KRI threshold is breached, the risk owner must investigate it, update the risk score and treatment plan, and escalate risks above MedDefense’s tolerance to James Chen and the CEO.

