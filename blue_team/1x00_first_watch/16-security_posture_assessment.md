# MedDefense Health Systems

## Security Posture Assessment

**Prepared for:** Board of Directors and Executive Leadership
**Prepared by:** Security Analyst, Office of the Deputy CISO
**Assessment status:** Final
**Overall risk rating:** **Critical**

---

# 1. Executive Summary

MedDefense Health Systems has basic security controls, including a perimeter firewall, endpoint protection on many workstations, passwords, VPN connections, backups and physical guards. However, these controls are incomplete and are not sufficient for an organization operating a 350-bed hospital, an outpatient clinic and systems containing protected health information for more than 50,000 patients.

The current security posture is rated **Critical** because a compromise of one workstation, medical device, VPN connection or public server could spread across the internal network. MedDefense has already experienced ransomware, website defacement, unauthorized patient-record access, a prolonged EHR outage and an undetected cryptocurrency miner. These events demonstrate that the identified risks are active operational problems, not theoretical possibilities.

## Most Critical Finding

The most critical finding is the absence of effective **internal network segmentation**. Clinical workstations, servers, Active Directory, medical devices and other systems are reachable across the same internal environment. This means that one compromised asset could provide a path to the EHR, PACS, billing systems, domain controllers, infusion pumps and patient monitors.

## Top Three Recommended Actions

1. **Segment the internal network and isolate medical devices.**
   Create separate security zones for clinical systems, servers, medical devices, administrative endpoints, guest Wi-Fi and remote sites.

2. **Implement MFA and centralized security monitoring.**
   Require MFA for VPN, privileged and clinical-system access, and deploy centralized logging and alerting to identify attacks before they cause operational damage.

3. **Create an isolated recovery capability and tested response plan.**
   Replicate backups offsite using immutable storage and test incident-response, disaster-recovery and clinical-downtime procedures.

## Budget Implication

The seven highest-priority treatments are estimated at **$118,400**, fitting within the proposed **$120,000 annual security budget** and leaving approximately **$1,600** for contingency.

---

# 2. Scope and Methodology

## 2.1 Assessment Scope

The assessment covered the three MedDefense locations:

| Site                        | Primary Function                            | Approximate Staff |
| --------------------------- | ------------------------------------------- | ----------------: |
| MedDefense Central Hospital | 350-bed acute-care hospital                 |             1,400 |
| Westside Clinic             | Outpatient and diagnostic services          |               180 |
| Corporate HQ                | Administration, executive leadership and IT |               220 |

The assessment included:

* Servers and databases
* Clinical and administrative endpoints
* Network infrastructure
* VPN and firewall configuration
* Medical IoT and diagnostic systems
* EHR, PACS, billing and patient portal applications
* Backup and recovery infrastructure
* Cloud services
* Identity and access controls
* Physical security
* Sensitive data flows
* Existing security policies and processes
* Security incidents from the previous six months
* Shadow IT and undocumented systems

MedDefense reports approximately 2,000 employees, although the listed site counts total approximately 1,800. This difference remains unresolved.

## 2.2 Sources Reviewed

The assessment used:

* HR onboarding and site documentation
* Partial ServiceDesk asset inventory
* Organization chart
* Draft network diagram
* Marcus Webb’s security notes and draft assessment
* FortiGate firewall configuration
* SSH configuration
* Password policy
* Sophos deployment report
* Veeam backup configuration
* Physical security contract
* Security training records
* Log-management summary
* Internal network scan
* Security incident records
* Physical walk-through observations
* Healthcare breach case studies
* Interviews and informal disclosures from IT and helpdesk staff

## 2.3 Methodology

The assessment followed these steps:

1. Consolidated assets into an asset registry.
2. Rated asset criticality using Confidentiality, Integrity and Availability.
3. Identified existing security controls.
4. Classified controls by category and function.
5. Mapped sensitive data at rest, in transit and in use.
6. Compared required protection with actual control coverage.
7. Prioritized gaps using asset criticality, data sensitivity and control absence.
8. Validated priorities against recent healthcare breach patterns.
9. Selected risk treatments under a $120,000 budget constraint.

## 2.4 Limitations and Assumptions

* The original asset list was incomplete and outdated.
* Some systems may have been offline during the network scan.
* Several cloud services and medical-device systems may remain undocumented.
* The firewall export was partial.
* No formal HIPAA Security Rule assessment had previously been completed.
* Some findings depend on informal notes that require operational confirmation.
* Cost estimates are planning estimates rather than formal vendor quotations.
* Proposed MRI controls have not yet been implemented.
* The exact number of endpoints and medical devices remains approximate.

---

# 3. Asset Landscape

## 3.1 Inventory Summary

### By Asset Type

| Asset Type                      | Identified Scope                                                                                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Servers and data stores         | At least 14 known or detected systems, including EHR, PACS, billing, Active Directory, file, print, backup, web, Westside and unknown Linux systems |
| Endpoints                       | Approximately 485 workstations, 60 thin clients, 30 laptops and 25 iPads                                                                            |
| Network devices                 | FortiGate firewall, Cisco core and access switches, 12 UniFi access points, Westside router and unmanaged switch                                    |
| Medical and clinical devices    | Approximately 80 patient monitors, 120 infusion pumps, MRI, CT, X-ray systems and nurse-call equipment                                              |
| Applications and cloud services | EHR, PACS, billing, patient portal, O365, Sophos and Veeam                                                                                          |
| Physical infrastructure         | Server room, network closets, badge system, cameras and security-guard service                                                                      |
| Shadow IT                       | Personal NAS, personal Google Drive, Raspberry Pi and two unidentified Linux systems                                                                |

### By Site

| Site             | Main Assets                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Central Hospital | Core servers, databases, network infrastructure, approximately 320 workstations, 60 thin clients, 25 iPads and most medical devices |
| Westside Clinic  | Local server, approximately 45 workstations, X-ray workstation, consumer router, unmanaged switch and unknown Linux device          |
| Corporate HQ     | Approximately 120 workstations, 30 laptops, O365 access and landlord-managed network                                                |
| Cloud            | O365 and an unauthorized Marketing Google Drive                                                                                     |

The network scan confirmed two undocumented Linux systems and that logical IP subnets do not provide actual security separation. Systems across the internal environment were mutually reachable.

## 3.2 Top Five Critical Assets

### 1. EHR System

The EHR application and database support clinical decisions across the hospital. Loss of confidentiality would expose protected health information; incorrect records could affect diagnosis or treatment; and an outage would force clinicians to work with incomplete paper records.

### 2. Medical IoT and Clinical Devices

Patient monitors, infusion pumps and nurse-call systems directly support patient care. Unauthorized changes to readings or dosage information could create immediate patient-safety consequences.

### 3. Network Core and Connectivity

The firewall, switches, Wi-Fi and VPN connections support nearly every business and clinical system. Because the network is flat, compromise of the core environment could affect multiple sites and clinical services simultaneously.

### 4. Identity and Access Infrastructure

Active Directory controls user access to clinical, administrative and physical systems. A domain compromise could allow attackers to create accounts, change privileges and distribute malware throughout the organization.

### 5. PACS and Imaging Infrastructure

PACS stores and transfers diagnostic images from MRI, CT, X-ray and other imaging systems. The MRI performs approximately 45 studies daily, and the PACS server is not included in the current backup process.

## 3.3 Data Classification Summary

| Classification | Main MedDefense Data                                                                                                                     |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Restricted     | Patient records, medical images, monitoring data, medication information, credentials, Social Security numbers and insurance information |
| Confidential   | Employee records, salaries, contracts, financial documents, legal records, audit logs and security information                           |
| Internal       | Internal memos, organization charts, meeting notes and routine operational documents                                                     |
| Public         | Approved website content, public contact information and published communications                                                        |

The widest data-protection weakness affects **Restricted patient and clinical data** moving through and being used on the flat network. Database access is broad, clinical sessions may remain unlocked, medical devices are exposed and centralized detection is absent.

---

# 4. Current Security Controls

## 4.1 Control Inventory Summary

The assessment identified:

* **23 existing controls**
* **5 proposed MRI compensating controls**
* **28 total documented controls**

### Existing Controls by Category

| Category                    |  Count |
| --------------------------- | -----: |
| Technical                   |     15 |
| Administrative              |      4 |
| Physical                    |      4 |
| **Total existing controls** | **23** |

### Existing Controls by Function

| Function     | Count |
| ------------ | ----: |
| Preventive   |    13 |
| Detective    |     8 |
| Corrective   |     1 |
| Compensating |     0 |
| Deterrent    |     1 |

## 4.2 Overall Maturity Assessment

MedDefense’s control environment is **initial and reactive**.

The organization has several useful preventive controls:

* FortiGate firewall with a default-deny rule
* Site-to-site VPNs
* SSH key authentication on one server
* Active Directory password and lockout settings
* Sophos protection on many Windows workstations
* Daily backups for selected systems
* Physical guards and cameras at selected entrances

However, the environment is significantly weaker in:

* Centralized detection and alerting
* Internal network segmentation
* Medical-device protection
* MFA
* Server endpoint protection
* Incident response
* Disaster recovery
* Compensating controls for legacy systems
* Change management
* Account lifecycle management
* Data loss prevention
* Shadow IT governance

## 4.3 Key Control Effectiveness Findings

### Strong or Effective Controls

* Default-deny perimeter firewall rule
* SSH key authentication and disabled root login on `ehr-srv-01`
* Sophos blocking and quarantine capability on managed workstations

### Controls with Important Limitations

* VPNs permit all services to the server subnet.
* Internal outbound traffic is unrestricted.
* Sophos does not protect Windows or Linux servers.
* MFA is recommended but not required.
* Backups are local and incomplete.
* PACS, Westside, O365 and medical-device configurations are not backed up.
* Logs exist but are not centralized or actively reviewed.
* Physical cameras do not cover server or network areas.
* Security training completion is low at Central and Westside.
* The password policy is outdated and inconsistently applied.

The control artifacts confirm that only 341 of 387 managed endpoints had current Sophos signatures, no servers were protected, backups were local-only, and no full disaster-recovery test had been completed.

---

# 5. Gap Analysis

The completed analysis identified **24 material gaps**:

| Risk Level | Number |
| ---------- | -----: |
| Critical   |     18 |
| High       |      6 |
| Medium     |      0 |
| Low        |      0 |
| **Total**  | **24** |

## 5.1 Critical Gaps

| Gap         | Description                                    | Affected Assets                                            | Potential Impact                                                             | Recommended Treatment                                          |
| ----------- | ---------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **GAP-001** | No internal network segmentation               | EHR, PACS, Active Directory, medical devices, network core | One compromised system could provide access to the full hospital environment | Mitigate through VLANs and internal firewall rules             |
| **GAP-002** | Medical devices exposed to wider network       | Monitors, pumps, MRI, nurse call                           | Device manipulation, patient-data exposure or interruption of patient care   | Mitigate through isolation, access restrictions and monitoring |
| **GAP-003** | PACS not backed up                             | PACS and imaging data                                      | Loss of diagnostic images and delays to clinical diagnosis                   | Mitigate through dedicated protected backup capacity           |
| **GAP-004** | Backups not isolated or offsite                | EHR, billing, AD, files, portal                            | Ransomware or physical incident could destroy production and recovery copies | Mitigate using immutable offsite replication                   |
| **GAP-005** | No centralized monitoring                      | All critical systems                                       | Attackers could remain undetected while moving laterally or stealing data    | Mitigate using centralized logging and alerting                |
| **GAP-006** | No incident-response or disaster-recovery plan | All sites and services                                     | Delayed containment, extended outages and regulatory mistakes                | Mitigate with tested plans and exercises                       |
| **GAP-007** | Weak privileged and remote authentication      | VPN, EHR, O365, administrators                             | Stolen credentials could provide direct access to Restricted data            | Mitigate with MFA and privileged-account controls              |
| **GAP-008** | No server endpoint protection                  | EHR, billing, PACS, AD, file and web servers               | Malware could run without prevention or detection                            | Mitigate through server EDR or equivalent controls             |
| **GAP-009** | Unsupported systems remain active              | MRI, billing server, print server                          | Exploitation of known vulnerabilities and clinical disruption                | Mitigate through isolation and compensating controls           |
| **GAP-010** | Shadow IT on internal network                  | Network core and sensitive data stores                     | Unmanaged systems could expose data or provide an attacker foothold          | Migrate, decommission and introduce approval controls          |
| **GAP-012** | Weak physical protection of IT areas           | Server room, switches, backups                             | Theft, tampering or intentional outage may not be detected                   | Mitigate with restricted badges, locks and cameras             |
| **GAP-013** | EHR and database access too broad              | EHR application and PostgreSQL database                    | Unauthorized access to or alteration of patient records                      | Restrict network and session access                            |
| **GAP-015** | No formal perimeter patch management           | VPN, firewall and public systems                           | Known vulnerabilities may provide external entry                             | Implement emergency patch and vulnerability process            |
| **GAP-016** | No automated employee offboarding              | AD, VPN, EHR and O365                                      | Former employees may retain access to patient and business data              | Integrate HR termination and account deactivation              |
| **GAP-017** | No DLP or export monitoring                    | EHR, file shares, O365 and HR systems                      | Large volumes of sensitive information could leave undetected                | Implement DLP and unusual-export alerts                        |
| **GAP-018** | Default and vendor credentials not governed    | Medical devices and vendor systems                         | Immediate unauthorized access to clinical devices                            | Change defaults and manage vendor access                       |
| **GAP-019** | DMZ outbound access not verified or restricted | Patient portal and internal systems                        | Compromised portal could become a bridge into clinical systems               | Restrict DMZ-to-internal communication                         |
| **GAP-024** | No formal change management                    | EHR, backups, servers and networks                         | Untested changes may cause outages, data corruption or security weaknesses   | Establish approval, testing and rollback process               |

## 5.2 High Gaps

| Gap         | Description                              | Affected Assets                       | Potential Impact                                                      | Recommended Treatment                                   |
| ----------- | ---------------------------------------- | ------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------- |
| **GAP-011** | Marketing data in personal Google Drive  | Marketing and communications          | Loss, disclosure or unauthorized alteration of company communications | Migrate to managed O365 storage                         |
| **GAP-014** | Incomplete security training             | Staff, email and clinical systems     | Phishing, mishandling of PHI and slow incident reporting              | Enforce completion and introduce role-specific training |
| **GAP-020** | Weak Westside Clinic security            | Westside router, server and VPN       | Compromise of Westside could provide access to Central                | Install managed firewall, lock closet and restrict VPN  |
| **GAP-021** | TLS 1.0 enabled on patient portal        | Web server and patient portal         | Weakened protection of patient communications                         | Disable deprecated protocols                            |
| **GAP-022** | Unrestricted USB storage                 | Clinical and administrative endpoints | Malware introduction or removal of Restricted data                    | Apply GPO and removable-media controls                  |
| **GAP-023** | Limited oversight of HQ landlord network | HQ endpoints and VPN                  | Third-party network weakness could affect HQ and Central              | Establish contractual and technical assurance controls  |

## 5.3 Gap Distribution Analysis

The greatest concentration of gaps is in:

* Network architecture
* Medical-device security
* Identity and access management
* Detection and monitoring
* Backup and recovery
* Administrative corrective processes

MedDefense is more **prevention-oriented than detection- or recovery-oriented**. If a preventive control is bypassed, the organization has limited ability to identify the attacker, contain the incident or restore operations confidently.

---

# 6. Risk Treatment Recommendations

## 6.1 Seven Priority Recommendations

| Priority | Gap     | Treatment | Recommended Action                                                   | Estimated Cost | Timeline                  |
| -------: | ------- | --------- | -------------------------------------------------------------------- | -------------: | ------------------------- |
|        1 | GAP-001 | Mitigate  | Segment internal network using VLANs and internal firewall policies  |        $30,000 | Long-term, over 1 month   |
|        2 | GAP-002 | Mitigate  | Isolate and monitor medical devices; restrict required communication |        $15,000 | Long-term, over 1 month   |
|        3 | GAP-004 | Mitigate  | Replicate backups to immutable offsite storage                       |        $14,400 | Short-term, under 1 month |
|        4 | GAP-005 | Mitigate  | Deploy centralized logging and alerting using a lower-cost platform  |        $22,000 | Long-term, over 1 month   |
|        5 | GAP-006 | Mitigate  | Develop and test incident-response and disaster-recovery plans       |        $12,000 | Short-term, under 1 month |
|        6 | GAP-007 | Mitigate  | Require MFA and improve privileged-account management                |        $17,000 | Short-term, under 1 month |
|        7 | GAP-015 | Mitigate  | Establish formal perimeter vulnerability and patch management        |         $8,000 | Quick win, under 1 week   |
|          |         |           | **Total**                                                            |   **$118,400** |                           |

## 6.2 Budget Allocation

| Security Initiative                     |   Allocation |
| --------------------------------------- | -----------: |
| Internal network segmentation           |      $30,000 |
| Medical-device isolation and monitoring |      $15,000 |
| Offsite immutable backups               |      $14,400 |
| Centralized security monitoring         |      $22,000 |
| Incident response and disaster recovery |      $12,000 |
| MFA and privileged-account controls     |      $17,000 |
| Perimeter patch management              |       $8,000 |
| **Total recommended spending**          | **$118,400** |
| **Remaining contingency**               |   **$1,600** |

## 6.3 Quick Wins — Within One Week

### Perimeter Patch and Vulnerability Process

* Assign system owners.
* Review firewall, VPN and patient portal updates.
* Define emergency patch deadlines.
* Document exceptions and temporary restrictions.

**Gap addressed:** GAP-015

### Disable TLS 1.0

* Confirm application compatibility.
* Disable deprecated TLS on the patient portal.

**Gap addressed:** GAP-021
**Expected cost:** Minimal internal effort

### Remove Exposed Credentials

* Remove network credentials from the unlocked closet.
* Change affected switch credentials.
* Change the shared Radiology password.
* Identify and change medical-device default credentials where supported.

**Gaps addressed:** GAP-007 and GAP-018

### Secure Physical Access

* Lock the network closet.
* Stop using a generic badge for server-room access.
* Introduce a temporary entry log.

**Gap addressed:** GAP-012

### Contain Shadow IT

* Disconnect unknown devices after preserving evidence.
* Move Marketing data from personal Google Drive.
* Identify and isolate the Cardiology NAS.

**Gaps addressed:** GAP-010 and GAP-011

## 6.4 Short-Term Priorities — Within One Month

### MFA Deployment

Implement MFA for:

* VPN access
* O365
* Administrative accounts
* Remote access
* EHR administrators where supported

**Gap addressed:** GAP-007

### Offsite Backup Replication

* Create an immutable offsite copy.
* Protect backup administrator accounts.
* Test restoration from the remote copy.

**Gap addressed:** GAP-004

### Incident-Response and Recovery Planning

Develop:

* Ransomware playbook
* Patient-data breach playbook
* Medical-device incident procedure
* Clinical downtime process
* Communication and regulatory-notification process

**Gap addressed:** GAP-006

### Restrict Database and VPN Access

* Limit PostgreSQL access to required application servers.
* Review MySQL requirements.
* Replace “ALL services” VPN rules with least-privilege rules.

**Gaps addressed:** GAP-013 and GAP-020

## 6.5 Long-Term Roadmap

### Network Segmentation

Implement separate zones for:

* Servers
* Clinical endpoints
* Medical devices
* Administrative endpoints
* Guest Wi-Fi
* Westside Clinic
* Corporate HQ
* Management systems

**Gap addressed:** GAP-001

### Medical-Device Security Program

* Isolate devices.
* Inventory firmware and ownership.
* Control vendor access.
* Monitor traffic.
* Document unpatchable systems.
* Coordinate with biomedical engineering.

**Gaps addressed:** GAP-002, GAP-009 and GAP-018

### Centralized Detection

* Collect firewall, Active Directory, server and application logs.
* Create alerts for unusual logins, lateral movement and data exports.
* Assign staff responsibility for alert review.

**Gap addressed:** GAP-005

## 6.6 Deferred Items

The following should be scheduled for the next fiscal period unless savings become available:

* Server endpoint detection and response
* PACS backup expansion
* Automated account offboarding
* DLP
* USB control
* Physical camera expansion
* Full shadow IT discovery and network access control
* Westside firewall replacement
* Security-awareness program expansion

These remain important and should be formally tracked in the risk register.

---

# 7. Conclusion and Next Steps

MedDefense’s current security posture creates a material risk to patient care, protected health information, revenue and organizational continuity. The organization has invested in several security tools, but the controls operate as separate measures rather than as a coordinated security program. A flat network, exposed medical devices, weak identity controls, limited monitoring and fragile recovery arrangements allow a single compromise to develop into an organization-wide incident.

If the recommended actions are not implemented, MedDefense should expect continued malware infections, unauthorized access and service outages. A more capable ransomware incident could affect the EHR, PACS, Active Directory, medical devices and backups simultaneously, causing prolonged clinical disruption, regulatory investigation, patient notification, litigation and significant recovery costs.

Approval of the proposed **$120,000 security budget** would allow MedDefense to address the most dangerous attack paths within the current fiscal year. The recommended program does not remove all risk, but it would substantially reduce the likelihood that one compromised system causes a hospital-wide event and would improve the organization’s ability to detect and recover from attacks.

## Next Phase: External Threat Landscape Assessment

This assessment explains MedDefense’s internal weaknesses. The next phase should identify the external actors most likely to exploit them.

The External Threat Landscape Assessment should:

* Identify relevant ransomware, cybercriminal, insider and hacktivist threats.
* Review common healthcare attack techniques.
* Map MITRE ATT&CK techniques to MedDefense systems and gaps.
* Apply STRIDE to the EHR, VPN, patient portal, PACS and Medical IoT architecture.
* Use CISA, HHS 405(d), HC3 and vendor threat intelligence.
* Develop realistic attack scenarios for tabletop exercises and investment planning.

Marcus Webb correctly identified that internal posture and external threat intelligence are two parts of the same risk picture. His draft highlighted the same major themes confirmed by this assessment: flat networking, weak MFA, medical-device exposure, inadequate monitoring and fragile recovery arrangements.

**Final assessment:** MedDefense requires immediate executive action. The recommended investments are proportionate to the organization’s clinical responsibilities and materially less costly than the operational, regulatory and patient-safety consequences of a major breach.

