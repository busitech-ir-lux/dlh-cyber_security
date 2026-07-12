# The Shadow Systems

## 1. Personal NAS in Cardiology

### Risk Assessment

**Possible sensitive data:**
The NAS may contain cardiology research data, patient information, medical images, study results or other protected health information.

**Controls that do not cover it:**
Because it is a personal device, it may not be covered by:

* Sophos endpoint protection
* Central logging and monitoring
* Official backup procedures
* Access reviews
* Password policy enforcement
* Vulnerability management
* Asset management
* Data-retention and deletion rules

**Worst-case scenario:**
If the NAS is compromised, patient or research data could be stolen, changed or deleted. An attacker could also use the NAS as a starting point to access other systems on the flat hospital network.

### Recommended Response

**Strategy: Migrate**

The data should be moved to an approved hospital file server or research storage system. The personal NAS should then be securely erased and disconnected.

This is the best option because the NAS was introduced only because the approved shared drive was considered too slow. The correct solution is to provide suitable approved storage, not to keep an unmanaged personal device connected to the hospital network.

---

## 2. Marketing Google Drive Linked to Personal Gmail

### Risk Assessment

**Possible sensitive data:**
The Google Drive may contain:

* Press communications
* Marketing plans
* Internal announcements
* Contact information
* Draft public statements
* Crisis communication documents
* Photos or media that have not yet been approved for release

Some files may be Public, but unpublished material and internal communications are likely Confidential or Internal.

**Controls that do not cover it:**
The service is probably not covered by:

* MedDefense account management
* Active Directory password controls
* Official MFA requirements
* O365 administration
* Access reviews
* Data-retention rules
* Backup procedures
* Audit logging
* Employee departure procedures
* Legal hold or e-discovery controls

**Worst-case scenario:**
If the personal Gmail account is compromised or the account owner leaves, MedDefense could lose access to its files. An attacker could leak confidential communications, publish false statements or modify official media content.

### Recommended Response

**Strategy: Migrate**

All files should be moved to an approved MedDefense O365 SharePoint or OneDrive location. Access should use organization-managed accounts.

The personal Google Drive should then be reviewed, securely emptied and no longer used for MedDefense work.

---

## 3. Raspberry Pi Network Monitor

### Risk Assessment

**Possible sensitive data or access:**
The Raspberry Pi may collect or provide access to:

* Network traffic
* IP addresses
* Hostnames
* Device information
* Open ports
* Network credentials
* Security logs
* Medical-device traffic
* Internal network architecture

Because it may have been used as a network monitor, it could have visibility into many systems.

**Controls that do not cover it:**
The device may not be covered by:

* Sophos endpoint protection
* Patch management
* Central log monitoring
* Account management
* Configuration standards
* Vulnerability scanning
* Backup procedures
* Documented ownership
* Physical access controls

**Worst-case scenario:**
If compromised, the Raspberry Pi could allow an attacker to monitor hospital traffic, collect credentials, map the network or move to servers and medical devices. Because the network is flat, the possible impact could affect Confidentiality, Integrity and Availability across the hospital.

### Recommended Response

**Strategy: Decommission**

The Raspberry Pi should be disconnected and preserved temporarily for investigation. IT should determine:

* what software it runs;
* whether it stores logs or credentials;
* whether it was communicating externally;
* whether it has been compromised.

After useful data is safely collected, the device should be securely erased and removed unless there is a clear business need to rebuild it as an approved, managed monitoring system.

---

# Asset Registry Update

| Asset ID | Name                          | Type           | Location                             | Owner                            | OS / Platform                    | Critical Services                    | Network Segment          | Status    | Notes                                                                                               |
| -------- | ----------------------------- | -------------- | ------------------------------------ | -------------------------------- | -------------------------------- | ------------------------------------ | ------------------------ | --------- | --------------------------------------------------------------------------------------------------- |
| A-043    | Cardiology Personal NAS       | Data Store     | Dr. Patel’s office, Central Hospital | Cardiology / Dr. Patel           | Unknown NAS platform             | Research data storage                | Central internal network | Shadow IT | Personally purchased device; may contain research or patient data; not approved or managed by IT.   |
| A-044    | Marketing Shared Google Drive | Application    | Cloud                                | Marketing / Personal Gmail owner | Google Drive                     | Media files and press communications | Internet / Cloud         | Shadow IT | Linked to a personal Gmail account; not managed through MedDefense O365 or organizational accounts. |
| A-045    | Second-Floor Raspberry Pi     | Network Device | Second floor, Central Hospital       | Unknown / Previous intern        | Raspberry Pi OS or unknown Linux | Possible network monitoring          | Central internal network | Shadow IT | Ownership, configuration, patch status and purpose are unclear; may have broad network visibility.  |

# Shadow IT Policy Recommendation

MedDefense should introduce a formal **Technology and Cloud Service Approval Policy** requiring employees to obtain IT and Security approval before connecting any device, application, storage service or cloud platform to MedDefense systems or using it for organizational data. The policy should also provide a simple request process, define approved alternatives and require regular network and cloud-service reviews, because employees are more likely to bypass security when approved tools are too slow, difficult to use or unavailable.

