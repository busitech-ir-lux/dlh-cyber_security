# The Validation Plan

## 1. Post-Patch Verification

### Finding 031 — Ghostcat on `ehr-srv-01`

**Validation checks:**

- Confirm Tomcat is updated to a fixed version.
    
- Rescan TCP port `8009`.
    
- Verify that AJP is disabled or restricted to approved systems.
    
- Confirm unauthenticated file-read testing no longer works.
    
- Verify that the EHR application starts correctly and can connect to the database.
    
- Confirm exposed application and database credentials were changed.
    

**Responsible:** IT Operations, EHR vendor and Security Analyst

---

### Findings 001 and 002 — Apache Vulnerabilities on `billing-srv-01`

**Validation checks:**

- Run `apache2 -v` or `httpd -v` and confirm the installed version is fixed.
    
- Verify that the updated Apache packages are installed.
    
- Confirm `mod_lua` is patched or disabled if not required.
    
- Rescan the Apache service with OpenVAS.
    
- Confirm tests for CVE-2021-44790 and CVE-2019-0211 no longer report vulnerability.
    
- Test billing functions, database connections and integrations.
    

**Responsible:** IT Operations, billing-system vendor and Security Analyst

---

### Finding 004 — Windows XP MRI Workstation

This system cannot be fully patched, so validation focuses on isolation.

**Validation checks:**

- From a normal workstation VLAN, confirm SMB port `445` and RDP port `3389` cannot be reached.
    
- Confirm the MRI workstation cannot access the internet.
    
- Verify that only approved PACS and vendor-management connections are permitted.
    
- Review firewall logs for blocked connection attempts.
    
- Test MRI and image-transfer workflows with Clinical Engineering.
    

**Responsible:** Network team, Clinical Engineering, MRI vendor and Security Analyst

---

## 2. Compensating Control Validation

### MRI Workstation

The Security Analyst should perform controlled network tests from the workstation, server and guest networks. Only documented clinical traffic should succeed. Firewall rules, VLAN membership and monitoring alerts should be reviewed monthly.

### Medical IoT Devices

For BD Alaris pumps and Philips IntelliVue monitors:

- confirm devices are placed in dedicated medical-device VLANs
    
- confirm default credentials have been removed
    
- verify firmware versions with the vendors
    
- test that only approved management, HL7, DICOM, DNS and time-server traffic is allowed
    
- confirm unauthorized systems cannot reach web or management interfaces
    
- complete clinical workflow testing after every network or firmware change
    

Residual risk must remain documented until the devices are replaced or fully patched.

---

## 3. Rescan Schedule

MedDefense should use the following schedule:

- **Weekly:** External and internet-facing systems
    
- **Monthly:** Full authenticated internal vulnerability scan
    
- **After every critical remediation:** Targeted rescan within 24 hours
    
- **Quarterly:** Medical-device and network-segmentation review
    
- **Annually:** Independent penetration test
    

Weekly external scans are necessary because exposed services are continuously targeted. Monthly authenticated scans provide enough frequency to detect missing patches and configuration drift without causing excessive operational disruption.

---

## 4. Continuous Intelligence

MedDefense should integrate threat intelligence into a weekly vulnerability-management meeting.

The Security Analyst should:

- review new CISA KEV entries daily or through automated alerts
    
- subscribe to Microsoft, Fortinet, Synology, Apache, Tomcat, Philips and BD advisories
    
- monitor NVD changes for technologies in the asset inventory
    
- compare new CVEs with installed software and firmware versions
    
- immediately escalate KEV-listed vulnerabilities affecting MedDefense assets
    
- update remediation priorities when active exploitation is reported
    

Any Critical KEV affecting an internet-facing or clinical system should trigger an emergency review within 24 hours.

---

## 5. Continuous Vulnerability Management Lifecycle

**Scan → Triage → Prioritize → Remediate → Validate → Repeat**

### Scan

The **Security Analyst** runs automated scans, asset discovery and targeted checks. Vendors assist with medical-device and proprietary-system assessments.

### Triage

The **Security Analyst** removes duplicates, investigates false positives and confirms affected versions and configurations.

### Prioritize

The **Security Analyst and Management** evaluate CVSS, asset criticality, CISA KEV status, exploit availability, kill-chain position and patient-safety impact.

### Remediate

**IT Operations** applies patches and configuration changes. **Vendors and Clinical Engineering** handle medical devices and specialized applications. **Management** approves downtime and funding.

### Validate

The **Security Analyst** rescans affected services, verifies versions, tests segmentation and confirms that vulnerabilities are no longer exploitable. IT and clinical teams perform functional testing.

### Repeat

The cycle restarts through scheduled scanning, new threat intelligence, configuration monitoring and periodic risk review. Findings remain open until technical validation confirms that the risk has been removed or formally accepted.
