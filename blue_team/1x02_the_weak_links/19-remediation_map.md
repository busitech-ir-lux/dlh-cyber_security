# The Remediation Map

## Finding 001 — CVE-2021-44790

**Response Type:** Patch

**Patch Source:** Apache security updates:  
[https://httpd.apache.org/security/vulnerabilities_24.html](https://httpd.apache.org/security/vulnerabilities_24.html)

**Prerequisites:** Back up the server and Apache configuration, test the billing application with the updated Apache version and schedule a maintenance window.

**Rollback Plan:** Restore the previous virtual-machine snapshot or reinstall the previous Apache package and configuration.

**Operational Risk:** The update could break `mod_lua`, application modules or billing-system integrations.

**Timeline:** Immediate  
**Owner:** IT and application vendor  
**Cost Estimate:** $1–10K

Apache lists CVE-2021-44790 among vulnerabilities corrected through updated Apache HTTP Server releases.

---

## Finding 002 — CVE-2019-0211

**Response Type:** Patch

**Patch Source:** Upgrade Apache HTTP Server to a supported release through the Ubuntu package manager or application vendor.

[https://httpd.apache.org/security/vulnerabilities_24.html](https://httpd.apache.org/security/vulnerabilities_24.html)

**Prerequisites:** Complete the Finding 001 application test, back up the system and verify compatibility with the billing application.

**Rollback Plan:** Restore the server snapshot or return to the previous package version if the application fails.

**Operational Risk:** Apache modules or custom scripts may stop working after the upgrade.

**Timeline:** Immediate  
**Owner:** IT and application vendor  
**Cost Estimate:** $1–10K

Apache states that CVE-2019-0211 affects versions 2.4.17–2.4.38 and was corrected in Apache 2.4.39.

---

## Finding 004 — Windows XP MRI Workstation

**Response Type:** Compensating Control

**Control Description:** Place `WS-RAD-01` in a dedicated medical-device VLAN. Allow only required communication with PACS and management systems. Block SMB, RDP and internet access from all other networks. Add network intrusion monitoring and application allowlisting.

**Residual Risk:** Windows XP remains permanently vulnerable. An attacker who reaches the medical-device VLAN or uses an authorized connection could still exploit the workstation.

**Timeline:** Immediate  
**Owner:** Security, IT, clinical engineering and MRI vendor  
**Cost Estimate:** $10–50K

---

## Finding 005 — Obsolete TLS on Patient Portal

**Response Type:** Configuration Change

**Change Description:** Disable TLS 1.0 and TLS 1.1. Permit only TLS 1.2 and TLS 1.3 with approved cipher suites.

**Impact Assessment:** Very old browsers, operating systems or third-party clients may no longer connect. Access logs should be reviewed before the change to identify incompatible users.

**Timeline:** 7 days  
**Owner:** IT and web-application vendor  
**Cost Estimate:** $0–1K

---

## Finding 008 — CVE-2021-34527 PrintNightmare

**Response Type:** Patch

**Patch Source:** Microsoft Security Update Guide and Windows Update:

[https://msrc.microsoft.com/update-guide/](https://msrc.microsoft.com/update-guide/)

**Prerequisites:** Back up the print server, document printer queues and drivers, test the update on a non-production server and schedule the change outside clinical working hours.

**Rollback Plan:** Restore the server snapshot and printer configuration. Keep network access restricted if the update must be removed.

**Operational Risk:** Printer drivers, queues or clinical printing workflows may stop functioning.

**Timeline:** Immediate  
**Owner:** IT  
**Cost Estimate:** $1–10K

Microsoft maintains applicable security fixes and deployment information through its Security Update Guide.

---

## Finding 010 — BD Alaris Network Weakness

**Response Type:** Compensating Control

**Control Description:** Confirm the exact firmware with BD, replace default credentials and isolate the pumps in a dedicated medical-device VLAN. Permit communication only with the Alaris management server, approved clinical systems, DNS and time services.

**Residual Risk:** Firmware or device-level weaknesses remain until the vendor confirms that every pump is running a corrected and supported version. A compromised authorized management system could still reach the pumps.

**Timeline:** Immediate  
**Owner:** Clinical engineering, Security and BD vendor  
**Cost Estimate:** $10–50K

---

## Finding 029 — CVE-2021-43798 Grafana

**Response Type:** Patch

**Patch Source:** Upgrade Grafana through the operating-system package manager or official Grafana repository:

[https://grafana.com/security/security-advisories/cve-2021-43798/](https://grafana.com/security/security-advisories/cve-2021-43798/)

**Prerequisites:** Identify the asset owner, back up Grafana configuration, dashboards, plug-ins and databases, and test plug-in compatibility.

**Rollback Plan:** Restore the Grafana backup or previous virtual-machine snapshot. Restrict access until a safe version can be restored.

**Operational Risk:** Dashboards, data-source connections or third-party plug-ins may fail after the upgrade.

**Timeline:** Immediate  
**Owner:** IT and Security  
**Cost Estimate:** $1–10K

---

## Finding 031 — CVE-2020-1938 Ghostcat

**Response Type:** Patch

**Patch Source:** Upgrade Apache Tomcat using the operating-system package manager or official Tomcat release:

[https://tomcat.apache.org/security-9.html](https://tomcat.apache.org/security-9.html)

**Prerequisites:** Back up the EHR application, Tomcat configuration and database connection settings. Test the application with the corrected Tomcat version and schedule an approved EHR maintenance window.

**Rollback Plan:** Restore the previous Tomcat installation and application backup. Keep AJP port 8009 blocked during rollback.

**Operational Risk:** The EHR application may fail to start, lose database connectivity or become temporarily unavailable.

**Timeline:** Immediate  
**Owner:** IT, EHR vendor and clinical operations  
**Cost Estimate:** $10–50K

As an immediate configuration safeguard, disable the AJP connector if it is not required. If it is required, bind it to localhost or an approved application address, require a secret and block port 8009 at the firewall.
