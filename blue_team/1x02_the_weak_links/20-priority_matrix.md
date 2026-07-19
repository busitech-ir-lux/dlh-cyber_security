# The Priority Matrix

This matrix includes **27 actionable findings**: 7 Actionable Critical and 20 Actionable Standard. Finding 027 is treated as Informational because inactive endpoint agents require investigation before remediation.

## Immediate — 24–48 Hours

|Finding|Description|Remediation Action|Owner|Estimated Cost|
|---|---|---|---|--:|
|001|Apache remote code execution on `billing-srv-01`|Patch Apache after application testing and back up the billing server before deployment.|IT / Billing Vendor|$1–10K|
|002|Apache local privilege escalation on `billing-srv-01`|Apply the supported Apache package update together with Finding 001.|IT / Billing Vendor|$0–1K|
|003|EHR PostgreSQL database reachable from all `10.10.0.0/16` hosts|Restrict database access to `ehr-srv-01` and approved administrative systems only.|IT / Security|$0–1K|
|004|Unsupported Windows XP MRI workstation with weaponized vulnerabilities|Immediately isolate it in a medical-device VLAN and block SMB, RDP and internet access except where explicitly required.|Security / Clinical Engineering / Vendor|$10–50K|
|007|LDAP signing disabled and SMBv1 enabled on the domain controller|Require LDAP signing, disable SMBv1 and test all dependent applications.|IT / Security|$0–1K|
|008|PrintNightmare and unsupported Windows Server 2012 R2|Apply all available security updates, restrict spooler access and begin migration planning.|IT|$1–10K|
|010|BD Alaris pumps with weak isolation and default credentials|Replace default credentials, verify firmware and isolate pumps in a dedicated medical-device VLAN.|Clinical Engineering / Security / BD|$10–50K|
|029|Undocumented Grafana server with unauthenticated file-read vulnerability|Isolate the host, identify its owner and upgrade Grafana to a fixed version.|IT / Security|$1–10K|
|031|Ghostcat vulnerability on `ehr-srv-01`|Patch Tomcat, disable or restrict AJP port 8009 and rotate exposed application credentials.|IT / EHR Vendor|$10–50K|

**Immediate estimated cost:** **$33–183K**

---

## Short-Term — Within 7 Days

|Finding|Description|Remediation Action|Owner|Estimated Cost|
|---|---|---|---|--:|
|005|Obsolete TLS protocols on the internet-facing patient portal|Disable TLS 1.0 and 1.1 and permit only approved TLS 1.2 and 1.3 configurations.|IT / Web Vendor|$0–1K|
|006|Billing MySQL service reachable from the entire internal network|Bind MySQL to the required interface and restrict port 3306 with firewall rules.|IT / Billing Vendor|$0–1K|
|009|SSH password authentication and no effective lockout|Require SSH keys, disable password authentication and deploy rate limiting or Fail2ban.|IT / Security|$0–1K|
|011|Ubuntu 18.04 billing server without ESM|Activate Ubuntu Pro ESM immediately and prepare migration to a supported Ubuntu LTS version.|IT / Billing Vendor|$1–10K|
|015|NAS administration and unencrypted backups exposed on the flat network|Restrict management access, encrypt backup data and introduce offline or immutable backups.|IT / Security|$10–50K|
|016|Philips IntelliVue web and HL7 interfaces accessible across the flat network|Place monitors in a dedicated VLAN and allow only required connections to approved clinical systems.|Clinical Engineering / Security / Philips|$10–50K|
|018|DES and RC4 Kerberos encryption enabled|Disable weak encryption after confirming that all service accounts and applications support AES.|IT / Security|$0–1K|
|028|Undocumented host exposing Cockpit, SSH and Jupyter|Isolate the system, identify its owner, remove unnecessary services and assess it for compromise.|IT / Security|$1–10K|

**Short-term estimated cost:** **$22–124K**

---

## Medium-Term — Within 30 Days

|Finding|Description|Remediation Action|Owner|Estimated Cost|
|---|---|---|---|--:|
|012|Missing HTTP security headers on the patient portal|Configure HSTS, CSP, X-Frame-Options and related browser security headers.|IT / Web Vendor|$0–1K|
|013|Patient portal TLS certificate nearing expiration|Renew the certificate and enable automated expiration monitoring and renewal.|IT|$0–1K|
|017|Tomcat version and stack-trace information disclosure|Disable detailed error pages, suppress version banners and remove unnecessary diagnostic output.|IT / EHR Vendor|$0–1K|
|019|RDP enabled across multiple workstations|Limit RDP to approved support systems through firewall rules and privileged access controls.|IT / Security|$1–10K|
|021|HTTP TRACE enabled on the patient portal|Disable the TRACE method in the web-server configuration.|IT / Web Vendor|$0–1K|
|023|Unrestricted USB storage on clinical workstations|Introduce removable-media controls, approved-device policies and endpoint logging.|IT / Security / Clinical|$1–10K|
|024|Unencrypted DICOM traffic between MRI and PACS|Implement DICOM TLS or isolate the traffic within a tightly controlled clinical VLAN.|Clinical Engineering / IT / Vendor|$1–10K|
|025|DNS zone transfers permitted too broadly|Restrict AXFR transfers to authorized secondary DNS servers only.|IT|$0–1K|
|026|Billing server kernel with numerous known vulnerabilities|Apply supported kernel updates through ESM and schedule a controlled server reboot.|IT / Billing Vendor|$1–10K|

**Medium-term estimated cost:** **$4–45K**

---

## Long-Term — Within 90 Days

|Finding|Description|Remediation Action|Owner|Estimated Cost|
|---|---|---|---|--:|
|014|Consumer-grade router terminates the Westside site-to-site VPN|Replace it with a centrally managed enterprise firewall and redesign the VPN with segmented access rules.|IT / Security / Network Vendor|$10–50K|

**Long-term estimated cost:** **$10–50K**

---

# Budget Summary

The total estimated remediation cost is approximately **$69–402K**. The minimum estimate is within the **$120,000 annual security budget**, but the realistic total could exceed it substantially because medical-device segmentation, backup redesign, EOL replacement and vendor-supported clinical changes are expensive.

The first budget allocation must cover Findings **001, 003, 004, 007, 008, 010, 029 and 031**, because they involve weaponized exploitation, critical assets, patient safety or direct paths to domain and EHR compromise. Low-cost configuration changes such as Findings 005, 006, 009, 012, 013, 017, 018, 021 and 025 should also be completed because they consume little budget.

The full MRI replacement, enterprise VPN redesign, advanced medical-device segmentation and complete backup modernization may need to be deferred or funded as separate capital projects. Deferral should apply only to the replacement or architectural work, not to immediate compensating controls such as VLAN isolation, firewall restrictions, credential changes and monitoring.
