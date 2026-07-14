# MedDefense Technical Vector Assessment

## 1. Vulnerable Software

**Vector Category:** Vulnerable Software

**MedDefense Evidence:**
`billing-srv-01` runs Apache 2.4.29 on Ubuntu 18.04. Standard Ubuntu support ended in June 2023, and extended support is not enabled. The server was previously compromised by an automated exploit and used for cryptocurrency mining.
**Affected Assets:**
`billing-srv-01`, billing records, financial services and other internal systems reachable from the server.

**Actor Most Likely to Exploit:**
Unskilled or opportunistic attacker. Automated scanners search the internet for known vulnerable software. Ransomware groups could also purchase or reuse this access.

**Exploitation Scenario:**
An attacker scans for Apache 2.4.29, exploits the known weakness and installs malware on `billing-srv-01`. Because the network is flat, the attacker could then scan internal servers and attempt to reach Active Directory or the EHR environment.

**Current Protection:**
The FortiGate protects the perimeter and stores traffic logs. However, Sophos protection is not installed on Windows or Linux servers, and logs are not reviewed centrally.

**Gap Reference:**
No separate patch-management Gap ID was created. The risk is increased by **M-01: Network Segmentation** and **M-04: Absence of Monitoring and Detection**.

---

## 2. Unsupported Systems

**Vector Category:** Unsupported Systems

**MedDefense Evidence:**
The MRI workstation `WS-RAD-01` runs Windows XP SP3 and exposes ports 135, 139 and 445. `print-srv-01` runs Windows Server 2012 R2, which reached end of support in October 2023.

**Affected Assets:**
MRI operations, PACS and imaging data, the print server and any internal systems reachable from these devices.

**Actor Most Likely to Exploit:**
Unskilled or opportunistic attacker.

**Exploitation Scenario:**
An attacker who compromises an internal workstation scans for old Windows systems and exploits an unpatched SMB or RPC weakness. The unsupported system becomes a weak foothold for credential theft and movement toward more valuable servers.

**Current Protection:**
Both systems are internal rather than directly internet-facing. Some workstations have Sophos protection, but current endpoint coverage does not include servers, and support for Windows XP is limited.

**Gap Reference:**
**M-08: Print Server End of Life** covers `print-srv-01`. The MRI workstation is also affected by **M-01** and the medical-device concerns in **M-03**.

---

## 3. Open Service Ports

**Vector Category:** Open Service Ports

**MedDefense Evidence:**

* MySQL port **3306** on `billing-srv-01` is accessible network-wide.
* PostgreSQL port **5432** on `ehr-db-01` is accessible network-wide.
* RDP port **3389** is enabled on reception, administrative and Westside systems.
* NAS management ports **5000/5001** are accessible throughout the network.
* Medical devices expose HTTP/HTTPS management interfaces on ports **80/443**.
* PACS exposes ports **4242** and **11112**.
  **Affected Assets:**
  EHR database, billing database, backup NAS, workstations, PACS and connected medical devices.

**Actor Most Likely to Exploit:**
Ransomware groups, especially after gaining access through phishing, VPN credentials or vulnerable software.

**Exploitation Scenario:**
After entering through one device, a ransomware affiliate scans the network for databases, RDP and management interfaces. The attacker uses these services to steal data, move between systems and locate backups before deploying ransomware.

**Current Protection:**
Services still require normal application or operating-system authentication. The FortiGate blocks unapproved external traffic, but there are no internal firewall rules between devices.

**Gap Reference:**
**M-01: Network Segmentation**, **M-03: Medical IoT Exposure** and **M-06: Westside Clinic Security**.

---

## 4. Default Credentials

**Vector Category:** Default Credentials

**MedDefense Evidence:**
Many medical devices have web interfaces that may use default credentials. The BD Alaris pumps run firmware 12.1.2 and have not been isolated as recommended by the vendor. Radiology also uses the shared PACS account `raduser/radiology1`.

**Affected Assets:**
BD Alaris pumps, Philips monitors, PACS imaging systems and patient information.

**Actor Most Likely to Exploit:**
Unskilled or opportunistic attacker.

**Exploitation Scenario:**
An attacker who reaches the internal network tries common vendor usernames and passwords against medical-device interfaces. Successful access could allow configuration changes, data access or use of the device as a path toward other systems.

**Current Protection:**
MedDefense has an eight-character password policy and account lockout for Active Directory systems. However, the policy permits shared accounts when individual accounts are considered difficult to use.

**Gap Reference:**
**M-03: Medical IoT Exposure**, **M-07: Shared Credentials in Radiology** and **M-05: No MFA**.

---

## 5. Unsecure Networks

**Vector Category:** Unsecure Networks

**MedDefense Evidence:**
All Central, Westside and HQ subnets were reachable from a single HQ workstation without restriction. There are no VLANs or internal firewalls. Westside uses a consumer Netgear router with no managed firewall, and the VPN allows all services toward the Central server subnet. The wireless access points were identified, but wireless client isolation and security configuration were not documented.
**Affected Assets:**
EHR servers, Active Directory, medical devices, backup infrastructure, PACS, workstations and Westside systems.

**Actor Most Likely to Exploit:**
Ransomware groups.

**Exploitation Scenario:**
An attacker compromises a Westside workstation, wireless device or consumer router. The broad site-to-site VPN and flat network then allow the attacker to scan Central systems, steal credentials and reach critical servers.

**Current Protection:**
The FortiGate provides perimeter filtering, and the sites communicate through encrypted VPN tunnels. However, VPN rules allow all services and do not apply least privilege.

**Gap Reference:**
**M-01: Network Segmentation** and **M-06: Westside Clinic Security**.

---

## 6. Removable Devices and Unmanaged Endpoints

**Vector Category:** Removable Devices

**MedDefense Evidence:**
USB storage is not restricted through Group Policy, and no DLP system detects files copied to USB, email or cloud storage. Physician iPads are unmanaged because no MDM system is deployed. Personal and unknown devices have also appeared on the network, including Dr. Patel’s NAS and undocumented Linux devices at `10.10.2.99` and `10.10.10.200`.
**Affected Assets:**
Patient records, research files, employee information, EHR data and the internal network.

**Actor Most Likely to Exploit:**
A malicious insider is most likely to misuse removable storage. Negligent insiders may also create exposure through lost devices or shadow IT.

**Exploitation Scenario:**
An employee copies patient records to a USB drive or personal NAS without creating a security alert. An unmanaged device could also introduce malware and, because the network is flat, provide an attacker with access to critical systems.

**Current Protection:**
Sophos protects most managed Windows workstations and may detect some malware. It does not manage mobile devices, servers or personal storage devices.

**Gap Reference:**
These are **unnumbered First Watch findings** covering unrestricted USB access, no DLP, no MDM and shadow IT. Their impact is increased by **M-01** and **M-04**.

