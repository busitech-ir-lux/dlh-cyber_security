# The Insider File — MedDefense Analysis

## Scenario 1: The Shared Login

**Classification:** Negligent
The technicians are not trying to cause harm, but sharing credentials removes accountability and exposes patient information.

**Behavioral Indicators:**

* The same account is active across many shifts and technicians.
* PACS access cannot be connected to an individual employee.
* The account remains logged in while different users access patient records.

**Existing Control from 1x00:** Access Control and Password Management. The password policy discourages shared accounts, but still allows them when individual accounts are considered inconvenient.

**Gap Exploited:** **M-07: Shared Credentials in Radiology.** This finding states that `raduser/radiology1` prevents MedDefense from identifying who accessed specific imaging records.

**Recommended Mitigation:**
Implement individual smart-card or proximity-badge authentication on PACS workstations. This provides fast access while keeping a separate audit trail for each technician.

---

## Scenario 2: The Ghost Account

**Classification:** Malicious, provisionally
Using an account after the contract ended is unauthorized. However, it must still be confirmed whether the former contractor used it or whether someone stole the credentials.

**Behavioral Indicators:**

* The VPN account remained active after the contract end date.
* Three logins occurred during unusual off-hours.
* The account was used despite having no current business purpose.

**Existing Control from 1x00:** Account Management, VPN Logging and Access Reviews should cover this activity, but the controls are mainly manual.

**Gap Exploited:** No automated contractor offboarding, supported by **M-04: Absence of Monitoring and Detection** and **M-05: No MFA on Any System**. The VPN logs were not centrally reviewed, and a password alone was enough to authenticate.

**Recommended Mitigation:**
Connect HR and contractor records to an automated offboarding process that disables all accounts immediately when employment or a contract ends.

---

## Scenario 3: The Personal NAS

**Classification:** Negligent
Dr. Patel intended to make his work easier, but knowingly placed patient files on an unauthorized and unprotected device.

**Behavioral Indicators:**

* An unknown device or MAC address appears on the network.
* Large amounts of patient data are copied from the EHR or file server to one office network port.
* The device communicates using storage protocols such as SMB without appearing in the asset inventory.

**Existing Control from 1x00:** Asset Inventory, Acceptable Use and Data Protection controls should cover this device. However, MedDefense’s inventory is incomplete and unmanaged devices are not actively blocked.

**Gap Exploited:** The shadow IT finding from First Watch, combined with the undocumented gaps for **no DLP controls** and unrestricted movement of sensitive patient data. The assessment states that patient information can leave through email, USB or cloud services without detection.

**Recommended Mitigation:**
Deploy Network Access Control to block unknown devices until IT has approved and registered them.

---

## Scenario 4: The Curious Employee

**Classification:** Malicious
The clerk intentionally accessed a record without a job-related reason and disclosed private information to another person. Not changing the record does not make the access acceptable.

**Behavioral Indicators:**

* The clerk accessed a patient outside her registration duties.
* There was no treatment, billing or administrative relationship with the patient.
* A high-profile patient record was accessed shortly before information appeared on social media.

**Existing Control from 1x00:** EHR role-based access and application audit logging cover this activity. The EHR records access, but MedDefense must request log exports from the vendor and may wait 48 hours.

**Gap Exploited:** **M-04: Absence of Monitoring and Detection.** MedDefense has no centralized alerts for unusual EHR access, meaning inappropriate viewing may only be found after a complaint or public disclosure.

**Recommended Mitigation:**
Enable automated EHR alerts when employees access VIP records, employee records or patients with no treatment relationship.

---

## Scenario 5: The Overworked Admin

**Classification:** Negligent
The administrator wanted to reduce the backlog, but storing and emailing privileged credentials created a serious security exposure.

**Behavioral Indicators:**

* A plaintext file contains Active Directory administrator credentials.
* Administrative credentials or scripts are sent through email.
* Password reset activity suddenly comes from several users using the same privileged account.

**Existing Control from 1x00:** Password Management, Privileged Access Management and Change Management should cover this scenario. The current password policy applies to administrators, but it does not provide a secure method for storing or sharing automation credentials.

**Gap Exploited:** The undocumented finding for **no formal change management process**, together with **M-05: No MFA on Any System**. Scripts and configuration changes can be introduced without review, while administrative accounts depend only on passwords.

**Recommended Mitigation:**
Store automation credentials in a privileged-access vault and allow the script to retrieve the secret without saving it in plaintext.

## Pattern Assessment

The main systemic weakness is that MedDefense gives users broad access but lacks the accountability and monitoring needed to detect misuse. **M-07: Shared Credentials in Radiology** makes it impossible to connect actions to individual technicians, while **M-04: Absence of Monitoring and Detection** means VPN, Active Directory and EHR activity is not reviewed or alerted on centrally. This is made worse by manual offboarding, incomplete asset management, no DLP and unrestricted USB use. Training also has major weaknesses: completion is only 71% at Central and 58% at Westside, with no role-specific training for clinical or IT staff. As a result, both careless behavior and deliberate misuse can continue without being identified quickly.

