# The Walk-Through

## Observation 1: Server Room Access

**Vulnerability:**
The server room uses the same generic badge given to all employees, including clinical, administrative, and custodial staff. There is also no camera covering the entrance and no visitor log.

**Threat:**
An unauthorized employee, contractor, visitor, or someone using a stolen badge could enter the server room without being noticed.

**Impact:**

* **Confidentiality:** Sensitive systems, stored data, or backup information could be accessed.
* **Integrity:** An attacker could change configurations, connect unauthorized equipment, or modify files.
* **Availability:** Servers, cables, or power connections could be damaged, disconnected, or stolen, causing system outages.

**Severity: High**
The server room contains critical systems, but access is not limited to authorized IT staff and there is no reliable way to monitor who enters.

---

## Observation 2: Network Closet

**Vulnerability:**
The network closet is unlocked and the door is left open. A username and password for the switch management interface are displayed next to the network equipment.

**Threat:**
Anyone who enters the closet could log in to the switches, change network settings, connect a malicious device, copy network traffic, or disconnect cables.

**Impact:**

* **Confidentiality:** An attacker could monitor network traffic and possibly capture sensitive information.
* **Integrity:** Switch settings, VLANs, or network routes could be changed without authorization.
* **Availability:** Network connections could be disabled, causing outages for users, systems, and medical devices.

**Severity: Critical**
The person would have both physical access to important network equipment and the credentials needed to control it.

---

## Observation 3: Nurse Station

**Vulnerability:**
The workstation is left logged into the EHR system with patient information visible. It has been unattended for at least 15 minutes, and staff are encouraged not to log out between shifts.

**Threat:**
A patient, visitor, cleaner, or unauthorized employee could use the active session to view, copy, change, or delete patient records.

**Impact:**

* **Confidentiality:** Private patient information could be seen or copied by someone without permission.
* **Integrity:** Medical records, notes, or treatment information could be changed.
* **Availability:** Important records could be deleted or made unreliable for clinical use.

**Severity: High**
The unattended session gives direct access to sensitive medical information without requiring the user to authenticate again.

---

## Observation 4: Medical IoT

**Vulnerability:**
The medical monitor uses firmware last updated in 2019 and appears to share the same network range as normal workstations. The screen also displays its IP address and firmware version.

**Threat:**
An attacker already connected to the internal network could identify the device, search for known weaknesses in the old firmware, and attempt to access or control it.

**Impact:**

* **Confidentiality:** Patient-monitoring information could be exposed.
* **Integrity:** Medical readings, settings, or transmitted data could be changed.
* **Availability:** The device could stop working, disconnect from the network, or become unavailable during patient care.

**Severity: Critical**
A successful attack could affect both sensitive patient information and the safe operation of a medical device.

---

## Observation 5: Emergency Exit

**Vulnerability:**
The fire exit between the public waiting area and the restricted administrative area is held open with a wooden wedge. This bypasses the normal physical access control.

**Threat:**
A patient, visitor, or attacker could enter the restricted area without a badge and reach offices belonging to IT and security staff.

**Impact:**

* **Confidentiality:** Sensitive documents, screens, meetings, or security information could be exposed.
* **Integrity:** Files, equipment, or office systems could be changed, damaged, or stolen.
* **Availability:** IT or administrative operations could be interrupted.
* **Physical safety:** Keeping a fire door open may also reduce fire protection and violate safety procedures.

**Severity: High**
The open door allows uncontrolled access from a public area into a restricted area that contains important staff, systems, and information.

