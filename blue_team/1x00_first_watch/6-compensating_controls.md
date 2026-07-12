# The Legacy Dilemma

## 1. Risk Analysis

The MRI workstation is a critical risk because it runs Windows XP Embedded, which has not received security updates since April 2014. This means known vulnerabilities may remain open and attackers may be able to exploit them using malware or remote attacks. The risk affects the whole hospital because the MRI is on the same VLAN as normal workstations, so a compromised MRI could be used to move to other systems, including PACS and possibly other clinical servers. Because the scanner is needed for about 45 studies per day, an attack could also interrupt patient care and affect Confidentiality, Integrity and Availability.

---

# 2. Compensating Control Strategy

## Control 1: Isolate the MRI on a Dedicated VLAN

**What it does:**
Move the MRI workstation to its own dedicated network segment. Firewall rules should allow communication only between the MRI and the PACS server using the exact required ports. All other access should be blocked.

**Classification:**
Technical + Compensating/Preventive

**How it reduces risk:**
The control limits what the MRI can communicate with. If the workstation is compromised, the attacker will have fewer opportunities to reach other hospital systems.

**Why it does not require OS modification:**
The change is made on network switches and firewalls, not on the MRI operating system.

**Limitations and residual risk:**
The MRI can still be attacked through the allowed connection to PACS. Incorrect firewall rules could also leave unnecessary access open.

---

## Control 2: Monitor MRI Network Traffic

**What it does:**
Monitor traffic entering and leaving the MRI network segment. Create alerts for unusual connections, unexpected destinations, scanning activity or large data transfers.

**Classification:**
Technical + Detective

**How it reduces risk:**
This control may identify a compromise before the attacker can cause greater damage. It can also help the security team investigate suspicious activity.

**Why it does not require OS modification:**
Monitoring can be performed using the firewall, network sensors or switch traffic mirroring.

**Limitations and residual risk:**
Monitoring does not stop every attack. It is only useful if alerts are reviewed and investigated quickly.

---

## Control 3: Allow Access Only from Approved Systems and Staff

**What it does:**
Create a documented access list showing which users, support staff and systems are allowed to interact with the MRI. Administrative access should be limited to approved radiology and vendor personnel.

**Classification:**
Administrative + Preventive

**How it reduces risk:**
The control reduces unnecessary access and lowers the chance that an unauthorized person changes settings, installs software or connects an unknown device.

**Why it does not require OS modification:**
The control is applied through procedures, account management and network access rules.

**Limitations and residual risk:**
Approved users may still make mistakes or misuse their access. Shared or vendor accounts may also reduce accountability.

---

## Control 4: Lock and Monitor the MRI Control Area

**What it does:**
Keep the MRI control workstation in a restricted area with badge access. Maintain a visitor and vendor access log and prevent unauthorized USB devices or laptops from being connected.

**Classification:**
Physical + Preventive/Detective

**How it reduces risk:**
This reduces the chance of physical tampering, malware installation, credential theft or unauthorized changes to the workstation.

**Why it does not require OS modification:**
The protection is applied to the room, access process and physical ports.

**Limitations and residual risk:**
This does not protect against attacks coming through the network or through an authorized person.

---

## Control 5: Create a Special Monitoring and Incident Procedure

**What it does:**
Create a written procedure for the MRI that explains:

* who is responsible for the device;
* how logs and alerts are reviewed;
* what to do if compromise is suspected;
* how the scanner is isolated safely;
* how radiology continues operating during an incident;
* when the manufacturer or vendor must be contacted.

**Classification:**
Administrative + Corrective/Compensating

**How it reduces risk:**
The procedure helps staff respond quickly without making unsafe decisions that could affect patient care or device certification.

**Why it does not require OS modification:**
It changes the response process, not the MRI software.

**Limitations and residual risk:**
The procedure does not prevent the initial attack. It must also be tested and kept current.

---

# 3. Implementation Priority

The first control should be **placing the MRI on a dedicated VLAN with strict firewall rules**.

This provides the greatest immediate risk reduction because the current main weakness is that the MRI shares a network with normal hospital workstations. Network isolation limits both directions of attack: it makes the MRI harder to reach, and it reduces the ability of an attacker to use the MRI to move to other systems. It also protects the wider hospital network without changing the operating system, replacing the scanner or interrupting its required PACS connection.

The remaining risk is that the MRI and PACS connection could still be attacked, so monitoring and access controls should be added after segmentation.

