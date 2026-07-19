# Patch Briefing

MedDefense should complete three urgent actions within the next 24–48 hours.

**1. Fix the EHR server vulnerability — Finding 031**

The EHR application server has a weakness that can allow an attacker on the internal network to read application files and potentially obtain database credentials. If exploited, the attacker could access patient records, alter clinical information or disrupt EHR availability.

**Action:** Update Tomcat, block or restrict port 8009 and change potentially exposed credentials.
**Estimated effort:** One planned maintenance window with application testing.
**Estimated cost:** **$10,000–$50,000**, including vendor support.

**2. Patch the billing server — Findings 001 and 002**

The billing server has two connected Apache vulnerabilities. The first may allow an attacker to enter the server remotely, and the second may allow full administrative control.

If exploited, MedDefense could lose billing data, experience service disruption and provide the attacker with a route to other internal systems.

**Action:** Back up the server, test the billing application and install the supported Apache updates.
**Estimated effort:** One to two days, including testing and rollback preparation.
**Estimated cost:** **$1,000–$10,000**.

**3. Isolate the Windows XP MRI workstation — Finding 004**

The MRI workstation is permanently unsupported and contains several vulnerabilities with working attack tools. It cannot be made safe through normal patching.

If compromised, attackers could interrupt MRI services, affect patient care and use the workstation to move across the hospital network.

**Action:** Place it in a dedicated network segment and block unnecessary SMB, RDP and internet access.
**Estimated effort:** One to three days with Clinical Engineering and the MRI vendor.
**Estimated cost:** **$10,000–$50,000**.

In three weeks, MedDefense has progressed from identifying its assets and control gaps, to understanding its threat actors and attack paths, to producing a validated and prioritized vulnerability remediation plan.

