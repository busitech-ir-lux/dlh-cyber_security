# The Legacy Systems

> NVD result counts change over time. Record the live count shown by NVD when you submit the project.

## 1. Windows XP SP3 — MRI Workstation

**Host:** `10.10.1.70` — `WS-RAD-01`

### EOL Research

Windows XP SP3 has been unsupported since 2014. NVD does not normally receive new Windows XP-specific CVEs because Microsoft no longer develops or patches it.

**Recent Critical CVE count:** 0 direct Windows XP SP3 CVEs published in the last two years.

The most important existing vulnerabilities remain:

- CVE-2019-0708 — BlueKeep, CVSS 9.8
    
- CVE-2008-4250 — Windows Server Service RCE, CVSS 10.0
    

### Permanent Exposure

An unpatched supported system can still receive a future update. An EOL system will not receive normal security patches, so its vulnerabilities remain permanently open. New attack methods may appear even when no new CVE is assigned.

### Scan Findings

- Finding 004 — Windows XP end-of-life
    
- CVE-2017-0144 — EternalBlue
    
- CVE-2019-0708 — BlueKeep
    
- CVE-2008-4250 — Remote code execution
    
- SMB port 445 open
    
- RDP port 3389 open
    
- No VLAN isolation
    

These vulnerabilities remain exploitable because Windows XP no longer receives security updates.

### Compensating Controls

Controls proposed in 1x00 included:

- place the MRI workstation in a dedicated VLAN
    
- allow only required communication with the PACS server
    
- block SMB and RDP from other subnets
    
- disable unnecessary services
    
- monitor all traffic to and from the workstation
    

These controls reduce risk but do not remove the vulnerabilities. Additional controls should include application allowlisting, strict physical access, continuous monitoring and a replacement plan.

---

## 2. Windows Server 2012 R2 — Print Server

**Host:** `10.10.2.31` — `print-srv-01`

### EOL Research

Windows Server 2012 R2 reached end of extended support on 10 October 2023. Systems enrolled in Microsoft Extended Security Updates may still receive limited updates, but the scan does not show that MedDefense uses ESU.

Recent Microsoft vulnerabilities that may affect Windows Server components include:

- CVE-2025-59287 — Windows Server Update Service RCE, CVSS 9.8
    
- CVE-2025-60724 — Microsoft Graphics Component RCE, CVSS 9.8
    

The exact NVD result count depends on installed Windows roles and components.

### Permanent Exposure

Without ESU, newly discovered Windows Server vulnerabilities will not receive patches for this server. Patching individual applications cannot remove the risk created by the unsupported operating system.

### Scan Findings

- Finding 008 — Windows Server 2012 R2 end-of-life
    
- CVE-2021-34527 — PrintNightmare
    
- Print Spooler service running
    
- Public exploit code available
    

The running Print Spooler makes PrintNightmare directly relevant.

### Compensating Controls

Recommended controls:

- restrict print-server access with firewall rules
    
- allow only approved workstations
    
- disable the Print Spooler where it is not required
    
- apply ESU updates if available
    
- monitor administrator activity
    
- prevent internet access from the server
    

These controls reduce exposure, but migration to a supported Windows Server version is still required.

---

## 3. Ubuntu 18.04 LTS Without ESM — Billing Server

**Host:** `10.10.2.15` — `billing-srv-01`

### EOL Research

Ubuntu 18.04 standard support ended in June 2023. Security updates are available only through Ubuntu Pro ESM, which is not enabled on this server.

Recent Linux and Ubuntu-related vulnerabilities may still affect packages installed on Ubuntu 18.04. Examples include:

- CVE-2025-5054 — Canonical Apport information disclosure
    
- CVE-2026-31431 — Linux kernel cryptographic subsystem vulnerability
    

The exact NVD count depends on the server’s installed kernel and packages, because Ubuntu vulnerabilities are usually assigned to individual components rather than to the complete OS.

### Permanent Exposure

The server is not fully unpatchable because MedDefense could activate Ubuntu Pro ESM. However, without ESM, new security fixes are not being installed. Application patching alone will not correct vulnerabilities in the kernel and operating-system packages.

### Scan Findings

- Finding 001 — CVE-2021-44790 Apache buffer overflow
    
- Finding 002 — CVE-2019-0211 privilege escalation
    
- Finding 006 — MySQL exposed on all interfaces
    
- Finding 009 — SSH password authentication enabled
    
- Finding 011 — Ubuntu 18.04 without ESM
    
- Finding 026 — outdated kernel with 47 known CVEs
    

The Apache and kernel weaknesses remain open partly because the server is not receiving proper security updates.

### Compensating Controls

Recommended controls:

- activate Ubuntu Pro ESM immediately
    
- restrict Apache, SSH and MySQL with firewall rules
    
- use SSH keys instead of passwords
    
- bind MySQL only to required interfaces
    
- install EDR and file-integrity monitoring
    
- rebuild the server because of its crypto-miner compromise history
    

These controls help, but migration to a supported Ubuntu LTS release is the better long-term solution.

---

# Business Decision

MedDefense should migrate the **Windows XP MRI workstation first**.

It controls clinical equipment, has Critical integrity and availability requirements and contains several mature remote-code-execution vulnerabilities. EternalBlue, BlueKeep and MS08-067 have public weaponized exploits, while the workstation has open SMB and RDP ports and no VLAN isolation. A compromise could interrupt MRI services, affect patient care and provide an attacker with a path into the flat network. The billing server can temporarily receive Ubuntu ESM, and Windows Server 2012 R2 may use ESU, but Windows XP has no realistic patching path.
