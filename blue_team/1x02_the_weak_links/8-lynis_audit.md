# The Self-Audit

## Part 1: Install and Run

```bash
sudo apt update
sudo apt install lynis -y
sudo lynis audit system
```

The audit was run on Kali Linux using Lynis 3.1.6.

---

## Part 2: Analyze Results

### Hardening Index

**Hardening Index: 60/100**

Lynis performed 273 tests. The score shows that some security controls are enabled, but the system still needs significant hardening.

### Warnings

Lynis reported only 2 warnings.

|Warning|What Lynis checks|Why it matters|Remediation|
|---|---|---|---|
|System reboot required|Checks whether updates need a reboot|Old kernel or library versions may still be active|Reboot the system|
|Fewer than 2 responsive DNS servers|Checks DNS availability|DNS failure could interrupt network access|Add a second working DNS server|

### Top 5 Suggestions

|Suggestion|Security improvement|
|---|---|
|Configure a firewall|Filters unwanted incoming and outgoing traffic|
|Install Fail2ban|Blocks repeated login attempts|
|Harden SSH|Disable unnecessary forwarding and reduce login attempts|
|Enable `auditd`|Records important security and system events|
|Install a malware scanner|Helps detect malware, rootkits and suspicious files|

### Category Breakdown

Lynis did not provide numerical scores for each category, so the categories were judged from the audit results.

**Strongest categories:**

- Time synchronization
    
- Basic user and group checks
    
- AppArmor
    
- Package database
    
- File-system basic checks
    

These areas had several successful checks, such as correct account consistency, active AppArmor and working time synchronization.

**Weakest categories:**

- Firewall and network protection
    
- Malware detection
    
- Intrusion detection
    
- SSH hardening
    
- Logging and auditing
    
- Kernel hardening
    

The system had no active firewall, no malware scanner, no IDS/IPS, no `auditd`, no remote logging and several weak kernel settings. This shows that the machine has basic protections but lacks stronger monitoring and defensive controls.

---

## Part 3: MedDefense Projection

Lynis would likely identify these findings on `billing-srv-01`:

|Expected finding|Reason|
|---|---|
|Unsupported Ubuntu version|Ubuntu 18.04 no longer receives normal security updates|
|Outdated kernel and packages|The scan found an old kernel and outdated Apache packages|
|Weak SSH configuration|Password authentication is enabled and there is no account lockout|
|Weak firewall configuration|MySQL listens on all interfaces and is reachable from the internal network|
|Missing malware and integrity monitoring|The server previously had a crypto-miner, showing weak detection and monitoring|

The audit results support these concerns because the Kali system also showed missing firewall, malware, auditing and hardening controls.
