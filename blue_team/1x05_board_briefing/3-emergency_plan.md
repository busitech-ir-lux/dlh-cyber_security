### The 72-Hour Plan

**Goal:** _Design an emergency response plan prioritizing the actions MedDefense must take in the next 72 hours to reduce exposure to Crimson Tide._

---

**Context:** The Security Strategy was a 6-month roadmap. Crimson Tide has compressed the timeline to 72 hours. You cannot implement the full strategy overnight. You must choose the actions that provide the maximum risk reduction in the minimum time, with the resources available right now.

The constraints are real:

- Sarah Park has 2 IT staff available tonight (plus herself)
    
- FortiGate firmware requires a support contract renewal ($2,400) before download
    
- The segmentation project requires new switch configurations (2-3 days minimum)
    
- Backup isolation can be done tonight (physical disconnect of NAS from network)
    
- AD Kerberos configuration changes require a maintenance window (risk of breaking authentication)
    

---

**Instructions:** Produce a **72-Hour Emergency Response Plan** organized into 3 tiers:

**Tier 1 - Tonight (0-12 hours):** Actions that can be taken immediately with no budget approval, no procurement and minimal risk of service disruption. These are the things you do before you sleep.

**Tier 2 - Tomorrow (12-36 hours):** Actions that require some coordination, possibly a brief service window, and may need emergency budget approval from the Board meeting.

**Tier 3 - This Week (36-72 hours):** Actions that require procurement, vendor involvement or configuration changes that need testing.

For each action:

```yaml
Action: [Specific description]
Phase Blocked: [Which Crimson Tide phase does this address?]
Owner: [James / Sarah / You / External vendor]
Prerequisites: [What must happen first?]
Risk of Action: [What could go wrong?]
Risk of Inaction: [What happens if this is not done?]
```

End with a **Resource Conflict Assessment:** Are any Tier 1 and Tier 2 actions in conflict (same person needed for multiple tasks, same system needing multiple changes) ? How do you resolve the conflicts ?

---
# Answer

# 3. The 72-Hour Emergency Response Plan

## Response priorities

1. Prevent new exploitation of the FortiGate.
    
2. Determine whether MedDefense is already compromised.
    
3. Protect the last usable recovery copies.
    
4. Prevent credential abuse and lateral movement.
    
5. Patch and restore the FortiGate to a trusted state.
    
6. Introduce temporary segmentation and monitoring.
    
7. Address Kerberos and backup weaknesses through controlled changes.
    

MedDefense’s flat network, unisolated `NAS-01`, absent central monitoring and lack of MFA create direct exposure to the Crimson Tide attack chain.

---

# Tier 1 — Tonight: 0–12 Hours

These actions require no procurement or new budget and should cause limited service disruption.

## Action 1: Activate emergency incident response and freeze non-essential changes

**Action:** James declares a suspected-security-incident state, opens a central incident record, assigns responsibilities and freezes all non-essential production changes. Every action, time, system and result must be recorded.

**Phase Blocked:** Supports all phases by preventing uncontrolled changes and coordinating containment.

**Owner:** James

**Prerequisites:** CEO and Sarah must be informed that emergency incident authority is active.

**Risk of Action:** Routine IT work and planned maintenance may be delayed.

**Risk of Inaction:** Staff may make conflicting changes, destroy evidence or accidentally create additional outages during the response.

---

## Action 2: Preserve FortiGate evidence and review it for compromise

**Action:** Export the FortiGate configuration, local logs, administrator activity, VPN sessions and routing information to an offline evidence location. Search for:

- oversized requests to `/remote/logincheck`;
    
- unusual or unknown user-agent strings;
    
- unexpected administrator or VPN sessions;
    
- unusual FortiOS CLI commands;
    
- configuration changes;
    
- new administrators;
    
- unexpected routes or firewall policies;
    
- large outbound transfers;
    
- activity involving `mega[.]nz` or Tor infrastructure.
    

Record hashes and timestamps for exported evidence.

**Phase Blocked:** Phases 1–4: initial access, reconnaissance, lateral movement and exfiltration.

**Owner:** You, supported by one of Sarah’s IT staff

**Prerequisites:** Obtain read-only administrative access and confirm the system clock and time zone.

**Risk of Action:** Exporting logs creates little operational risk, but inexperienced analysis could produce false positives or overlook indicators.

**Risk of Inaction:** MedDefense may patch over evidence and fail to recognise that Crimson Tide already has access. The advisory identifies specific FortiGate and behavioural indicators that must be reviewed.

---

## Action 3: Disable or tightly restrict the vulnerable SSL-VPN service

**Action:** After evidence preservation, disable the public SSL-VPN portal until the FortiGate is patched. Before doing this, confirm that the Central–Westside and Central–HQ site-to-site tunnels use separate IPsec configurations. Do not shut down the FortiGate or disable all VPN connectivity.

If SSL-VPN cannot be completely disabled because of critical remote clinical access, apply temporary restrictions:

- allow only approved source IP addresses;
    
- disable unused SSL-VPN accounts and portals;
    
- remove internet exposure from the management interface;
    
- terminate unnecessary active sessions;
    
- restrict SSL-VPN users to only essential systems.
    

**Phase Blocked:** Phase 1 — Initial Access.

**Owner:** Sarah

**Prerequisites:** Export logs and configuration first; verify the difference between remote-access SSL-VPN and site-to-site IPsec tunnels.

**Risk of Action:** Remote staff may temporarily lose access. Incorrect configuration could disrupt a site-to-site VPN or clinical remote access.

**Risk of Inaction:** Attackers can continue exploiting CVE-2023-27997 remotely without credentials or user interaction. This is the highest immediate risk.

---

## Action 4: Physically isolate `NAS-01`

**Action:** Verify the time and status of the most recent successful backup, export the Veeam job history, then physically disconnect `NAS-01` from the production network. Do not erase, reboot or reconnect it until the environment has been checked.

Where possible, also disable saved administrative sessions and remove backup-management credentials from general administrator workstations.

**Phase Blocked:** Phase 5 — Backup Destruction; partially reduces Phase 7 extortion leverage.

**Owner:** Sarah’s second IT staff member

**Prerequisites:** Confirm that no backup or restore operation is currently active and record the current NAS status.

**Risk of Action:** Nightly backups cannot continue while the NAS is disconnected. A clinical restore request may take longer.

**Risk of Inaction:** Crimson Tide could destroy both production systems and their online backups. MedDefense’s current backup NAS is on the same flat network as production, making it directly accessible after lateral movement.

---

## Action 5: Conduct a rapid IOC hunt on Active Directory and critical servers

**Action:** Search `ad-dc-01`, `ad-dc-02`, `backup-srv-01`, `ehr-db-01`, `billing-srv-01`, `file-srv-01` and available endpoint-management data for:

- `rclone.exe` or unfamiliar Rclone binaries;
    
- the advisory’s file hashes;
    
- `vssadmin delete shadows`;
    
- new or modified GPOs;
    
- unusual scheduled tasks or services;
    
- suspicious RDP, SSH and WMI activity;
    
- LSASS access or Mimikatz indicators;
    
- newly created privileged accounts;
    
- unusual Kerberos service-ticket requests;
    
- outbound transfers larger than 5 GB.
    

Immediately isolate any confirmed compromised endpoint, but do not power it off unless patient safety or active encryption requires it.

**Phase Blocked:** Phases 2–6.

**Owner:** You

**Prerequisites:** Sarah must provide access to Domain Controller logs, endpoint consoles and critical servers.

**Risk of Action:** Aggressive isolation could interrupt an essential application. Large log searches may temporarily increase system load.

**Risk of Inaction:** An attacker who entered several days earlier may already be moving laterally or preparing ransomware deployment.

---

## Action 6: Protect Active Directory against immediate destructive use

**Action:** Review Domain Admins, Enterprise Admins, Group Policy Creator Owners and other privileged groups. Disable unknown, dormant or unnecessary privileged accounts. Export current GPOs and establish manual monitoring for new GPO creation.

Do not disable RC4 tonight and do not perform a mass credential rotation before the FortiGate is contained. A compromised FortiGate could capture replacement credentials again.

**Phase Blocked:** Phases 3 and 6 — Lateral Movement and Ransomware Deployment.

**Owner:** Sarah

**Prerequisites:** Confirm each account owner before disabling an account.

**Risk of Action:** Disabling a legitimate service or emergency administrator account could interrupt operations.

**Risk of Inaction:** A compromised privileged account could be used to deploy ransomware to the entire Windows domain through Group Policy.

---

# Tier 2 — Tomorrow: 12–36 Hours

These actions require Board approval, vendor coordination or a controlled maintenance window.

## Action 7: Obtain emergency approval for the Fortinet support renewal

**Action:** Request immediate Board approval for the **$2,400 support renewal**. Contact Fortinet or an authorised reseller during the Board meeting and obtain access to the approved FortiOS firmware and Fortinet Technical Assistance Centre.

**Phase Blocked:** Phase 1 — Initial Access.

**Owner:** James

**Prerequisites:** Board or CEO emergency spending approval and purchasing support.

**Risk of Action:** Direct financial cost of $2,400.

**Risk of Inaction:** MedDefense remains unable to obtain the official firmware needed to remove the known vulnerability from its only perimeter appliance.

---

## Action 8: Patch or rebuild the FortiGate during an emergency maintenance window

**Action:** With Fortinet support:

1. Verify the correct firmware for the FortiGate 100F.
    
2. Download FortiOS 7.0.14 from the authorised source.
    
3. Verify the downloaded file and preserve the existing configuration.
    
4. Notify all three sites of a short network maintenance window.
    
5. Apply the firmware update.
    
6. Verify internet access, the patient portal, site-to-site IPsec tunnels and required remote services.
    
7. Review the configuration for unauthorised administrators, routes, certificates and policies.
    

If evidence indicates that the FortiGate was compromised, do not rely on patching alone. Rebuild or factory-reset the appliance from a reviewed known-good configuration under Fortinet guidance.

**Phase Blocked:** Phase 1; also limits Phases 2 and 3.

**Owner:** Sarah and External vendor

**Prerequisites:** Support contract renewal, firmware access, configuration backup, rollback plan and approved maintenance window.

**Risk of Action:** A failed update or configuration problem could interrupt internet access and VPN connectivity for all three sites.

**Risk of Inaction:** The only perimeter defence remains vulnerable to unauthenticated remote compromise.

---

## Action 9: Rotate exposed credentials after the FortiGate is trusted

**Action:** After the FortiGate has been patched or rebuilt, terminate existing sessions and rotate:

- FortiGate administrator credentials;
    
- SSL-VPN credentials;
    
- VPN service-account credentials;
    
- Domain Administrator passwords;
    
- privileged service accounts that could have been exposed;
    
- local administrator credentials on critical servers.
    

Use unique passwords and record each rotation through the incident process.

**Phase Blocked:** Phases 2, 3 and 6.

**Owner:** Sarah

**Prerequisites:** Complete FortiGate remediation first and identify dependencies for service accounts.

**Risk of Action:** Applications, scheduled tasks or VPN connections may fail if stored credentials are not updated everywhere.

**Risk of Inaction:** Crimson Tide may continue using credentials collected before remediation, even after the FortiGate is patched.

---

## Action 10: Implement emergency MFA for remote and privileged access

**Action:** Enable MFA first for FortiGate administration, remote-access VPN and Domain Administrator access. Use existing Microsoft Entra ID capabilities where technically supported, with Fortinet assistance for VPN integration.

Maintain two controlled emergency-access accounts with strong unique credentials and documented access procedures to prevent administrative lockout.

**Phase Blocked:** Partially blocks Phases 2, 3 and 6.

**Owner:** Sarah and External vendor

**Prerequisites:** Stable FortiGate configuration, tested identity-provider connection and emergency-access procedure.

**Risk of Action:** Misconfiguration could lock out administrators or remote users. Some legacy clients may not support the selected authentication flow.

**Risk of Inaction:** Stolen passwords remain sufficient for VPN and administrative access. MedDefense currently lacks organisation-wide MFA.

---

## Action 11: Apply temporary lateral-movement restrictions

**Action:** After the FortiGate update, implement temporary firewall and access-control rules that:

- restrict VPN users to specifically required systems;
    
- block workstation-to-workstation RDP;
    
- block general workstation access to Domain Controllers;
    
- block SSH, WMI and SMB between zones except where explicitly required;
    
- allow `ehr-db-01` connections only from approved EHR systems;
    
- restrict access to `backup-srv-01` and `NAS-01` to named backup administrators;
    
- deny direct medical-device internet access where technically safe.
    

These are compensating controls until the full VLAN project is completed.

**Phase Blocked:** Phases 3, 4, 5 and 6.

**Owner:** Sarah and External vendor

**Prerequisites:** Application-flow review, current configuration backup and clinical owner approval for sensitive systems.

**Risk of Action:** Incomplete knowledge of application dependencies could interrupt EHR, PACS, printing or clinical-device integrations.

**Risk of Inaction:** The flat `10.10.0.0/16` environment allows one compromised system to reach nearly every other system.

---

## Action 12: Decide whether to escalate to a formal breach investigation

**Action:** James reviews the Tier 1 findings with legal counsel and executive leadership. If evidence suggests exploitation, credential theft, unauthorised access or exfiltration:

- declare a confirmed incident;
    
- engage external digital forensics and incident response;
    
- contact cyber-insurance representatives;
    
- preserve all relevant systems and logs;
    
- prepare regulatory and law-enforcement notifications;
    
- begin downtime and clinical-continuity planning.
    

**Phase Blocked:** Does not directly block a phase, but reduces the operational and legal impact of Phases 4–7.

**Owner:** James

**Prerequisites:** Initial technical findings and legal review.

**Risk of Action:** External response costs, operational scrutiny and possible regulatory reporting obligations.

**Risk of Inaction:** MedDefense may lose evidence, miss notification deadlines or allow an active attacker to continue operating unnoticed.

---

# Tier 3 — This Week: 36–72 Hours

These actions require tested configuration changes, vendor support or procurement.

## Action 13: Implement minimum viable network segmentation

**Action:** Configure, test and deploy at least four separate security zones:

1. Servers
    
2. Workstations
    
3. Medical devices
    
4. Management and backup systems
    

Use deny-by-default inter-zone rules, then allow only documented clinical and business traffic. Prioritise isolation of Domain Controllers, EHR systems, PACS, medical devices and backup infrastructure.

**Phase Blocked:** Phases 3, 4, 5 and 6.

**Owner:** Sarah and External vendor

**Prerequisites:** Current network-flow mapping, switch configuration backups, clinical testing and a rollback plan.

**Risk of Action:** Incorrect VLAN or firewall configuration could interrupt EHR access, medical-device communication, PACS transfers, printing or site connectivity.

**Risk of Inaction:** Crimson Tide can continue moving freely across the flat network. The switches support VLANs, but none are currently configured.

---

## Action 14: Disable RC4 and DES and enforce AES Kerberos

**Action:** Inventory service accounts, identify systems that still depend on RC4 or DES, reset compatible service-account passwords so AES keys are generated, test authentication and then disable DES and RC4 during a controlled maintenance window.

Monitor authentication failures closely after the change.

**Phase Blocked:** Phase 3 — Lateral Movement.

**Owner:** Sarah and External vendor

**Prerequisites:** Service-account inventory, legacy-application compatibility testing and rollback procedure.

**Risk of Action:** Legacy applications, services or medical systems may fail to authenticate.

**Risk of Inaction:** Attackers can request RC4-encrypted service tickets and crack them offline through Kerberoasting.

---

## Action 15: Establish an isolated and immutable recovery copy

**Action:** Procure or activate an approved immutable cloud or offsite backup target. Until this is operational, connect `NAS-01` only during controlled backup windows, verify the backup, then disconnect it again.

Test restoration of at least one critical EHR file or system to prove the backup is usable.

**Phase Blocked:** Phase 5 and partially Phase 7.

**Owner:** Sarah and External vendor

**Prerequisites:** Emergency budget approval, secure vendor configuration and a defined recovery test.

**Risk of Action:** Initial replication may consume bandwidth, and incorrect retention settings could create unexpected costs or incomplete protection.

**Risk of Inaction:** Local production and backups may be destroyed in the same attack, leaving MedDefense dependent on old monthly media and potentially causing unacceptable data loss.

---

## Action 16: Deploy minimum viable central monitoring

**Action:** Establish an emergency central log collector or limited Wazuh deployment covering:

- FortiGate;
    
- `ad-dc-01` and `ad-dc-02`;
    
- `backup-srv-01`;
    
- `ehr-db-01`;
    
- `billing-srv-01`;
    
- critical Windows servers.
    

Configure immediate alerts for:

- new GPOs;
    
- privileged-account creation;
    
- repeated Kerberos service-ticket requests;
    
- `vssadmin` use;
    
- Rclone execution;
    
- large outbound transfers;
    
- security-log clearing;
    
- disabled endpoint protection.
    

**Phase Blocked:** Partially addresses Phases 2–6.

**Owner:** You and External vendor

**Prerequisites:** A server or virtual machine for the collector, log-forwarding access and agreed alert ownership.

**Risk of Action:** Poorly tuned rules may create false positives, and log collection may consume storage.

**Risk of Inaction:** MedDefense may not detect Crimson Tide until encryption or clinical disruption becomes visible. Current logs are local and have no central alerting.

---

## Action 17: Restrict database and outbound data access

**Action:** Apply host and network controls so that:

- `ehr-db-01` accepts database connections only from `ehr-srv-01` and approved administration systems;
    
- billing databases accept connections only from the billing application;
    
- database files cannot be read by unnecessary accounts;
    
- servers cannot upload data to unapproved cloud-storage services;
    
- large outbound transfers trigger alerts;
    
- `mega[.]nz` is temporarily blocked unless a documented business requirement exists.
    

Full database encryption should follow as a separate tested project because it cannot safely be implemented overnight.

**Phase Blocked:** Phase 4 — Data Exfiltration.

**Owner:** Sarah and You

**Prerequisites:** Application dependency review, database administrator involvement and testing.

**Risk of Action:** Incorrect restrictions could interrupt EHR or billing services. Blocking cloud storage may affect legitimate departmental workflows.

**Risk of Inaction:** An attacker may copy patient, billing and employee data before deploying ransomware, preserving extortion leverage even if systems are restored.

---

# Resource Conflict Assessment

The main conflict is **Sarah Park**. She is required for FortiGate containment, firmware deployment, credential rotation, MFA, temporary ACLs, segmentation, Kerberos changes and backup recovery. The FortiGate is also a technical conflict point because patching, VPN changes, MFA integration and firewall-rule changes all affect the same critical appliance.

The conflict should be resolved through the following sequence:

1. **Tonight:** Sarah handles SSL-VPN containment and privileged-account review. IT Staff 1 supports FortiGate evidence collection. IT Staff 2 verifies and disconnects `NAS-01`. You perform IOC hunting. James manages incident command and the Board.
    
2. **Tomorrow morning:** James obtains the £2,400 approval and coordinates Fortinet. Sarah and the external vendor patch or rebuild the FortiGate.
    
3. **After patching:** Rotate credentials and terminate old sessions. Do not rotate them before the appliance is trusted.
    
4. **After stability testing:** Enable MFA and apply temporary access restrictions. Do not combine these changes with the firmware upgrade in one untested step.
    
5. **Within 36–72 hours:** The external vendor leads switch and VLAN work while Sarah supervises. You deploy monitoring and continue threat hunting.
    
6. **Last:** Change Kerberos encryption only after service-account compatibility testing. It should not occur during the same maintenance window as FortiGate or segmentation changes.
    

Only one major change should be made to the FortiGate at a time, with a configuration backup, success test and rollback point after each change. This reduces the possibility that the emergency response itself disconnects all three MedDefense sites.
