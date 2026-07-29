### The Kill Chain Overlay

**Goal:** _Overlay the Crimson Tide attack chain onto the kill chains you built in 1x01, identifying where they converge and where MedDefense's planned controls would intercept._

---

**Context:** You built 5 kill chains for MedDefense in Project 1x01. Crimson Tide's attack chain is a real-world instance of those theoretical models. How accurately did your threat modeling predict this attack ? Where does the Crimson Tide chain match your kill chains, and where does it diverge ?

---

**Instructions:**

**Part 1 - The Overlay**

Take your Kill Chain #1 (ransomware) from 1x01 T10. Lay it alongside the Crimson Tide 7-phase attack chain. For each step, identify:

- Whether your predicted step matches the Crimson Tide step
    
- Where your prediction was accurate
    
- Where Crimson Tide does something your model did not anticipate
    

**Part 2 - Control Interception Map**

From your Security Strategy (1x03), identify which planned controls would intercept the Crimson Tide chain and at which phase:

```less
Phase [N] | Planned Control [from 1x03] | Status [Funded/Not Deployed, Deployed, Not Funded] | Would It Stop This Phase? [Yes/Partially/No]
```

**Part 3 - The Gap Between Plan and Reality**

In one paragraph, assess: If MedDefense had fully implemented the Security Strategy from 1x03, how many of the 7 Crimson Tide phases would have been blocked ? How many would still succeed ? What does this tell you about the residual risk even after full strategy implementation ?

---
# Answer

# 2. The Kill Chain Overlay

## Part 1 — The Overlay

Kill Chain #1 predicted a ransomware affiliate entering through VPN compromise or stolen credentials, discovering the network, stealing additional credentials, reaching Active Directory and critical servers, exfiltrating data, destroying backups, deploying ransomware and applying double-extortion pressure. Crimson Tide follows the same strategic sequence.

|Crimson Tide phase|Kill Chain #1 prediction|Match?|Where the prediction was accurate|What the model did not anticipate|
|---|---|--:|---|---|
|**Phase 1: Initial Access**|Gain entry through a vulnerable VPN appliance, phishing or stolen VPN credentials.|**Yes**|The model correctly identified MedDefense’s FortiGate VPN as a likely entry point for ransomware affiliates.|Crimson Tide uses one exact vulnerability, **CVE-2023-27997**, to achieve pre-authentication code execution directly on the FortiGate. The original model allowed several possible entry methods and did not identify this exact CVE.|
|**Phase 2: Internal Reconnaissance**|Establish a foothold, identify subnets, Domain Controllers, EHR systems, backup infrastructure and other high-value assets.|**Yes**|The model correctly predicted that the attacker would map the internal network before taking destructive action.|Crimson Tide captures VPN credentials directly from FortiGate memory and obtains the routing table using built-in FortiOS commands. The original model did not specify appliance-memory credential capture.|
|**Phase 3: Lateral Movement**|Steal credentials, escalate privileges, obtain Domain Admin access and move to Active Directory, EHR, billing, backup and medical systems across the flat network.|**Yes**|The prediction accurately identified weak credentials, excessive privileges, the flat network and Active Directory as the primary enablers of lateral movement.|Crimson Tide specifically uses **RDP, SSH and WMI**, together with **Mimikatz** and Kerberoasting of RC4-encrypted service tickets. The original model predicted credential theft and privilege escalation but not every individual technique.|
|**Phase 4: Data Exfiltration**|Locate and steal patient, billing, employee and insurance data before encryption to create double-extortion leverage.|**Yes**|The predicted targets and the purpose of exfiltration match Crimson Tide almost exactly.|Crimson Tide uses **Rclone** and legitimate cloud storage and may copy raw database files because they are not encrypted at rest. The original model did not fully describe raw database-file theft without database credentials.|
|**Phase 5: Backup Destruction**|Locate `backup-srv-01` and `NAS-01`, delete or encrypt backups and remove recovery options before deploying ransomware.|**Yes**|The model correctly recognised that the attacker must neutralise backups before encryption to increase the chance of payment.|Crimson Tide explicitly uses `vssadmin delete shadows`, destroys backup software catalogues and checks unencrypted backups before deleting them.|
|**Phase 6: Ransomware Deployment**|Use the compromised Domain Controller to push ransomware through Group Policy to servers and workstations.|**Yes**|The predicted use of Domain Admin privileges and GPO-based enterprise deployment matches the advisory directly.|Crimson Tide targets Linux servers separately through SSH. It does not directly encrypt embedded medical devices, but those devices fail when dependent EHR and PACS backends become unavailable.|
|**Phase 7: Extortion**|Demand payment for decryption and threaten to publish stolen patient information.|**Yes**|The prediction correctly included double extortion: payment for recovery and payment to prevent disclosure.|Crimson Tide also contacts the CEO and CFO directly by email and may call the hospital’s main telephone line. The model did not anticipate this direct executive-pressure method or the 96-hour deadline.|

The regional ransomware case used during 1x01 had already demonstrated the sequence of VPN exploitation, flat-network movement, Domain Controller compromise, data exfiltration, GPO deployment and backup loss. Kill Chain #1 therefore predicted **all seven Crimson Tide phases at the strategic level**.

### Prediction accuracy assessment

**Strategic phase accuracy: 7/7**

The threat model correctly predicted the attacker’s objectives and sequence. Its main limitations were at the tactical level: the exact FortiGate CVE, credential capture from appliance memory, RC4 Kerberoasting, raw database copying, specific utilities such as Rclone and `vssadmin`, separate Linux deployment and direct telephone or email pressure against executives. The advisory’s complete observed chain is documented in the provided Crimson Tide file.

---

## Part 2 — Control Interception Map

The approved 1x03 security package funded MFA, network segmentation, Wazuh SIEM, EDR, a Westside managed firewall and immutable offsite backups within the £120,000 budget. The outsourced 24/7 SOC and full medical-device monitoring were deferred or not funded. At the time of the advisory, the funded controls were **not yet fully deployed**.

|Phase|Planned control from 1x03|Status|Would it stop this phase?|
|---|---|---|---|
|**1 — Initial Access**|Wazuh SIEM monitoring of FortiGate logs|**Funded / Not Deployed**|**Partially.** It could alert on the oversized `/remote/logincheck` request, abnormal CLI activity or unusual VPN sessions, but it would not prevent the pre-authentication vulnerability from being exploited.|
|**1 — Initial Access**|MFA for VPN access|**Funded / Not Deployed**|**No.** CVE-2023-27997 is exploited before authentication, so MFA would not stop the initial FortiGate compromise.|
|**2 — Internal Reconnaissance**|Wazuh SIEM and centralised log alerting|**Funded / Not Deployed**|**Partially.** It could detect abnormal FortiGate commands, credential use and discovery activity, allowing responders to interrupt the attacker. It would not prevent the attacker from reading information already available on the compromised appliance.|
|**2 — Internal Reconnaissance**|MFA for VPN and administrative accounts|**Funded / Not Deployed**|**Partially.** MFA would make stolen passwords less useful, but it would not stop the attacker from reading the FortiGate routing table or accessing information through an already-compromised appliance or session.|
|**3 — Lateral Movement**|Network segmentation with separate server, workstation, medical-device and management zones|**Funded / Not Deployed**|**Yes, for unrestricted lateral movement.** Proper firewall rules would prevent the attacker from reaching every MedDefense system from one compromised point.|
|**3 — Lateral Movement**|MFA for privileged and administrative accounts|**Funded / Not Deployed**|**Partially.** It would reduce the usefulness of harvested passwords and make Domain Admin compromise harder, although service-account and session theft could still create risk.|
|**3 — Lateral Movement**|EDR on servers and workstations|**Funded / Not Deployed**|**Partially.** It could detect or block Mimikatz, LSASS dumping, WMI misuse, suspicious RDP activity and remote command execution. EDR is not guaranteed to detect every technique.|
|**3 — Lateral Movement**|Managed firewall and restricted VPN ACLs at Westside|**Funded / Not Deployed**|**Partially.** It would reduce exposure from Westside and stop unrestricted site-to-site access, but it would not by itself contain an attacker who already controls the Central FortiGate.|
|**4 — Data Exfiltration**|Network segmentation|**Funded / Not Deployed**|**Partially.** It would restrict which compromised systems could reach `ehr-db-01`, `billing-srv-01` and file servers. It would not protect data once an authorised server or account was compromised.|
|**4 — Data Exfiltration**|Wazuh SIEM and EDR|**Funded / Not Deployed**|**Partially.** These controls could detect Rclone, large archive creation and unusual outbound transfers, but the strategy did not fund a complete DLP capability or database encryption control.|
|**4 — Data Exfiltration**|Outsourced 24/7 SOC|**Not Funded**|**Partially.** Continuous monitoring could identify large transfers and respond during the attacker’s dwell period, but monitoring alone would not guarantee prevention.|
|**5 — Backup Destruction**|Immutable offsite backups|**Funded / Not Deployed**|**Yes, against complete backup destruction.** Attackers might delete local Veeam copies and `NAS-01`, but they could not alter or destroy properly configured immutable offsite recovery copies.|
|**5 — Backup Destruction**|Network segmentation and restricted backup-management access|**Funded / Not Deployed**|**Partially.** It would make `NAS-01` and backup services harder to reach but would not replace immutability or offline copies.|
|**6 — Ransomware Deployment**|EDR for servers and workstations|**Funded / Not Deployed**|**Partially.** It could block the ransomware payload, suspicious GPO activity or mass file encryption, but a new or modified payload could evade detection.|
|**6 — Ransomware Deployment**|Network segmentation|**Funded / Not Deployed**|**Partially.** It would contain deployment to individual zones and prevent organisation-wide spread, but systems inside a compromised zone could still be encrypted.|
|**6 — Ransomware Deployment**|Wazuh SIEM|**Funded / Not Deployed**|**Partially.** It could alert on new GPO creation, remote execution, security-tool disabling and mass encryption, allowing emergency containment.|
|**7 — Extortion**|Immutable offsite backups|**Funded / Not Deployed**|**Partially.** Recoverable backups reduce the attacker’s decryption leverage, but they do not prevent threats to publish already stolen patient information.|
|**7 — Extortion**|Wazuh SIEM, EDR and incident-response escalation|**Funded / Not Deployed**|**Partially.** Earlier detection could reduce the volume of stolen data and operational damage, but no technical control can guarantee that an attacker will not issue an extortion demand.|

The current posture confirms why these controls matter: MedDefense has a flat network, no effective central monitoring, no MFA, incomplete endpoint coverage and locally accessible backups. Sophos currently covers workstations but not Windows or Linux servers, while the Veeam backups are stored on the same network and in the same server-room area as production systems.

---

## Part 3 — The Gap Between Plan and Reality

Using a strict phase-objective standard, full implementation of the 1x03 strategy would probably have **blocked 3 of the 7 phases**: unrestricted lateral movement in Phase 3, destruction of all usable backups in Phase 5 and enterprise-wide ransomware deployment in Phase 6. The remaining **4 phases could still succeed**: exploitation of the unpatched FortiGate in Phase 1, some internal reconnaissance in Phase 2, possible data exfiltration in Phase 4 and data-leak extortion in Phase 7. The strategy would greatly reduce the blast radius, improve detection and preserve recovery options, but it would not eliminate residual risk because MFA cannot stop a pre-authentication FortiGate exploit, EDR and SIEM are not guaranteed prevention controls, and the funded package did not fully address database encryption, DLP, egress filtering or rapid vendor patch access. This demonstrates that a strong security strategy creates defence in depth and limits consequences, but it cannot make MedDefense completely safe.
