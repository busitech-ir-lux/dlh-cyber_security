# 18. Six-Month Security Roadmap

## Month 1 — August 2026: Governance and Quick Wins

| Action                                                  | Owner                      | Dependency                                      | Completion Criteria                                                |
| ------------------------------------------------------- | -------------------------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| Approve the security roadmap and governance roles       | CEO and Deputy CISO        | Board approval of the budget                    | Roles and responsibilities are formally documented                 |
| Enable MFA for VPN and administrator accounts           | IT Director                | Complete list of VPN and administrator accounts | 100% of VPN and administrator accounts require MFA                 |
| Disable dormant, shared and default accounts            | IT Director and Dept Heads | Account inventory                               | Unnecessary accounts are disabled and exceptions documented        |
| Patch the FortiGate and critical servers                | IT Director                | Maintenance windows approved                    | Critical systems are rescanned and vulnerable versions are removed |
| Approve the Acceptable Use Policy                       | CEO and Deputy CISO        | Policy draft completed                          | Policy is published and distributed to staff                       |
| Start procurement for EDR, firewall and backup services | IT Director                | Budget approval                                 | Purchase orders or contracts are approved                          |

---

## Month 2 — September 2026: Inventory and Architecture Design

| Action                                    | Owner                            | Dependency                   | Completion Criteria                                         |
| ----------------------------------------- | -------------------------------- | ---------------------------- | ----------------------------------------------------------- |
| Complete enterprise asset inventory       | Security Analyst and IT Director | Department cooperation       | All known devices have an owner, location and purpose       |
| Complete software and account inventories | Security Analyst and IT Director | Asset inventory              | Unsupported software and privileged accounts are identified |
| Create the network architecture diagram   | IT Director                      | Asset inventory              | All systems are assigned to a proposed network zone         |
| Define VLANs and firewall rules           | IT Director and Security Analyst | Network diagram              | Rules are documented, reviewed and approved                 |
| Test current backups                      | IT Director                      | Critical systems identified  | EHR and billing data are successfully restored              |
| Prepare Wazuh infrastructure              | Security Analyst                 | Server and storage available | Wazuh server is installed and ready for log sources         |

---

## Month 3 — October 2026: Network Segmentation

| Action                                                      | Owner            | Dependency                                 | Completion Criteria                                       |
| ----------------------------------------------------------- | ---------------- | ------------------------------------------ | --------------------------------------------------------- |
| Create server, clinical, management, guest and backup VLANs | IT Director      | Approved architecture and firewall rules   | VLANs are active and correctly routed                     |
| Deploy the Westside managed firewall                        | IT Director      | Equipment delivered and VPN rules approved | Consumer router is removed and the VPN is restricted      |
| Move guest and non-clinical IoT devices                     | IT Team          | Guest VLAN available                       | Guest devices cannot access internal systems              |
| Restrict access to EHR and databases                        | IT Director      | Server VLAN available                      | Only approved systems can reach EHR and database services |
| Begin central log collection                                | Security Analyst | Wazuh server and network access available  | Firewall, AD and critical server logs appear in Wazuh     |

---

## Month 4 — November 2026: Core Security Controls

| Action                                     | Owner                            | Dependency                                | Completion Criteria                                         |
| ------------------------------------------ | -------------------------------- | ----------------------------------------- | ----------------------------------------------------------- |
| Deploy EDR to workstations and servers     | IT Director and Security Analyst | Software inventory and licences available | At least 95% of supported endpoints report to EDR           |
| Configure Wazuh alerts and dashboards      | Security Analyst                 | Critical logs collected                   | High-priority alerts have owners and response instructions  |
| Begin immutable offsite backup replication | IT Director                      | Backup process verified                   | Encrypted offsite copies are created successfully           |
| Create incident-response procedures        | Deputy CISO and Security Analyst | Monitoring and escalation roles defined   | Ransomware and phishing playbooks are approved              |
| Start monthly vulnerability scanning       | Security Analyst                 | Asset and software inventories complete   | First scan is completed and remediation tickets are created |

---

## Month 5 — December 2026: Clinical Isolation and Testing

| Action                                     | Owner                                | Dependency                       | Completion Criteria                                             |
| ------------------------------------------ | ------------------------------------ | -------------------------------- | --------------------------------------------------------------- |
| Move medical devices into a dedicated VLAN | IT Director and Clinical Engineering | Network segmentation operational | Medical devices cannot directly access user or guest zones      |
| Isolate the Windows XP MRI workstation     | IT Director and Radiology Head       | Medical-device VLAN available    | Internet access is blocked and only required traffic is allowed |
| Remove default medical-device credentials  | IT Director and Clinical Engineering | Device inventory completed       | No known medical device uses a default password                 |
| Test segmentation firewall rules           | Security Analyst                     | All zones operational            | Unauthorized cross-zone test traffic is blocked                 |
| Conduct a ransomware tabletop exercise     | Deputy CISO                          | Incident-response plan completed | Roles, escalation and communication procedures are tested       |

---

## Month 6 — January 2027: Validation and Optimization

| Action                                    | Owner                            | Dependency                                | Completion Criteria                                       |
| ----------------------------------------- | -------------------------------- | ----------------------------------------- | --------------------------------------------------------- |
| Perform vulnerability rescanning          | Security Analyst                 | Patching and control deployment completed | Critical findings are closed or formally accepted         |
| Test recovery from immutable backups      | IT Director                      | Offsite replication operational           | EHR and billing data are restored successfully            |
| Review EHR, PACS and administrator access | Dept Heads and IT Director       | Individual accounts established           | Shared accounts are removed and access is approved        |
| Update the Risk Register                  | Security Analyst and Deputy CISO | Validation results available              | Residual risk scores and treatments are current           |
| Reassess NIST and CIS maturity            | Deputy CISO and Security Analyst | Six-month controls completed              | Progress toward Managed and CIS IG1 targets is documented |
| Present results to the Board              | Deputy CISO                      | Final metrics and risk register completed | Board receives the report and approves Year 2 priorities  |

# Dependency Chain

```text
Asset inventory
    ↓
Network architecture diagram
    ↓
Network segmentation
    ↓
Medical-device and backup isolation
```

```text
Wazuh installation
    ↓
Log-source connection
    ↓
Alert configuration
    ↓
Alert monitoring and incident response
```

```text
Backup testing
    ↓
Offsite immutable replication
    ↓
Recovery testing
```

```text
Software inventory
    ↓
Vulnerability scanning
    ↓
Patching and replacement planning
    ↓
Validation scan
```

# Major Milestones

## Milestone 1 — August 31, 2026: Immediate Risk Reduction

**Completed:**

* MFA enabled
* critical systems patched
* dormant and default accounts removed
* AUP approved

**Success Indicator:** 100% of VPN and administrator accounts require MFA, and no Critical vulnerability remains open without an approved treatment.

## Milestone 2 — October 31, 2026: Segmented Network

**Completed:**

* core VLANs operational
* Westside firewall installed
* guest access isolated
* EHR access restricted

**Success Indicator:** Unauthorized traffic between guest, clinical, server and management zones is blocked during testing.

## Milestone 3 — November 30, 2026: Detection and Recovery Operational

**Completed:**

* EDR deployed
* Wazuh collecting critical logs
* alerts assigned
* offsite backups replicating

**Success Indicator:** At least 95% of endpoints report to EDR, four critical log sources report to Wazuh and backup replication completes successfully.

## Milestone 4 — January 31, 2027: Strategy Validated

**Completed:**

* recovery test completed
* ransomware exercise performed
* vulnerabilities rescanned
* Risk Register updated
* Board report delivered

**Success Indicator:** All High and Critical risks have an owner, treatment decision and current residual-risk rating.

# Risks to the Timeline

## Risk 1 — Clinical Systems Cannot Be Interrupted

Hospital systems and medical devices may have limited maintenance windows, delaying patching or segmentation.

**Contingency Plan:** Schedule changes during low-activity periods, test changes in stages and maintain a rollback plan. Prioritize internet-facing and high-risk systems when all systems cannot be changed together.

## Risk 2 — Limited IT and Security Staff

The IT Director, Security Analyst and Deputy CISO may not have enough time to complete all activities while supporting daily operations.

**Contingency Plan:** Use vendor implementation support for EDR and firewall deployment, assign clear weekly priorities and defer lower-risk administrative tasks rather than delaying MFA, segmentation, monitoring or backups.

