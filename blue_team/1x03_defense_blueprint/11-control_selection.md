# 11. Control Selection

> Costs are shared across several risks. They must not be added together for every row. The complete funded control program remains **$120,000**.

| Risk         | Selected Control                                                                                 | CIS Control Mapping                                                                      | NIST CSF Mapping    | Type / Category                                  |                                               Implementation Cost | Expected Risk Reduction                                                              | Dependencies                                                              |
| ------------ | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------ | ----------------------------------------------------------------: | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| **RISK-001** | Segment the EHR network, restrict database access and require MFA for administrators.            | 3.3 Data ACLs; 6.5 Administrative MFA; 12.2 Secure Network Architecture                  | PR.AA, PR.DS, PR.IR | Preventive / Technical                           |                         $35,000 segmentation + shared $12,000 MFA | ALE reduced from **$3,025,000 to $726,000**, a reduction of **$2,299,000**.          | Asset inventory and network diagram must exist first.                     |
| **RISK-002** | Enable VPN MFA, patch the FortiGate and restrict remote access.                                  | 6.4 Remote-Access MFA; 7.3–7.4 Patch Management; 12.7 Secure Remote Access               | PR.AA, PR.PS, PR.IR | Preventive / Technical                           |                                                           $12,000 | ALE reduced from **$2,864,400 to $477,400**, a reduction of **$2,387,000**.          | Account inventory and administrator identification.                       |
| **RISK-003** | Deploy EDR, patch the billing server and replicate backups to immutable offsite storage.         | 7.3–7.4 Patch Management; 10.1–10.2 Malware Defence; 11.2–11.4 Data Recovery             | PR.PS, DE.CM, RC.RP | Preventive, Detective and Corrective / Technical |                                     $24,000 EDR + $14,000 backups | ALE reduced from **$135,278 to $18,920**, a reduction of **$116,358**.               | Software inventory before patching; backup setup before recovery testing. |
| **RISK-004** | Deploy Wazuh and centralize logs and security alerts.                                            | 8.1–8.3 Audit Logs; 13.1 Centralized Alerting; 13.6 Network Flow Logs                    | DE.CM, DE.AE        | Detective / Technical and Operational            |                                                           $26,000 | Estimated annual risk reduction of **$349,847** across EHR and ransomware risks.     | Log sources, storage and alert ownership must be defined first.           |
| **RISK-005** | Create VLANs for servers, workstations, medical devices, backups and guests.                     | 12.2 Secure Network Architecture; 12.4 Network Diagrams                                  | PR.IR               | Preventive / Technical                           |                                                           $35,000 | Supports the **$2,299,000 EHR risk reduction** and limits post-VPN lateral movement. | Complete asset inventory and approved network architecture.               |
| **RISK-006** | Use individual accounts, restrict removable media and deliver security awareness training.       | 5.1–5.2 Account Management; 14.1–14.6 Security Training; 3.3 Data ACLs                   | PR.AA, PR.AT, PR.DS | Preventive / Administrative and Technical        |              Included in access-management and endpoint programme | ALE reduced from **$300,000 to $96,000**, a reduction of **$204,000**.               | Account inventory and approved Acceptable Use Policy.                     |
| **RISK-007** | Place medical devices in a dedicated VLAN, remove default credentials and monitor their traffic. | 4.7 Default Accounts; 12.2 Secure Network Architecture; 13.1 Centralized Alerting        | PR.PS, PR.IR, DE.CM | Preventive and Detective / Technical             |                 Included in $35,000 segmentation and $26,000 SIEM | ALE reduced from approximately **$85,000 to $15,000**, a reduction of **$70,000**.   | Network segmentation must be implemented before device isolation.         |
| **RISK-008** | Replace the Westside consumer router with a managed firewall and restricted VPN rules.           | 12.1 Updated Network Infrastructure; 12.2 Secure Architecture; 12.7 Secure Remote Access | PR.PS, PR.IR        | Preventive / Technical                           |                                                            $9,000 | ALE reduced from **$286,440 to $95,480**, a reduction of **$190,960**.               | Westside asset inventory and approved VPN access requirements.            |
| **RISK-009** | Establish monthly scanning, patch deadlines and replacement plans for unsupported systems.       | 2.1–2.2 Software Inventory; 7.1–7.4 Vulnerability Management                             | ID.AM, PR.PS        | Preventive / Operational and Technical           |                 Labour included in the $24,000 endpoint programme | Contributes to reducing billing ransomware ALE from **$135,278 to $18,920**.         | Software inventory must be completed before automated patching.           |
| **RISK-010** | Replace shared PACS accounts, review permissions and protect PACS traffic.                       | 5.1–5.2 Account Management; 6.1–6.2 Access Granting and Revoking; 3.3 Data ACLs          | PR.AA, PR.DS        | Preventive / Technical and Administrative        | Included in the $12,000 access programme and $35,000 segmentation | Contributes to reducing insider ALE from **$300,000 to $96,000**.                    | Individual user identities and department-owner approval are required.    |

# Control Dependency Map

```text
Enterprise asset inventory
        |
        +--> Network architecture diagram
        |          |
        |          +--> Network segmentation
        |                    |
        |                    +--> EHR isolation
        |                    +--> Medical-device isolation
        |                    +--> Backup-network isolation
        |
        +--> Software inventory
        |          |
        |          +--> Vulnerability scanning
        |                    |
        |                    +--> Patch management
        |                    +--> Unsupported-system replacement
        |
        +--> Account inventory
                   |
                   +--> Individual PACS accounts
                   +--> VPN and administrator MFA
                   +--> Access reviews

Network segmentation + managed log sources
        |
        +--> Wazuh SIEM
                   |
                   +--> Centralized alerting
                   +--> Incident investigation
                   +--> Future 24/7 SOC monitoring

Automated backups
        |
        +--> Immutable offsite replication
                   |
                   +--> Recovery testing
```

The highest-priority sequence is **asset and account inventory → MFA and segmentation → Wazuh monitoring → EDR and backup improvements → control testing**.

