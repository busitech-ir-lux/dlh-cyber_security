# Network Forensics Investigation Report

## Executive Summary

MedDefense experienced a phishing-related network compromise that progressed from contact with a credential-harvesting domain to suspicious external communications, VPN access, internal movement and DNS tunneling. Packet evidence shows activity spanning April 14-15, with the phishing interaction occurring before the later internal compromise. The incident involved a clinical workstation, the billing server, the VPN endpoint and other internal systems reached through RDP and SMB. DNS TXT traffic from the billing server is consistent with low-volume data exfiltration, although the exact plaintext contents cannot be fully confirmed from packet evidence alone. Some internal access attempts were denied or reset, showing that not every attempted destination was successfully reached.

---

## Investigation Scope

The following packet captures were analyzed:

- `normal_baseline_clinical.pcap`
- `phishing_click.pcap`
- `c2_beaconing.pcap`
- `dns_exfil.pcap`
- `lateral_movement.pcap`
- `full_timeline.pcap`

The captures cover normal traffic before the incident and suspicious activity across April 14-15.

Primary analysis tool:

- `tshark`

Supporting command-line tools:

- Bash
- awk
- sort
- grep
- sha256sum

Evidence not used as primary evidence in this investigation included endpoint telemetry, EDR data, SIEM alerts, VPN server logs, domain-controller logs, application logs and server-side attacker infrastructure logs.

The project is intentionally based primarily on PCAP evidence, allowing DNS, TLS, RDP, SMB, timing and communication behavior to be reconstructed directly from network traffic. :contentReference[oaicite:1]{index=1}

---

## Methodology

The investigation used the following process:

1. Establish normal behavior from `normal_baseline_clinical.pcap`.
2. Search the suspicious captures for known campaign domains and IP addresses.
3. Examine DNS names, query types, query rates and encoded-looking labels.
4. Examine TLS metadata such as SNI and connection characteristics without claiming access to encrypted plaintext.
5. Measure connection timing to identify repeated automated behavior.
6. Examine RDP, SMB, authentication-related and TCP reset activity for lateral movement.
7. Correlate timestamps across all PCAPs to reconstruct the attack sequence.
8. Separate confirmed packet evidence from analytical inference.

Every important conclusion is tied to packet timestamps or observable protocol behavior. This follows the project requirement that packet findings remain reproducible and timestamped. :contentReference[oaicite:2]{index=2}

---

## Findings by Attack Phase

### Phase 1 - Initial Access

**Technique:** T1566.002 - Spearphishing Link  
**Evidence source:** 4x00 phishing investigation  
**Confidence:** High for phishing context; not direct PCAP evidence

The earlier phishing investigation identified a malicious campaign targeting MedDefense and linked the user to the phishing infrastructure.

**What PCAP proves:** The packet captures do not prove delivery of the phishing email itself.

---

### Phase 2 - Credential-Harvesting Session

**PCAP:** `phishing_click.pcap`  
**Timestamp:** 2026-04-14T11:02:33.142000000-0400  
**Source:** 10.10.2.15  
**Destination domain:** `meddefense-portal.com`  
**Destination infrastructure:** `91.234.99.107`  
**Technique:** T1056.003 - Web Portal Capture  
**Confidence:** Strong inference

The workstation resolved `meddefense-portal.com` and established communication with the associated infrastructure.

**Packet evidence proves:** DNS and TLS/HTTPS communication with the phishing infrastructure.

**Packet evidence does not prove:** The exact username or password entered because the application content is encrypted.

---

### Phase 3 - Command-and-Control Beaconing

**PCAP:** `c2_beaconing.pcap`  
**First observed:** 2026-04-14T22:00:12.000000000-0400  
**Last observed:** 2026-04-14T23:55:08.269493000-0400  
**Source:** `10.10.2.15`  
**Destination:** `91.234.99.107:443`  
**Observed sessions:** 24  
**Technique:** T1071.001 - Web Protocols  
**Confidence:** High

Repeated HTTPS connections occurred from the same internal workstation to the same external infrastructure.

**Packet evidence proves:** Repeated communication with measurable timing regularity.

**Assessment:** The behavior is consistent with automated beaconing rather than normal interactive browsing.

---

### Phase 4 - VPN Pivot

**PCAP:** `full_timeline.pcap`  
**Timestamp:** 2026-04-15T09:45:22.000000000-0400  
**Source:** `154.118.42.89`  
**Destination:** `10.10.0.1:443`  
**Technique:** T1133 - External Remote Services  
**Related technique:** T1078.002 - Valid Accounts: Domain Accounts  
**Confidence:** Strong inference

An external system established an HTTPS/VPN-style connection to the MedDefense VPN endpoint before the observed lateral movement.

**Packet evidence proves:** The external network connection and its timing.

**Strong inference:** The VPN activity is consistent with the use of the previously exposed credentials.

**Not confirmed from PCAP alone:** The exact password, MFA result or authentication decision.

---

### Phase 5 - RDP Lateral Movement

**PCAP:** `lateral_movement.pcap`  
**Timestamp:** 2026-04-15T10:30:12.445000000-0400  
**Source:** `10.10.2.15`  
**Destination:** `10.10.1.10:3389`  
**Technique:** T1021.001 - Remote Desktop Protocol  
**Confidence:** High for the network connection

The clinical workstation initiated RDP traffic toward the billing server.

**Packet evidence proves:** RDP communication between the two systems.

**Packet evidence alone does not prove:** Every action performed inside the remote session.

---

### Phase 6 - SMB Discovery and Internal Access

**PCAP:** `lateral_movement.pcap`  
**First observed:** 2026-04-15T10:35:22.891000000-0400  
**Source:** `10.10.1.10`  
**Techniques:** T1021.002, T1135, T1083  
**Confidence:** High

After reaching the billing environment, SMB traffic was observed toward other internal systems.

Observed evidence includes:

- SMB access-denied responses: 0
- TCP reset activity involving billing-srv-01: 2
- NAS-related SMB packets involving `10.10.1.60`: 58

**Packet evidence proves:** Internal SMB communication, enumeration-related behavior and failed/reset access attempts where present.

---

### Phase 7 - DNS Tunneling / Exfiltration

**PCAP:** `dns_exfil.pcap`  
**First observed:** 2026-04-15T18:15:02.300000000-0400  
**Last observed:** 2026-04-15T18:39:46.952494000-0400  
**Source:** `10.10.1.10`  
**Domain:** `data-sync.meddefense-portal.com`  
**TXT queries observed:** 120  
**Technique:** T1048.003 - Exfiltration Over Alternative Protocol  
**Confidence:** High for DNS tunneling pattern; medium for exact data contents

Repeated TXT queries contained long encoded-looking subdomain labels.

Estimated encoded payload corresponds to approximately:

- 3914 bytes if Base32
- 4697 bytes if Base64

**Packet evidence proves:** Repeated TXT queries carrying encoded-looking DNS labels.

**Assessment:** The traffic is consistent with DNS-based data exfiltration.

**Not confirmed:** Complete plaintext contents of the transferred data.

---

## Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | 4x00 + phishing PCAP | High | DNS, TLS SNI, proxy blocking |
| IPv4 | `91.234.99.107` | 4x00 + packet evidence | High | Firewall, NetFlow, connection monitoring |
| Domain | `data-sync.meddefense-portal.com` | DNS exfiltration PCAP | High | DNS tunnel detection |
| IPv4 | `154.118.42.89` | Full timeline PCAP | High | VPN monitoring and enrichment |
| Internal host | `10.10.2.15` | Multiple PCAPs | High | Investigation pivot |
| Internal host | `10.10.1.10` | Lateral/DNS PCAPs | High | Investigation pivot |
| VPN endpoint | `10.10.0.1` | Full timeline PCAP | High | VPN access monitoring |

Additional IOCs identified in the original 4x00 investigation should remain in the combined IOC register even when they do not reappear in these PCAPs.

---

## Impact Assessment

### Systems involved

- WS-NURSE-04 - `10.10.2.15`
- VPN endpoint - `10.10.0.1`
- billing-srv-01 - `10.10.1.10`
- NAS-01 - `10.10.1.60` where SMB traffic is present
- additional internal systems contacted during SMB activity

### Credential exposure

The phishing investigation already identified likely credential exposure. Network evidence now strongly supports the sequence from phishing activity to later external VPN access and internal movement.

The exact plaintext password remains unconfirmed.

### Data exposure

DNS TXT tunneling from billing-srv-01 indicates likely low-volume data exfiltration.

Estimated raw tunneled data:

- Base32 estimate: approximately 3914 bytes
- Base64 estimate: approximately 4697 bytes

The exact contents and complete record count cannot be confirmed from network metadata alone.

### Systems protected or not reached

The capture contains:

- 0 SMB access-denied responses
- 2 TCP reset events involving billing-srv-01

These responses show that at least some attempted operations or connections were rejected.

### Business and regulatory concern

Because the incident involved clinical and billing infrastructure, the organization should determine whether personal, healthcare or billing information was exposed. Packet evidence establishes a credible exfiltration path but does not by itself determine the legal classification or exact data contents.

---

## Detection Gap Analysis

The packet investigation revealed several activities that were observable but were not necessarily detected during the incident.

### Behavioral beaconing gap

Repeated HTTPS connections to the same destination had a regular timing pattern. Frequency and interval-based detection could identify similar behavior.

### DNS tunneling gap

Long encoded-looking TXT queries occurred repeatedly to a campaign-related domain. DNS query-length, TXT-frequency and encoded-label detection should be implemented.

### VPN anomaly gap

The external VPN connection should be enriched with source geography, ASN and account login history.

### Lateral movement gap

Unexpected RDP from a clinical workstation to a server and subsequent SMB enumeration should be monitored against normal user and asset roles.

### TLS / phishing infrastructure gap

TLS SNI can be compared against campaign IOC lists and internal first-seen domain tables even when HTTPS content is encrypted.

---

## Detection Rules Recommended

| Rule | Required Data | Detects | Main False Positives |
|---|---|---|---|
| C2 Beaconing Frequency | NetFlow, Zeek, firewall or PCAP sessions | C2 beaconing | monitoring agents, updates, backups |
| Long DNS Label | DNS logs / PCAP | DNS tunneling | CDNs, cloud-generated names |
| VPN Geography / ASN Anomaly | VPN logs + GeoIP/ASN | suspicious VPN pivot | employee travel, mobile ISPs |
| Cross-Role RDP | RDP/network logs + asset/user roles | lateral movement | approved IT support |
| High-Frequency TXT Tunnel | DNS logs / Zeek | DNS exfiltration | legitimate TXT automation |
| TLS SNI Campaign IOC | TLS SNI + IOC/first-seen list | phishing infrastructure access | legitimate newly observed domains |

---

## Recommendations

### Immediate - Next 24 Hours

- Isolate WS-NURSE-04 and billing-srv-01 pending endpoint investigation.
- Reset credentials associated with the incident and revoke active sessions.
- Block confirmed malicious domains and external infrastructure.
- Preserve the PCAPs and associated logs as investigation evidence.
- Review active VPN sessions and authentication events.
- Search DNS and firewall telemetry for the identified IOCs.

### Short-Term - Next 7 Days

- Deploy beaconing, DNS tunneling and cross-role RDP detections.
- Review VPN access from unusual source countries and ASNs.
- Review DNS egress and TXT-query visibility.
- Search the environment for additional systems communicating with campaign infrastructure.
- Review SMB and RDP activity involving the compromised systems.

### Medium-Term - Next 30 Days

- Strengthen email authentication and phishing controls.
- Improve DNS anomaly monitoring.
- Implement role-based restrictions for RDP and SMB.
- Review VPN authentication and MFA controls.
- Conduct a healthcare/billing data exposure assessment.
- Incorporate the new IOCs and behavior patterns into SOC detection content.

---

## Evidence Chain

The PCAP files were analyzed read-only using `tshark`. SHA-256 values below provide file-integrity references for the analyzed copies.

| PCAP | Purpose | Capture Window | SHA-256 |
|---|---|---|---|
| `normal_baseline_clinical.pcap` | Normal network baseline | 2026-04-14T01:59:59.796374000-0400 to 2026-04-14T02:29:57.873363000-0400 | `fd473ee11df705eb447baf0741a0a0d9202820709b925f6564bfcc1f4a7b65bd` |
| `phishing_click.pcap` | Phishing click and TLS metadata | 2026-04-14T11:02:33.142000000-0400 to 2026-04-14T11:03:22.772000000-0400 | `ecc9d24abc892883bda52919995e626e39829633d5601f9810fb710012f7cd61` |
| `c2_beaconing.pcap` | Repeated C2-style communications | 2026-04-14T22:00:12.000000000-0400 to 2026-04-14T23:59:11.641168000-0400 | `d8c3d1b88a88e1d27d39f44127ae8024c53db6c9f6b6eb27951bfb7db6f33a95` |
| `dns_exfil.pcap` | DNS tunnel / TXT analysis | 2026-04-15T18:15:02.300000000-0400 to 2026-04-15T18:44:56.049569000-0400 | `447cb45b498a03e77283e10ccbade38733df3d1210faef2d3995d04dd97faa32` |
| `lateral_movement.pcap` | RDP and SMB lateral movement | 2026-04-15T10:30:12.445000000-0400 to 2026-04-15T10:57:42.612402000-0400 | `7ae0cd46df2b82af6fa83db95560a78d3b582ef56cd56438bc5ff43545320586` |
| `full_timeline.pcap` | Cross-phase correlation and VPN activity | 2026-04-14T11:02:33.142000000-0400 to 2026-04-15T18:16:00.005000000-0400 | `56cc866cf302ca1bad0e4885ea7f37f7d211d084553278f5d3a65bf330b77d22` |

**Evidence handling note:** The original PCAP files should be preserved unchanged. Analysis should be performed against working copies, and hashes should be retained so future analysts can verify file integrity.

---

## Continuity with 4x00

The earlier 4x00 investigation established the phishing campaign, campaign infrastructure and likely exposure of user credentials.

This network investigation extends those findings in four important ways:

1. **Credential exposure is more strongly supported.**  
   The phishing-domain interaction is followed by suspicious external VPN activity and internal movement consistent with subsequent credential use.

2. **The post-click network timeline is now documented.**  
   Packet evidence connects the phishing interaction, repeated outbound communication, VPN activity, RDP movement, SMB discovery and DNS tunneling.

3. **Campaign infrastructure is linked to later activity.**  
   Infrastructure associated with the phishing event also appears in post-click network behavior.

4. **The impact assessment expands beyond phishing.**  
   The investigation now includes lateral movement and a DNS tunnel consistent with data exfiltration.

The evidence therefore changes the incident from a phishing-only investigation into a broader network compromise investigation.

---

## Evidence Confidence Summary

**Confirmed by packet evidence:**

- DNS/TLS communication with campaign infrastructure
- repeated HTTPS beaconing behavior
- external connection to the VPN endpoint
- RDP network communication
- SMB activity and rejected/reset connections
- DNS TXT tunneling pattern

**Strongly inferred:**

- credential submission at the phishing portal
- later use of the exposed account for VPN access
- exfiltration of structured data through the DNS tunnel

**Not confirmed by PCAP alone:**

- plaintext password
- endpoint malware execution
- exact commands inside encrypted traffic
- complete plaintext exfiltrated dataset
- MFA decision
- SIEM or EDR alert status
- identity of the person controlling the attacker infrastructure
