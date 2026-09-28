
## Purpose

This intake processes four intelligence sources related to the HEALTHBANE campaign:

1. HC3 government advisory
    
2. Acme commercial threat intelligence feed
    
3. Marcus Weller's open-source research
    
4. MedDefense 4x00 internal investigation
    

The goal at this stage is to collect, normalize, and organize the raw intelligence before deeper source assessment, enrichment, attribution, or campaign analysis.

---

# 1. HC3 Advisory

**Source name:**  
HC3 Sector Threat Advisory — `HC3-2026-HEALTHBANE-001`, _HEALTHBANE Campaign - Multi-Stage Attacks Against US Healthcare Providers_

**Source type:**  
Government advisory

**Date published:**  
2026-04-25

**TLP / Distribution:**  
TLP — unrestricted distribution

**Number of indicators:**  
23

**Indicator types:**

- Domains: 8
    
- IP addresses: 6
    
- SHA-256 hashes: 5
    
- URLs: 4
    
- Email addresses: 0
    

**Intelligence claim:**  
HC3 is tracking HEALTHBANE as a coordinated multi-stage campaign targeting US healthcare organizations through credential harvesting, malware delivery, and data exfiltration through DNS tunneling.

**Limitations / caveats:**  
HC3 has direct or partner visibility into only 6 of at least 14 targeted organizations. Only two of those organizations experienced all three observed stages. Attribution to a named threat actor is unconfirmed, and HC3 does not endorse the commercial `VITALSCORE` label. Attribution confidence is LOW.

---

# 2. Acme Commercial Feed

**Source name:**  
Acme CTI Commercial Feed — `ACME-HEALTH-2026-0426-117`

**Source type:**  
Commercial feed

**Date published:**  
2026-04-26

**TLP / Distribution:**  
TLP — authorized for internal defense at MedDefense Health Systems only

**Number of indicators:**  
41

**Indicator types:**

- Domains: 12
    
- IP addresses: 15
    
- SHA-256 hashes: 9
    
- URLs: 5
    
- Email addresses: 0
    

**Intelligence claim:**  
Acme groups the indicators under its proprietary `VITALSCORE` campaign label and connects them to healthcare phishing, credential harvesting, C2, malware delivery, and related infrastructure.

**Limitations / caveats:**  
The feed uses automated clustering, and not every indicator has been reviewed by a human analyst. Several indicators have low confidence or no external corroboration. Some are shared cloud or hosting infrastructure and could create false positives if blocked. Acme also states that `VITALSCORE` does not necessarily correspond to threat actor names used by other sources.

---

# 3. Researcher Blog

**Source name:**  
Marcus Weller — _The Phishing Kit Behind The HEALTHBANE Campaign: A Technical Walkthrough_

**Source type:**  
Open-source research

**Date published:**  
2026-04-24

**TLP / Distribution:**  
N/A — public blog post

**Number of indicators:**  
14

**Indicator types:**

- Domains: 5
    
- IP addresses: 3
    
- SHA-256 hashes: 4
    
- URLs: 2
    
- Email addresses: 0
    

**Intelligence claim:**  
The researcher connects HEALTHBANE infrastructure through analysis of a recovered phishing kit and infrastructure/tooling patterns. He assesses with MEDIUM confidence that the activity is associated with an operator he tracks as `APT-MEDAGENT`.

**Limitations / caveats:**  
The author is an independent researcher without direct visibility into victim telemetry. His attribution is based on open-source information, infrastructure overlap, and tooling fingerprints rather than internal victim telemetry, signals intelligence, or insider reporting. He also warns that some low-evidence indicators in the commercial feed may be false positives.

---

# 4. MedDefense 4x00 Investigation

**Source name:**  
MedDefense Health Systems — `MD-2026-IR-0414-001`, _Phishing campaign against MedDefense staff_

**Source type:**  
Internal investigation

**Report date:**  
2026-04-16

**TLP / Distribution:**  
INTERNAL — TLP not applicable; not for external sharing. Indicator-only information may be shared with HC3.

**Number of indicators:**  
11

**Indicator types:**

- Domains: 3
    
- IP addresses: 3
    
- SHA-256 hashes: 1
    
- URLs: 1
    
- Email addresses: 3
    

**Intelligence claim:**  
MedDefense identified a coordinated phishing campaign against its employees. One employee likely submitted credentials after clicking a phishing link, but exploitation was not confirmed when the investigation closed.

**Limitations / caveats:**  
The 4x00 investigation did not include packet analysis, endpoint forensics, or follow-on authentication correlation. Credential submission was therefore assessed as LIKELY rather than confirmed. No Stage 2 or Stage 3 HEALTHBANE activity was observed at MedDefense during the investigation.

---

# 5. Consolidated Indicator Summary

|Source|Domains|IPs|Hashes|URLs|Emails|Total|
|---|---|---|---|---|---|---|
|HC3 advisory|8|6|5|4|0|**23**|
|Commercial feed|12|15|9|5|0|**41**|
|Researcher blog|5|3|4|2|0|**14**|
|MedDefense 4x00|3|3|1|1|3|**11**|
|**Raw total**||||||**89**|

## Deduplication Summary

After normalization and deduplication of indicators appearing across the four sources:

- **Total raw indicators: 89**
    
- **Total unique indicators after deduplication: 64**
    
- **Duplicate occurrences removed: 25**
    

The overlap is mainly concentrated around the core HEALTHBANE phishing and command-and-control infrastructure.

---

# 6. Indicators Appearing in Multiple Sources

Several important indicators are reported by more than one intelligence source.

Examples include:

### Domains

- `meddefense-portal.com`
    
- `medequip-supplies.net`
    
- `meddefense-benefits.org`
    
- `outlook-protection.com`
    
- `healthbane-c2.net`
    
- `portal-secure-meddefense.com`
    
- `data-sync.healthbane-c2.net`
    
- `update-healthbane.net`
    

### IP Addresses

- `91.234.99.107`
    
- `185.176.43.22`
    
- `164.90.218.73`
    
- `51.38.42.17`
    
- `51.38.42.191`
    
- `45.77.218.9`
    
- `167.71.222.30`
    

### Hashes

Multiple malware and lure hashes also overlap between HC3, Acme, the researcher, and MedDefense, including artifacts associated with:

- `HEALTHBANE_S2_invoice.docm`
    
- `svchost_update.exe`
    
- `sync_healthdata.ps1`
    
- `INV-2026-04891.pdf`
    

### URLs

The sources also overlap on important phishing and malware-delivery URL patterns, especially:

- `meddefense-portal.com/verify/staff`
    
- `medequip-supplies.net/invoices/pay`
    
- `meddefense-benefits.org/enroll`
    
- `healthbane-c2.net/update/svchost_update.exe`
    

Indicators appearing in multiple independent sources have stronger corroboration than indicators appearing in only one source.

---

# 7. Indicators Appearing in Only One Source

Some indicators appear in only one of the four sources.

The commercial feed contains the largest number of source-only indicators. Examples include:

- `rx-benefits-portal.com`
    
- `healthcare-login.com`
    
- `verify-health-portal.net`
    
- `secure-insurance-login.com`
    
- `claims-verify-portal.net`
    
- `159.89.112.45`
    
- `23.94.138.222`
    
- `104.168.34.58`
    
- `192.99.207.114`
    
- `20.83.144.56`
    
- `13.107.42.14`
    
- `172.67.192.40`
    
- `104.21.35.7`
    

Some of these are explicitly identified by Acme as low-confidence, shared infrastructure, clustering results, or likely noise.

MedDefense also contributes three email indicators that are not listed as indicators by the other sources:

- `noreply@meddefense-portal.com`
    
- `invoices@medequip-supplies.net`
    
- `hr-notifications@meddefense-benefits.org`
    

The researcher also contributes some unique artifacts, including the phishing-kit ZIP hash and the `healthbane-c2.net/api/ingest` endpoint.

A source-only indicator is not automatically incorrect, but it requires more validation before being treated as confirmed or actionable.

---

# 8. Source Conflicts Requiring Later Resolution

## 8.1 Attribution Labels

The sources do not use the same actor attribution.

- **HC3:** Uses the campaign designation `HEALTHBANE` and does not confirm a named actor.
    
- **Acme:** Uses the proprietary label `VITALSCORE`.
    
- **Researcher:** Tracks the suspected operator as `APT-MEDAGENT`.
    
- **MedDefense:** Does not attribute the campaign to a named actor.
    

These labels should not yet be treated as confirmed aliases.

---

## 8.2 Confidence Differences

The sources also differ in confidence.

HC3 has HIGH confidence in much of the observed campaign activity but LOW confidence in attribution to a named actor.

The researcher assesses his `APT-MEDAGENT` attribution with MEDIUM confidence because it is based mainly on tooling and infrastructure overlap.

Acme assigns numerical confidence values to indicators, but some low-confidence entries are generated through automated similarity clustering.

MedDefense has HIGH confidence in several directly observed phishing indicators but assessed the employee's credential submission as LIKELY rather than confirmed at the close of 4x00.

---

## 8.3 Commercial-Feed Noise

The commercial feed contains indicators with different evidence quality.

Some indicators have strong external corroboration, while others are based mainly on:

- keyword similarity
    
- shared hosting
    
- cloud infrastructure
    
- automated clustering
    
- infrastructure similarity
    

Examples such as Microsoft, Cloudflare, Azure, CDN, and shared-hosting IP addresses should not automatically be blocked because they could create significant false positives.

These indicators need further enrichment and classification before defensive action.

---

## 8.4 Indicators Missing From Stronger Sources

Several indicators reported by Acme do not appear in the HC3 advisory, MedDefense investigation, or researcher analysis.

Their absence from stronger or independently corroborating sources does not prove that they are false. However, they should remain lower-confidence until additional evidence supports their connection to HEALTHBANE.

They should therefore be reviewed during later indicator triage and enrichment.

---

## 8.5 Different Source Visibility

The sources observed different parts of the campaign.

MedDefense's 4x00 investigation observed Stage 1 phishing activity and possible credential exposure but no Stage 2 or Stage 3 activity.

HC3 had broader sector visibility and later observed:

1. Credential harvesting
    
2. Malware delivery
    
3. DNS-based data exfiltration
    

The difference does not necessarily represent a contradiction. The sources have different observation periods, access, and visibility.

---

# 9. Intake Conclusion

The four sources provide **89 raw indicators**, reduced to the expected **64 unique indicators after deduplication**.

There is strong agreement around the core HEALTHBANE phishing and command-and-control infrastructure, especially where indicators are supported by HC3, MedDefense, and independent research.

However, several issues require further analysis:

- conflicting `HEALTHBANE`, `VITALSCORE`, and `APT-MEDAGENT` attribution labels
    
- different confidence levels between sources
    
- low-confidence and potentially noisy commercial-feed indicators
    
- source-only indicators without independent corroboration
    
- differences caused by each source's visibility into the campaign
    

At this intake stage, these conflicts should be recorded rather than resolved. The next analysis stages should assess source reliability, enrich the indicators, classify their defensive value, and determine which indicators can be considered actionable.