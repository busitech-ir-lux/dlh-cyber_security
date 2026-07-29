### The CVE Deep Dive

**Goal:** _Research CVE-2023-27997 on NVD and assess its exploitability using the tools you mastered in Projects 0x02 and 0x04._

---

**Context:** The advisory names CVE-2023-27997 as the initial access vector. You have the tools and the skills to research this CVE with the same rigor you applied to the scan findings in 1x02. This time, the urgency is not academic. This CVE is being actively exploited against hospitals in your region right now.

---

**Instructions:**

**Part 1 - NVD Research**

Go to nvd.nist.gov and research CVE-2023-27997. Document:

- Full description
    
- CVSS v3.1 vector string and base score
    
- CWE classification
    
- Affected products and versions
    
- References (vendor advisory, patches)
    

**Part 2 - Exploit Assessment**

Using searchsploit and Exploit-DB, assess exploit availability:

- Is there a public exploit ?
    
- Is this CVE in the CISA KEV catalog ?
    
- What is your Exploitability Score (1-5, using the scale from 1x02 T4) ?
    

**Part 3 - MedDefense CVSS Contextualization**

Using the NIST CVSS Calculator, apply Environmental Metrics specific to MedDefense's FortiGate. Consider:

- The FortiGate is the ONLY perimeter defense (no redundancy)
    
- It terminates all VPN tunnels (all 3 sites depend on it)
    
- It sits on kill chain #1, #2 and #3 from 1x01
    
- The support contract has expired (patching requires renewal first)
    

What is the adjusted CVSS score for MedDefense ? Is it higher or lower than the base score ?

---

# Answer

# 1. The CVE Deep Dive: CVE-2023-27997

## Part 1 — NVD Research

### Full description

CVE-2023-27997 is a **heap-based buffer overflow** in the SSL-VPN component of Fortinet FortiOS and FortiProxy. An unauthenticated remote attacker can send specially crafted requests to the SSL-VPN interface and potentially execute arbitrary code or commands on the affected appliance. Successful exploitation may give the attacker control of the firewall and VPN gateway.

### CVSS v3.1

|Item|NVD result|
|---|---|
|Base score|**9.8 — Critical**|
|Vector|`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`|
|Attack Vector|Network|
|Attack Complexity|Low|
|Privileges Required|None|
|User Interaction|None|
|Scope|Unchanged|
|Confidentiality|High|
|Integrity|High|
|Availability|High|

The vulnerability is especially severe because it can be exploited remotely, before authentication, without user interaction.

### CWE classification

NVD and Fortinet provide two closely related classifications:

- **CWE-122 — Heap-based Buffer Overflow**, assigned by Fortinet.
    
- **CWE-787 — Out-of-bounds Write**, used by NIST as the broader weakness category.
    

Both describe unsafe memory writing that can corrupt the application’s heap and enable code execution.

### Affected products and versions

|Product|Affected versions|Minimum fixed version|
|---|---|---|
|FortiOS 7.2|7.2.0–7.2.4|7.2.5 or later|
|FortiOS 7.0|7.0.0–7.0.11|7.0.12 or later|
|FortiOS 6.4|6.4.0–6.4.12|6.4.13 or later|
|FortiOS 6.2|6.2.0–6.2.13|6.2.14 or later|
|FortiOS 6.0|6.0.0–6.0.16|6.0.17 or later|
|FortiProxy 7.2|7.2.0–7.2.3|7.2.4 or later|
|FortiProxy 7.0|7.0.0–7.0.9|7.0.10 or later|
|FortiProxy 2.0|2.0.0–2.0.12|2.0.13 or later|
|FortiProxy 1.2 and 1.1|Supported vulnerable releases|Migrate to a fixed release|

FortiOS 7.4 is not affected. If upgrading cannot be completed immediately, Fortinet identifies **disabling SSL-VPN** as the primary workaround.

### MedDefense applicability

MedDefense’s FortiGate 100F runs **FortiOS 7.0.9**, which is inside the affected range of 7.0.0–7.0.11. Therefore, MedDefense is confirmed vulnerable while SSL-VPN remains enabled and the appliance remains unpatched. The available FortiOS 7.0.14 release is newer than the minimum fixed version and contains the required correction.

### Main references

1. NVD record for CVE-2023-27997.
    
2. Fortinet PSIRT advisory **FG-IR-23-097**.
    
3. Fortinet FortiOS and FortiProxy fixed-release notes.
    
4. CISA Known Exploited Vulnerabilities catalogue.
    
5. CISA alert concerning Fortinet’s June 2023 security updates.
    

---

## Part 2 — Exploit Assessment

### SearchSploit and Exploit-DB result

The appropriate SearchSploit query is:

```bash
searchsploit --cve 2023-27997
```

At the time of this assessment, no dedicated exploit entry for CVE-2023-27997 was identified in the official Exploit-DB/SearchSploit index.

This does **not** mean that no public exploit information exists. SearchSploit only searches the Exploit-DB collection; it does not cover every public GitHub repository, research publication or vendor-specific proof of concept.

### Is there a public exploit?

**Yes — public proof-of-concept and detailed exploit research are available outside Exploit-DB.**

LEXFO, the research organisation that analysed the vulnerability, publicly documented the pre-authentication exploitation process and demonstrated code-execution techniques against vulnerable FortiGate appliances. Therefore, attackers have enough public technical information to reproduce or develop functional exploitation.

### Is this CVE in the CISA KEV catalogue?

**Yes.**

CISA added CVE-2023-27997 to the Known Exploited Vulnerabilities catalogue on **13 June 2023**, with a federal remediation deadline of **4 July 2023**. CISA’s current assessment identifies exploitation as active, the attack as automatable and the technical impact as total.

### Exploitability Score

## **5/5 — Maximum exploitability**

Justification:

- Exploitable remotely through the network.
    
- Internet-facing SSL-VPN attack surface.
    
- No authentication required.
    
- No user interaction required.
    
- Low attack complexity.
    
- Public exploitation research and PoC material exist.
    
- Listed in CISA KEV.
    
- Confirmed active exploitation.
    
- Successful exploitation can provide control of the perimeter appliance.
    

This vulnerability is not theoretical. It provides a practical initial-access path into organisations running vulnerable FortiGate SSL-VPN services.

---

## Part 3 — MedDefense CVSS Contextualisation

### Environmental metric selection

|Metric|Value|MedDefense justification|
|---|---|---|
|Confidentiality Requirement|`CR:H`|The FortiGate processes VPN credentials, sessions and access to systems containing patient and financial data.|
|Integrity Requirement|`IR:H`|Compromise could allow modification of firewall rules, routes, VPN settings and security policies.|
|Availability Requirement|`AR:H`|It is the only perimeter defence, has no redundancy and supports VPN access for all three sites.|
|Modified Attack Vector|`MAV:N`|The SSL-VPN interface is remotely accessible.|
|Modified Attack Complexity|`MAC:L`|No MedDefense control materially increases exploitation difficulty.|
|Modified Privileges Required|`MPR:N`|The attack occurs before authentication.|
|Modified User Interaction|`MUI:N`|No employee action is required.|
|Modified Scope|`MS:U`|The immediate vulnerable security authority remains the FortiGate appliance.|
|Modified Confidentiality|`MC:H`|Appliance compromise can expose credentials, sessions and protected network access.|
|Modified Integrity|`MI:H`|An attacker could change firewall, routing and VPN configurations.|
|Modified Availability|`MA:H`|Failure or malicious modification could disconnect all three MedDefense sites.|

Environmental metrics are intended to represent the importance of the vulnerable component and the controls present in the organisation’s own environment.

### Environmental vector

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H
```

### Adjusted MedDefense score

## **Environmental score: 9.8 — Critical**

### Comparison with the base score

The MedDefense-adjusted score is **the same as the 9.8 base score**.

It is not higher because the base vector already assigns High impact to confidentiality, integrity and availability and is already close to the CVSS maximum. Setting the three environmental security requirements to High confirms the extreme importance of the appliance but does not mathematically increase the score beyond 9.8 under this vector.

### Expired support contract

The expired support contract does not directly change a CVSS environmental metric. A vendor patch officially exists, so the vulnerability still has an available official fix.

However, the expired contract is an important **operational risk multiplier** because:

- MedDefense cannot immediately download the firmware.
    
- Contract renewal must occur before patching.
    
- The delay increases the exposure window.
    
- The vulnerable system is the only perimeter gateway.
    
- All three sites depend on it.
    
- It supports three previously identified attack chains.
    

Therefore, the numerical severity remains **9.8**, but MedDefense’s actual organisational risk is higher than the CVSS number alone communicates.

## Final assessment

|Measure|Result|
|---|---|
|NVD base score|**9.8 Critical**|
|MedDefense environmental score|**9.8 Critical**|
|Exploitability score|**5/5**|
|Public exploit material|**Yes, outside Exploit-DB**|
|Exploit-DB entry|**No dedicated entry identified**|
|CISA KEV|**Yes**|
|MedDefense affected|**Yes — FortiOS 7.0.9**|
|Required action|**Patch immediately or disable SSL-VPN until patched**|

CVE-2023-27997 represents an immediate and unacceptable risk to MedDefense. The vulnerable appliance is internet-facing, has no redundant replacement, controls all site-to-site VPN connectivity and is already being used as the initial-access vector in the Crimson Tide scenario. MedDefense should preserve and inspect FortiGate logs, disable SSL-VPN if the firmware cannot be obtained immediately, renew the support contract and upgrade the appliance under emergency change control.
