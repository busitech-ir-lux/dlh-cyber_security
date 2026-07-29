### The Risk Register Update

**Goal:** _Update the MedDefense Risk Register with the Crimson Tide threat, demonstrating that a Risk Register is a living document that responds to new intelligence._

---

**Context:** Your Risk Register from 1x03 T10 had a ransomware entry. Crimson Tide is not just "ransomware." It is a specific campaign with specific TTPs targeting MedDefense's specific profile. The existing entry must be updated, and a new entry for the FortiGate vulnerability must be added.

---

**Instructions:**

**Part 1 - Update Existing Entry**

Find the ransomware risk entry in your 1x03 Risk Register. Update it with:

- New threat source: Crimson Tide (CT) group
    
- Updated likelihood: Using the new ARO from T5
    
- Updated ALE
    
- Updated treatment justification: Does the current treatment decision still hold ?
    
- New KRI: What specific indicator would signal that Crimson Tide is targeting MedDefense ?
    

**Part 2 - New Entry: FortiGate Vulnerability**

Add a new risk entry (RISK-NEW-001) for CVE-2023-27997 on the FortiGate:

- Complete all fields from the 1x03 Risk Register template
    
- Treatment decision: The FortiGate support contract costs $2,400 to renew. The patch requires the contract. Calculate whether the patching cost is justified against the ALE.
    

**Part 3 - Register Governance Test**

The Risk Register governance note from 1x03 defined review triggers. Does the Crimson Tide advisory qualify as an out-of-cycle review trigger ? Quote the trigger criteria and explain why this event meets them.

---

# Answer

# 7. The Risk Register Update

## Part 1 — Updated Existing Ransomware Entry

### RISK-003 — Ransomware encrypts the billing server and connected backups

|Field|Original entry|Updated entry|
|---|---|---|
|**Risk ID**|RISK-003|RISK-003|
|**Risk title**|Ransomware encrypts the billing server and connected backups|Crimson Tide compromises MedDefense, exfiltrates regulated data, destroys backups and deploys ransomware across servers and workstations|
|**Risk category**|Cybersecurity / Operational / Availability|Cybersecurity / Operational / Patient Safety / Privacy|
|**Threat source**|BlackReef-style Ransomware-as-a-Service affiliates|**Crimson Tide RaaS affiliate network**|
|**Affected assets**|`billing-srv-01`, connected systems and backup storage|FortiGate 100F, `ad-dc-01`, `ad-dc-02`, `billing-srv-01`, `ehr-db-01`, `file-srv-01`, `pacs-srv-01`, `backup-srv-01`, `NAS-01`, Windows workstations and dependent medical devices|
|**Vulnerabilities and gaps**|M-02; Findings 001, 002 and 015|CVE-2023-27997; M-01 flat network; M-02 unisolated backups; M-04 no central monitoring; M-05 no MFA; Finding 018 weak Kerberos encryption; unencrypted EHR and backup data|
|**Existing controls**|Sophos on workstations, nightly Veeam backups and local system logs|Sophos on most workstations, local FortiGate logs, Veeam backups and normal account authentication; however, servers lack complete EDR coverage, backups are reachable from production and logs are not centrally monitored|
|**Asset value / loss basis**|$473,000|$473,000|
|**Exposure factor**|100%|100%|
|**Single Loss Expectancy**|$473,000|**$473,000**|
|**Annual Rate of Occurrence**|0.286|**1.0**|
|**Annual Loss Expectancy**|$135,278|**$473,000**|
|**Likelihood**|Possible|**Almost Certain during the active campaign**|
|**Impact**|Critical|**Critical**|
|**Inherent risk rating**|Critical|**Critical — Emergency**|
|**Treatment decision**|Mitigate|**Mitigate immediately**|
|**Risk owner**|James Chen, Deputy CISO|James Chen, Deputy CISO|
|**Control owner**|Sarah Park, IT Director|Sarah Park, IT Director|
|**Original KRI**|Failed backup test or a critical billing vulnerability remaining open for more than 14 days|Replaced with a campaign-specific KRI|
|**New KRI**|—|**One or more oversized requests to `/remote/logincheck`, an unexplained FortiGate administrator/CLI session, or an unexpected VPN session within a 24-hour period**|
|**Treatment status**|Open; planned mitigation|**Open — emergency remediation in progress**|
|**Original review date**|31 August 2026|**Out-of-cycle review opened 29 July 2026; daily review during the 72-hour response, then monthly**|

### Updated ALE calculation

```text
SLE = $473,000
Updated ARO = 1.0

Updated ALE = SLE × ARO
Updated ALE = $473,000 × 1.0
Updated ALE = $473,000 per year
```

The likelihood increases because Crimson Tide has successfully attacked five comparable hospitals in ten days, including three in MedDefense’s region, and uses an attack chain that directly matches MedDefense’s FortiGate, flat network, weak Kerberos configuration and accessible backups.

### Updated treatment justification

The original **Mitigate** decision remains correct, but the original roadmap timeline is no longer acceptable. Treatment must move from normal six-month implementation to emergency action because:

- MedDefense runs a vulnerable FortiOS version;
    
- exploitation requires no authentication;
    
- the campaign is active against similar hospitals;
    
- all seven phases map to MedDefense;
    
- the updated ALE is approximately 3.5 times the original ALE;
    
- the current controls do not reliably interrupt the attack chain.
    

Immediate treatment includes disabling or restricting SSL-VPN, renewing Fortinet support, patching the FortiGate, isolating `NAS-01`, reviewing logs, rotating credentials, accelerating segmentation and deploying monitoring.

---

# Part 2 — New Risk Entry: FortiGate Vulnerability

## RISK-NEW-001 — Exploitation of CVE-2023-27997 on the FortiGate 100F

|Field|Entry|
|---|---|
|**Risk ID**|RISK-NEW-001|
|**Risk title**|Unauthenticated exploitation of the MedDefense FortiGate through CVE-2023-27997|
|**Risk statement**|A Crimson Tide affiliate or another remote attacker may exploit CVE-2023-27997 on the internet-facing FortiGate 100F, gaining control of MedDefense’s only perimeter appliance and using it to capture credentials, discover internal networks and begin the ransomware attack chain.|
|**Risk category**|Cybersecurity / Network Infrastructure / Operational Resilience|
|**Threat source**|Crimson Tide affiliates, initial-access brokers and other opportunistic attackers using public exploit research|
|**Affected asset**|FortiGate 100F at MedDefense Central|
|**Asset role**|Only perimeter firewall and termination point for VPN connectivity supporting all three MedDefense sites|
|**Vulnerability**|CVE-2023-27997 — FortiOS SSL-VPN pre-authentication heap-based buffer overflow|
|**CWE**|CWE-122: Heap-based Buffer Overflow; broader NVD mapping CWE-787: Out-of-bounds Write|
|**Affected MedDefense version**|FortiOS 7.0.9|
|**Affected version range**|FortiOS 7.0.0–7.0.11|
|**Minimum fixed version**|FortiOS 7.0.12 or later; MedDefense has identified 7.0.14 as the available target release|
|**CVSS v3.1**|9.8 Critical|
|**CVSS vector**|`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`|
|**CISA KEV status**|Yes|
|**Public exploit status**|Public proof-of-concept and technical exploitation research are available|
|**Exploitability score**|5/5|
|**Existing controls**|FortiGate local logging, administrative authentication and normal firewall functionality|
|**Control weaknesses**|Vulnerability is exploited before authentication; no central monitoring; expired support contract prevents immediate firmware download; no redundant perimeter appliance|
|**Likelihood / ARO**|Almost Certain / 1.0 while exposed during the active campaign|
|**Impact**|Critical: firewall compromise, VPN credential exposure, loss of site connectivity, lateral movement and possible organisation-wide ransomware|
|**SLE**|$473,000, using the established ransomware loss scenario|
|**ALE**|**$473,000 per year**|
|**Inherent risk rating**|Critical — Emergency|
|**Treatment decision**|**Mitigate immediately**|
|**Treatment plan**|Preserve and inspect FortiGate logs; disable or restrict SSL-VPN; renew Fortinet support; obtain and verify FortiOS 7.0.14; patch or rebuild during an emergency maintenance window; terminate sessions; rotate credentials; enable MFA; validate all three VPN connections|
|**Treatment owner**|Sarah Park|
|**Risk owner**|James Chen|
|**Executive approver**|Dr. Patricia Morales|
|**Required cost**|$2,400 annual Fortinet support renewal|
|**Status**|Open — emergency action required|
|**Target date**|Contract renewal and exposure restriction within 24 hours; patching within 36 hours|
|**Residual risk after treatment**|Low for exploitation through CVE-2023-27997 after the patch is verified; broader ransomware risk remains High under RISK-003 because phishing, stolen credentials and other vulnerabilities remain possible|
|**KRI**|FortiOS version below 7.0.12, SSL-VPN publicly reachable while unpatched, or any matching FortiGate exploitation indicator|
|**Review frequency**|Daily until patched and validated; monthly afterward|

The advisory identifies CVE-2023-27997 as Phase 1 of the attack and specifically directs affected organisations to patch immediately or disable SSL-VPN.

## Cost justification

```text
Annual risk exposure = $473,000
Support renewal cost = $2,400
```

The minimum risk reduction required for the support renewal to break even is:

```text
Break-even reduction
= Control cost ÷ ALE

= $2,400 ÷ $473,000
= 0.00507
= approximately 0.51%
```

The renewal is financially justified if patching reduces the annual ransomware risk by more than **0.51%**.

Because the patch removes Crimson Tide’s confirmed initial-access vulnerability, the expected reduction is clearly greater than 0.51%.

### Cost-benefit conclusion

|Measure|Result|
|---|--:|
|Updated ALE|$473,000|
|Support renewal|$2,400|
|Cost as percentage of ALE|0.51%|
|Decision|**Approve immediately**|

The maximum loss avoided cannot be attributed entirely to this patch because ransomware could enter through other vectors. Nevertheless, the renewal cost is extremely small compared with the exposure and removes the exact entry method currently being used against similar hospitals.

---

# Part 3 — Register Governance Test

## Original governance trigger criteria

The Risk Register governance note states:

> “The register is reviewed monthly and receives an out-of-cycle review after an incident, critical vulnerability, major system change, audit finding, new regulatory requirement or supplier change. A KRI breach triggers investigation, risk-score and treatment review, and escalation where the risk exceeds tolerance.”

The governance structure assigns accountability for security operations and remediation to James Chen, while Sarah Park is responsible for technical execution; executive risk acceptance remains with the CEO.

## Does Crimson Tide qualify?

**Yes. The Crimson Tide advisory clearly requires an out-of-cycle review.**

It meets several trigger conditions:

### 1. Critical vulnerability

CVE-2023-27997 is a Critical, remotely exploitable vulnerability affecting MedDefense’s actual FortiOS 7.0.9 installation. This alone activates the out-of-cycle review requirement.

### 2. Incident-related intelligence

Although MedDefense does not yet have a confirmed incident, five comparable hospitals have been compromised and one nearby hospital remains in active containment. This materially changes MedDefense’s threat likelihood.

### 3. KRI escalation

The FortiGate is operating below the fixed firmware version while publicly exposed. Under the new KRI, this represents an immediate threshold breach requiring investigation and treatment review.

### 4. Supplier and support dependency

The expired Fortinet support contract prevents access to the necessary patch. This changes the effectiveness of the existing vulnerability-management treatment and requires executive spending approval.

### 5. Risk score exceeds tolerance

The updated ARO increases from 0.286 to 1.0, raising ALE from $135,278 to $473,000. The risk remains Critical and exceeds any reasonable tolerance for patient-care disruption, loss of regulated data and destruction of recovery systems.

## Governance conclusion

Crimson Tide is exactly the type of event for which out-of-cycle reviews exist. Waiting for the normal monthly review would leave MedDefense exposed to an active regional campaign using a confirmed vulnerability in its only perimeter appliance. The register must therefore be updated immediately, the treatment plan escalated to emergency status and the Board asked to approve the $2,400 support renewal and related response costs.
