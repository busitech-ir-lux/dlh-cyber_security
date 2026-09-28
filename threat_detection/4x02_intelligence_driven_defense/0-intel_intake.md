

\### Intelligence Intake Summary



This intake processes four HEALTHBANE intelligence sources and organizes their indicators and claims into a common structure for later assessment. At this stage, indicators are collected and compared, but conflicting attribution and confidence claims are not resolved.



\---



\### Source 1 — HC3 Advisory



\*\*1. Source name:\*\*  

HC3 Sector Threat Advisory — `HC3-2026-HEALTHBANE-001`, \_HEALTHBANE Campaign - Multi-Stage Attacks Against US Healthcare Providers\_



\*\*2. Source type:\*\*  

Government advisory



\*\*3. Date published or report date:\*\*  

2026-04-25



\*\*4. TLP classification or distribution marking:\*\*  

TLP:CLEAR — unrestricted distribution. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\*\*5. Number of indicators provided:\*\*  

23



\*\*6. Types of indicators:\*\*



\- 8 domains

\- 6 IP addresses

\- 5 SHA-256 hashes

\- 4 URLs

\- 0 email addresses HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\*\*7. One-line summary of the intelligence claim:\*\*  

HC3 assesses HEALTHBANE as a coordinated, multi-stage campaign targeting US healthcare organizations through credential phishing, malware delivery, and DNS-based data exfiltration. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\*\*8. Key limitations or caveats stated by the source:\*\*  

HC3 has direct or partner visibility into only 6 of at least 14 targeted organizations, and only two showed all three stages. Attribution to a named actor is \*\*unconfirmed\*\*, with HC3 explicitly declining to endorse commercial tracking names. Attribution confidence is LOW. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE… HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\---



\### Source 2 — Acme Commercial Feed



\*\*1. Source name:\*\*  

Acme CTI Commercial Feed — `ACME-HEALTH-2026-0426-117`



\*\*2. Source type:\*\*  

Commercial feed



\*\*3. Date published or report date:\*\*  

2026-04-26 08:14 UTC



\*\*4. TLP classification or distribution marking:\*\*  

TLP:AMBER — authorized for internal defense at MedDefense Health Systems only.



\*\*5. Number of indicators provided:\*\*  

41



\*\*6. Types of indicators:\*\*



\- 12 domains

\- 15 IP addresses

\- 9 SHA-256 hashes

\- 5 URLs

\- 0 email addresses



\*\*7. One-line summary of the intelligence claim:\*\*  

Acme clusters 41 indicators under its proprietary \*\*VITALSCORE\*\* campaign label, including confirmed-looking HEALTHBANE infrastructure as well as lower-confidence indicators connected through similarity analysis.



\*\*8. Key limitations or caveats stated by the source:\*\*  

The feed is partly automated. Indicators are auto-tagged by Acme's clustering engine and only a sample received human analyst review. Acme also warns that VITALSCORE does not necessarily correspond to externally tracked actor names. commercial\_feed\_extract



Several entries have very weak support. Examples include shared DigitalOcean infrastructure, CDN and Cloudflare addresses, and a Microsoft Outlook cloud IP. Acme itself marks some as likely noise or explicitly warns not to block them. commercial\_feed\_extract



\---



\### Source 3 — Researcher Blog



\*\*1. Source name:\*\*  

Marcus Weller — \_The Phishing Kit Behind The HEALTHBANE Campaign: A Technical Walkthrough\_



\*\*2. Source type:\*\*  

Open-source research



\*\*3. Date published or report date:\*\*  

2026-04-24 14:22 UTC



\*\*4. TLP classification or distribution marking:\*\*  

N/A — public blog post with no TLP marking. researcher\_blog\_analysis



\*\*5. Number of indicators provided:\*\*  

14



\*\*6. Types of indicators:\*\*



\- 5 domains

\- 3 IP addresses

\- 4 SHA-256 hashes

\- 2 URLs

\- 0 email addresses researcher\_blog\_analysis



\*\*7. One-line summary of the intelligence claim:\*\*  

The researcher links HEALTHBANE infrastructure through a recovered phishing kit and tooling/infrastructure fingerprints and assesses with MEDIUM confidence that the operator corresponds to an actor he privately tracks as \*\*APT-MEDAGENT\*\*.



\*\*8. Key limitations or caveats stated by the source:\*\*  

The researcher is working alone and has no victim telemetry. His attribution is based entirely on open-source infrastructure and tooling overlap rather than telemetry, signals intelligence, or insider reporting. researcher\_blog\_analysis



He also warns that Acme's VITALSCORE clustering can generate false positives and that low-evidence commercial indicators should not be over-weighted. researcher\_blog\_analysis



\---



\### Source 4 — MedDefense 4x00 Investigation



\*\*1. Source name:\*\*  

MedDefense Health Systems — `MD-2026-IR-0414-001`, \_Phishing campaign against MedDefense staff\_



\*\*2. Source type:\*\*  

Internal investigation



\*\*3. Date published or report date:\*\*  

2026-04-16



\*\*4. TLP classification or distribution marking:\*\*  

INTERNAL — TLP not applicable; not for external sharing. An indicator-only extract may be distributed to HC3. meddefense\_4x00\_findings



\*\*5. Number of indicators provided:\*\*  

11



\*\*6. Types of indicators:\*\*



\- 3 domains

\- 3 IP addresses

\- 1 SHA-256 hash

\- 1 URL

\- 3 email addresses meddefense\_4x00\_findings



\*\*7. One-line summary of the intelligence claim:\*\*  

MedDefense identified a coordinated phishing campaign against staff and assessed that one employee likely submitted credentials, but no confirmed exploitation had been observed when the 4x00 investigation closed.



\*\*8. Key limitations or caveats stated by the source:\*\*  

The investigation did not include packet analysis, endpoint forensics, or follow-on authentication correlation. Credential exposure was therefore \*\*likely but not yet confirmed\*\*, and no Stage 2 or Stage 3 activity had been observed at MedDefense. meddefense\_4x00\_findings



\---



\# Consolidated View



\### 1. Total raw indicators across all sources



|Source|Raw indicators|

|---|---|

|HC3|23|

|Commercial feed|41|

|Researcher blog|14|

|MedDefense 4x00|11|

|\*\*Total\*\*|\*\*89\*\*|



The supplied files therefore agree exactly with the expected \*\*89 raw indicators\*\*.



\### 2. Total unique indicators after deduplication



Direct extraction of the supplied materials produces:



\- \*\*50 unique exact indicator values\*\*

\- \*\*48 unique indicators after normalizing equivalent parameterized MedDefense phishing URLs\*\*



This \*\*does not match the provided expected reference count of 64\*\*.



For example, the same MedDefense phishing endpoint appears as a template using `<8hex>` in HC3, `<hex>` in the commercial feed, and as the concrete victim URL containing `dmarsh` and `a8f3e2d1` in the internal investigation. These should logically be treated as the same URL pattern during normalization. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE… meddefense\_4x00\_findings



\*\*Reference expected by task: 64\*\*  

\*\*Actual from supplied files: 48 normalized unique indicators\*\*



This discrepancy should be documented rather than silently changing the data.



\### 3. Indicators that appear in multiple sources



There is strong cross-source overlap around the core HEALTHBANE infrastructure. Important repeated indicators include:



\- `meddefense-portal.com`

\- `medequip-supplies.net`

\- `meddefense-benefits.org`

\- `outlook-protection.com`

\- `healthbane-c2.net`

\- `portal-secure-meddefense.com`

\- `91.234.99.107`

\- `185.176.43.22`

\- `164.90.218.73`

\- `51.38.42.17`

\- `51.38.42.191`

\- the HEALTHBANE Stage 2 document and PowerShell hashes

\- the invoice lure PDF hash

\- the MedDefense credential-harvesting URL pattern



This cross-source corroboration is strongest for the original phishing infrastructure. HC3 itself states that its indicators came from six partner organizations, sensors, and open-source corroboration. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\### 4. Indicators that appear in only one source



The main source-only indicators come from the commercial feed. These include low-confidence or similarity-clustered domains, shared hosting/CDN addresses, and several hashes not corroborated by HC3, MedDefense, or the researcher.



Examples include:



`secure-insurance-login.com`, `claims-verify-portal.net`, `159.89.112.45`, `192.99.207.114`, `20.83.144.56`, `13.107.42.14`, `172.67.192.40`, and `104.21.35.7`.



Some are explicitly described by Acme as shared infrastructure, likely noise, or unsafe to block. commercial\_feed\_extract



MedDefense also uniquely contributes the three sender email addresses:



`noreply@meddefense-portal.com`  

`invoices@medequip-supplies.net`  

`hr-notifications@meddefense-benefits.org` meddefense\_4x00\_findings



The researcher uniquely contributes some artifacts, including the phishing-kit ZIP hash and the `/api/ingest` URL. researcher\_blog\_analysis



\---



\# Source Conflicts to Resolve Later



\*\*Attribution labels:\*\* HC3 calls the campaign \*\*HEALTHBANE\*\* and does not confirm a named actor. Acme uses \*\*VITALSCORE\*\*. The researcher uses \*\*APT-MEDAGENT\*\* and considers VITALSCORE a possible alias, but cannot confirm that the two labels correspond exactly. HC3\_Advisory\_HEALTHBANE\_TLP\_CLE… researcher\_blog\_analysis



\*\*Confidence differences:\*\* HC3 has HIGH confidence in the observed campaign stages but LOW confidence in actor attribution. The researcher assigns MEDIUM confidence to his attribution. Acme assigns numerical confidence values to individual indicators, including low-confidence automatically clustered items.



\*\*Commercial-feed noise:\*\* The Acme feed contains indicators produced through similarity clustering with little or no external corroboration. Some entries are explicitly identified as shared infrastructure, likely noise, or unsuitable for blocking. These should not automatically be treated as confirmed HEALTHBANE IOCs. commercial\_feed\_extract



\*\*Indicators missing from stronger sources:\*\* Several Acme indicators do not appear in HC3, MedDefense, or the researcher material. Their absence does not automatically prove they are false, but they require additional validation before being considered actionable.



\*\*Different visibility:\*\* MedDefense observed only the phishing/credential-harvesting stage and explicitly reported no Stage 2/3 activity. HC3 later had visibility across six organizations and confirmed Stage 2 and Stage 3 activity at two organizations. The difference is therefore not necessarily contradictory; the sources have different scopes and observation periods. meddefense\_4x00\_findings HC3\_Advisory\_HEALTHBANE\_TLP\_CLE…



\*\*Intake conclusion:\*\* The four sources strongly corroborate the core HEALTHBANE phishing infrastructure, but they differ substantially in scope, confidence, attribution, and indicator quality. The HC3 and direct MedDefense findings provide stronger evidence for core activity, while the commercial feed requires further triage because it deliberately includes lower-confidence automated clustering. Attribution and low-confidence source-only indicators should remain unresolved at this intake stage.

