# Forensic Investigation Report

**Case number:** LH-2026-0414-01  
**Incident ID:** IR-2026-0414-01  
**Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z [ACQ-01]  
**Report date:** 2026-10-18 (document drafting date; incident occurred 2026-04-13–14)  
**Lead investigator:** PENDING — not supplied  
**Classification:** Internal — Legal Hold  
**Distribution:** Dr. Patricia Morales (CISO); Helena Reyes (General Counsel); James Chen (SOC Lead) [CASE-01: assignment specification]  
**Report status:** **PRELIMINARY / NOT EVIDENCE-VALIDATED — NOT FOR FINAL LEGAL OR BOARD SIGN-OFF**. Disk and memory images, SOC, proxy, AD, and LIS original logs have not been provided for examination; no actual integrity baselines or CoC access entries have been verified [ART-001, ART-002, ART-003; LOG-PROXY, LOG-AD, LOG-SIEM, LIS-AUDIT pending].

---

## 1. Executive Summary

An investigation scenario involving MedDefense describes stolen staff credentials, suspected unauthorized remote access, malicious activity on clinical workstations, and access to patient laboratory information [CASE-01; `correlated_timeline.md`, candidate events]. **These earlier steps are investigative leads, not yet validated forensic conclusions** because the supporting proxy, authentication, disk, and memory records were not available for independent review [LOG-PROXY, LOG-AD, ART-001-Fxx, ART-002-Mxx, ART-003-Mxx pending].

The strongest supplied case-specific finding is that, between **03:43 and 03:44 UTC on 14 April 2026**, an account named `dmarsh` accessed **14 laboratory report PDFs** on `LIS-WSIDE-01`, outside its authorized ER-patient scope [SUPPLIED-SUMMARY-01, Task 7]. Those reports reportedly include patient names, dates of birth, treating physician identities and blood/metabolic laboratory results [SUPPLIED-SUMMARY-01]. The number of *unique patients* needs verification against the underlying audit records [LIS-AUDIT pending].

The supplied summary states that network logs did **not confirm exfiltration to external command-and-control addresses** [SUPPLIED-SUMMARY-01]. This is **not evidence that the records were never acquired, read, copied, or disclosed**. A preliminary HIPAA review therefore treats the unauthorized access as a **presumed breach unless an applicable exception or documented low-probability risk assessment supports a different outcome** [SUPPLIED-SUMMARY-01; `hipaa_breach_assessment.md`]. Legal and privacy teams must make the final reportability decision based on original records.

Evidence integrity requires special caution: the acquirer recorded **no acquisition-time hashes**, a **read-write access of the live filesystem before imaging**, and a **custody documentation gap** [ACQ-01, `chain_of_custody.md`]. These limitations do not prove tampering, but they limit what can be asserted about the images' state at acquisition.

## 2. Methodology

The planned evidence set consists of a RAW disk image of `WST-WS-031` (ART-001), a memory image of the same host (ART-002), and a memory image of `WST-WS-017` (ART-003), acquired by Mike Torres on 14 April 2026 [ACQ-01]. The disk image was acquired with FTK Imager from 04:51–06:14Z; memory acquisitions used WinPmem at 03:02Z and 03:38Z, respectively [ACQ-01].

The defined process is: calculate an initial SHA-256 baseline where none existed, reverify it before each session with `verify_artifacts.sh`, maintain an append-only chain of custody, access disk evidence read-only, examine partitions and filesystem using TSK (`mmls`, `fsstat`, `fls`, `mactime`, `icat`), inspect registry/tasks and execution traces, and examine both images with Volatility 3 [ART-001; ART-002; ART-003; `filesystem_analysis.md`; `persistence_analysis.md`; `memory_analysis.md`]. SIEM alerts are contextual leads; proxy, AD, and LIS records require source-level corroboration [LOG-SIEM, LOG-PROXY, LOG-AD, LIS-AUDIT pending]. **These tools have not been run against the original artifacts for this draft.**

## 3. Technical Findings

### 3.1 Disk artifacts — ART-001

**ART-001-F00 (confirmed from acquisition notes):** Mike Torres acquired `wst-ws-031.dd` in RAW format using FTK Imager, starting at 04:51Z and completing at 06:14Z; he reported checking for `update.xml` through a live read-write filesystem mount before the image was created [ACQ-01]. This introduces a potential metadata-integrity concern; it does not independently establish that the file was malicious [ACQ-01].

**ART-001-F01+ (unverified):** A possible staging XML, additional dropped files and suspicious entries under `C:\Users\dmarsh\AppData\Local\Temp\` remain to be established from TSK file entries and SHA-256 hashes [ART-001; `filesystem_analysis.md`, pending]. No inode number, MAC time, recovered byte count or file hash is yet defensible.

**ART-001-R01+ (unverified):** User `Run`/`RunOnce` keys, XML scheduled tasks, UserAssist, ShimCache, Amcache and Recent LNKs are specified investigative targets, **not confirmed persistence installations or execution events** [ART-001; `persistence_analysis.md`, pending].

### 3.2 Memory artifacts — ART-002 and ART-003

**ART-002-M00 (acquisition record only):** The acquirer reports capturing live WST-WS-031 memory at 03:02Z while it was beaconing [ACQ-01]. No independently inspected connection or process record is available [ART-002-M01–M08 pending].

**ART-002-M01–M08 (unverified):** The proposed PowerShell-to-MSBuild process chain, network endpoint, injected memory, loaded modules and any LSASS interaction must be supported by actual Volatility output. A suspicious memory VAD alone is not proof of injection. SAM hash availability is not proof of hash theft or Kerberos ticket access [ART-002; `memory_analysis.md`].

**ART-003-M01–M03 (unverified):** An alleged second beacon from WST-WS-017 must be checked using its own process list, network scan, and command-line artifacts [ART-003; `memory_analysis.md`].

### 3.3 Network and proxy evidence

**LOG-PROXY-01 (unverified):** The project description proposes a phishing link click and submission to a lookalike login site, followed by possible beacon traffic [LOG-PROXY; LOG-SIEM pending]. Neither the timestamp nor the content of the requests has been independently examined; an HTTP request alone cannot prove submission of a password [LOG-PROXY pending].

**LOG-NET-01 (limited source statement):** The scenario summary reports that no exfiltration to the external C2 addresses was confirmed in network logs [SUPPLIED-SUMMARY-01]. Other transfer routes and local viewing have not been excluded [LOG-PROXY; original network records pending].

### 3.4 Authentication and patient records

**LOG-AD-01 (unverified):** Possible VPN reuse of `dmarsh` credentials, Kerberos TGS requests for `cifs/WST-WS-017` and `cifs/LIS-WSIDE-01`, and remote logons require original AD/VPN and destination-host logs [LOG-AD pending]. A TGS request does not alone establish lateral movement [LOG-AD pending].

**SUPPLIED-SUMMARY-01 (confirmed *within the supplied scenario*, original audit pending):** The scenario states that the `dmarsh` account accessed 14 ER-patient lab report PDFs under `/LIS/reports/daily/*.pdf` at LIS-WSIDE-01 during 03:43Z–03:44Z, beyond its authorized access [SUPPLIED-SUMMARY-01]. Exact filenames, unique-patient count, file-open semantics and whether any copies were saved are not independently validated [LIS-AUDIT pending].

## 4. Condensed Incident Timeline

The following are **candidate events in hypothesized sequence**, except the dated source-summary access and acquisition markers. Timestamps, linkage and technique attribution require source-level verification [CASE-01; `correlated_timeline.md`].

| UTC timestamp | Event | Status | Evidence reference |
|---|---|---|---|
| Apr 13 — exact time unverified | Suspected phishing link and credential submission | Possible | LOG-PROXY-01 pending |
| Unverified | Suspected use of staff account through VPN | Possible | LOG-AD-01 pending |
| Unverified | Suspected PowerShell / MSBuild activity, staged files | Possible | ART-002-M02/M03; ART-001-F01 pending |
| Unverified | Suspected Run-key/task persistence | Possible | ART-001-R01+ pending |
| Unverified | Suspected WST-WS-017 and LIS-WSIDE-01 lateral movement | Possible | LOG-AD-01; ART-003-M01–M03 pending |
| **2026-04-14 03:43–03:44Z** | **Fourteen laboratory PDFs reportedly accessed outside authorized scope** | Supplied finding; audit unverified | SUPPLIED-SUMMARY-01 |
| 2026-04-14 03:02Z / 03:38Z | WST-WS-031 / WST-WS-017 memory captures (collection markers, not attacker events) | Acquisition-record supported | ACQ-01 |
| 2026-04-14 04:51–06:14Z | WST-WS-031 disk collection (collection marker) | Acquisition-record supported | ACQ-01 |

## 5. HIPAA Breach Scope Determination

**Potentially affected PHI:** identifiers (name, birth date), attending physician, complete blood count and metabolite-panel results in 14 PDFs [SUPPLIED-SUMMARY-01]. **Potential patient count:** up to 14 if each PDF corresponds to a different person; unique individuals are **unverified** [SUPPLIED-SUMMARY-01; LIS-AUDIT pending].

**Preliminary four-factor evaluation:** (1) direct identifiers plus lab results raise sensitivity; (2) the account accessed ER records beyond its privileges; (3) report access is asserted but underlying audit and viewing semantics must be confirmed; and (4) lack of confirmed external exfiltration does not provide sufficient mitigation to establish low probability of compromise [SUPPLIED-SUMMARY-01; `hipaa_breach_assessment.md`]. **Outcome:** treat as **presumptive breach**, subject to counsel's documented assessment, PHI-security status and applicable exceptions. If reportable and under 500 individuals, individual notice is generally required without unreasonable delay and no later than 60 days from discovery; HHS Secretary reporting may be made within 60 days following the discovery calendar year [HIPAA-LEGAL-01: HHS Breach Notification Rule].

## 6. Gaps and Limitations

- No acquisition SHA-256 baselines; current initial baseline and verification results not provided [ACQ-01; `chain_of_custody.md`].
- Live read-write filesystem examination before disk imaging; possible metadata modification [ACQ-01].
- Missing documented custody from acquisition through SOC handoff [ACQ-01].
- No source disk/memory image, TSK/Volatility output, registry extracts, recovered files or verified hash values to inspect [ART-001, ART-002, ART-003 pending].
- No underlying proxy, SIEM, AD/VPN, LIS audit or patient-mapping records were supplied; attacker identity, exact sequence, confirmed persistence, lateral movement and exfiltration cannot be established from this record [LOG-PROXY, LOG-SIEM, LOG-AD, LIS-AUDIT pending].

## 7. Recommendations

1. **Evidence integrity:** Create and independently verify current baseline hashes; use write-protected evidence storage and mandatory access/event logging before every forensic session [ACQ-01; ART-001–ART-003].
2. **Identity security:** Disable/revoke suspicious `dmarsh` sessions, rotate affected credentials and tokens, enforce phishing-resistant MFA for remote access, and inspect VPN/AD logs for correlated misuse [CASE-01; LOG-AD-01 pending].
3. **Endpoint eradication:** Do not close containment until all verified malicious scheduled tasks, Run keys, binaries and cross-host indicators are inventoried, removed and rescanned; preserve evidence before changes [ART-001-Fxx, ART-001-Rxx, ART-002-Mxx pending].
4. **Clinical access:** Apply least privilege to LIS patient reports, limit lateral access between clinical segments, alert on out-of-role PDF reads, and retain queryable LIS audit records [SUPPLIED-SUMMARY-01].
5. **Privacy response:** Confirm unique patients and whether files were viewed/copied, document the four-factor risk analysis, have counsel determine notice duties, and maintain a defensible decision trail [SUPPLIED-SUMMARY-01; HIPAA-LEGAL-01].

---

### Evidence reference key

- **ACQ-01:** Mike Torres, *Acquisition Notes — IR-2026-0414-01*, signed 2026-04-14T07:42Z (provided in Task 1).
- **CASE-01:** User-supplied assignment instructions and expected scenarios in Tasks 5–8 (**scenario, not underlying records**).
- **SUPPLIED-SUMMARY-01:** User-supplied Task 7 finding summary (**asserted finding, original audit unavailable**).
- **ART-001/002/003:** Source disk/memory registry entries in `chain_of_custody.md`; related `Fxx`, `Rxx`, `Mxx` are pending analysis identifiers, **not yet independently verified findings**.
- **LOG-PROXY, LOG-AD, LOG-SIEM, LIS-AUDIT:** Mentioned external logs; original records not supplied. No citation to a line number is possible.
- **HIPAA-LEGAL-01:** HHS, *Breach Notification Rule*, https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html ; HHS *Submitting Notice of a Breach to the Secretary*, https://www.hhs.gov/hipaa/for-professionals/breach-notification/breach-reporting/index.html .

**End of preliminary report. Do not mark approved until evidence verification, analysis, line-level references, and review are complete.**
