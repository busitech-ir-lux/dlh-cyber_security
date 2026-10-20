# Threat Intelligence Brief: IR-2026-0414-01
**Classification:** Internal — TLP:AMBER  
**Assessment date:** 2026-10-20  
**Sources:** Provided offline snapshots taken 2026-04-14; forensic findings summary  
**Confidence:** High on observed incident actions; low to moderate on actor attribution.

## IOC Enrichment

| IOC | Type | First seen | Last seen or reported | Reputation / tags | Associated reports / source |
|---|---|---|---|---|---|
| `185.220.101.47` | C2 IP | VT first submission 2023-11-07 | AbuseIPDB last report 2026-04-14 02:52Z | Tor exit, anonymizer; VT 22 malicious, 5 suspicious; AbuseIPDB 84/100, 9,412 reports | OTX 47 pulses including Tor Exit Relays and “MSBuild loader campaign targeting healthcare”; VT, OTX, AbuseIPDB |
| `91.234.99.107` | C2 IP | VT first submission 2024-07-09 | AbuseIPDB last report 2026-04-13 22:18Z | Cobalt Strike, bulletproof hosting; VT 18 malicious, 8 suspicious; AbuseIPDB 92/100, 1,874 reports | OTX 12 pulses including “Cobalt Strike C2 infrastructure” and “Healthcare breach wave”; VT, OTX, AbuseIPDB |
| `ms0365-support[.]login-verification[.]click` | phishing domain | URLhaus 2026-04-07 | URLhaus snapshot 2026-04-14; last seen specifically unavailable | phishing, Microsoft365 typosquat; VT 28 malicious, 4 suspicious; URLhaus blacklist listed | URLhaus /auth and /auth/submit phishing, /auth/drop/update.zip loader; VT, URLhaus |
| `a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3` | `update.xml` SHA-256 | VT first submission 2025-04-09 | VT last submission 2025-04-15 | Trojan.MSIL.MSBuildLoader; VT 34 malicious, 3 suspicious; msbuild, inline-task, shellcode-loader | VT `hash_update_xml.json`; matching forensic hash ART-001-F01 |

**Snapshot data-quality note:** Several VirusTotal Unix timestamps convert to dates in **2025**, although snapshots were taken on **2026-04-14**. They are reproduced as provided, not silently adjusted. URLhaus 2026 observation dates are more recent. “First seen” means first seen *by that source*, not creation date or first malicious use. No independent second open-source report was provided for the file hash: its second source here is the **internal forensic summary**, not an open-source intelligence feed. A second OSINT hash source remains an enrichment gap.

## TTP Cluster Match

| Technique | Closest supported actor profile | Confidence |
|---|---|---|
| T1566.002 phishing link and T1078 valid accounts | Financially motivated credential-theft / ransomware-affiliate intrusion pattern | Moderate, pattern-based |
| T1127.001 MSBuild LOLBin execution | OTX healthcare MSBuild loader campaign **behavioral match** | Moderate |
| T1003.001 LSASS material + T1558.003 listed in technique summary | Credential theft / Kerberos-abuse operations across many groups | Low for specific actor attribution |
| T1550.003 Pass-the-Ticket + T1071.001 C2 | OTX healthcare breach-wave and Cobalt Strike C2 cluster **infrastructure overlap** | Moderate for infrastructure association, low for unique actor |

No named MITRE ATT&CK Group can be attributed with confidence from these files alone. TTP overlap, especially common tools like PowerShell, MSBuild, and Cobalt Strike, is **not** a unique actor fingerprint. A current ATT&CK Groups database lookup with stronger malware, campaign, victimology, and infrastructure evidence is necessary before naming a specific group.

## Actor Profile Summary

The observed intrusion moved from a Microsoft 365-themed phishing site and compromised `MEDDEFENSE\dmarsh` credentials into PowerShell-launched MSBuild (`update.xml`), public-IP HTTPS command and control, and access to a second workstation. The primary IP is tagged as Tor exit infrastructure; the secondary IP is associated in offline OTX pulses with Cobalt Strike infrastructure and healthcare-targeting campaigns. This combination resembles a financially motivated intrusion set that values stealthy execution and post-compromise expansion, but no individual actor is identified.

At MedDefense, the attack reached `LIS-WSIDE-01`, where AD logs recorded reads of **14 PDF reports containing PHI**. This establishes sensitive data access, not confirmed off-network transfer. The supplied findings also show a Run key and scheduled task pointing to `update.exe`, which warrants a persistence hunt. The timeline, memory evidence, and intelligence support monitoring for additional implant execution, credential reuse, and data staging, but they do not prove deployment of a named second-stage payload.

## Predicted Next Steps (hypotheses, not confirmed actions)

- Maintain access using the observed `WindowsUpdateSvc` Run key or the scheduled task, or move to other startup mechanisms.
- Reuse stolen credentials or Kerberos tickets against additional clinical endpoints and shares.
- Deploy a Cobalt Strike-like beacon or alternate remote-access implant; association is based on infrastructure tagging only.
- Stage additional clinical documents and attempt transfer, encryption, or extortion.

## Recommended Proactive Hunting

1. **Persistence:** Hunt for new Run key entries or scheduled tasks invoking user-profile Temp executables, including the known `update.exe` and task GUID.
2. **LOLBins:** Correlate PowerShell/script-host parent → `MSBuild.exe`, `csc.exe`, `vbc.exe`, or `jsc.exe`, especially with Temp XML/project arguments.
3. **Network:** Identify MSBuild and other build-tool processes making repeated HTTPS connections to previously unseen public hosts/IPs; correlate with process creation within five minutes.
4. **Credentials and movement:** Search for LSASS access anomalies, unusual Kerberos logons, and the same account reaching multiple clinical hosts within a short interval.
5. **PHI staging:** Flag unusual PDF read bursts on `LIS_REPORTS$`, creation of archive/staging directories, and outbound flows after those reads.

## Handling and follow-up

Block confirmed malicious IOCs subject to business validation, review identity and endpoint compromise scope, obtain missing DLP logs, and check persistence on `WST-WS-031`, `WST-WS-017`, and `LIS-WSIDE-01`. Revalidate intelligence using fresh feeds before relying on it for enduring blocklists.
