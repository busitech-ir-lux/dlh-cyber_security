\## Introduction



> \_"The investigator who can only see one piece of the puzzle will draw the wrong picture every time."\_ — \_Adapted from Locard's Exchange Principle\_



Six weeks ago you opened a batch of suspicious emails and asked a simple question: is MedDefense being targeted ? The answer was yes. Since then you have chased the HEALTHBANE campaign across five investigation domains. You analyzed phishing lures and extracted IOCs. You decoded network traffic and found C2 beaconing hidden in routine HTTPS connections. You consumed threat intelligence from government advisories and commercial feeds and built an ATT\&CK mapping that transformed scattered indicators into a structured adversary profile. You triaged three malware samples and understood exactly how the attacker turns a stolen credential into exfiltrated patient data. And you hunted proactively through 14 days of SIEM data, finding lateral movement that no detection rule caught.



Each investigation answered questions. Each also raised new ones. The phishing analysis could not tell you what happened after the click. The network forensics could not explain the malware payloads. The intelligence mapping could not confirm which techniques were actually used against MedDefense. The malware analysis could not reveal how the attacker moved laterally. And the threat hunt found lateral movement but could not determine the full scope of compromise.



You have five partial pictures. This project creates the complete one.



Attack reconstruction is the discipline of integrating evidence from multiple investigation domains into a single, coherent, chronological account of an attack. It is not a summary of previous work. It is an analytical process that reveals things no single investigation could: timeline contradictions that expose gaps in collection, technique correlations that confirm attribution confidence, evidence convergences that strengthen findings from LOW to HIGH confidence, and defensive blind spots that only become visible when you see the full kill chain.



This is the work that separates a junior analyst who produces findings from a senior analyst who produces understanding.



\### Why This Matters



In professional incident response, the reconstruction report is the deliverable that matters most. It is the document that the CISO presents to the board. It is the artifact that legal counsel uses to determine regulatory notification obligations. It is the reference that detection engineering uses to close coverage gaps. It is the record that auditors review to assess whether the organization met its duty of care.



A reconstruction that misses a phase, contradicts its own evidence, or fails to connect findings across sources is worse than no report at all. It creates false confidence. It closes investigations that should remain open. It lets the attacker retain footholds that the analyst failed to connect.



\---



\## Context



\*\*Week seventeen at MedDefense Health Systems. Thursday morning.\*\*



James Chen stands at the whiteboard. The entire security operations team is present. Dr. Patricia Morales is on video. The whiteboard shows a timeline with five colored segments, each labeled with a project number. There are gaps between the segments.



\_"It has been six weeks since the first phishing email. In that time, this team has done more analytical work on a single campaign than most organizations manage in a year. But here is the problem."\_



He draws circles around the gaps on the whiteboard.



\_"We investigated in pieces. Each investigation was excellent. Each produced findings I would put in front of any auditor. But when I try to assemble them into a single story for the board, the pieces do not connect cleanly. The timestamp from the network analysis does not match the timestamp from the SIEM hunt. The IOC from the phishing investigation appears in the malware analysis but NOT in the network capture. The ATT\&CK mapping from 4x02 says a technique was 'inferred' but the hunt from 4x04 confirmed a DIFFERENT variant of that technique."\_



He pauses.



\_"And then there is the incident response."\_



James explains: after the threat hunt recommended immediate incident response for WS-RECV-03, the IR team spent five days isolating the host, imaging its disk, capturing volatile memory before shutdown, and pulling 14 days of firewall session logs from the segment switch. Their evidence package arrived this morning.



\_"The IR findings make the reconstruction both easier and harder. Easier because they fill gaps we could not fill before. Harder because they surface things we did not expect."\_



He lists the surprises:



\_"First: the memory capture found a scheduled task on WS-RECV-03 that was set to execute every night at 02:00. That is a persistence mechanism we never detected. Our SIEM rules did not look for scheduled task creation. Our hunt hypotheses did not include persistence. The attacker was not just moving laterally. They were establishing a foothold."\_



\_"Second: the disk forensics recovered deleted files in a temporary directory. Compressed archives containing what appear to be database query results. Patient records. The attacker was STAGING data for exfiltration. They had already accessed the health records database and were preparing to move data out. Our network forensics from 4x01 found the DNS exfiltration CHANNEL but we assumed it was only used for C2. The disk evidence suggests it was also used -- or was about to be used -- for data exfiltration."\_



\_"Third: the firewall session logs show connections from WS-RECV-03 to an IP address that does not appear ANYWHERE in our previous investigations. Not in the phishing domains, not in the C2 infrastructure, not in the threat intelligence feeds. Either this is a secondary C2 channel we completely missed, or it is unrelated. I need to know which."\_



Dr. Morales speaks from the screen:



\_"The board meets in one week. They want three answers. First: exactly what happened, from start to finish, with evidence behind every claim. Second: exactly what data was at risk and whether any left our network. Third: exactly what we are doing to ensure this never happens again. I have presented incremental updates after each investigation. This time I need the complete picture. One report. One timeline. One recommendation package."\_



James turns to you.



\_"I need you to take everything we have -- every finding from every investigation, plus the new IR evidence -- and reconstruct the full HEALTHBANE attack against MedDefense. Not a summary of five projects. A RECONSTRUCTION. Every phase connected. Every technique mapped. Every IOC cross-referenced. Every gap identified and documented. Every claim supported by evidence from at least two independent sources where possible."\_



It contains:



\*\*New evidence (from incident response):\*\*



\- `ir\_evidence/memory\_artifacts.txt` -- Volatile memory forensics from WS-RECV-03: process list at capture time, active network connections, loaded modules, registry hive extracts including scheduled task definitions

&#x20;   

\- `ir\_evidence/disk\_forensics\_report.txt` -- Disk image analysis: recovered deleted files, prefetch entries, NTFS $MFT timeline for key directories, scheduled task XML, registry persistence keys, anti-forensics indicators

&#x20;   

\- `ir\_evidence/firewall\_sessions\_ws\_recv\_03.json` -- Fourteen days of stateful firewall session logs for the WS-RECV-03 network segment (source IP, destination IP, port, protocol, bytes transferred, timestamps, session duration)

&#x20;   

\- `ir\_evidence/ir\_team\_notes.txt` -- The IR team's preliminary observations (some confirmed, some flagged as unverified, some requiring analyst validation)

&#x20;   



\*\*Previous investigation summaries (consolidated reference):\*\*



\- `previous\_findings/4x00\_phishing\_summary.txt` -- Key findings from the phishing dissection: campaign classification, extracted IOCs, credential exposure assessment, detection rules deployed

&#x20;   

\- `previous\_findings/4x01\_network\_timeline.txt` -- Network forensics timeline: C2 beaconing pattern, DNS exfiltration indicators, lateral movement traces, PCAP-derived IOCs

&#x20;   

\- `previous\_findings/4x02\_attack\_mapping.json` -- HEALTHBANE ATT\&CK Navigator layer at 40% coverage (post-intelligence analysis) with technique confidence levels

&#x20;   

\- `previous\_findings/4x03\_malware\_summary.txt` -- Malware triage findings: dropper capabilities, RAT C2 protocol, exfiltrator targeting and methodology, behavioral IOCs, ATT\&CK update to 55%

&#x20;   

\- `previous\_findings/4x04\_hunting\_report.txt` -- Threat hunt findings: confirmed Stage 4 lateral movement, behavioral anomalies, detection rules deployed, ATT\&CK update to 80%, remaining gaps

&#x20;   



\*\*Reference files:\*\*



\- `reference/network\_topology.txt` -- MedDefense network topology with host roles, VLANs and authorized users

&#x20;   

\- `reference/healthbane\_ioc\_master.json` -- Consolidated IOC database from all previous investigations (4x00 through 4x04)

&#x20;   

\- `reference/attck\_navigator\_80pct.json` -- Current ATT\&CK Navigator layer at 80% coverage (post-4x04)

&#x20;   

\- `reference/meddefense\_asset\_inventory.txt` -- Asset classification with data sensitivity ratings (which systems hold patient data, financial data, operational data)

&#x20;   



\---



\## Learning Objectives



By the end of this project, you are expected to be able to explain to anyone, \*\*without the help of Google\*\*:



\*\*Cross-Evidence Correlation\*\*



\- How to integrate findings from multiple investigation domains (email, network, endpoint, intelligence, SIEM) into a unified analytical picture

&#x20;   

\- How to identify convergences (findings confirmed by multiple independent sources) and divergences (findings contradicted or unsupported across sources)

&#x20;   

\- How to assess evidence reliability: which sources are authoritative for which claims, and why network timestamps may not match SIEM timestamps for the same event

&#x20;   

\- How to resolve apparent contradictions between evidence sources by analyzing collection gaps, timezone differences, clock skew and evidence preservation limitations

&#x20;   



\*\*Attack Timeline Reconstruction\*\*



\- How to construct a chronological attack narrative from fragmented, multi-source evidence spanning days or weeks

&#x20;   

\- How to establish temporal anchors: high-confidence events that serve as fixed points around which less certain events are ordered

&#x20;   

\- How to distinguish between "confirmed sequence" (event A caused event B, evidenced by direct correlation) and "inferred sequence" (event A likely preceded event B based on technique logic)

&#x20;   

\- How to identify dwell time, breakout time and operational tempo from reconstructed timelines

&#x20;   



\*\*ATT\&CK Mapping at Scale\*\*



\- How to map a complete multi-phase attack to MITRE ATT\&CK with confidence annotations per technique, distinguishing between confirmed (direct evidence), probable (strong circumstantial evidence) and possible (technique logic supports but evidence is indirect)

&#x20;   

\- How to identify coverage gaps that represent genuine blind spots versus gaps that reflect collection limitations

&#x20;   

\- Why ATT\&CK coverage percentages can create a false sense of security and how reconstruction reveals the techniques that matter most

&#x20;   



\*\*Impact Assessment\*\*



\- How to determine the organizational impact of an attack by mapping compromised systems to the asset inventory and data classification

&#x20;   

\- How to distinguish between confirmed data exposure (evidence of access), potential data exposure (access was possible but unconfirmed) and prevented data exposure (staging detected before exfiltration)

&#x20;   

\- How to assess regulatory implications (HIPAA notification triggers) based on evidence rather than assumption

&#x20;   



\*\*Professional Reporting\*\*



\- How to produce an attack reconstruction report that serves both technical and executive audiences without compromising analytical rigor

&#x20;   

\- How to structure evidence citations so that every claim in the report traces back to a specific finding, timestamp and source

&#x20;   

\- How to document what is NOT known with the same rigor as what IS known, and why intellectual honesty strengthens rather than weakens a report

&#x20;   



\---



\## Resources



\_Read or Watch:\_



\*\*Incident Reconstruction\*\*



\- \[NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://intranet.hbtn.io/rltoken/jyIO5CD9m6QPNDRMEENrXA) -- The authoritative framework for evidence handling and reconstruction.

&#x20;   

\- \[Attack Chain Reconstruction from Multi-Source Evidence](https://intranet.hbtn.io/rltoken/wEJsSnNnHG5agjS1kYKfxg) -- Practitioner methodology for cross-source correlation.

&#x20;   



\*\*Evidence Correlation\*\*



\- \[MITRE ATT\&CK: Getting Started](https://intranet.hbtn.io/rltoken/EW2SCh50K0tFYaaIkQUf6g) -- Framework usage for complete campaign mapping.



\*\*Impact Assessment\*\*



\- \[HHS HIPAA Breach Notification Rule](https://intranet.hbtn.io/rltoken/Oz4wI0RPjCV6EEsbEGZZlg) -- Regulatory context for healthcare data exposure assessment.

&#x20;   

\- \[CISA: Incident Response Playbook](https://intranet.hbtn.io/rltoken/TH\_gTyNC3ulTX6bMmuRhhA) -- Federal incident response framework with reconstruction guidance.

&#x20;   



\*\*Man or Help:\*\*



\- `man jq`

&#x20;   

\- `man grep`

&#x20;   

\- `man sort`

&#x20;   

\- `man uniq`

&#x20;   

\- `man date`

&#x20;   

\- `man diff`

&#x20;   



