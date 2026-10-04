Introduction

"The absence of evidence is not the evidence of absence." — Donald Rumsfeld



You have built a detection stack. YARA rules, SIEM alerts, IOC databases, Suricata signatures. You can detect the HEALTHBANE dropper when it lands. You can detect the RAT when it beacons. You can detect the exfiltrator when it tunnels data through DNS. Your ATT\&CK coverage sits at 55% and your detection posture has improved significantly since the beginning of Module 4.



And none of it caught Stage 4.



Because Stage 4 does not depend on custom malware. It does not require a new executable. It does not require attacker-controlled internet infrastructure. It does not trigger YARA, file-hash IOCs or blocklists. Stage 4 uses PsExec, WMI, PowerShell Remoting and stolen service account credentials. These are legitimate administration tools. They become malicious only when the context is wrong: the wrong user, the wrong source host, the wrong time, the wrong target and the wrong sequence of actions.



This is Living Off The Land. This is why detection alone is not enough.



Why This Matters

Threat hunting is the proactive search for activity that bypassed automated detection. Detection waits for a rule to fire. Hunting starts with a hypothesis and searches the data directly.



A detection engineer writes:



alert when PsExec runs



A threat hunter asks:



Has PsExec ever run from a non-admin workstation between midnight and 5 AM targeting a database server?



That difference matters. Sophisticated attackers deliberately choose techniques that fall outside your detection perimeter. They use tools that administrators also use. They blend into normal operations until you compare behavior against a baseline.



In this project, you will hunt for HEALTHBANE Stage 4 using only the provided SIEM exports, references and baseline files. No live SIEM is required. No external infrastructure is required. The full project is self-contained inside the 4x04 material folder.



Context

Week sixteen at MedDefense Health Systems. Monday morning.



Sarah Park drops a classified advisory on James Chen's desk.



"HC3 just issued HEALTHBANE-ADV-2026-004. It is bad news, James."



The advisory says that the two healthcare organizations fully compromised by HEALTHBANE showed a fourth stage of activity. Before the exfiltrator ran, and in some cases before Stage 2 malware was fully deployed, the attacker moved laterally through the network using legitimate Windows administration tools.



PsExec. WMI. PowerShell Remoting. Stolen service account credentials.



No custom malware. No custom C2. No new infrastructure.



James reads the advisory silently.



"They used a compromised workstation as a pivot point. From there they used PsExec to reach the database servers, WMI to enumerate systems, PowerShell Remoting to stage files and service account credentials to move laterally. The activity happened between 1 AM and 5 AM. The SOC never saw it because every tool the attacker used is a tool IT uses for maintenance."



Robert Kim, the IT administrator, looks uncomfortable.



"Those are my tools. I use PsExec for deployment. I use WMI for inventory. I use PowerShell Remoting for patch management. Our SIEM logs that as normal activity."



James nods.



"Exactly. So now the question is not whether the tool is suspicious. The question is whether the context is suspicious. Did this happen to us? We need a threat hunt, not a detection review."



Dr. Morales adds:



"The board heard that our detection posture reached 55% ATT\&CK coverage. If Stage 4 happened in the uncovered 45%, I need to explain why the percentage created a false sense of security and what we are doing to close the gap."



Your job is to hunt the last 14 days of MedDefense SIEM data and answer the question:



Did HEALTHBANE Stage 4 happen in the MedDefense environment?



Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:



Threat Hunting Methodology



The difference between alert-driven detection and hypothesis-driven threat hunting



How to derive hunt hypotheses from an advisory and ATT\&CK gap analysis



How to define a positive finding before running the query



Why hunting requires a documented baseline



Why absence of SIEM alerts does not prove absence of threat activity



Living Off The Land Detection



Why PsExec, WMI and PowerShell Remoting are hard to detect with static IOCs



How legitimate tools become suspicious through source host, user, target and time context



How service account misuse reveals credential compromise



How off-hours activity can identify adversary operations



Baseline Analysis



How to profile legitimate administrator behavior



How to use an authorized schedule as a false-positive filter



How to validate service account authentication against an authorization matrix



How to separate normal maintenance from adversary lateral movement



Evidence Correlation



How to combine separate findings into a unified attack timeline



How to correlate credential theft, lateral movement, reconnaissance and staging



How to map hunt findings to MITRE ATT\&CK



How to turn hunt findings into new detection rules



Reporting



How to write a hunting report for SOC and leadership audiences



How to explain the coverage illusion



How to document remaining gaps and next-step recommendations



Resources

Read or Watch:



Threat Hunting



Introduction to Threat Hunting -- Methodology overview from a practitioner perspective.



MITRE ATT\&CK: Lateral Movement -- Technique catalog for the primary hunt domain.



Sqrrl (now AWS): A Framework for Cyber Threat Hunting -- The hypothesis-driven hunting loop.



Living Off The Land



LOLBAS Project -- Catalog of Windows LOLBins with documented abuse techniques.



Microsoft: PsExec Documentation -- Understanding the legitimate tool attackers abuse.



SIEM Querying



jq Manual -- Essential for every query in this project.

Man or Help:



man jq



man grep



man sort



man uniq



man wc



man date



Requirements

General

A README.md file at the root of the project folder is mandatory.



All files must end with a new line.



Do not modify provided reference, baseline or SIEM files in place.



Your scripts should read from the provided local files and produce deterministic output.



This project is self-contained. Do not require a live Wazuh, Suricata, EDR, Windows host or internet connection.



Scripting

Bash scripts must start with #!/bin/bash.



Scripts should pass shellcheck.



Use jq for JSON parsing.



Scripts should work with the provided relative paths:



reference/



baseline/



siem\_export/



If a script creates an output file, clearly state the filename in the output.



Analysis

Every hunt finding must include evidence:



timestamp



source host



user account



target host



command or event detail



why the event is anomalous



Clearly distinguish:



baseline activity



anomalous activity



confirmed findings



inferred conclusions



Do not treat all admin-tool usage as malicious.



Use Robert Kim's schedule and baseline as the false-positive filter.



Use service account authorization rules when evaluating account misuse.



Lab Materials

Download the complete 4x04 threat hunting material folder from the platform:



Download the provided materials

Expected local structure:



4x04/

├── baseline

│   └── robert\_kim\_activity.json

├── reference

│   ├── 4x03\_attack\_mapping.json

│   ├── admin\_schedule.txt

│   ├── hc3\_advisory\_004.txt

│   ├── network\_topology.txt

│   └── service\_accounts.txt

└── siem\_export

&#x20;   ├── wazuh\_alerts\_14d.json

&#x20;   └── wazuh\_raw\_sysmon\_14d.json

Primary files:



reference/hc3\_advisory\_004.txt - HC3 HEALTHBANE Stage 4 advisory



reference/4x03\_attack\_mapping.json - current ATT\&CK coverage after 4x03



reference/admin\_schedule.txt - Robert Kim's authorized maintenance schedule



reference/service\_accounts.txt - service account authorization matrix



reference/network\_topology.txt - host roles, segments and authorized usage



baseline/robert\_kim\_activity.json - legitimate admin baseline dataset



siem\_export/wazuh\_alerts\_14d.json - 14-day Wazuh alert export



siem\_export/wazuh\_raw\_sysmon\_14d.json - raw Sysmon-style events for detailed hunt queries



Expected Outcome

At the end of this project, you should have:



A hunt brief derived from intelligence and ATT\&CK gaps



Five structured hunt hypotheses



A documented baseline for legitimate admin activity



Data reconnaissance of the SIEM export



Hunt results for PsExec, WMI, LSASS, PowerShell Remoting and service account abuse



Temporal analysis proving off-hours clustering



Correlated attack timeline



Updated ATT\&CK Navigator layer



Detection gap analysis



New hunt-derived detection rules



Final threat hunting report

