\# Intelligence-Driven Defense



Introduction

"The goal is to turn data into information, and information into insight." — Carly Fiorina



You have spent the past two projects doing what SOC analysts do every day: investigating evidence. In 4x00, you analyzed phishing emails and extracted campaign indicators. In 4x01, you analyzed network packet captures and reconstructed what happened on the wire. Both projects were incident-response driven: evidence arrived, you analyzed it, and you reported findings.



But the best defenders do not only react.



Intelligence-driven defense starts before the next alert arrives. Instead of waiting for the attacker to appear in logs or packet captures, defenders study the adversary's infrastructure, behavior, tooling and targeting patterns. They consume threat intelligence from sector partners, government advisories, commercial feeds and open-source researchers. They assess what is reliable, enrich what is useful, discard what is noisy and turn the final intelligence into detection logic.



In this project, MedDefense receives multiple intelligence sources about a campaign now tracked as HEALTHBANE. The sources do not fully agree. HC3 publishes a TLP:CLEAR advisory with confirmed healthcare-sector intelligence. A commercial feed labels related activity as VITALSCORE but includes intentional noise and weakly clustered indicators. A public researcher claims overlap with APT-MEDAGENT but admits the attribution is only medium confidence. MedDefense also has its own internal findings from 4x00.



Your job is to turn those raw sources into intelligence.



You will parse the sources, triage indicators, assess source credibility, enrich IOCs, map infrastructure, produce an indicator database, reconstruct the campaign kill chain, map ATT\&CK techniques, identify detection gaps, write YARA rules, test them and produce a final intelligence brief.



This project is independent. No live SIEM, Wazuh server, Suricata sensor or previous Module 2/3 infrastructure is required. When a task asks for detection rules or operationalization, you will write rules, detection logic, JSON outputs or documentation artifacts locally. The work should be evidence-based and reproducible using the provided materials.



Why This Matters

Every SOC beyond Tier 1 requires intelligence operationalization. Tier 2 analysts, threat intelligence analysts and detection engineers all need to consume intelligence, evaluate sources, enrich indicators, map adversary behavior and translate findings into detection.



The difference between an analyst who reads a threat report and an analyst who operationalizes intelligence is this:



one knows what happened somewhere else

the other prepares their organization to detect what may happen next

The HEALTHBANE campaign is built to teach this skill. Some indicators are high-confidence and actionable. Some are only contextual. Some are noisy, broad or weakly attributed. Some sources agree. Others conflict. The work is not simply copying IOCs into a list. The work is deciding what to trust, what to block, what to monitor, what to hunt for and what still needs collection.



The skills you build here directly support later threat hunting, malware analysis, detection engineering and executive reporting.



Context

Week twelve at MedDefense Health Systems. Monday morning.



Three weeks have passed since the phishing investigation.



The IOCs MedDefense submitted to HC3 were useful. HC3 has now published a comprehensive TLP:CLEAR advisory describing a coordinated campaign targeting healthcare organizations. The advisory designates the campaign HEALTHBANE and includes indicators from multiple affected organizations.



James Chen calls a meeting. Dr. Patricia Morales is on the call.



"HC3 published the advisory Friday. It confirms what we suspected but goes further than our internal investigation. The phishing emails we caught were Stage 1. Two other organizations did not stop the campaign early enough. They saw Stage 2 malware delivery and Stage 3 data exfiltration."



He pauses.



"We stopped the campaign at MedDefense before later-stage compromise, but only because a user reported the email and the team investigated quickly. If the attacker returns with new infrastructure, our old domain and IP blocklists may not help. We need to understand the adversary's behavior, not just yesterday's IOCs."



Dr. Morales adds:



"The board meeting is in 10 days. I need to explain our defensive posture against HEALTHBANE. I do not need a list of random indicators. I need to know what we trust, what we can detect, what we cannot detect and what we are doing about it."



You receive the 4x02 intelligence package.



It includes:



an HC3 sector advisory

a commercial CTI feed extract

a researcher's technical blog analysis

MedDefense's internal 4x00 findings

a YARA sample corpus with benign and malicious files

The sources disagree in important ways.



HC3 calls attribution unconfirmed.

The commercial feed uses the proprietary label VITALSCORE.

The researcher uses APT-MEDAGENT with medium confidence.

MedDefense's internal report avoids attribution entirely.



Your task is to produce a disciplined intelligence analysis that separates facts from assessments, indicators from noise and confirmed behavior from inference.

