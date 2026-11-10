# DLH Cyber Security Academy

Cybersecurity coursework, hands-on labs, and investigation notes from the DLH Cyber Security Academy. This repository follows a learning path from security fundamentals and system hardening to threat detection, incident response, and security governance.

The work includes scripts, configurations, detection rules, analysis reports, and supporting lab evidence. Many of the applied modules use **MedDefense Health Systems**, a simulated healthcare organisation, as a shared scenario.

## Repository overview

| Track | Focus |
| --- | --- |
| [Common Core](common_core/) | Security fundamentals, networking, Linux, web application security, and scripting |
| [Blue Team](blue_team/) | Defensive analysis, system hardening, telemetry, detection engineering, and SOC operations |
| [Threat Detection](threat_detection/) | Phishing analysis, network investigation, threat intelligence, malware analysis, and threat hunting |
| [Incident Response & Digital Forensics](ir_dfir_playbook/) | Response planning, containment, evidence handling, incident review, and breach response |
| [Governance, Risk & Compliance](grc/) | Compliance, business continuity, identity management, SOC automation, and security awareness |

## Common Core

Foundational topics supporting the applied tracks. Open a topic directory for its exercises and learning materials.

| Topic | Focus |
| --- | --- |
| [Cybersecurity Basics](common_core/cybersecurity_basics/) | Cybersecurity concepts, forensic methodologies, cryptography, and shell fundamentals |
| [Network Security](common_core/network_security/) | Reconnaissance, host discovery, and network traffic analysis |
| [Linux Security](common_core/linux_security/) | Permissions, mandatory access control, and network services |
| [Web Application Security](common_core/web_application_security/) | OWASP concepts, Burp Suite, content discovery, and upload vulnerabilities |
| [CVE, CWE & NVD](common_core/CVE_CWE_and_NVD/) | Vulnerability identifiers, weakness classification, and vulnerability research |
| [Understanding Vulnerabilities](common_core/Understanding_Vulnerabilities_Reading/) | Reading and exercises on vulnerability concepts |
| [Security Scripting](common_core/scripting_cyber/) | Python scripting for security tasks |
| [Threat Modelling](common_core/threat-modeling-fundamentals/) | Threat modelling concepts and exercises |
| [Security Policy Analysis](common_core/security-policy-analysis/) | Policy analysis and security governance fundamentals |

## Blue Team

Three stages move from defensive foundations through system hardening to operational detection and triage.

### Defensive foundations · `1x`

| Module | Focus |
| --- | --- |
| [1x00 · The First Watch](blue_team/1x00_first_watch/) | SOC fundamentals, asset discovery, and initial security assessment |
| [1x01 · Know Your Enemy](blue_team/1x01_know_your_enemy/) | Threat intelligence, adversary profiling, and ATT&CK mapping |
| [1x02 · The Weak Links](blue_team/1x02_the_weak_links/) | Vulnerability assessment and remediation prioritisation |
| [1x03 · Defence Blueprint](blue_team/1x03_defense_blueprint/) | Security controls, risk assessment, and defensive planning |
| [1x04 · Crypto Foundation](blue_team/1x04_crypto_foundation/) | Cryptography, certificates, and key management |
| [1x05 · Board Briefing](blue_team/1x05_board_briefing/) | Executive reporting and security risk communication |

### System and network hardening · `2x`

| Module | Focus |
| --- | --- |
| [2x00 · Locking the Gates](blue_team/2x00_locking_the_gates/) | Linux hardening, access controls, auditing, and validation |
| [2x01 · Windows Fortress](blue_team/2x01_windows_fortress/) | Windows hardening and security configuration |
| [2x02 · Eyes on Endpoint](blue_team/2x02_eyes_on_endpoint/) | Endpoint telemetry and monitoring validation |
| [2x03 · Patch Equation](blue_team/2x03_patch_equation/) | Patch planning, deployment, validation, and configuration drift |
| [2x04 · Perimeter Defence](blue_team/2x04_perimeter_defense/) | Network segmentation, firewall controls, and network monitoring |
| [2x05 · Defensible Endpoint](blue_team/2x05_defensible_endpoint/) | Integrated hardening, verification, and operational handoff |

### Detection engineering and SOC operations · `3x`

| Module | Focus |
| --- | --- |
| [3x00 · Evidence Pipeline](blue_team/3x00_evidence_pipeline/) | Event collection, parsing, normalisation, and enrichment |
| [3x01 · Reading the Noise](blue_team/3x01_reading_the_noise/) | Baseline analysis and anomaly identification |
| [3x02 · The Alert Factory](blue_team/3x02_the_alert_factory/) | Sigma detection rules, tuning, and detection validation |
| [3x03 · Triage Shift](blue_team/3x03_triage_shift/) | Alert prioritisation, investigation, and escalation |
| [3x04 · Cross-Platform Detection](blue_team/3x04_cross_platform_detection/) | Detection analysis across platforms |
| [3x05 · The 24-Hour Watch](blue_team/3x05_the_24_hour_watch/) | SOC monitoring and operational response |

## Threat Detection · `4x`

Investigations connect individual indicators to network activity, adversary behaviour, and a reconstructed attack narrative.

| Module | Focus |
| --- | --- |
| [4x00 · Phishing Dissection](threat_detection/4x00_phishing_dissection/) | Phishing investigation and indicator extraction |
| [4x01 · Wire Shark Territory](threat_detection/4x01_wire_shark_territory/) | Packet analysis and suspicious network activity |
| [4x02 · Intelligence-Driven Defence](threat_detection/4x02_intelligence_driven_defense/) | Threat intelligence, adversary mapping, and detection development |
| [4x03 · Malware Awareness](threat_detection/4x03_malware_awareness/) | Malware triage and behaviour analysis |
| [4x04 · Threat Hunting](threat_detection/4x04_threat_hunting/) | Hypothesis-driven investigation and detection gaps |
| [4x05 · Attack Reconstruction](threat_detection/4x05_attack_reconstruction/) | Evidence correlation and attack timeline reconstruction |

## Incident Response & Digital Forensics · `5x`

Response playbooks and exercises cover preparation, containment, forensic investigation, and organisational recovery.

| Module | Focus |
| --- | --- |
| [5x00 · Incident Response](ir_dfir_playbook/5x00_incident_response/) | Response planning, roles, and escalation procedures |
| [5x01 · Contain and Control](ir_dfir_playbook/5x01_Contain_Control/) | Containment, recovery, and operational validation |
| [5x02 · The Evidence Trail](ir_dfir_playbook/5x02_evidence_trail/) | Evidence preservation, verification, and forensic analysis |
| [5x03 · Post-Incident Review](ir_dfir_playbook/5x03_post_incident_review/) | Lessons learned and detection improvements |
| [5x04 · Tabletop Exercise](ir_dfir_playbook/5x04_tabletop/) | Scenario-based organisational response exercises |
| [5x05 · Breach Response](ir_dfir_playbook/5x05_breach_response/) | Integrated incident investigation and stakeholder reporting |

[Shared response materials](ir_dfir_playbook/5x00_shared/) support the incident response exercises.

## Governance, Risk & Compliance · `6x`

These modules connect technical controls to policy, audit evidence, continuity planning, and human factors.

| Module | Focus |
| --- | --- |
| [6x00 · Compliance Engine](grc/6x00_compliance_engine/) | Control assessment, policy development, and audit evidence |
| [6x01 · Business Continuity & Disaster Recovery](grc/6x01_bc_dr/) | Business impact analysis, recovery planning, and recovery testing |
| [6x02 · Identity at Scale](grc/6x02_iam_scale/) | Identity governance, privileged access, federation, and IAM auditing |
| [6x03 · The SOC Playbook](grc/6x03_soc_playbook/) | Indicator enrichment, case management, and response automation |
| [6x04 · Security Awareness](grc/6x04_security_awareness/) | Awareness programme design, social engineering, and effectiveness measurement |

## Navigating the repository

Start with **Common Core** for the foundations, then follow the numbered modules from `1x` through `6x` for the applied learning sequence. For a specific topic, use the track and module links above.

Within each module, the README introduces the scenario and tasks. Supporting files contain the implementation, analysis, or evidence for those exercises; some modules also include learning objectives and task notes. Common Core exercises use `0x` prefixes, while the applied tracks use `1x` through `6x`. Numbering is retained from the coursework and may contain gaps.

The coursework draws on CompTIA Security+ topics and frameworks such as NIST CSF, CIS Controls, MITRE ATT&CK, and OWASP. This repository documents learning and lab work; module contents reflect the scope of the individual exercises.
