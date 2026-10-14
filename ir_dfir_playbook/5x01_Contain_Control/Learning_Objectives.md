# Technical

## 1. How do you perform initial triage on progressively revealed alert and log evidence?

Initial triage means quickly investigating an alert to decide whether it is a real security incident, how serious it is, and what needs immediate attention.

Start with the available evidence, then update your assessment as new logs and alerts arrive.

Steps:

1. Review the alert: Check its timestamp, affected host, user, suspicious process, and destination IP.
2. Confirm the activity: Compare SIEM alerts with endpoint (EDR), Windows, and network logs.
3. Check the context: Is this activity normal for the user and workstation?
4. Assess the impact: Determine whether important systems or sensitive data are at risk.
5. Declare and prioritize: Open an incident record if the evidence supports an incident, and update its severity as more information appears.

MedDefense example: `WST-WS-031` runs an unusual process and connects to a suspicious IP. Since this workstation accesses the Laboratory Information System (LIS), the activity requires urgent investigation.

Key point: An alert is a warning, not automatically proof of compromise.

## 2. How do you preserve volatile and non-volatile evidence before containment?

Evidence preservation means collecting and protecting information needed to investigate the incident before response actions destroy or change it.

There are two main types:

| Evidence type | Examples                                                          | Why it matters                                                                     |
| ------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Volatile      | RAM, running processes, active connections, logged-in sessions    | Can disappear when the system is restarted, disconnected, or processes are stopped |
| Non-volatile  | Disk files, Windows event logs, registry entries, scheduled tasks | Usually survives a restart but may still be changed or deleted                     |

Recommended approach:

1. Record the current system state and timestamps.
2. Capture volatile evidence first when feasible, especially memory and active processes.
3. Collect relevant logs, suspicious files, and persistence information.
4. Record evidence hashes, collection methods, timestamps, and who handled each item.
5. Store evidence securely and maintain chain of custody (a record of who collected, accessed, or transferred it).

Example: Before terminating a suspicious process, capture its command line, process tree, network connections, and relevant memory evidence.

Important: If an attack is actively spreading, urgent containment may take priority over complete evidence collection. Document what evidence could not be preserved and why.

## 3. How do you select containment strategies against explicit operational trade-offs?

Containment means stopping or limiting an attack to prevent further damage while preserving the ability to investigate.

Different containment methods have different effects on security, evidence, and business operations.

| Strategy                    | Security benefit                          | Possible cost                                                  |
| --------------------------- | ----------------------------------------- | -------------------------------------------------------------- |
| Isolate workstation         | Stops most network communication          | May interrupt clinical work and remote evidence collection     |
| Block malicious IP          | Stops communication with that destination | Attacker may use another IP; shared services could be affected |
| Disable compromised account | Prevents further use of that identity     | Legitimate user loses access                                   |
| Terminate malicious process | Stops that process immediately            | May destroy volatile evidence; persistence may restart it      |
| Restrict network segment    | Limits lateral movement                   | May disrupt multiple hospital systems                          |

How to choose:

Evaluate the threat's urgency, affected assets, clinical service availability, evidence requirements, and whether the action can be reversed.

MedDefense example: If `WST-WS-031` is actively communicating with an attacker, EDR network isolation may be appropriate after rapid evidence collection. However, first consider whether laboratory operations depend on the workstation.

Key point: Choose the action that reduces the threat sufficiently with the least acceptable operational damage. Record the reason for the choice and rejected alternatives.

## 4. How do you execute eradication steps with verification across Windows persistence surfaces?

Eradication means removing the attacker's access, malicious components, and mechanisms that could allow the compromise to return.

Stopping one malicious process is not enough. Attackers may establish persistence, meaning ways to regain access after a restart or logout.

| Windows surface | What to investigate                                       | Verification                              |
| --------------- | --------------------------------------------------------- | ----------------------------------------- |
| Processes       | Malicious executables and child processes                 | No unauthorized processes restart         |
| Scheduled tasks | Tasks executing suspicious commands                       | Malicious tasks removed and do not return |
| Services        | Unknown or modified Windows services                      | Services and configurations are clean     |
| Registry        | Suspicious Run/RunOnce entries and other autorun settings | Unauthorized entries removed              |
| Startup folders | Files automatically launched at login                     | No malicious startup files remain         |
| Credentials     | Compromised passwords, tokens, sessions                   | Credentials rotated and sessions revoked  |
| Network access  | Backdoors and unauthorized remote access                  | No attacker-controlled connections remain |

Example: An attacker abuses `msbuild.exe` to execute malicious code. Since MSBuild is a legitimate Microsoft tool, simply deleting or blocking it may break normal operations. Investigate the malicious project file, parent process, execution mechanism, and persistence method instead.

After cleanup, verify results using endpoint scans, autorun inspections, logs, and network monitoring. If the system cannot be trusted, rebuild it from a known-clean image.

Key point: Eradication is complete only when the identified malicious mechanisms have been removed and verification supports that conclusion.

## 5. How do you validate service recovery with proof instead of assumption?

Recovery means safely returning affected systems to normal operation after containment and eradication.

A workstation starting successfully does not prove it is secure or fully operational.

Recovery validation:

1. Confirm malicious processes and persistence mechanisms are absent.
2. Verify the system has required security updates and protections.
3. Confirm EDR, logging, and monitoring work correctly.
4. Test legitimate network connections and application functionality.
5. Ask the service owner to validate critical business functions.
6. Monitor for repeated malicious behavior before closing the incident.

MedDefense example: After restoring `WST-WS-031`, confirm that the laboratory technician can access the LIS, required workflows function correctly, and no suspicious outbound connections or unauthorized executions return.

Key point: Recovery requires two kinds of proof: security validation and operational validation.

---
# Conceptual

## 1. What is the correct order of operations between evidence preservation and containment?

The general principle is to preserve important evidence before taking actions that could destroy it, provided the delay does not create unacceptable risk.

Detect

Assess

Preserve

Contain

If immediate damage or spread is likely, containment may happen earlier. Document the exception.

Why this order matters: Restarting a compromised workstation may erase RAM evidence, while killing a process can remove information about its activity.

Example: Capture the suspicious process information and active network connections before isolating the workstation, when it is safe to do so.

The goal is not to collect everything before acting. It is to balance forensic value against the risk of further damage.

## 2. How should incident severity be reassessed when the scope changes?

Incident severity is not fixed. It must be reviewed whenever new evidence changes the understanding of the attack.

Consider:

- Scope: How many hosts, accounts, or network segments are affected?
- Impact: Are critical services, patient information, or important systems involved?
- Threat activity: Is the attacker still active or moving laterally?
- Urgency: How quickly could the situation become worse?

Example:

At first, only `WST-WS-031` appears compromised. Later, logs reveal suspicious authentication attempts against a laboratory server.

This suggests possible lateral movement—an attacker attempting to reach other systems from the initial compromised host.

The analyst should expand the investigation, reassess severity, consider additional containment, and document the change with its supporting evidence.

Key point: Severity should reflect the current known impact and credible risk, not only the original alert.

## 3. What does eradication completeness mean across process, credential, and network persistence?

Eradication completeness means removing every identified way the attacker can continue operating or return.

There are three important areas:

| Area                   | What must be addressed                                                                             |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| Process persistence    | Malicious programs, scheduled tasks, services, startup entries, and other execution mechanisms     |
| Credential persistence | Stolen passwords, active sessions, access tokens, malicious accounts, and unauthorized privileges  |
| Network persistence    | Backdoors, remote-access channels, unauthorized network rules, and attacker-controlled connections |

Example: You delete a malicious executable, but the attacker still has Daniel Marsh's stolen credentials. The attacker may simply log in again.

Therefore, eradication must address both the malware and the compromised identity, along with any remaining network access paths.

Key point: Removing malware does not necessarily remove the attacker.

## 4. Why is handoff quality a measurable outcome rather than a courtesy?

A handoff transfers responsibility for an incident from one analyst or team to another.

A good handoff allows the next analyst to continue immediately without repeating the investigation or guessing what happened.

It should include:

- Incident ID, current severity, status, and owner
- Affected hosts, accounts, and services
- Timestamped incident timeline
- Confirmed findings and remaining uncertainties
- Evidence locations and integrity information
- Containment actions, results, and operational impact
- Eradication and recovery progress
- Outstanding tasks, responsible people, and escalation requirements

How can quality be measured?

Check whether the handoff contains all required fields, whether evidence can be located, whether actions are reproducible, and whether every outstanding task has an owner.

MedDefense example: When Dr. Patricia Morales and Helena Reyes become available, they should immediately understand what happened, what was done, and what still requires action.

Key point: A handoff is successful when another analyst can safely continue the response using the documentation alone.

---

# Transversal

## 1. How do you maintain a timeline under pressure?

An incident timeline is a chronological record of important observations, decisions, and actions.

Open it as soon as the incident is declared, then update it throughout the response.

A useful timeline records:

- Timestamp and timezone (preferably UTC)
- Event or observation
- Evidence source
- Action or decision
- Result
- Responsible analyst

Example — illustrative timeline, not confirmed incident findings:

| Time (UTC) | Event                                       |
| ---------- | ------------------------------------------- |
| 02:47      | Initial monitoring alert received           |
| 02:50      | Endpoint alert reviewed                     |
| 02:54      | Incident declared and timeline opened       |
| 03:00      | Volatile evidence collected                 |
| 03:05      | Workstation isolated                        |
| 03:10      | Isolation verified; investigation continues |

Use the actual event time when available, and distinguish it from the time the analyst discovered or recorded the event. Avoid guessing timestamps.

Key point: Record actions as they happen. Reconstructing the timeline later increases the chance of mistakes.

## 2. How do you justify every decision at the moment it is taken?

Every important response decision should explain what was decided, why, what evidence supported it, and what consequences were expected.

A useful decision record contains:

| Field        | Example                                             |
| ------------ | --------------------------------------------------- |
| Decision     | Isolate `WST-WS-031`                                |
| Evidence     | Suspicious execution and outbound communication     |
| Reason       | Prevent further attacker communication              |
| Alternative  | Block only the suspicious destination IP            |
| Trade-off    | Temporary loss of workstation network access        |
| Verification | Confirm isolation through EDR and network telemetry |
| Owner/time   | Responsible analyst and UTC timestamp               |

This is important because the best decision is not always obvious during an incident. Investigators and managers need to understand the information available at the time, rather than judging decisions only with information discovered afterward.

Key point: Document the reasoning when the decision is made, not just the action afterward.

## 3. How do you separate what is known from what is assumed?

During an incident, some information is confirmed by evidence, while other information is only suspected.

Confusing these can lead to incorrect containment decisions, severity assessments, and reports.

| Classification    | Example                                                                     |
| ----------------- | --------------------------------------------------------------------------- |
| Known fact        | EDR recorded a process connecting to a specific external IP                 |
| Hypothesis        | The process may be communicating with an attacker                           |
| Unknown           | Whether patient information was transferred                                 |
| Next verification | Examine network telemetry, process activity, and available data-access logs |

Avoid writing "The attacker stole patient records" when the only evidence is an unusual network connection.

Instead, write "Suspicious outbound communication was observed. Data exfiltration has not been confirmed."

As new evidence arrives, update the findings and preserve the original record of what was believed earlier.

Key point: Facts require supporting evidence. Hypotheses require investigation.

---
## Complete incident-response workflow

This combines the learning objectives into the order you will generally follow in the project.

1. Detect and triage — Review alerts, logs, affected assets, and suspicious activity.
2. Declare and document — Open the incident record, establish severity, and start the timeline.
3. Preserve evidence — Collect important volatile and non-volatile evidence while considering urgency.
4. Select and apply containment — Evaluate operational trade-offs, act, and verify that the threat is restricted.
5. Reassess scope — Investigate additional systems, accounts, and possible lateral movement.
6. Eradicate and verify — Remove malicious processes, persistence, compromised credentials, and unauthorized access.
7. Recover and validate — Restore systems, test clinical services, and monitor for recurrence.
8. Prepare the handoff — Document evidence, decisions, completed work, remaining risks, and next owners.

## Important terminology

| Term              | Simple meaning                                               |
| ----------------- | ------------------------------------------------------------ |
| Triage            | Quickly assess an alert and determine its priority           |
| Containment       | Stop or limit an ongoing attack                              |
| Eradication       | Remove the attacker and malicious mechanisms                 |
| Recovery          | Safely restore normal operations                             |
| Volatile evidence | Information that can disappear quickly                       |
| Chain of custody  | Record of how evidence was handled                           |
| Persistence       | A method attackers use to maintain or regain access          |
| Lateral movement  | Moving from one compromised system to another                |
| LOLBins           | Legitimate system tools abused for malicious purposes        |
| IOC               | Indicator of Compromise, such as a malicious file hash or IP |
| EDR               | Endpoint Detection and Response                              |
| Handoff           | Transfer of incident responsibility and documentation        |

## Final takeaway

The important lesson of Contain and Control is that incident response is not simply stopping malicious activity. A competent analyst must be able to investigate, preserve, decide, act, verify, and document in the correct order, while considering operational consequences.

For this project, three principles are especially important:

Preserve evidence without allowing unnecessary damage. Contain threats without ignoring clinical operations. Never claim eradication or recovery without verification.

