# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-26  
**Simulated by:** Exercise designer (self-run scripted simulation)  
**Classification:** Internal - Exercise Use Only  
**Version tested:** 1.0; version 1.1 changes recorded below.  
**Important:** This is a fictional role-play, **not an exercise actually conducted with MedDefense leadership**. Responses are invented to test artifact quality, not claims about real employees.

## INJ-00 (T+0 minutes)

**Inject delivered verbatim:** “The SOC has flagged unusual outbound traffic from Main scheduling server SCHED-SVR-01 to 193.42.100.77. The alert fired 45 minutes ago; EDR records outbound connections every four hours. Scheduling is still operating. Host names for the other two sites are not yet confirmed.”

**Simulated participant responses:**
- **James Chen:** “I declare provisional SEV2 at T+2; preserve EDR and flows before changes.”
- **Sarah Park:** “I notify Patricia and Robert at T+4 and check availability.”
- **Dr. Patricia Morales:** “I will own incident command once confirmed.”
- **Helena Reyes:** “I am available if patient information is implicated.”
- **Marcus Webb:** “I will await verified facts.”
- **Robert Kim:** “I preserve host/network events; I have not yet investigated the update origin.”
- **Clinical Director representative:** “I want appointment services monitored.”

**Evaluation (each criterion):**
- **INJ-00/C01: PASS** — Observed in this simulation: within 5 minutes declare provisional incident severity with rationale; see dialogue above.
- **INJ-00/C02: PASS** — Observed in this simulation: name two notified leadership/technical roles; see dialogue above.
- **INJ-00/C03: PASS** — Observed in this simulation: preserve edr/network records before disruptive changes; see dialogue above.

**Facilitator probe:** “Who is incident commander?” **Revealed:** The team could explain its initial command response, but still had incomplete information.

## INJ-01 (T+20 minutes)

**Inject delivered verbatim:** “Nexus posts a verified advisory: its build pipeline was compromised three days ago, and a malicious component was included in a digitally signed automatic agent update. No safe patch exists yet. Main has the update; Nexus cannot immediately confirm the other two sites. The clinical director reports two time-sensitive appointments could be missed if scheduling stops, and one appointment time already conflicts with a printed clinic list. Sarah recommends isolation; clinical leadership objects to a total shutdown.”

**Simulated participant responses:**
- **James Chen:** “Signed update makes the vendor pathway plausible; I need hash/build history.”
- **Sarah Park:** “I recommend isolation but cannot name final authority; I want to wait.”
- **Dr. Patricia Morales:** “I request an explicit cross-functional decision.”
- **Helena Reyes:** “Assess any implications for data access.”
- **Marcus Webb:** “I will prepare staff messaging if downtime happens.”
- **Robert Kim:** “I can disable FHIR synchronization but need clinical instruction.”
- **Clinical Director representative:** “Total shutdown risks urgent care; I object and have no documented fallback.”

**Evaluation (each criterion):**
- **INJ-01/C01: FAIL** — Observed in this simulation: isolation authority or decision missing; see dialogue above.
- **INJ-01/C02: FAIL** — Observed in this simulation: no patient-safety fallback defined; see dialogue above.
- **INJ-01/C03: FAIL** — Observed in this simulation: no verified security contact initiated; see dialogue above.

**Facilitator probe:** “Who can authorize disruption?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## INJ-02 (T+35 minutes)

**Inject delivered verbatim:** “Nexus SecOps acknowledges the event but has no complete affected-customer list. It says possible access to patient names, dates of birth, contact details, appointment times, and insurance data. Nexus has not sent formal BAA breach notice and cannot yet prove exfiltration. The first security email was sent to the account executive, who has not replied.”

**Simulated participant responses:**
- **James Chen:** “I can collect FHIR transaction logs but cannot estimate the affected individuals yet; a vendor request has not been logged.”
- **Sarah Park:** “The vendor should send us written evidence.”
- **Dr. Patricia Morales:** “Open vendor incident escalation and log timelines.”
- **Helena Reyes:** “I think HIPAA gives the vendor only 24 hours; I will decide based on that.”
- **Marcus Webb:** “I will not publicly assert a breach.”
- **Robert Kim:** “The API contains demographics and insurance payloads.”
- **Clinical Director representative:** “We need to protect patients whose appointments change.”

**Evaluation (each criterion):**
- **INJ-02/C01: FAIL** — Observed in this simulation: vendor communication has no tracked request; see dialogue above.
- **INJ-02/C02: PASS** — Observed in this simulation: identify possible ephi fields and unknown affected individuals; see dialogue above.
- **INJ-02/C03: FAIL** — Observed in this simulation: contractual/regulatory clock confused; see dialogue above.

**Facilitator probe:** “Which contact is 24x7?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## INJ-03 (T+50 minutes)

**Inject delivered verbatim:** “Epic audit comparisons show 46 appointments have mismatched times or statuses in the past 72 hours across all three sites; eight involve patients with time-sensitive care. The mismatch origin is not known. Nexus admits the malicious code could read outbound FHIR payloads, but it has not confirmed data theft.”

**Simulated participant responses:**
- **James Chen:** “Preserve EDR and Epic audit events for the 72-hour window.”
- **Sarah Park:** “Disable untrusted inbound updates pending clinical checks.”
- **Dr. Patricia Morales:** “Escalate patient safety to the board.”
- **Helena Reyes:** “Start an assessment but I have not assigned the exposure evidence owner.”
- **Marcus Webb:** “Draft internal information for staff.”
- **Robert Kim:** “I can export all 46 discrepancies, but nobody has been assigned to reconcile them.”
- **Clinical Director representative:** “I will contact the eight urgent patients today and verify visits.”

**Evaluation (each criterion):**
- **INJ-03/C01: FAIL** — Observed in this simulation: no named reconciliation process; see dialogue above.
- **INJ-03/C02: PASS** — Observed in this simulation: prioritize eight urgent patients for verification; see dialogue above.
- **INJ-03/C03: FAIL** — Observed in this simulation: exposure investigation or documentation absent; see dialogue above.

**Facilitator probe:** “Who checks each of the 46 records?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## INJ-04 (T+65 minutes)

**Inject delivered verbatim:** “A local reporter emails: “We hear patients at MedDefense had their appointments changed after a vendor hack. Has health data been stolen? Please respond in 15 minutes.” A staff member has already drafted a social post saying “No patient records were compromised.””

**Simulated participant responses:**
- **James Chen:** “We cannot yet prove exfiltration.”
- **Sarah Park:** “Keep service notice accurate for registration desks.”
- **Dr. Patricia Morales:** “I approve Legal and Comms handling this.”
- **Helena Reyes:** “The statement must use verified facts only.”
- **Marcus Webb:** “I approve a factual holding statement, name myself spokesperson, and set a 30-minute update; but I have not stopped the draft “no compromise” social post.”
- **Robert Kim:** “No infrastructure facts for media before clearance.”
- **Clinical Director representative:** “Give patients a number for scheduling questions.”

**Evaluation (each criterion):**
- **INJ-04/C01: FAIL** — Observed in this simulation: unverified no-breach statement allowed; see dialogue above.
- **INJ-04/C02: PASS** — Observed in this simulation: produce counsel-approved factual holding statement; see dialogue above.
- **INJ-04/C03: PASS** — Observed in this simulation: name one spokesperson and next update time; see dialogue above.

**Facilitator probe:** “Who can publish a statement?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## INJ-05 (T+80 minutes)

**Inject delivered verbatim:** “The board chair requests a concise decision brief in 90 minutes. It must say what is confirmed, what remains unknown, patient safety impact, HIPAA posture, vendor exposure, and which leadership decisions are needed. CFO asks if all 3,500 weekly patients are affected.”

**Simulated participant responses:**
- **James Chen:** “Current indicators and unknowns will be in the brief.”
- **Sarah Park:** “I will document isolation and continuity options.”
- **Dr. Patricia Morales:** “I own the board brief due T+170; I will state 3,500 weekly interactions as 3,500 affected patients and request the board decision.”
- **Helena Reyes:** “I will document breach status as under assessment.”
- **Marcus Webb:** “I can prepare a one-page external comms posture.”
- **Robert Kim:** “Do not put unverified system host counts in the board brief.”
- **Clinical Director representative:** “I will summarize urgent-patient actions.”

**Evaluation (each criterion):**
- **INJ-05/C01: PASS** — Observed in this simulation: assign brief owner and 90-minute delivery time; see dialogue above.
- **INJ-05/C02: FAIL** — Observed in this simulation: affected patient count fabricated; see dialogue above.
- **INJ-05/C03: PASS** — Observed in this simulation: include patient impact, legal posture, decisions, and next update; see dialogue above.

**Facilitator probe:** “Who writes the brief?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## INJ-06 (T+100 minutes)

**Inject delivered verbatim:** “Nexus proposes re-enabling signed automatic updates immediately after reinstalling the agent but cannot prove its signing infrastructure is clean. Patient clinics want normal scheduling restored tomorrow. Reviewers still cannot determine which FHIR payloads were read or whether 46 changed appointments were malicious or operational.”

**Simulated participant responses:**
- **James Chen:** “I still need vendor process-tree and FHIR evidence.”
- **Sarah Park:** “I propose using the newly signed build without independent trust checks.”
- **Dr. Patricia Morales:** “Board decision: remain restricted pending clean-build proof; assign tasks.”
- **Helena Reyes:** “Exfiltration remains unknown; I will investigate further but no checkpoint is agreed.”
- **Marcus Webb:** “I will give patients only confirmed service changes.”
- **Robert Kim:** “I have no monitored test or clinical sign-off process ready.”
- **Clinical Director representative:** “I cannot sign off on appointment integrity until checked.”

**Evaluation (each criterion):**
- **INJ-06/C01: FAIL** — Observed in this simulation: signed update accepted without assurance; see dialogue above.
- **INJ-06/C02: FAIL** — Observed in this simulation: no clinical sign-off or monitored verification; see dialogue above.
- **INJ-06/C03: FAIL** — Observed in this simulation: unresolved questions have no owner or next review; see dialogue above.

**Facilitator probe:** “What proof makes future builds trustworthy?” **Revealed:** The team lacked a documented decision owner or proof for at least one requirement.

## Design feedback — observed flaws and implemented changes

### DF-01: Integrity clue arrived after continuity decision
**Problem:** A pure shutdown decision at INJ-01 was too disconnected from patient safety; the strongest integrity evidence appeared at INJ-03. **Change implemented in version 1.1:** Move a preliminary conflicting appointment record into INJ-01; keep quantified 46-record discovery at INJ-03.

### DF-02: Site host names were being invented
**Problem:** The vendor profile confirms `SCHED-SVR-01` at Main only, so assuming named hosts at West and North would make a fabricated inventory fact appear verified. **Change implemented in version 1.1:** Initial scenario and INJ-00 identify Main's confirmed host, require other sites' agent deployments to be checked, and later report cross-site mismatches as new evidence.

### DF-03: The 24-hour notice question invited a false legal assumption
**Problem:** The initial legal prompt could blur the 24-hour BAA term and federal HIPAA legal notice. **Change implemented in version 1.1:** INJ-02 and criterion INJ-02/C03 specifically require the participant to distinguish the contractual 24 hours from the HIPAA Business Associate rule.

**Re-test plan:** Run the three revised passages with an independent facilitator; pass design review only if participants understand the opening facts and each criterion has an observable answer without coaching. The results above are the original simulation scores, not results of that re-test.
