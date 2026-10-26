# Facilitator Script: Nexus Supply Chain Compromise Tabletop

**Date:** 2026-10-26  
**Facilitator:** Exercise facilitator (assigned before delivery)  
**Classification:** Internal - Exercise Use Only  
**Version:** 1.1

## Pre-exercise checklist
- [ ] Arrange seating so all seven roles can respond, with a separate observer seat.
- [ ] Give participants `exercise_scenario.md` and `participant_guide.md` only.
- [ ] Keep capability map, inject schedule and evaluation criteria private.
- [ ] Verify timer, whiteboard, private observer scoring sheet, and decision log.
- [ ] Obtain consent before any recording; otherwise take handwritten notes.
- [ ] Tell observers not to speak or coach; identify a person to time-stamp decisions.
- [ ] Use simulated calls/emails only; never contact the actual addresses.

## Ground rules — read aloud
“This is a discussion-based tabletop exercise, not an actual incident response or a briefing. I will introduce timed updates. State what your role would decide, who can approve it, what you would do next, and when you would review it. You may ask for information, but if that information is unavailable you must decide how to manage the uncertainty. I will remain neutral, and I will not provide the answer. There are no personal grades; our observations concern organizational capability. We will record both complete and incomplete responses.”

## Timeline and control
Exercise time is simulated. Start T+0 when INJ-00 is read. Deliver injects at T+0, 20, 35, 50, 65, 80, and 100 minutes. Each inject receives discussion until the next listed delivery; for final inject allow 15 minutes, followed by 15-minute debrief. If the discussion stalls, ask neutral probes without giving away the diagnosis. Score only evidence before the next inject. Collect decisions with timestamp, authority, owner, and rationale.

## INJ-00 (T+0 minutes)

**Read aloud verbatim:** “The SOC has flagged unusual outbound traffic from Main scheduling server SCHED-SVR-01 to 193.42.100.77. The alert fired 45 minutes ago; EDR records outbound connections every four hours. Scheduling is still operating. Host names for the other two sites are not yet confirmed.”

**Delivery:** T+0; allow 20 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Declare incident/severity; identify first notifications and preserve telemetry.

**Neutral probes:**
- Who is incident commander?
- What is preserved before isolation?
- Which sites and update paths need validation?
- What makes signed software trustworthy?

**Non-engagement flag:** If James Chen has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-01.”

## INJ-01 (T+20 minutes)

**Read aloud verbatim:** “Nexus posts a verified advisory: its build pipeline was compromised three days ago, and a malicious component was included in a digitally signed automatic agent update. No safe patch exists yet. Main has the update; Nexus cannot immediately confirm the other two sites. The clinical director reports two time-sensitive appointments could be missed if scheduling stops, and one appointment time already conflicts with a printed clinic list. Sarah recommends isolation; clinical leadership objects to a total shutdown.”

**Delivery:** T+20; allow 15 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Choose isolate/limit/continue with accountable clinical and IT approval, safe fallback and review time; contact Nexus.

**Neutral probes:**
- Who can authorize disruption?
- What will urgent patients do today?
- Can synchronization stop while staff confirm appointments?
- Who owns the vendor escalation?

**Non-engagement flag:** If Sarah Park has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-02.”

## INJ-02 (T+35 minutes)

**Read aloud verbatim:** “Nexus SecOps acknowledges the event but has no complete affected-customer list. It says possible access to patient names, dates of birth, contact details, appointment times, and insurance data. Nexus has not sent formal BAA breach notice and cannot yet prove exfiltration. The first security email was sent to the account executive, who has not replied.”

**Delivery:** T+35; allow 15 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Escalate vendor contact; start exposure scoping and contractual/legal notice assessment without claiming breach is confirmed.

**Neutral probes:**
- Which contact is 24x7?
- What is the vendor discovery time?
- What does the BAA require versus federal law?
- What records could have left?

**Non-engagement flag:** If Helena Reyes has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-03.”

## INJ-03 (T+50 minutes)

**Read aloud verbatim:** “Epic audit comparisons show 46 appointments have mismatched times or statuses in the past 72 hours across all three sites; eight involve patients with time-sensitive care. The mismatch origin is not known. Nexus admits the malicious code could read outbound FHIR payloads, but it has not confirmed data theft.”

**Delivery:** T+50; allow 15 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Prioritize clinical verification and isolate corrupted scheduling updates; determine whether and how to assess ePHI breach risk.

**Neutral probes:**
- Who checks each of the 46 records?
- Which eight need urgent clinical calls?
- Which audit source is trusted?
- Does unknown exfiltration mean no breach?

**Non-engagement flag:** If Clinical Director representative has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-04.”

## INJ-04 (T+65 minutes)

**Read aloud verbatim:** “A local reporter emails: “We hear patients at MedDefense had their appointments changed after a vendor hack. Has health data been stolen? Please respond in 15 minutes.” A staff member has already drafted a social post saying “No patient records were compromised.””

**Delivery:** T+65; allow 15 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Approve holding statement and internal speaking rules, without unsupported assertions.

**Neutral probes:**
- Who can publish a statement?
- What facts are actually verified?
- Will staff get speaking guidance?
- When do you update the reporter?

**Non-engagement flag:** If Marcus Webb has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-05.”

## INJ-05 (T+80 minutes)

**Read aloud verbatim:** “The board chair requests a concise decision brief in 90 minutes. It must say what is confirmed, what remains unknown, patient safety impact, HIPAA posture, vendor exposure, and which leadership decisions are needed. CFO asks if all 3,500 weekly patients are affected.”

**Delivery:** T+80; allow 20 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Assign a board brief with clear risk, uncertainty, recommendations and accountable authors.

**Neutral probes:**
- Who writes the brief?
- Is 3,500 a weekly transaction volume or breach count?
- What must the board authorize?
- What is the next update time?

**Non-engagement flag:** If Dr. Patricia Morales has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is INJ-06.”

## INJ-06 (T+100 minutes)

**Read aloud verbatim:** “Nexus proposes re-enabling signed automatic updates immediately after reinstalling the agent but cannot prove its signing infrastructure is clean. Patient clinics want normal scheduling restored tomorrow. Reviewers still cannot determine which FHIR payloads were read or whether 46 changed appointments were malicious or operational.”

**Delivery:** T+100; allow 15 minutes before next phase, noting that INJ-05 includes planning for a simulated 90-minute board deadline.

**Decision to capture:** Decide recovery conditions and board recommendation with unresolved questions, owner and next checkpoint.

**Neutral probes:**
- What proof makes future builds trustworthy?
- Who signs off on patient schedules?
- Who owns the unresolved PHI scope?
- What would stop reactivation?

**Non-engagement flag:** If Sarah Park has not made a decision, ask that person which authority or action their role owns; do not supply the answer.

**Transition:** “We will record that decision and any unresolved questions. The next update is the debrief.”

## Private facilitator notes — do not distribute
- **CAP-01:** Look for challenge to code-signing trust. Known residual risk: certificate verification only; no independent client hash pin; missing npm software bill of materials.
- **CAP-02:** Contact path was documented but not jointly tested; 24x7 Nexus SecOps is the security escalation point. Do not assume delivery worked merely because a role says “email the vendor.”
- **CAP-03:** Distinguish technical network isolation from clinical service shutdown; evidence of named approval matters.
- **CAP-04:** Data flow includes demographics and insurance, not just appointments. An uncertainty statement is appropriate; a “no leak” claim is not.
- **CAP-05:** BAA says 24 hours after discovery for Nexus notice. HIPAA BA notice must be without unreasonable delay and within 60 days; covered-entity notification depends on breach assessment and relevant thresholds.
- **CAP-06:** Verify patients' real appointments from trusted records, preserving chain of evidence before reconciliation.
- **CAP-07:** A statement should not turn a suspicion into confirmed breach or confirmed safety.
- **CAP-08:** The executive brief must request decisions, not just summarize security telemetry.

## Wrap-up (15 minutes)
Ask, without grading individuals: “Which coordination worked?” “Where did we lack authority or information?” “Which patient-safety decision was most uncomfortable?” “What would you change in the first hour?” “Which unresolved item needs an owner tomorrow?” Capture proposed fixes separately from observed evidence. Thank participants; say the after-action report will use inject/criterion references, owners and validation tests.
