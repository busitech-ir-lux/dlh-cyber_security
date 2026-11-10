# Vishing and Social Engineering Scenario Scripts

**Owner:** Awareness Lead  
**Status:** Draft; CISO/HR approval required, Legal review for recording and escalation  
**Modes:** Controlled live call, tabletop or onboarding practice

## Facilitator Runbook

Before each exercise, record scenario/version, approved target cohort, timing clearance, facilitator, observer, stop authority and debrief contact. Use only approved internal identities; CFO identity remains `[AUTHORIZED_CFO_NAME]` until authorized. No source establishes that approval already exists. No recording by default; recording requires Legal approval, approved notice/consent arrangements and restricted retention. Do not use public personal information to personalize these scripts.

For live calls, employees receive general prior program notice without the exact call timing. Tabletop participants know it is a simulation and describe choices verbally. Apply all campaign exclusions, 21-day exposure cooldown and clinical blackouts. Do not interrupt real medical emergencies or impersonate emergency clinicians. Unit leadership clears clinical calls; decline or reschedule if patient care competes.

The caller tests stated willingness only. **Never ask the employee to speak a password/MFA code, trigger a reset, approve a prompt, download/install anything, share a screen, transfer money or send a real document.** If compliance begins, interrupt immediately using the exact stop line: “Stop here—this is a MedDefense training simulation. Please do not share information or take any action.” Then debrief. If the employee starts a real action, stop and notify Security promptly to prevent it.

Caller may use the approved initial line and one branch only; no repeated pressure. At verification, respect the employee's decision and end the call so a genuine directory callback can occur. Never give a substitute callback number. Score observable decisions, not tone, speed, confidence or personality. Use anonymized summaries; individual results remain with the program manager. No manager disclosure except the HR-confirmed coaching conditions in the campaign plan; phone scores must not be relabeled “two clicked waves.”

## V-01: IT Helpdesk Impersonation

**Target:** General clinical or administrative staff (SEG-B/C; approved SEG-A practice)  
**Attacker objective:** Obtain a password or acceptance of an attacker-initiated reset  
**Mechanisms:** Familiarity, authority and urgency  
**Attacker-perspective simulated success:** Employee states willingness to disclose a secret or accept an unsolicited reset; no real reset or disclosure occurs.

### Exact Caller Dialogue

**Opening:** “Hello, this is [APPROVED_HELPDESK_ALIAS] calling about an account verification ticket. I am checking whether your access will be ready for your next work session. If someone claiming to be IT asked for your current password or asked you to accept a reset you did not start, would you follow that request, or verify it independently? Please do not tell me any password or take any action.”

The explicit hypothetical preserves safety; it tests verification reasoning rather than covert password harvesting. Do not claim live-test results are directly comparable to a real attack's success rate.

| Employee response | Exact caller branch |
| --- | --- |
| Compliance: “Yes, I would do that” or begins disclosure | “Stop here—this is a MedDefense training simulation. Please do not share information or take any action. We will practice the safe verification route now.” |
| Hesitation: “Why do you need that?” | “It is reasonable to pause an unexpected account request. What known MedDefense contact would you use to verify it? Do not provide a password or approve a reset.” Then reveal the simulation and debrief |
| Verification request/refusal | “Please end this call and use the helpdesk contact already in your directory. I will not give you another number. You can report this call to Security.” End call; observer records safe route; reveal simulation through approved follow-up |

### Assessment Rubric

| Decision | Pass | Partial | Fail |
| --- | --- | --- | --- |
| Secret/reset boundary | Explicitly refuses secret sharing and unsolicited reset | Does not comply but cannot explain safe boundary | States willingness or starts actual disclosure/action; caller stops immediately |
| Verification | Ends call and independently uses known directory path | Asks questions or requests ticket but relies on caller-provided identity | Treats caller claim/ticket number as proof |
| Reporting | Reports to Security and records alias, displayed number, time and request without secrets | Plans to report but needs route prompt | Does not report after opportunity/instruction |

Full pass: all three decisions pass without coaching prompts. Prompted success is learning, not an unassisted pass. Record N/A if interrupted for patient care, not failure.

### Immediate Debrief

“This was a simulation. The authority claim and account-access timing made the call realistic. The safe response was to refuse secrets and unsolicited resets, then use the known directory path. A real attacker could use compromised identity to enter work systems and support the credential-to-endpoint path documented in the prior incident. Reporting after an uncertain response still helps.” Ask the employee to name the callback route and report to ext. 4-SECURITY. Offer private support; no shame or performance-review use.

## V-02: Vendor Support Escalation

**Target:** Clinical supervisor/staff (SEG-A/B); SEG-D tabletop adaptation  
**Attacker objective:** Unverified remote tool installation or screen access for an “emergency Epic patch”  
**Mechanisms:** Authority, urgency and technical dependency  
**Attacker-perspective simulated success:** Employee agrees to grant/install before independent verification; no tool, session or link is supplied.

### Exact Caller Dialogue

**Opening:** “Hello, this is [APPROVED_VENDOR_ALIAS], about an emergency Epic patch review. I would like to arrange a remote support session for the workstation used by your unit. Before any action, can you explain how you would approve and verify this support request? Do not install software or share your screen during this call.”

| Employee response | Exact caller branch |
| --- | --- |
| Compliance: “Go ahead” or offers screen access | “Stop here—this is a MedDefense training simulation. Please do not share information or take any action. No support session will be opened.” |
| Hesitation: asks for more details/ticket | “There is no approved change ticket available on this call. What would you do before permitting support access?” After the answer: “This was a simulation; let's review the approved callback and ticket process.” |
| Verification request/refusal | “Please use the approved vendor contact list and confirm the ticket with MedDefense IT. I will not supply a different callback number. End this call and report the request to Security.” End and arrange immediate debrief |

### Assessment Rubric

| Decision | Pass | Partial | Fail |
| --- | --- | --- | --- |
| Remote-access boundary | Refuses any tool/session until verified and authorized | Delays but is unclear on approval | Agrees to install/share before checks; stop |
| Verification and scope | Known vendor-list callback plus IT ticket/scope confirmation | Requests ticket only or trusts displayed caller number | Accepts urgency/vendor name as authorization |
| Reporting and care | Reports time, alias, displayed number and request; preserves patient-care priorities | Needs prompt for reporting | Bypasses reporting or normal care/support approval |

Full pass requires every pass criterion unprompted. A necessary patient-care interruption is N/A; reschedule safely.

### Immediate Debrief

“This was a simulation. Clinical vendors are a normal part of operations; urgency during an equipment problem makes requests plausible. Verify through the approved vendor contact list and IT ticket process. A real unverified session could expose patient information, alter an endpoint or support privileged movement. No remote access was opened.” Rehearse a known callback and Security report. Reinforce that refusing unverified access is helpful, not obstructive.

## V-03: Executive Authority Impersonation

**Target:** Administrative/finance staff (SEG-C/E), executive assistants (SEG-F)  
**Attacker objective:** Financial action or sensitive-document release based only on a phone call  
**Mechanisms:** Authority and social proof  
**Attacker-perspective simulated success:** Employee agrees to act solely on caller identity; no transfer/document request is executed.

### Exact Caller Dialogue

**Opening:** “This is [AUTHORIZED_CFO_NAME] from the CFO office. The finance team is waiting on a settlement review before today's discussion. If I asked you by phone to initiate the financial step or send the confidential review packet, what approval and verification would you use? Please do not send anything or open a payment transaction during this call.”

| Employee response | Exact caller branch |
| --- | --- |
| Compliance: offers to proceed on caller instruction | “Stop here—this is a MedDefense training simulation. Please do not share information or take any action. No payment or document release is authorized.” |
| Hesitation: asks why urgent or requests email | “An email in the same request chain would not independently verify me. How would you confirm the request using a contact you already trust?” Reveal simulation after response; debrief |
| Verification request/refusal | “Please call the executive office using the known directory entry and keep the normal finance or document approvals. Do not use a number I provide. End this call and report the request to Security.” End and arrange debrief |

### Assessment Rubric

| Decision | Pass | Partial | Fail |
| --- | --- | --- | --- |
| Financial/document boundary | Refuses action solely on phone instruction | Delays but would accept same-thread confirmation | Agrees to act on caller authority; stop |
| Independent verification | Uses known executive-office directory callback | Requests email or ticket only | Trusts name, voice or confidentiality claim |
| Approval and reporting | Retains normal approvals and reports alias/time/number/request to Security | Does only one of approval check and reporting | Bypasses approvals or keeps request secret from Security |

Full pass requires all pass criteria without prompting; use N/A for interrupted/unobserved steps. Tabletop and live results remain labeled separately.

### Immediate Debrief

“This was a simulation. The waiting finance team and executive identity created pressure to be helpful. Any unusual money or confidential-document request needs independent verification and normal approvals. A real attacker could cause a fraudulent payment or release board/contract material even without a clicked link.” Rehearse the known office callback and Security report. Do not disclose the employee's result publicly.

## Closure and Support

Debrief immediately, confirm no action/secret disclosure occurred and give the employee an opportunity to ask questions privately. Record only scenario, mode, eligible participant code, observable choices, stop reason and coaching needs. No audio or secret contents in records. Apply 18-month individual-data retention and role restrictions from the campaign plan. HR can pause on welfare concerns; Clinical Operations can halt unsafe clinical calls; CISO authorizes restart with the relevant owner. A real compromise follows SOC incident handling separately.

## Sources

- [Healthcare patterns](../6x04/threat_intel/healthcare_social_engineering_patterns.md), [incident summary](../6x04/incident_context/module5_incident_summary.md), [attack path](../6x04/incident_context/cobalt_strike_phishing_path.md).
- [Facilitator notes](../6x04/templates/vishing_facilitator_notes.md), [ethics](../6x04/campaign_design/simulation_ethics_guidelines.md), [HR privacy](../6x04/campaign_design/hr_privacy_rules.md).
- [Campaign plan](phishing_campaign_plan.md) and [email templates](phishing_templates.md).
