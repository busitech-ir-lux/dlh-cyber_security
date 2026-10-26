# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-26 (simulated)  
**Report date:** 2026-10-26  
**Facilitator:** Exercise designer (simulated)  
**Participants simulated:** James Chen, Sarah Park, Dr. Patricia Morales, Helena Reyes, Marcus Webb, Robert Kim, Clinical Director representative  
**Classification:** Internal - Exercise Use Only

## Executive summary
This **self-run simulation**, not a live MedDefense exercise, tested eight organizational capabilities using seven timed injects. The most significant simulated gaps were unclear authority to contain a patient-facing vendor integration, an undefined clinical fallback and integrity reconciliation, and an unsafe assumption that a newly vendor-signed build could be trusted immediately. Vendor escalation and HIPAA timing were also handled inconsistently. The single highest-priority action is to establish and rehearse a **joint IT–clinical containment and recovery authorization procedure**, including safety fallback, evidence preservation and explicit return-to-service sign-off. These findings are hypotheses to validate in a live exercise; they do not establish actual deficiencies in MedDefense.

## Findings table

| ID | Inject / criterion | Capability | Gap | Severity | Recommended action | Owner | Deadline | Validation |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-01/C01 | CAP-01,CAP-02,CAP-03 | Isolation authority or decision missing | P1 | Make or escalate isolation decision to named authority. Create a written procedure, name an alternate, and rehearse the decision. | IT Director | 21 days | Document review and focused re-test |
| F-002 | INJ-01/C02 | CAP-01,CAP-02,CAP-03 | No patient-safety fallback defined | P1 | Clinical role identifies fallback and urgent-patient impact. Create a written procedure, name an alternate, and rehearse the decision. | Clinical Director representative | 21 days | Document review and focused re-test |
| F-003 | INJ-01/C03 | CAP-01,CAP-02,CAP-03 | No verified security contact initiated | P2 | Escalate using verified 24x7 Nexus security contact. Create a written procedure, name an alternate, and rehearse the decision. | IT Director | 14 days | Document review and focused re-test |
| F-004 | INJ-02/C01 | CAP-02,CAP-04,CAP-05 | Vendor communication has no tracked request | P2 | Contact Nexus SecOps and request written timeline/discovery time. Create a written procedure, name an alternate, and rehearse the decision. | General Counsel | 14 days | Document review and focused re-test |
| F-005 | INJ-02/C03 | CAP-02,CAP-04,CAP-05 | Contractual/regulatory clock confused | P2 | Distinguish BAA 24h from HIPAA outer 60-day BA rule. Create a written procedure, name an alternate, and rehearse the decision. | General Counsel | 14 days | Document review and focused re-test |
| F-006 | INJ-03/C01 | CAP-04,CAP-05,CAP-06 | No named reconciliation process | P1 | Name owner and process for checking all 46 mismatches. Create a written procedure, name an alternate, and rehearse the decision. | Clinical Director representative | 21 days | Document review and focused re-test |
| F-007 | INJ-03/C03 | CAP-04,CAP-05,CAP-06 | Exposure investigation or documentation absent | P2 | Record PHI risk assessment and unresolved exfiltration evidence. Create a written procedure, name an alternate, and rehearse the decision. | Clinical Director representative | 14 days | Document review and focused re-test |
| F-008 | INJ-04/C01 | CAP-07 | Unverified no-breach statement allowed | P2 | Prevent publication of unapproved no-breach statement. Create a written procedure, name an alternate, and rehearse the decision. | Communications Director | 14 days | Document review and focused re-test |
| F-009 | INJ-05/C02 | CAP-08 | Affected patient count fabricated | P2 | Separate known, unknown and 3,500 weekly volume from affected total. Create a written procedure, name an alternate, and rehearse the decision. | CISO | 14 days | Document review and focused re-test |
| F-010 | INJ-06/C01 | CAP-03,CAP-06,CAP-08 | Signed update accepted without assurance | P1 | Block automatic update trust until vendor assurance independently checked. Create a written procedure, name an alternate, and rehearse the decision. | Infrastructure Lead | 21 days | Document review and focused re-test |
| F-011 | INJ-06/C02 | CAP-03,CAP-06,CAP-08 | No clinical sign-off or monitored verification | P1 | Document clinical integrity sign-off and monitored staged restart. Create a written procedure, name an alternate, and rehearse the decision. | Infrastructure Lead | 21 days | Document review and focused re-test |
| F-012 | INJ-06/C03 | CAP-03,CAP-06,CAP-08 | Unresolved questions have no owner or next review | P2 | Record unresolved PHI questions, owner and next checkpoint. Create a written procedure, name an alternate, and rehearse the decision. | Infrastructure Lead | 14 days | Document review and focused re-test |

## P1 finding narratives

### F-001: Isolation authority or decision missing
In INJ-01/C01, the simulation produced no observable satisfactory decision: isolation authority or decision missing. This matters because the affected service supports three sites and can alter patient care decisions. **Action:** Make or escalate isolation decision to named authority. Create a written procedure, name an alternate, and rehearse the decision. **Owner:** IT Director. **Deadline:** 21 days. **Proof of closure:** document review and focused re-test.

### F-002: No patient-safety fallback defined
In INJ-01/C02, the simulation produced no observable satisfactory decision: no patient-safety fallback defined. This matters because the affected service supports three sites and can alter patient care decisions. **Action:** Clinical role identifies fallback and urgent-patient impact. Create a written procedure, name an alternate, and rehearse the decision. **Owner:** Clinical Director representative. **Deadline:** 21 days. **Proof of closure:** document review and focused re-test.

### F-006: No named reconciliation process
In INJ-03/C01, the simulation produced no observable satisfactory decision: no named reconciliation process. This matters because the affected service supports three sites and can alter patient care decisions. **Action:** Name owner and process for checking all 46 mismatches. Create a written procedure, name an alternate, and rehearse the decision. **Owner:** Clinical Director representative. **Deadline:** 21 days. **Proof of closure:** document review and focused re-test.

### F-010: Signed update accepted without assurance
In INJ-06/C01, the simulation produced no observable satisfactory decision: signed update accepted without assurance. This matters because the affected service supports three sites and can alter patient care decisions. **Action:** Block automatic update trust until vendor assurance independently checked. Create a written procedure, name an alternate, and rehearse the decision. **Owner:** Infrastructure Lead. **Deadline:** 21 days. **Proof of closure:** document review and focused re-test.

### F-011: No clinical sign-off or monitored verification
In INJ-06/C02, the simulation produced no observable satisfactory decision: no clinical sign-off or monitored verification. This matters because the affected service supports three sites and can alter patient care decisions. **Action:** Document clinical integrity sign-off and monitored staged restart. Create a written procedure, name an alternate, and rehearse the decision. **Owner:** Infrastructure Lead. **Deadline:** 21 days. **Proof of closure:** document review and focused re-test.

## What worked
- **INJ-00/C01-C02:** James declared a provisional SEV2 incident at T+2 and Sarah named initial recipients, enabling command activation.
- **INJ-03/C02:** Clinical leadership prioritized the eight urgent patients rather than treating every mismatch as equally time critical.
- **INJ-04/C02-C03:** A factual counsel-approved media holding response and designated communications channel were proposed, despite a separate failure to prevent an unapproved draft.

## Exercise design feedback
- **DF-01:** Added an early appointment discrepancy to INJ-01 so the clinical integrity trade-off is visible before the shutdown decision.
- **DF-02:** Removed unsupported host inventory claims; only Main's `SCHED-SVR-01` is confirmed at opening, and other sites must be scoped.
- **DF-03:** Explicitly split Nexus's contractual 24-hour notification term from the federal HIPAA Business Associate requirement.

## Improvement tracking
The owner of each item must supply the revised procedure or evidence by its deadline. An independent observer verifies closure through a focused repeat of the linked inject and criterion; the CISO reviews open P1 actions weekly until closed. Findings represent simulated observations until validated by a real exercise.
