# Task 7 — HIPAA Breach Scope Assessment

**Case:** LH-2026-0414-01  
**Source:** Investigation finding summary supplied in Task 7 (original LIS audit records not provided). **The multiple-choice questions and options were not supplied**, so this provides a reasoned assessment rather than guessed MCQ letters.

## Documented scenario facts

- Fourteen laboratory report PDFs were reportedly accessed on `LIS-WSIDE-01` between **2026-04-14T03:43Z and 03:44Z** under the `dmarsh` account.
- Reports contain names, dates of birth, attending physicians, CBC and metabolite-panel laboratory results; this is identifiable **PHI/ePHI**.
- The user is a lab technician without legitimate access to the affected ER patients; the scenario describes access as unauthorized.
- No external C2 exfiltration was confirmed in the available network logs. This **does not establish** that the documents were not viewed, retained or disclosed by other methods.
- The summary refers to 14 PDFs, but a precise count of **unique individuals** requires mapping report files to patient identifiers.

## Four-factor risk assessment under 45 CFR §164.402

| Factor | Case evaluation | Effect on low-probability-of-compromise test |
|---|---|---|
| 1. Nature and extent of PHI | Direct identifiers and sensitive clinical lab results in 14 reports | Favors compromise concern |
| 2. Unauthorized recipient/person | Access outside dmarsh's assigned clinical role; account may have been misused | Favors compromise concern; identify actual operator |
| 3. Whether PHI was actually acquired/viewed | Reported audit events show PDF access; verify whether access reflects read/view vs metadata only | Strong concern if content was opened/read; underlying audit pending |
| 4. Mitigation | No confirmed C2 exfiltration; evidence does not demonstrate retrieval was prevented or data rendered inaccessible | Insufficient to establish low probability of compromise |

## Preliminary determination

**Presumptive reportable breach, pending confirmation of the original audit trail, whether PHI was unsecured, and counsel/privacy-officer review.** HIPAA presumes an impermissible access to PHI is a breach unless a documented four-factor assessment establishes a low probability that PHI was compromised or a regulatory exception applies. The available scenario does **not** support a low-probability finding simply because external exfiltration was not observed. No obvious exception is shown by the supplied facts.

For a breach involving **fewer than 500 individuals**: notify affected individuals **without unreasonable delay and no later than 60 calendar days after discovery**; notify the HHS Secretary **within 60 days after the end of the calendar year in which the breach was discovered**. A media notice for a breach affecting over 500 residents of a state or jurisdiction would not normally be triggered by 14 individuals. State laws, contracts, and other regulations may separately apply. Deadlines must be tied to the actual documented *discovery date*, not automatically the attack timestamp.

## Recommended next actions

1. Preserve and verify the LIS file access records and identify each unique affected patient.
2. Confirm access type, content viewing/download evidence, account/session operator, and encryption status.
3. Ask MedDefense privacy officer/General Counsel to complete and sign the four-factor assessment and notification decision.
4. Document mitigation, containment, communication, notifications, and any exceptions under the litigation hold.

**Official basis:** HHS HIPAA Breach Notification Rule: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html ; HHS breach-reporting guidance: https://www.hhs.gov/hipaa/for-professionals/breach-notification/breach-reporting/index.html .
