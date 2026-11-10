# Phishing Email Templates: MedDefense Health Systems

**Inventory:** T-EPIC-01, T-MFA-02, T-HR-03, T-BEC-04  
**Status:** Draft; ethics review and CISO/HR approvals pending  
**Use:** Approved internal training only; [campaign plan](phishing_campaign_plan.md)

All sender addresses below are inert reserved `.invalid` display examples. They specify recognition cues, not real sending identities. Operator must obtain an approved internal simulation sender that preserves those cues. `[SIMULATION_LINK]` is the only link token; replace only within the approved platform with a training destination. No credentials, patient information, payments or remote access may be requested or collected. Expected ranges come from supplied category benchmarks, not measured template results.

## T-EPIC-01: Epic EHR Account Management

**Segment:** SEG-B  
**Tier:** Baseline  
**Mechanism:** Authority + urgency  
**Expected first-exposure clicks:** 40–62% (EHR category range)  
**Deployment:** Tue–Thu 07:15–08:30, cleared general floor cohorts only; exclude critical ICU/OR coverage, active safety events, accreditation, shortages and November–January.

```text
From: Epic Account Services <verification@epic-notice.invalid>
To: [First Name Last Name] <[EMPLOYEE_ADDRESS]>
Subject: Epic access verification: patient record access hold in 48 hours

Dear [First Name],

An incomplete security verification is recorded for your Epic EHR account.
The account-management process places patient record access on hold after
48 hours if verification remains incomplete. This could interrupt chart review
and medication documentation at your next scheduled shift.

Please review the account verification notice by [APPROVED_DATE_PLUS_2]:
[SIMULATION_LINK]

For manual review, use the IT helpdesk contact in the MedDefense directory.

Epic Account Services
Account management notification for MedDefense Health Systems
```

**Teaching signals:** External-looking sender despite internal account task; unexpected verification link; deadline tied to care access. The claim about account-management policy is lure text, not a statement of actual MedDefense policy.

**Attacker notes:** The supplied kit used familiar clinical workflow wording, mobile rendering and copied identity context to reduce hesitation. Real attacks can turn a click into credential exposure and follow-on compromise. These observations explain the risk; no login clone or harvesting flow is included.

**Operator safety:** Test the training redirect, omit real patient data and stop if clinical coverage changes. The 48-hour deadline is fictional and must never change real Epic access.

## T-MFA-02: IT Helpdesk MFA Enrollment

**Segment:** SEG-C  
**Tier:** Baseline  
**Mechanism:** Familiarity + authority  
**Expected first-exposure clicks:** 25–42% (MFA/compliance category)  
**Deployment:** Tue–Thu 09:00–11:00; avoid payroll/close; confirm actual MFA communications schedule before use. The supplied IAM summary identifies verification needs but supplies no rollout date.

```text
From: MedDefense IT Compliance <enrollment@it-compliance.invalid>
To: [First Name Last Name] <[EMPLOYEE_ADDRESS]>
Subject: MFA enrollment task due [APPROVED_COMPLIANCE_DATE]

Hello [First Name],

MedDefense IT is reviewing MFA enrollment for access to administrative
systems. Your enrollment task is marked pending in this review.

Please open the compliance task before [APPROVED_COMPLIANCE_DATE]
to review the enrollment steps for your account:
[SIMULATION_LINK]

The compliance team is closing this enrollment review on that date.
For questions, use the helpdesk entry in the MedDefense directory.

MedDefense IT Helpdesk
Compliance enrollment review
```

**Teaching signals:** IT-branded display name with unsuitable external-looking address; unexpected linked enrollment task; known portal route available instead.

**Attacker notes:** Routine MFA communications make an administrative pretext familiar. A real attacker could seek remote-access identity information or unauthorized authentication approval. Training must never elicit an MFA code, password or approval.

**Operator safety:** IT owner validates the timing; do not claim a historical rollout date or trigger real enrollment changes. Defer if the actual communications calendar cannot support the premise.

## T-HR-03: HR Open Enrollment Benefits Deadline

**Segments:** SEG-C and SEG-E  
**Tier:** Intermediate  
**Mechanism:** Urgency + scarcity  
**Expected first-exposure clicks:** 22–38% (HR benefits category)  
**Deployment:** Tue–Thu C 09:00–11:00, E 10:00–14:00; HR-approved enrollment context only; avoid payroll, close and audit deadlines.

```text
From: MedDefense Benefits Team <benefits@enrollment-notice.invalid>
To: [First Name Last Name] <[EMPLOYEE_ADDRESS]>
Subject: Benefits enrollment review closes [APPROVED_ENROLLMENT_DATE]

Hello [First Name],

The open enrollment review shows a pending benefits selection for your profile.
After [APPROVED_ENROLLMENT_DATE], changes may need to wait until the next
eligible enrollment event. Please check your selection and any contribution
changes before the review window closes:
[SIMULATION_LINK]

Use the HR directory contact if you need help reviewing your options.

MedDefense Human Resources
Benefits enrollment team
```

**Teaching signals:** Personal financial pressure and unexpected pending status; external-looking sender; email directs the employee away from the known HR intranet route. This is fictional status text, not an actual benefits determination.

**Attacker notes:** The source pattern exploits concern about benefits or payroll. A real attacker could seek HRIS identity and payroll-related information. The simulation explains that consequence without collecting any personal details.

**Operator safety:** HR approves wording and date; do not threaten termination, loss of salary or personal hardship. Do not send during a distress-sensitive case. Defer if enrollment timing is not credible.

## T-BEC-04: Executive Document Review

**Segments:** SEG-E and SEG-F  
**Tier:** Advanced  
**Mechanism:** Authority + social proof  
**Expected first-exposure clicks:** 8–22% (BEC category; action risk requires separate observation)  
**Deployment:** Tue–Thu E 10:00–14:00; F assistant-cleared window; avoid board days, month-end and audit deadlines. Independent-verification practice precedes use.

```text
From: [AUTHORIZED_CFO_NAME], CFO <cfo-office@executive-notice.invalid>
Reply-To: review-desk@document-review.invalid
To: [First Name Last Name] <[EMPLOYEE_ADDRESS]>
Subject: Review needed: vendor settlement approval packet

[First Name],

The finance team is waiting on the vendor settlement review packet before
our approval discussion. Please review the proposed payment summary and
mark any issues in the review task before [APPROVED_REVIEW_TIME]:
[SIMULATION_LINK]

The executive office has reserved time to close this review today.
Use the review task for the document so the comments stay together.

[AUTHORIZED_CFO_NAME]
Chief Financial Officer
MedDefense Health Systems
```

**Teaching signals:** Unexpected financial document, authority/deadline pressure and mismatched reply route. The `.invalid` cues make this draft inspectable; approved controlled rendering must retain a clear learning opportunity. No real CFO identity is supplied, and no name is inferred from unrelated task characters.

**Attacker notes:** The source describes fewer clicks but potentially high-impact offline action. A real BEC request may seek money or confidential documents without an obviously malicious link. Train independent verification and normal payment approval rather than relying solely on spelling, links or technical email indicators.

**Operator safety:** Document review is fictional; no banking details, actual payment authorization or sensitive-document upload. Route replies to approved controlled handling; any attempted real action stops the exercise immediately. Record verification separately from click telemetry.

## Sources

- [Threat profile](social_engineering_threat_profile.md), [campaign plan](phishing_campaign_plan.md).
- [Kit](../6x04/threat_intel/phishing_kit_analysis_summary.md), [headers](../6x04/threat_intel/email_header_inspection_results.md), [patterns](../6x04/threat_intel/healthcare_social_engineering_patterns.md), [ranges](../6x04/threat_intel/lure_effectiveness_benchmarks.md).
- [Template constraints](../6x04/templates/phishing_template_constraints.md), [clinical constraints](../6x04/campaign_design/clinical_schedule_constraints.md), [ethics](../6x04/campaign_design/simulation_ethics_guidelines.md).
