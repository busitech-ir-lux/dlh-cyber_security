# Insider Threat Awareness Program: MedDefense

**Owner:** Awareness Lead with SOC, HR and Legal  
**Status:** Draft; manager guide requires HR/Legal review before distribution; anonymous channel requires Legal review and tested triage before launch

## 1. Observable Indicator Framework

An indicator calls for proportionate triage, not a conclusion about intent. Compromised credentials, mistakes and legitimate work can produce the same signals. The following proposed indicators operationalize supplied cases and constraints. Do not infer risk from personality, health, protected characteristics, employment disagreement or lawful workplace communication.

| Category | Specific observable indicator | Positioned observer |
| --- | --- | --- |
| Access | Dormant privileged account resumes use outside its documented function | SOC, IT |
| Access | Service account is used for interactive sign-in | SOC, IT |
| Access | Transferred employee retains prior Server Admins membership | IT, HR, manager |
| Access | Contractor account remains enabled after recorded end date | Manager, HR, IT |
| Access | Administrative user accesses patient records inconsistent with assigned work | SOC/EHR audit reviewer; manager provides context |
| Behavioral | A vendor repeatedly asks helpdesk to bypass approval for Domain Admin | IT, coworker |
| Behavioral | A colleague asks another employee for a password/MFA code | Coworker, manager |
| Behavioral | A caller asks for remote support without a ticket | IT, clinical coworker |
| Behavioral | A staff member repeats an observed attempt to bypass access approval after being directed to the process | Manager, IT |
| Behavioral | A person begins an administrative task from personal email/device outside approved sessions | IT; coworker if directly observed |
| Contextual | A role transfer is recorded without an accompanying access-review task | HR, manager, IT |
| Contextual | A project closes while its migration-era admin account remains enabled | IT, project manager |
| Contextual | A vendor support request has no documented owner, scope or expiry | IT, manager |
| Contextual | Privileged account activity has no matching approved change/IR context | SOC, IT |
| Contextual | A service account has no documented business function or accountable owner during review | IT, manager |

Contextual signals explain why access might be inappropriate; they do not profile a person. Simulation confusion/distress is a support need, not an insider-risk indicator.

## 2. Technical Monitoring Framework

These five source-backed analytic specifications map to the supplied reference for the Module 3 pipeline. Actual Module 3 configuration, field normalization and rule IDs are absent; SOC must validate ingestion, account classification, baselines and test events before claiming coverage. Thresholds below reproduce the reference unless marked proposed.

| Indicator | Log source and detection logic | IAM/incident cross-reference | Triage and benign explanation |
| --- | --- | --- | --- |
| Dormant privileged activation | Windows Security 4624 joined to IAM privileged-account inventory; last expected activity >90 days before successful logon | IAM-001 svc_epic_int, IAM-002 svc_helpdesk, IAM-004 admin.legacy | Check approved change/IR and service owner; recovery work may be legitimate |
| Interactive service account | Windows Security 4624 LogonType 2 or 10 and account name starts svc_; validate against authoritative service inventory | IAM-002, IAM-006 svc_backup and overprivileged automation | Confirm expected automation type; interactive troubleshooting still requires approval |
| Privileged membership change | Windows Security 4728/4732/4756 adding user to Domain Admins or Server Admins, matched by group identity/SID | IAM-005 j.yamamoto transfer; IAM-003 t.morrison and IAM-007 b.carter review context | Check ticket, approver, owner, scope and expiry; not every membership event is abuse |
| Suspicious LSASS access | Sysmon Event 10 targeting LSASS from suspicious source process; SOC validates approved tooling and process context before escalation | Cobalt Strike credential-access path | Check executable, signer, source host and approved security tooling; preserve evidence via incident process |
| Role-inconsistent patient access | EHR audit logs joined to assignment/unit/role; flag records outside established role/unit pattern | Insider case D; not a specific named IAM finding | Verify treatment/payment/operations need privately; cross-unit cover may justify access |

Proposed pipeline workflow: normalize account/host/time → enrich from IAM and approved-change context → correlate related events → create restricted SOC case → validate technical evidence → bring HR/Legal in at threshold. No numeric EHR volume threshold is supplied; tune on authorized workflows rather than inventing a deployed number. Do not publish sensitive patient details in training or manager reports.

## 3. Reporting and Triage

Immediate access, patient-record or privileged misuse concern: ext. 4-SECURITY. Non-urgent observable concern: security@meddefense.org. Personnel-sensitive workplace issue: HR hotline from the verified staff directory; no number is supplied. Managers may pass operational facts to Security/HR without confronting the subject.

Anonymous reporting is a **proposed web form**, not an existing URL. Before launch, Legal approves the channel/privacy notice and HR/SOC test the following procedure, restricted access, secure case acknowledgment and ownership. The notice must explain anonymity limits: do not request identifying fields or promise technical anonymity that the platform cannot provide; Legal must validate metadata handling. Until ready, do not advertise an invented link.

1. Intake records date, channel, observable facts, affected system and urgency. Reporter identity is optional; avoid collecting patient content. Offer an anonymous case token for follow-up if supported and approved.
2. SOC screens immediate security/patient-safety risk promptly; route active compromise to incident response. Proposed service target: same-working-day urgency review, acknowledgment within two working days where a reply path exists.
3. Validate minimal technical evidence and business context with authorized owners. Record missing facts and alternative explanations; do not open an intrusive employee investigation solely on anonymous accusation.
4. Include HR for employee conduct, manager action or coaching. Escalate to **HR and Legal** if technical evidence supports a policy violation, a pattern repeats after coaching, privileged or patient-record misuse is suspected, retaliation is reported or the manager is the subject. Route around a subject manager.
5. HR/Legal authorize investigation scope and minimum disclosure. Preserve relevant logs under approved evidence procedures; no personal-device searches by managers. Separate simulation data from real-incident evidence.
6. Record outcome: substantiated, benign, insufficient evidence or referred; document rationale and corrective process/access changes. Acknowledge good-faith reporting without disclosing personnel details. Offer support and review retaliation concerns.

**Non-retaliation:** MedDefense prohibits retaliation against anyone raising a good-faith security or safety concern. Report retaliation privately to HR; HR and Legal review and enforce the prohibition through the established personnel process. The supplied material does not name a policy number or sanctions, so none are invented. HR/Legal must link the approved policy before publication. A mistaken good-faith report is not a basis for retaliation.

Individual simulation data expires at 18 months unless an active HR-reviewed coaching process needs it. Investigation case retention is a separate Legal-approved schedule; no duration is supplied. Define that schedule and access list before anonymous-channel launch.

## 4. Manager Quick Reference

**[MedDefense branding placeholder] · Version 1.0 · 2026-11-10 · HR/Legal approval pending**

Observe work context: role moves, contractor end dates, unusual access/privilege requests, repeated approval bypasses and access inconsistent with assigned duties. Tell IT promptly when roles/contracts change. Staff confusion or distress after training needs support, not suspicion.

Before escalation, document date/time, exact observed behavior, system/process, business context, witnesses if any and whether immediate safety risk exists. Separate direct observation from hearsay. Do not add motives, personality judgments or unnecessary patient details.

Escalate access/patient-record concerns, unusual vendor privileges, repeated process bypasses and retained access after transfer/end date to Security. Use ext. 4-SECURITY for immediate risk; otherwise security@meddefense.org. Refer personnel sensitivity or simulation distress privately to HR through the staff directory. Do not delay urgent reporting to handle it locally. If your own manager is involved, use Security or HR directly.

Do not confront a “suspected insider,” investigate personal devices, tell the team, speculate about motive or put simulation clicks in performance reviews. Managers receive aggregate simulation data only unless HR confirms two consecutive clicked waves **and** incomplete assigned microtraining, with disclosure solely for coaching. No simulation result supports discipline by itself.

Protect the reporter and subject. Good-faith reports are protected from retaliation; HR/Legal review retaliation concerns. Follow authorized case handling; do not create a parallel personnel file. This guide cannot be distributed before HR and Legal review.

## 5. Employee Culture and Ethics Statement

The following statement is 200 words; release only after the anonymous channel is approved and operational.

MedDefense protects patient care by helping people recognize and report unusual access, unsafe requests, and process failures. Our insider threat awareness program focuses on observable facts, including accounts used outside their documented purpose, unexplained access to patient records, and requests that bypass normal approval. A concern is a starting point for careful review, never proof that someone intended harm.

You do not need to investigate or confront anyone. Report concerns to Security at extension 4-SECURITY. Use security@meddefense.org for other security concerns, or the approved anonymous reporting channel when available. Personnel concerns can go directly to HR. Describe what happened, when, and which process was involved. Avoid speculation about motives, personality, or protected characteristics.

Security checks business context and technical evidence. HR and Legal join when employee conduct, privacy, or regulatory obligations require their involvement. Information is shared only with people who need it for authorized review. Managers must not search personal devices or discuss concerns with the team.

Good-faith reporting is protected from retaliation. HR and Legal review retaliation concerns. Simulation results are protected training information, never performance review material. This program supports safer decisions, fair treatment, and patient trust. Ask Security or HR whenever you need clarification or support.

## Sources

- [Privileged findings](../6x04/iam_context/privileged_account_findings.md), [IAM summary](../6x04/iam_context/iam_audit_summary_6x02.md).
- [Cases](../6x04/insider_threat/insider_threat_case_notes.md), [technical reference](../6x04/insider_threat/technical_indicators_reference.md), [triage model](../6x04/insider_threat/reporting_and_triage_model.md), [manager constraints](../6x04/insider_threat/manager_reference_constraints.md).
- [HR rules](../6x04/campaign_design/hr_privacy_rules.md), [ethics](../6x04/campaign_design/simulation_ethics_guidelines.md), [campaign plan](phishing_campaign_plan.md).
