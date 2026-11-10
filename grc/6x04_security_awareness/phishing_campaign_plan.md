# Phishing Simulation Campaign Plan: MedDefense

**Owner:** IT Security Awareness Lead  
**Status:** Proposed; launch only after documented approval  
**Planning population:** 1,610; reconciled eligible roster required

## 1. Overview and Launch Controls

Use a CISO-approved simulation platform with role-restricted telemetry, scheduled sends, approved training redirects, report-button integration and immediate microtraining. No vendor is supplied or selected. The proposed $28,000 license requires confirmation against the reconciled population. Objectives: ≤35% clicks, ≥35% reports and ≤25-minute mean reporting delay at day 90; ≤12%, ≥65% and ≤10 minutes respectively at 18 months.

The Awareness Lead owns the approval register and roster. HR reviews privacy and support exclusions; Clinical Operations or the relevant business owner reviews timing; Communications checks readability; Legal reviews high-risk content and escalation procedures (recorded vishing additionally requires Legal). CISO approves templates and launch. SOC Manager reviews reporting workflow and aggregate results. CISO/board receive aggregates; only the program manager sees individual click data.

Before day 1, the Lead must record: approved platform and telemetry test, dated CISO/HR approvals, business-owner clearances, resolved roster totals, approved sender identities, actual MFA/benefits dates, current blackout calendar, Outlook report-button instructions and HR support route. Test click/report deduplication, mail-scanner filtering, training redirect, acknowledgment within 60 seconds, access restrictions and deletion settings using test accounts. Failure of any gate blocks sending, not preparation.

Employees receive a plain-language notice before launch: simulations occur without announcing exact dates; clicking triggers protected training; reporting after clicking helps; no performance-review use; support is available privately through HR or Security. No secret collection, open tracking pixels or personal-device monitoring. Open data is optional only if separately approved and reliable; it is not a required outcome metric.

## 2. Segments and Assignment

Estimates come from `role_inventory.csv` and `employee_segments.csv`, not department row counts. HR must deduplicate remote workers into their home segment; remote work is an overlay, not a seventh population.

| Segment | Estimated staff | Primary vectors and assigned activity | Additional exclusions |
| --- | ---: | --- | --- |
| SEG-A Clinical leadership | 115 | Vendor/support and clinical phone escalation; V-02 and V-01 tabletop, baseline before advanced | Accreditation rounding and active safety events |
| SEG-B General clinical | 860 | Epic/EHR, patient messages, workstation risks; T-EPIC-01 baseline | ICU/OR critical coverage; ED only cleared limited sample; no shortages |
| SEG-C Administration/billing | 420 | MFA, HR and document requests; T-MFA-02 then T-HR-03 | Payroll close and finance-adjacent close work; HR approval for benefits |
| SEG-D IT/security | 105 | Vendor requests and privilege misuse; V-02 tabletop and IT guide | Active incident responders and unsafe change windows |
| SEG-E Finance/procurement | 75 | Benefits then BEC/payment requests; T-HR-03 then T-BEC-04 | Month-end close, audit submission/deadlines |
| SEG-F Executives/assistants | 35 | BEC/confidential documents; verification practice then T-BEC-04 | Board meeting days; executive assistant clears schedule; results aggregate to CISO only |

All segments exclude leave, first employment week, active patient-safety events, IR assignments and HR-approved support plans. OR staff are not separately counted in supplied tables; roster validation must identify relevant coverage before any send. Managers see aggregates only; suppress groups under 10 and merge periods/groups when needed to prevent identification (proposed privacy control).

## 3. Four Waves in 90 Days

Proposed window: February–April after sign-off, with four send weeks starting on Tuesdays separated by 28 days. Day 1 means the first approved Tuesday in February; waves begin days 1, 29, 57 and 85. Wave 4 completes by day 87; day 90 captures 72-hour training results. A blackout shifts launch or defers the affected cohort; do not compress cooldown to preserve a deadline.

| Wave | Days | Segments and tier | Delivery and rationale |
| --- | --- | --- | --- |
| 1 | 1–3 | B: T-EPIC-01 baseline; C: T-MFA-02 baseline; A/D: baseline tabletop orientation, no email lure | Tue–Thu B 07:15–08:30 cleared floor staff; C 09:00–11:00. Introduce observable cues and reporting under normal workflows |
| 2 | 29–31 | B: T-EPIC-01 comparable baseline; C/E: T-HR-03 intermediate after HR-path primer | B same cleared window; C 09:00–11:00, E 10:00–14:00 Tue–Thu. HR confirms plausible enrollment timing; otherwise defer HR template, not invent a deadline |
| 3 | 57–59 | B: T-EPIC-01 baseline; C: T-MFA-02 baseline; A/D: facilitated V-02 practice | Tue–Thu approved B/C windows; tabletop scheduled with unit/IT leads. Maintain comparison while practicing phone verification separately |
| 4 | 85–87 | E/F: T-BEC-04 advanced; C: T-HR-03 intermediate; B: T-EPIC-01 baseline | E Tue–Thu 10:00–14:00; F assistant-cleared 10:00–14:00; B/C as above. E/F receive independent-verification practice at least 21 days earlier |

Four waves are program-wide events, not a claim that every employee receives four emails. No unrequested fifth template is invented for A/D; their phone exercises have separate denominators. Use one message per eligible recipient per wave; a late recipient must still have ≥21 days from their last exposure. The Lead checks last-exposure timestamps before upload and records excluded/deferred counts. Clinical Operations may select a smaller safe cohort; record cohort size and sampling method. Never infer full-workforce performance from a small convenience sample.

The supplied annual calendar is suggested; its wave numbering differs. This four-wave initial design follows the explicit task requirement. Later campaigns are refresh waves, not retroactive changes to the first 90 days.

## 4. Metrics Dictionary

All percentages use unique eligible humans, exclude test accounts, bounces and verified automated scanner events, and retain numerator/denominator. A confirmed human click counts once per recipient/wave; repeat clicks within one email do not constitute repeated failure. Finalize click/report windows seven days after each delivery; day-90 wave-4 totals are provisional until that window closes. Report after-click events count in both metrics. Deduplicate Outlook and SOC intake reports. The following targets are proposed operating commitments except where supplied benchmarks/CSV anchor them.

| Metric and formula | Interval | 90-day target | 18-month target | Deterioration means |
| --- | --- | --- | --- | --- |
| Click rate = human clickers / delivered recipients ×100 | Each wave, monthly, quarterly | ≤35%; clinical ≤40% | ≤12% overall; clinical ≤12% (proposed) | Inspect lure mix, shift load and recognition cues before changing content |
| Report rate = recipients reporting assigned lure / delivered recipients ×100 | Wave and quarterly | ≥35% | ≥65% | Check report-button availability, trust and acknowledgment |
| Repeat clicker rate = people clicking both current and immediately prior program email wave / people delivered both waves ×100 | Eligible wave pairs; quarterly pool of pair observations | Establish baseline; <12% operating ceiling | ≤4% | Offer private coaching; assess training access; never infer malice |
| Mean time to report = sum(first report time − delivery time) / recipients reporting | Wave and quarterly; minutes | ≤25 min | ≤10 min | Rehearse rapid reporting; check SOC routing. Also show median, 90th percentile and reporting coverage |
| Training completion = clickers completing assigned module within 72 h / clickers assigned module ×100 | Per assignment, wave and quarterly | ≥95% (stricter than CSV 90%) | ≥95% (proposed maintenance) | Fix scheduling/accessibility and reminders before escalating |
| False-positive report rate = unique legitimate messages reported / unique legitimate messages delivered ×100 | Monthly and quarterly | Establish baseline | ≤baseline +0.5 percentage points AND within approved SOC capacity (proposed) | Check confusing business mail and triage workload; do not discourage good-faith reports |

A legitimate message means one adjudicated benign by SOC; exclude simulations and confirmed attacks from that metric. Also report legitimate reports / all adjudicated non-simulation reports and analyst hours, because mail-volume denominators can hide workload. SOC approves a weekly analyst-hour capacity before launch; no numeric capacity is evidenced. No reports means reporting latency is N/A, not zero. No matched wave pair means repeat rate N/A. Show 95% Wilson intervals for proportions and cohort counts; avoid treating tiny segment changes as proof of improvement.

Supplemental board metrics: finance BEC verification = finance recipients independently verifying before action / delivered BEC recipients; vishing success = assessed participants completing full verification pass / assessed participants; manager confidence = mean fixed survey score on a 1–5 scale. Establish day-90 baselines. The annual plan sets later milestones. Verification must be observed through approved facilitator/verification logs, not inferred from silence or absence of a click.

## 5. Escalation and Support

First click: automatic immediate module; private reminder at 48 hours if unfinished. After 72 hours, the manager of the awareness program checks access, leave and workload privately. Individual event remains with the program manager.

Two consecutive clicked waves: program manager offers private additional practice. **Only if assigned microtraining is also incomplete** does the program manager refer the documented pattern to HR for threshold review. HR verifies the two wave events, training availability and incompletion, exclusions, welfare needs and coaching purpose. Only HR-confirmed escalation permits the minimum individual information to the department manager for coaching. Two clicks with completed training do not authorize manager disclosure. No click history goes into performance reviews, compensation or discipline.

Simulation failure alone is not evidence of insider threat. A separate real-world indicator (such as unapproved privileged access, suspected patient-record misuse or actual credential compromise) is handled through SOC incident triage, with HR/Legal where conduct/privacy warrants it. Never use simulation scoring to manufacture misconduct evidence.

Distress: stop contact, offer private HR support through the verified HR directory and ext. 4-SECURITY, and suspend the person's participation pending HR review. Clinical Operations can halt unsafe clinical delivery immediately; Lead/SOC Manager can halt sends for a real incident; HR can halt for welfare; CISO authorizes restart after the relevant owner clears the cause. Record reasons without unnecessary health details.

## 6. Data and Closure

Program manager has individual clicks; manager and SOC metrics have individual report events; HR gets repeat status only after the documented threshold. Restrict platform roles accordingly, including exports. Board/CISO and department summaries are aggregate. Retain individual data 18 months, then delete or aggregate unless needed in active HR-reviewed coaching. Log deletion and approved exceptions.

After each wave, the Lead validates scanner exclusions, delivery counts, 72-hour completions, employee concerns and operational impact with HR/SOC/business owners. Weekly operations review and quarterly CISO metrics review govern adjustments. No leaderboard, public naming, real passwords, real transfers, trauma themes or automatic discipline.

## Sources

- [Threat profile](social_engineering_threat_profile.md).
- [Role inventory](../6x04/iam_context/role_inventory.csv), [segments](../6x04/iam_context/employee_segments.csv), [IAM summary](../6x04/iam_context/iam_audit_summary_6x02.md), [department breakdown](../6x04/campaign_design/workforce_population_breakdown.csv).
- [HR privacy](../6x04/campaign_design/hr_privacy_rules.md), [clinical constraints](../6x04/campaign_design/clinical_schedule_constraints.md), [ethics](../6x04/campaign_design/simulation_ethics_guidelines.md).
- [Metrics baseline](../6x04/program_governance/metrics_baseline.csv), [benchmarks](../6x04/threat_intel/lure_effectiveness_benchmarks.md), [governance](../6x04/program_governance/program_governance_roles.md).
