# Security Awareness & Human Defense: Task Responses

Prepared: 2026-11-10. Status: proposed program for review; no approvals, deployments or results are asserted.

| Task | Response |
| --- | --- |
| 0 | [Quiz study notes](00_quiz_notes.md) |
| 1 | [Threat profile](social_engineering_threat_profile.md) |
| 2 | [Campaign plan](phishing_campaign_plan.md) |
| 3 | [Email templates](phishing_templates.md) |
| 4 | [Post-click intervention](post_click_intervention.md) |
| 5 | [Clinical](guidance_clinical_staff.md), [IT](guidance_it_staff.md), [executives](guidance_executives.md), [remote workers](guidance_remote_workers.md) |
| 6 | [Vishing scripts](vishing_scenarios.md) |
| 7 | [Insider threat program](insider_threat_program.md) |
| 8 | [Annual plan](awareness_program_plan.md) |
| 9 | [Effectiveness brief and dashboard](program_effectiveness_brief.md) |

## Evidence and interpretation rules

Answers use the supplied [README](../README.md), [task instructions](../tasks.md) and local [6x04 materials](../6x04/). Source lists in each answer identify exact artifacts. Public links in the README are optional conceptual references; no external claims or independently verified industry statistics are added here. Numbers described as benchmarks are supplied course planning ranges, not independently validated research findings. Proposed operational choices and targets are identified as such.

The task 0 file contains a kickoff briefing but no actual quiz questions. Notes support study without inventing a quiz or an answer key.

## Material differences and implementation gates

- `role_inventory.csv` and `employee_segments.csv` agree on six segment estimates totaling **1,610**. `workforce_population_breakdown.csv` lists **1,311** staff. Its SEG-A/B/C/D/E/F subtotals are 34/689/391/87/75/35; gaps against segment estimates are 81/171/29/18/0/0. Do not invent the missing departments. Use 1,610 for provisional scope; HR reconciles a unique eligible roster before licensing or sends. The README's illustrative 1,200 is not the segment total.
- `metrics_baseline.csv` sets 90-day post-click completion at 90%; `lure_effectiveness_benchmarks.md` asks for 95% within 72 hours. Adopt the stricter **95% within 72 hours** operating target and disclose both in reports. The CSV is otherwise the milestone anchor.
- The 18-month click target is ≤12% in `lure_effectiveness_benchmarks.md`; the 36-month CSV target is also 12%. Retain that later ceiling rather than inventing further reduction. Report target rises from ≥65% at 18 months to ≥70% at 36 months.
- The task 1 example's 45–62% EHR range differs from the material's 40–62%; use the material. Template expectations use material category ranges, not promises.
- The kickoff's 07:14 email and “beacon before first patient” are scenario narration. `campaign_reconstruction.md` gives 06:58 delivery and 07:07 first click. `module5_incident_summary.md` gives 4 h 33 min from first click to first SOC correlation; README detection “within four minutes” has a different/unspecified start point. Keep these separate; do not synthesize a forensic timeline.
- Actual incident cost, platform vendor, approved sender identities, CFO name, MFA rollout dates, accreditation dates, anonymous-form URL, HR hotline number and exact Outlook button placement are absent. Approval registers must resolve these before operation. Placeholder sender addresses use reserved `.invalid` domains; they are display specifications, not sending infrastructure.
- Budget material supplies an $84,000 estimate but no wage rates, external benchmark quote or program management allocation. The annual plan shows these gaps and explicit opportunity-cost assumptions separately.
- Module 3 pipeline configurations are not supplied. The insider framework uses `technical_indicators_reference.md` as the supplied mapping and requires pipeline validation; it does not claim deployed rules.

## Use and privacy

All dates, windows, thresholds and procedures introduced by these answers are proposed design choices. The annual plan uses February–January after a future approval cycle because this document is prepared in November 2026 and new clinical waves are prohibited November–January. It does not backdate approvals to the task's Q3 2026 board scenario.

Only the awareness program manager sees individual clicks. Managers receive aggregates unless all four HR conditions are met: two consecutive clicked waves, incomplete assigned microtraining, HR confirmation and coaching purpose. Results never enter performance reviews. Individual data expires after 18 months unless an active HR-reviewed coaching process requires it.
