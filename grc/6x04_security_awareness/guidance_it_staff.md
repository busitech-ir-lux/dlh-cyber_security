# Security Quick Reference: IT Staff

[MedDefense branding placeholder]  
Version 1.0 · 2026-11-10 · Draft for approval

## Your Biggest Threats

- Privilege creep: a vendor requests broad admin rights without a scoped ticket or expiry. Watch for “temporary” access without an owner.
- Dormant automation: a service account logs on interactively or outside its function. Watch for svc_ logons, unexplained server access or LSASS alerts.
- Incomplete transfer/offboarding: former staff or moved employees retain admin groups. Watch for contractor end dates or role changes absent from access review.

## What to Do Right Now

- Review owners, purpose, last expected use and privileges of svc_epic_int, svc_helpdesk and svc_backup through approved IAM tickets; scope automation credentials.
- Validate removal/review of admin.legacy, t.morrison, j.yamamoto and b.carter access findings; close migration accounts through change control, with service-impact checks.
- Use managed devices and tracked privileged sessions; require independent verification, approved tickets and expiry for vendor access, and report unexplained privilege events to SOC.

## When Something Looks Wrong

Report it to Security: select the suspicious email in Outlook and use the phishing report button; for a call, access concern or unavailable button, call **ext. 4-SECURITY**. Report even after clicking. You do not need to prove an attack.

## What Not to Do

- Do not run admin actions from personal email, personal devices or untracked sessions.
- Do not leave ownerless or dormant service accounts privileged because a project once needed them.
- Do not dismiss interactive service-account use or reset access without a documented verification path.

## Contact

Security: **ext. 4-SECURITY · security@meddefense.org**. Outlook: select the message, then choose the organization's phishing report button. Exact label and ribbon/menu location must be confirmed by IT and inserted before publication; the supplied material does not specify them.

<!-- Source basis: ../6x04/threat_intel/healthcare_social_engineering_patterns.md;
../6x04/incident_context/security_awareness_gap_notes.md;
../6x04/iam_context/privileged_account_findings.md;
../6x04/iam_context/iam_audit_summary_6x02.md;
../6x04/templates/role_based_guidance_style_guide.md;
../6x04/campaign_design/workforce_population_breakdown.csv;
../6x04/campaign_design/clinical_schedule_constraints.md.
Actions are proposed guidance, not assertions that the controls are deployed. -->
