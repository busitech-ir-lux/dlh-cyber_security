# Social Engineering Threat Profile: MedDefense Health Systems

**Prepared by:** Security awareness program design (student response)  
**Date:** 2026-11-10  
**Distribution:** Security Team, CISO; HR receives Section 5 only  
**Status:** Proposed; CISO approval pending

## 1. Target Analysis

The following is a **planning priority order**, not a measured sector targeting-frequency ranking. Supplied patterns identify targets but provide no sector counts. Incident deliveries support clinical priority (20/41 across floor staff and supervisors), then administration/billing (8/41), then finance/executives (9/41 combined, but only 5 finance). Administration versus the combined finance/executive group cannot be ranked by frequency from those counts. No named threat actor attribution is supplied.

| Priority population | Role conditions and observed behavior | Likely access objective | Exploitable timing |
| --- | --- | --- | --- |
| 1. Clinical floor staff and supervisors | Epic access supports charting, orders and medication records; handoff and mobile use reduce scrutiny. Floor staff clicked 10/15; supervisors 3/5 | Epic credentials, ePHI access and a foothold for follow-on movement | Shift-start/handoff; approved floor delivery 07:15–08:30 or 19:15–20:30; no ICU/OR critical coverage or active safety events |
| 2. Administrative/billing staff | Expected compliance tasks reward quick completion; 5/8 clicked and 2/8 reported | Billing portal, HRIS, email and sensitive document access | Tuesday–Thursday 09:00–11:00 for safe simulation; attackers exploit compliance deadlines and payroll workflows |
| 3. Finance, procurement and executive offices | Reluctance to challenge authority; finance may reply or consider offline actions despite fewer clicks (2/5 finance clicked) | ERP/payment approval, banking-change fraud, confidential board/contract documents | Payment runs, deadlines and executive availability; header evidence notes late Friday morning lures. Simulations instead avoid close, audit deadlines and board days |

IT is a separate high-impact audience: vendor/change-window lures can lead to privileged follow-on action even though only 1/4 incident recipients clicked. It is not presented as a measured top-three sector target.

## 2. Attack Vector Inventory

The source set documents principally email and telephone channels. These four distinct operational patterns are **not four independently evidenced delivery media**; inventing SMS or social-network campaigns would exceed the evidence.

| Vector and delivery | Documented lure example | Attacker objective and likely MedDefense asset |
| --- | --- | --- |
| EHR impersonation by email and linked workflow | Epic verification/access hold or secure clinical message; MSG-001 and MSG-004 were clicked | Capture identity/session access; Epic and downstream ePHI; subsequent endpoint foothold is a documented incident path, not an automatic result of every click |
| IT compliance impersonation by email | “Open compliance task” for MFA enrollment; MSG-002 was reported | Capture access through a trusted-looking administrative task; billing portal, remote access and email |
| Vendor support impersonation by phone or support-themed email | Emergency Epic patch/support callback; MSG-005 vendor patch email was reported late | Gain remote access or excessive privilege; Epic-connected endpoints, support tooling and IAM |
| Executive/BEC impersonation by email or phone | CFO document/payment request; MSG-003 opened only; reply-to mismatch observed | Induce payment authorization or sensitive-document release; ERP, payment workflow and board documents |

The kit's familiar portal appearance, prefilled identity and mobile rendering reduce hesitation. Reproduce decision pressure in training, never the credential-harvesting mechanism.

## 3. Lure Effectiveness Analysis

These are supplied planning ranges, not MedDefense measured simulation outcomes. Ranking follows `lure_effectiveness_benchmarks.md` exactly; BEC ranks sixth by clicks but remains high consequence.

| Rank | Lure category | Mechanism | Healthcare relevance | Expected clicks |
| --- | --- | --- | --- | --- |
| 1 | EHR account suspension | Authority + urgency | Losing chart access threatens ability to deliver care | 40–62% |
| 2 | Secure patient message | Familiarity + urgency | Patient-context notifications are routine | 34–50% |
| 3 | MFA/compliance enrollment | Familiarity + authority | Expected IT tasks and remote-access changes | 25–42% |
| 4 | HR benefits deadline | Scarcity + urgency | Personal financial consequences encourage fast action | 22–38% |
| 5 | Vendor emergency support | Authority + urgency | Vendor dependency during clinical equipment/application issues | 18–35% |

Executive/BEC's supplied 8–22% range measures clicks, not payment willingness. Compare like templates over time; raw overall reductions can result from easier lures or a different recipient mix.

## 4. Detection and Disruption Opportunities

| Vector | Decision point and cue | Safe action | Practical obstacle |
| --- | --- | --- | --- |
| EHR email | Before opening verification link: external sender and unexpected access deadline; later, familiar login appearance is insufficient proof | Open Epic through the known route; verify via known IT contact; report even after clicking | Shift pressure, mobile sender truncation and fear of blocked patient access |
| MFA email | Before completing enrollment: unexpected link and compliance instruction from an unsuitable domain | Open the known portal independently and confirm through known IT channel | Staff expect genuine rollout tasks; familiarity disguises the unusual request |
| Vendor contact | Before remote access or privilege approval: no approved ticket, scope or verified callback | End the call and use approved vendor contact list; confirm ticket with IT; report | Equipment problems create pressure to restore care quickly |
| Executive/BEC | Before sending documents or authorizing payment: unusual channel, reply-to mismatch or bypass of normal approval | Independent directory callback and normal approval process; report | Apparent confidentiality and executive authority discourage challenge |

Display names and SPF/DKIM success do not establish organizational legitimacy. Employees need a usable reporting route rather than raw-header analysis. The incident review records 23/41 clicks, 6/41 reports and 74-minute mean reporting time; confirmed credential exposure occurred, but ePHI exfiltration was not confirmed.

## 5. Simulation Design Requirements

1. Use Epic, MFA, benefits and finance workflow language with one teachable signal per template; mobile layouts must expose the sender cue. Use only approved placeholders and training landing pages; never ask for credentials or collect patient information.
2. Send T-EPIC-01 only to approved SEG-B floor cohorts Tuesday–Thursday 07:15–08:30 after clinical clearance. Exclude ICU/OR critical windows, staffing shortages, active codes/downtime/IR, accreditation and November–January. Do not copy the attacker's unsafe timing.
3. Start SEG-B/C with baseline lures. Introduce HR intermediate and BEC advanced only after relevant verification training. Keep comparable template/segment results alongside pooled metrics.
4. Use an authorized CFO identity placeholder until approved; include independent callback opportunities in BEC/vishing. No supplied CFO name or rollout date may be invented. No real transfer, remote-access session or secret disclosure is allowed.
5. Keep at least 21 days between exposures to the same population; attach immediate five-minute instruction to each click and acknowledgment within 60 seconds of a report. Protect individual data and implement the complete HR coaching threshold in the campaign plan.

## Sources

- [Kit analysis](../6x04/threat_intel/phishing_kit_analysis_summary.md), [headers](../6x04/threat_intel/email_header_inspection_results.md), [campaign reconstruction](../6x04/threat_intel/campaign_reconstruction.md).
- [Healthcare patterns](../6x04/threat_intel/healthcare_social_engineering_patterns.md), [lure benchmarks](../6x04/threat_intel/lure_effectiveness_benchmarks.md).
- [Incident summary](../6x04/incident_context/module5_incident_summary.md), [click review](../6x04/incident_context/post_incident_click_rate_review.md), [attack path](../6x04/incident_context/cobalt_strike_phishing_path.md).
- [Clinical constraints](../6x04/campaign_design/clinical_schedule_constraints.md).
