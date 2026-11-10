# MedDefense SOC Automation Strategy

**Version:** 1.0 | **Date:** 2026-11-10 | **Owner:** SOC Lead; approval pending

## Current state analysis

`soc_volume_baseline.md` gives 120–180 total alerts/day; use 150 for planning.
At eight minutes each, that is **20 analyst-hours/day**: 13.4 hours of enrichment
at 67% and 6.6 hours of other triage. Two analysts per shift does not establish
total daily staffing capacity. The incident example records 45 minutes spent on
one IP lookup while the attack continued; reducing that delay is the immediate
business objective, not a promise to prevent every lateral movement.

Task 6 calls all 150 alerts phishing alerts, conflicting with the baseline and
the candidate seed's 90 phishing-enrichment alerts/day. Use 90 phishing, 12
credential, and a planning remainder of 48 other/unclassified alerts for the
source-based scenario; the remainder is arithmetic, not an observed type count.
Show the required 150-phishing scenario separately as a ceiling illustration.
Do not combine these numbers with the README's different monthly effort examples.

## Automation candidates

Volumes and effort below come from `automation_candidate_matrix_seed.csv`.
They overlap and must not be summed as independent savings. Risk ratings describe
the possible consequence of incorrect classification; they are not measured rates.

| Priority / process | Daily volume | Manual effort | Complexity | FP risk | Recommended type | Gate before action automation |
| --- | --- | --- | --- | --- | --- | --- |
| 1: Phishing IOC lookup | 90 | 5 min/item | Low | Low | enrich-only | Source freshness, error-to-review handling, and audited results. |
| 2: Case preparation | 60 | 2 min/item | Low | Low | enrich-and-triage | Cross-alert deduplication, idempotent writes, and ownership before live tickets. |
| 3: Credential enrichment | 12 | 8 min/item | Medium | Medium | enrich-and-triage | Current privilege context; conditional escalation only in Phase 3. |
| 4: Benign phishing closure | 35 | 3 min/item | Medium | Medium | enrich-and-act, after approval | Measured false-negative rate <2%, plus closure review and rollback. |
| 5: Isolation recommendation | 4 | 10 min/item | High | High | enrich-and-triage; human action | <1% response false positives, clinical review, exceptions, and analyst authorization. |
| 6: Mailbox quarantine | 15 | 6 min/item | High | High | enrich-and-act only after separate approval | <1% false positives; protected clinical senders, reversible action and gateway controls. |

Privileged account disablement remains human-only: the seed lists one event/day,
15 minutes, and a <0.1% false-positive gate. No autonomous blocking, quarantine,
isolation, or account changes are approved in this three-phase rollout.

## Expected efficiency gains

Use `(volume × manual_effort × automation_rate) / 60` for daily hours saved.
Here automation_rate=0.67 assumes **all enrichment time is removed**, with decisions
still human; it is a gross ceiling, not an observed 67% end-to-end automation rate.

| Scenario | Calculation | Gross daily saving | 30-day saving |
| --- | --- | --- | --- |
| Source-based phishing scenario | 90 × 8 × 0.67 / 60 | 8.04 h | 241.2 h |
| Required 150-phishing illustration | 150 × 8 × 0.67 / 60 | 13.4 h | 402 h |
| Conservative planning assumption: remove half of enrichment at volume 90 | 90 × 8 × 0.335 / 60 | 4.02 h | 120.6 h |

Thirty calendar days assumes continuous hospital operation. Applying the overall
67% enrichment share to phishing is an assumption. Confidence is **low**: the five
local fixtures matched expectations, but they establish neither net labor savings
nor production accuracy. Measure analyst handling time before and during the pilot.
Rework, slow DNS, stale evidence, duplicate tickets, supervision, and maintenance
reduce savings; different volume or workflow mix invalidates the projection.
No salary rate or implementation cost is supplied, so no cash ROI is claimed.

## Risks of over-automation

1. **A trusted sender hides a multi-phase attack.** Auto-closing an internal/allowlisted alert could
   conceal credential theft and later movement toward patient records. Require behavior correlation,
   protected high-risk detections, and review of would-be closures; feed ALLOW alone cannot
   authorize closure.
2. **Isolation interrupts clinical work.** A false isolation recommendation acted on blindly could
   disconnect a workstation used for urgent results. Keep human authorization, clinical
   consultation, device exceptions, and a tested reversal path; the lab writes a queue only.
3. **Account action removes emergency access.** Disabling an overprivileged integration or support
   account could interrupt records or recovery. Keep disablement human-only, verify dependencies
   with the service owner, and record emergency access and rollback decisions.

Define false-positive rate as FP/(FP+TN) in independently adjudicated benign events,
and false-negative rate as FN/(TP+FN) in adjudicated malicious events. Also monitor
malicious events among proposed closures. Production auto-close needs the seed's
<2% false-negative gate and a proposed <5% false-positive gate, sufficient labeled
samples, documented uncertainty, and at least 30 days of observation. Five fixtures
cannot supply those denominators. An insufficient malicious sample blocks approval.
A missed serious incident stops closure immediately, regardless of the aggregate.

## Implementation roadmap

| Phase | 90-day scope and deliverables | Success criteria and exit gate |
| --- | --- | --- |
| 1: Days 1–90, enrichment only | Read-only staging input; no production cases, closures, escalations, or response. Measure latency and analyst time; add freshness checks, a version-keyed TTL cache, deduplication, and audit monitoring. Run the lab playbooks only on disconnected copies. | At least 30 days of independent labels; documented error denominators and uncertainty; freshness/error paths tested. Before Phase 2, meet closure gates, obtain SOC owner and clinical approval, and test override, reopening, exceptions, and change rollback. |
| 2: Days 91–180, confirmed-benign auto-close | Approved adapter creates/updates cases idempotently and closes only explicitly approved benign patterns. Keep other routing manual; retain evidence and sample closures for review. | No unhandled evidence gaps; closure sampling, rapid reopening, audit completeness, and error thresholds remain acceptable. Any gate breach returns to manual review. |
| 3: Days 181–270, conditional escalation | Add approved priority/escalation rules and verified on-call delivery, with durable outbox/retry and queue reconciliation. | Match labeled routing outcomes, monitor delivery and workload, and rehearse overrides. Isolation, quarantine, account action, and firewall changes still require humans. |

These are proposed 90-day windows, not deployed capabilities. The required sequence
limits production consequences while evidence accumulates. Lab auto-close and
escalation demonstrate logic but are not permission to skip Phase 1. Correlate exact
replays by source/event ID; attach related events to a case using a reviewed entity,
rule, and time window without discarding new indicators or greater severity.

TTL stores must include normalized IOC, source version, observation and expiry.
Choose and measure a bounded TTL during Phase 1; invalidate on feed updates and do
not cache lookup failure as ALLOW. Optional external APIs would additionally need
rate-limit handling, backoff, privacy review, and credentials; none are used here.
