# SOC Automation Brief for James Chen

**Date:** 2026-11-10 | **Status:** Tested local prototype; production approval pending

## What was built

- An enrichment engine checks indicators against the local intelligence feed and explains its score.
- A persistent case manager keeps findings, notes, linked indicators, and status together.
- A phishing playbook prioritizes suspicious mail and closes clearly benign simulated cases.
- A credential playbook checks account privilege and records isolation recommendations for human
  authorization.

## Integration test results

Alert 001, a known malicious sender, became a Critical escalated case.
Alert 002, an unknown external sender, became a High case for review.
Alert 003, an internal benign fixture, became a Low closed case.
Alert 007, malicious-source credential activity by an administrator account, became
Critical with a pending isolation recommendation.
Alert 009, internal activity by a standard user, became Medium for review without
isolation. All five matched expectations; this does not measure real-world errors
([test results](integration_test_results.md)).

## Efficiency estimate

The source-based 90-phishing-alert scenario could remove up to **241.2 analyst-hours
per 30-day month** if all enrichment time disappears. Removing half would save
120.6 hours. The task's separate 150-phishing illustration gives 402 hours as a
ceiling. Confidence is low: these are gross assumptions, without rework or support
costs, and the source baseline actually says 150 total alerts/day
([strategy](automation_strategy.md)).

## What the playbooks cannot do yet

1. They do not prevent duplicate cases across alerts or reuse results through a timed cache; stale
   feed and account snapshots are not rejected.
2. They do not deliver on-call notifications or perform mailbox, endpoint, account, or firewall
   actions; isolation is only a human queue.
3. They lack production closure gates, protected evidence storage, and reliable recovery from
   partial database/file writes.

## What James Chen needs to authorize

Authorize read-only staging input and assigned analyst time for a minimum 30-day
independent accuracy and workload review. Require clinical and security approval,
error-rate gates, exceptions, and tested reopening/rollback before production
closure. Assign Engineering to cost deduplication, caching, current identity data,
protected storage, and reliable delivery; no purchase budget can be justified
from the supplied cost data alone.

## Recommendation

Approve the enrichment-only pilot plan by **2026-11-17**, with accountable owners;
retain human decisions until the strategy's measured gates are met.
