# Learning objectives: The SOC Playbook

These answers cover every objective in the README. The
[task index](README2.md) links the implementations, task explanations, source
copies, and actual test evidence. This is a locally executed prototype using the
supplied simulation materials, not a deployed SOC service or a claimed SSH-container
execution.

## Technical objectives

### Build an IOC enrichment module with classification and scoring

The [enrichment engine](tasks/enrich_ioc.py) separates identifying an input, reducing
it to a host, classifying its address, checking the local feed, and scoring the
result. This keeps the rules reusable: a CLI call and a playbook import use the
same `enrich_ioc` function instead of separate lookup logic.

An IPv4 address, IPv6 address, domain, or HTTP(S) URL is accepted. URLs are reduced
to their hostname, without downloading content or looking up its address. Explicit
checks distinguish documentation ranges from private addresses, which is important
because the fixtures deliberately use documentation addresses. Host normalization
also makes repeated URL, sender-domain, and sender-IP values comparable.

The required scoring rules produce these examples:

| Evidence | Score | Verdict |
| --- | --- | --- |
| 198.51.100.42 is listed with confidence 95 | 95 | BLOCK |
| 203.0.113.99 is listed with confidence 72 | 72 | INVESTIGATE |
| 192.168.1.100 is private | 0 | ALLOW |
| 8.8.8.8 is on the benign list | 0 | ALLOW |
| A valid unknown external domain has no match | 30 | INVESTIGATE |

BLOCK is a classification label, not a firewall command. Private and loopback
exemptions have an explanatory note. Malformed inputs and unusable feed data remain
reviewable rather than becoming clean results. Reverse DNS is best-effort context;
NXDOMAIN and TIMEOUT do not override a malicious feed match.

All ten supplied CSV rows matched expected type, class, score, and verdict in
[actual validation](tasks/evidence/enrichment_validation_results.json). The batch
result contains five BLOCK, two INVESTIGATE, and three ALLOW records. No external
reputation API or third-party Python package was required.

### Implement a normalized SQLite case manager

A normalized case store separates the main case from its many notes and linked
indicators. The [case manager](tasks/case_manager.py) uses the exact three-table
reference structure: `cases`, `case_notes`, and `case_iocs`. Foreign keys link the
children to a real case, and parameterized queries keep data separate from SQL.

The module initializes the local database on import, creates daily sequential case
IDs, adds notes, updates status, closes with a resolution, and returns nested case
data. A transaction inserts a case and all its IOC links together; an invalid IOC
rolls the insertion back rather than leaving an incomplete record. ID creation is
allocated under a SQLite write transaction, while the standalone ID helper only
returns a candidate and does not reserve it.

The canonical database contains five cases, including the benign closed case.
The CLI default listing shows actionable cases, while the Python `list_cases()`
function returns all summaries when no filter is supplied. Full case retrieval
includes notes and indicators. The regression suite compares table metadata with
the supplied SQL and tests status, note, closure, and rollback behavior.

This persistence survives separate process runs, but it does not provide production
access control, encryption, immutable logs, or cross-alert correlation. Those
limits remain explicit in [case_manager.md](tasks/case_manager.md).

### Build two executable playbooks with a full decision trail

The [phishing playbook](tasks/playbook_phishing_triage.py) extracts sender and URL
hosts, normalizes them, and enriches each unique host once. Any BLOCK escalates to
Critical; otherwise INVESTIGATE requires High review; a complete all-ALLOW simulated
alert closes Low. Missing evidence, malformed URLs, or failed enrichment prevent
uncertainty from silently turning into closure.

The [credential playbook](tasks/playbook_credential_exposure.py) adds privilege
context and technique descriptions. A known malicious source, or an uncertain
source with a Domain Admin, becomes Critical with a pending isolation recommendation.
An internal/ALLOW source with a Domain Admin still becomes High/escalated. An
internal standard user remains Medium for manual review, without isolation.

Both import the same enrichment and case modules. Cases retain indicator evidence,
reasoning, status, and notes; `playbook_audit.log` links every successful canonical
execution to its alert and case. The credential queue also references that case.
The scripts do not read fixture `expected` fields, isolate hosts, quarantine mail,
disable accounts, change firewall rules, or send notifications.

The technique dictionary names the four techniques in the supplied reference,
including T1003.001 LSASS Memory and T1550.002 Pass the Hash. A technique label
explains observed behavior; it does not by itself prove an incident or perform
credential extraction. See the [MITRE technique reference](https://attack.mitre.org/techniques/T1003/001/).

### Run and verify the five end-to-end scenarios

The [integration runner](tasks/run_integration_tests.py) starts in a fresh working
directory, copies unchanged fixtures, runs real CLI processes, and compares output,
case data, and queue state with `expected_outcomes.csv`. It refuses to reset an
existing evidence store. The [report](tasks/integration_test_results.md) preserves
exact stdout and complete retrieved case records, not copied example transcripts.

| Scenario | Actual matched outcome |
| --- | --- |
| Phishing 001: known malicious sender | Critical, escalated. |
| Phishing 002: unknown external sender | High, open for review. |
| Phishing 003: internal benign fixture | Low, closed with the required resolution. |
| Credential 007: C2 source and Domain Admin | Critical, escalated; one host recommendation pending authorization. |
| Credential 009: internal standard user | Medium, open; no isolation recommendation. |

All five passed. Nineteen separate regression tests also passed in isolated
workspaces, covering errors, all credential branches, schema behavior, and the
additional internal privileged alert 008. The first regression attempt had two
missing-reference setup errors; those outputs are retained and the corrected run
is documented. These are test results, not a measured production error rate.

## Conceptual objectives

### Separate enrichment from actions that require approval

Enrichment adds evidence; triage prepares a decision; response changes a working
system. A lookup error may waste time, while an incorrect isolation or account
action can interrupt clinical care. Automating a response therefore needs more
than a correct branch in code: it needs measured error rates, clinical review,
exceptions, recorded authorization, and a tested reversal path where possible.

The prototype's isolation file is a human-authorization queue only. Its phishing
closure changes a local simulated case, and the strategy explicitly prohibits
direct production use until approval gates exist. A private source is not proof
of safety, and an allowlisted sender can still be compromised. These distinctions
prevent an enrichment exemption from being mistaken for incident clearance.

### Explain why deduplication must precede ticket integration

Within-alert deduplication avoids repeated lookups. Alert 001 contains four IOC
occurrences but only two unique hosts, so the phishing playbook enriches two
values. This is different from deduplicating repeated alerts or replayed events.

Without cross-alert idempotency, one repeated detection creates another case on
every run, producing a ticket storm. The regression suite deliberately replays
an alert and confirms this current limitation. Before live integration, use a
stable source/event ID for exact replay handling and a reviewed correlation key
for related events. Preserve new observations and severity increases rather than
silently discarding everything with a familiar IP.

Case creation, audit append, and queue append are also separate writes. A retry
after a partial failure can duplicate evidence or miss an action recommendation.
A durable outbox and reconciliation process must connect these writes reliably;
within-alert IOC deduplication alone cannot solve that problem.

### Explain TTL caching and rate limits

A TTL cache stores a result until a defined expiry. Repeated queries can reuse
fresh results, reducing latency and demand on an external service. A useful cache
records the normalized IOC, source/version, observation time, and expiry, and
invalidates results when a source update or analyst correction makes them obsolete.

The current prototype has no TTL cache: it rereads the local feed per enrichment.
This is functional offline but is not an external-API rate-limit solution. A
production API adapter would also need request budgets, backoff, response validation,
and clear handling of unavailable data. Never turn a timeout into a cached ALLOW
result. Source freshness and cache expiry must prevent stale benign decisions
from bypassing review.

## Transversal objectives

### Quantify effort, savings, and healthcare risks

The [strategy](tasks/automation_strategy.md) separates measured fixture outcomes
from modeled savings. The baseline gives 150 total alerts/day at eight minutes:
20 analyst-hours/day, including 13.4 enrichment hours at 67% and 6.6 hours of other
triage. Task 6 separately calls those 150 phishing alerts, while the candidate
seed gives 90 phishing-enrichment items. Both scenarios are shown transparently.

At volume 90, removing the full assumed enrichment share gives
`90 × 8 × 0.67 / 60 = 8.04 hours/day`, or 241.2 hours over 30 days. Removing half
gives 120.6 hours/month. The 150-phishing illustration gives 402 gross hours/month,
not a forecast established by the total-alert baseline. Rework, support, stale
sources, and duplicate cases can reduce or invalidate these estimates. No salary
rate or cost evidence exists for a monetary ROI claim.

The three specific risks are closure hiding a multi-phase attack, workstation
isolation interrupting clinical work, and account disablement removing emergency
or integration access. Each has preventive approval, review, and recovery controls.
False positives and false negatives use explicitly different denominators;
matching known fixtures does not establish either real-world rate.

### Write a concise, decision-focused strategy and brief

The strategy uses the required order: three 90-day phases for enrichment only,
confirmed-benign auto-close, and conditional escalation. The template's different
order does not override the explicit task. Production Phase 1 does not inherit the
lab playbooks' closure or escalation actions; later adapters must enforce the
phase boundaries and independently measured approval gates.

The [SOC lead brief](tasks/soc_automation_brief.md) states what was built, explains
each of the five outcomes in plain language, gives the savings assumptions,
identifies current limitations, and requests a read-only pilot and analyst
measurement time. It asks for owners and a costed implementation plan instead of
inventing a tooling price or claiming production readiness. The short documents
support an accountable decision while the longer test report preserves the full
evidence needed for independent review.
