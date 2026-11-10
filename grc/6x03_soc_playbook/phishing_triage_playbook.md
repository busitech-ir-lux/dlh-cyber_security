# Task 3: Phishing triage playbook

**Implementation:** [playbook_phishing_triage.py](playbook_phishing_triage.py)  
**Supporting modules:** [enrichment](enrich_ioc.py), [cases](case_manager.py),
[shared helpers](playbook_common.py)  
**Decision source:** `phishing_triage_decision_logic.md`

## Processing

The script accepts any supplied JSON alert path. It extracts the sender IP,
the domain after the sender email's final @, and each valid body URL's hostname.
Normalized unique hosts are enriched once per alert. It never visits a URL or
uses the alert's `expected` test annotations to make a decision.

| Evidence | Verdict | Severity | Status |
| --- | --- | --- | --- |
| At least one BLOCK IOC | ESCALATE | Critical | escalated |
| Otherwise an INVESTIGATE IOC, missing evidence, or extraction warning | REVIEW | High | open |
| Complete extracted evidence, all ALLOW | CLOSE | Low | closed |

Every outcome creates a case with indicator links and a note containing the full
enrichment results and rationale. Simulated closure uses the exact resolution
`no_indicators_of_compromise`. Escalations identify the triggering IOCs in a
separate case note. The append-only audit line records the alert, unique IOC
counts, verdict, case ID, and severity.

The input for alert 001 contains four indicator occurrences and two unique hosts:
the IP and domain both appear again in body URLs. It therefore logs two enriched
IOCs and two skipped duplicates. The sample's inconsistent three-IOC counts are
not copied into the actual evidence.

## Execution and validation

From this task folder, the following appends a new case and log record:

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json
```

Preserve the canonical database when experimenting; use the integration runner's
fresh-workspace option. The [actual integration report](integration_test_results.md)
records these matched outcomes:

- Alert 001: ESCALATE, Critical, escalated.
- Alert 002: REVIEW, High, open.
- Alert 003: CLOSE, Low, closed with the required benign resolution.

A missing sender IP is skipped with a warning. A malformed URL is warned about and
skipped. Either uncertainty prevents an all-ALLOW remainder from silently closing
the alert. If enrichment raises an exception, that IOC becomes INVESTIGATE and
processing continues. Empty evidence also requires review. Malformed JSON, missing
required top-level fields, or persistence failures produce exit code 1; successful
triage returns 0 regardless of the verdict.

## Operational boundary

Closure changes only the simulated local case. The script has no mail gateway
connection, sender blocking, mailbox quarantine, or message delivery. Escalation
is a case status and note, not a claim that an on-call analyst received a message.
The audit and stdout explicitly describe that limitation.

There is no production auto-close approval gate in this prototype. Do not route
live alerts directly to it: allowlisted/internal metadata is insufficient to
clear a real behavioral detection. Use the staged rollout, independently labeled
error measurements, analyst override, and clinical review in
[automation_strategy.md](automation_strategy.md).
