# SOC playbook integration test results

**Test date:** 2026-11-10  
**Version:** 1.0  
**Environment:** Local Python execution against supplied fixtures; prescribed SSH lab not connected

## Scope and method

These are real CLI runs with the local feed and account inventory, not copied
sample outputs. The source alert `expected` objects are never read by the playbooks;
the runner compares actual case data with `integration/expected_outcomes.csv`.
All five runs used a fresh database and audit log. Existing evidence is never reset;
the runner refuses reuse and supports a separate `--workdir` for later runs.
No external API, mail, account, firewall, or endpoint action is called.

Run `python3 run_integration_tests.py` from a fresh task working directory with
access to the original `../opt/meddefense/materials`, or supply `--materials` and
`--workdir`. The supplied execution used a temporary staging directory before
copying the completed artifacts into this project. Commands below use the same
working-directory-relative arguments; subprocesses located the scripts by their
absolute staging paths. Raw stdout and stderr are saved separately in `evidence/`.

The local fixtures contain RFC documentation addresses, not live hostile targets.
Reverse DNS is best-effort metadata; verdicts depend on the supplied feed and rules,
not network availability. Timestamps and case IDs reflect actual November execution,
not the April dates inside the source alerts.

## Results overview

| Alert | Expected verdict / severity / status | Actual verdict / severity / status | Isolation queued | Runtime, seconds | Result |
| --- | --- | --- | --- | --- | --- |
| ALT-20260428-001 | ESCALATE / Critical / escalated | ESCALATE / Critical / escalated | no | 0.1085 | PASS |
| ALT-20260428-002 | REVIEW / High / open | REVIEW / High / open | no | 0.0986 | PASS |
| ALT-20260428-003 | CLOSE / Low / closed | CLOSE / Low / closed | no | 0.0936 | PASS |
| ALT-20260428-007 | ESCALATE / Critical / escalated | ESCALATE / Critical / escalated | yes | 0.0887 | PASS |
| ALT-20260428-009 | MANUAL_REVIEW / Medium / open | MANUAL_REVIEW / Medium / open | no | 0.0921 | PASS |

## Scenario 1: ALT-20260428-001

Known malicious sender IP and typosquat domain

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json
```

**Actual stdout, unchanged:**

```text
[2026-11-10T10:33:44Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 4 extracted, 2 enriched, 2 dedup skipped
  198.51.100.42            ipv4    BLOCK       score=95 (c2, cobalt_strike, beacon)
  meddefense-secure.net    domain  BLOCK       score=97 (typosquat, phishing, credential_harvest, impersonation)
Verdict    : ESCALATE
Case       : CASE-20261110-001  Severity: Critical  Status: escalated
Action     : Escalation recorded; on-call notification delivery is not integrated
```

**Actual stderr:** Empty.

**Case query:**

```bash
python3 case_manager.py get CASE-20261110-001
```

**Actual case query stdout, unchanged:**

```json
{
  "case_id": "CASE-20261110-001",
  "alert_id": "ALT-20260428-001",
  "severity": "Critical",
  "title": "Phishing: Known indicator escalated",
  "description": "Simulated triage for rule phishing_email_suspicious_sender; source event time 2026-04-28T09:14:32Z",
  "status": "escalated",
  "created_at": "2026-11-10T10:33:44Z",
  "updated_at": "2026-11-10T10:33:44Z",
  "resolution": null,
  "notes": [
    {
      "note": "{\"deduplicated\": 2, \"enrichment\": [{\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"case_reference\": \"MD-IR-2026-03-CS-001\", \"category\": \"c2\", \"confidence\": 95, \"first_seen\": \"2026-03-12\", \"in_benign_list\": false, \"in_malicious_feed\": true, \"last_seen\": \"2026-04-27\", \"notes\": \"Observed during Cobalt Strike beacon triage and credential access investigation.\", \"source\": \"meddefense-internal\", \"tags\": [\"cobalt_strike\", \"beacon\"]}, \"ioc\": \"198.51.100.42\", \"ip_class\": \"documentation\", \"reverse_dns\": \"NXDOMAIN\", \"score\": 95, \"type\": \"ipv4\", \"verdict\": \"BLOCK\"}, {\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"case_reference\": \"MD-PHISH-2026-04-MDS\", \"category\": \"typosquat\", \"confidence\": 97, \"first_seen\": \"2026-04-10\", \"in_benign_list\": false, \"in_malicious_feed\": true, \"last_seen\": \"2026-04-27\", \"notes\": \"Impersonates MedDefense login and billing workflows.\", \"source\": \"meddefense-internal\", \"tags\": [\"phishing\", \"credential_harvest\", \"impersonation\"]}, \"ioc\": \"meddefense-secure.net\", \"ip_class\": \"N/A\", \"reverse_dns\": \"N/A\", \"score\": 97, \"type\": \"domain\", \"verdict\": \"BLOCK\"}], \"extracted\": 4, \"playbook_verdict\": \"ESCALATE\", \"simulation_only\": true, \"warnings\": []}",
      "created_at": "2026-11-10T10:33:44Z"
    },
    {
      "note": "Escalation triggered by: 198.51.100.42, meddefense-secure.net. On-call notification delivery is not integrated; analyst must review escalated cases.",
      "created_at": "2026-11-10T10:33:44Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "198.51.100.42",
      "ioc_type": "ipv4",
      "verdict": "BLOCK",
      "score": 95
    },
    {
      "ioc_value": "meddefense-secure.net",
      "ioc_type": "domain",
      "verdict": "BLOCK",
      "score": 97
    }
  ]
}
```

**Expected versus actual:** PASS. Exit code 0; expected queue no; actual queue no.


## Scenario 2: ALT-20260428-002

Unknown external sender and domain require review

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-002.json
```

**Actual stdout, unchanged:**

```text
[2026-11-10T10:33:44Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-002
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 2 enriched, 1 dedup skipped
  203.0.113.5              ipv4    INVESTIGATE score=30 (unknown)
  external-health-news.com domain  INVESTIGATE score=30 (unknown)
Verdict    : REVIEW
Case       : CASE-20261110-002  Severity: High  Status: open
Action     : Case recorded for analyst review; no mail action taken
```

**Actual stderr:** Empty.

**Case query:**

```bash
python3 case_manager.py get CASE-20261110-002
```

**Actual case query stdout, unchanged:**

```json
{
  "case_id": "CASE-20261110-002",
  "alert_id": "ALT-20260428-002",
  "severity": "High",
  "title": "Phishing: Sender review",
  "description": "Simulated triage for rule phishing_email_suspicious_sender; source event time 2026-04-28T09:31:05Z",
  "status": "open",
  "created_at": "2026-11-10T10:33:44Z",
  "updated_at": "2026-11-10T10:33:44Z",
  "resolution": null,
  "notes": [
    {
      "note": "{\"deduplicated\": 2, \"enrichment\": [{\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"in_benign_list\": false, \"in_malicious_feed\": false}, \"ioc\": \"203.0.113.5\", \"ip_class\": \"documentation\", \"reverse_dns\": \"NXDOMAIN\", \"score\": 30, \"type\": \"ipv4\", \"verdict\": \"INVESTIGATE\"}, {\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"in_benign_list\": false, \"in_malicious_feed\": false}, \"ioc\": \"external-health-news.com\", \"ip_class\": \"N/A\", \"reverse_dns\": \"N/A\", \"score\": 30, \"type\": \"domain\", \"verdict\": \"INVESTIGATE\"}], \"extracted\": 3, \"playbook_verdict\": \"REVIEW\", \"simulation_only\": true, \"warnings\": []}",
      "created_at": "2026-11-10T10:33:44Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "203.0.113.5",
      "ioc_type": "ipv4",
      "verdict": "INVESTIGATE",
      "score": 30
    },
    {
      "ioc_value": "external-health-news.com",
      "ioc_type": "domain",
      "verdict": "INVESTIGATE",
      "score": 30
    }
  ]
}
```

**Expected versus actual:** PASS. Exit code 0; expected queue no; actual queue no.


## Scenario 3: ALT-20260428-003

Internal sender and private IP with no suspicious external IOC

**Command:**

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-003.json
```

**Actual stdout, unchanged:**

```text
[2026-11-10T10:33:44Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-003
Rule       : phishing_email_suspicious_sender
IOCs       : 2 extracted, 2 enriched, 0 dedup skipped
  10.0.1.25                ipv4    ALLOW       score=0 (unknown)
  meddefense.internal      domain  ALLOW       score=0 (unknown)
Verdict    : CLOSE
Case       : CASE-20261110-003  Severity: Low  Status: closed
Action     : Simulated benign case closed; production auto-close is not approved
```

**Actual stderr:** Empty.

**Case query:**

```bash
python3 case_manager.py get CASE-20261110-003
```

**Actual case query stdout, unchanged:**

```json
{
  "case_id": "CASE-20261110-003",
  "alert_id": "ALT-20260428-003",
  "severity": "Low",
  "title": "Phishing: Benign simulation",
  "description": "Simulated triage for rule phishing_email_suspicious_sender; source event time 2026-04-28T10:02:19Z",
  "status": "closed",
  "created_at": "2026-11-10T10:33:44Z",
  "updated_at": "2026-11-10T10:33:44Z",
  "resolution": "no_indicators_of_compromise",
  "notes": [
    {
      "note": "{\"deduplicated\": 2, \"enrichment\": [{\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"in_benign_list\": false, \"in_malicious_feed\": false}, \"ioc\": \"10.0.1.25\", \"ip_class\": \"private\", \"note\": \"Private address range; internal network traffic\", \"reverse_dns\": \"NXDOMAIN\", \"score\": 0, \"type\": \"ipv4\", \"verdict\": \"ALLOW\"}, {\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"in_benign_list\": true, \"in_malicious_feed\": false}, \"ioc\": \"meddefense.internal\", \"ip_class\": \"N/A\", \"reverse_dns\": \"N/A\", \"score\": 0, \"type\": \"domain\", \"verdict\": \"ALLOW\"}], \"extracted\": 2, \"playbook_verdict\": \"CLOSE\", \"simulation_only\": true, \"warnings\": []}",
      "created_at": "2026-11-10T10:33:44Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "10.0.1.25",
      "ioc_type": "ipv4",
      "verdict": "ALLOW",
      "score": 0
    },
    {
      "ioc_value": "meddefense.internal",
      "ioc_type": "domain",
      "verdict": "ALLOW",
      "score": 0
    }
  ]
}
```

**Expected versus actual:** PASS. Exit code 0; expected queue no; actual queue no.


## Scenario 4: ALT-20260428-007

Known C2 source IP and Domain Admin service account

**Command:**

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json
```

**Actual stdout, unchanged:**

```text
[2026-11-10T10:33:44Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-007
Host       : WST-WS-031
User       : svc_helpdesk  Privilege: Domain Admin
Source IP  : 198.51.100.42  Verdict: BLOCK  Score: 95
MITRE      : T1003.001 OS Credential Dumping: LSASS Memory
Verdict    : ESCALATE
Case       : CASE-20261110-004  Severity: Critical  Status: escalated
Action     : Host written to isolation_queue.json for analyst authorization
```

**Actual stderr:** Empty.

**Case query:**

```bash
python3 case_manager.py get CASE-20261110-004
```

**Actual case query stdout, unchanged:**

```json
{
  "case_id": "CASE-20261110-004",
  "alert_id": "ALT-20260428-007",
  "severity": "Critical",
  "title": "Credential exposure: WST-WS-031",
  "description": "OS Credential Dumping: LSASS Memory on WST-WS-031 from 198.51.100.42 (BLOCK) by Domain Admin svc_helpdesk",
  "status": "escalated",
  "created_at": "2026-11-10T10:33:44Z",
  "updated_at": "2026-11-10T10:33:44Z",
  "resolution": null,
  "notes": [
    {
      "note": "{\"enrichment\": {\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"case_reference\": \"MD-IR-2026-03-CS-001\", \"category\": \"c2\", \"confidence\": 95, \"first_seen\": \"2026-03-12\", \"in_benign_list\": false, \"in_malicious_feed\": true, \"last_seen\": \"2026-04-27\", \"notes\": \"Observed during Cobalt Strike beacon triage and credential access investigation.\", \"source\": \"meddefense-internal\", \"tags\": [\"cobalt_strike\", \"beacon\"]}, \"ioc\": \"198.51.100.42\", \"ip_class\": \"documentation\", \"reverse_dns\": \"NXDOMAIN\", \"score\": 95, \"type\": \"ipv4\", \"verdict\": \"BLOCK\"}, \"human_authorization_required\": true, \"inventory_exported_at\": \"2026-04-28T08:00:00Z\", \"mitre_technique\": \"T1003.001\", \"playbook_verdict\": \"ESCALATE\", \"privilege\": \"Domain Admin\", \"reason\": \"OS Credential Dumping: LSASS Memory on WST-WS-031 from 198.51.100.42 (BLOCK) by Domain Admin svc_helpdesk\", \"source_event_time\": \"2026-04-28T14:33:18Z\", \"technique_name\": \"OS Credential Dumping: LSASS Memory\"}",
      "created_at": "2026-11-10T10:33:44Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "198.51.100.42",
      "ioc_type": "ipv4",
      "verdict": "BLOCK",
      "score": 95
    }
  ]
}
```

**Expected versus actual:** PASS. Exit code 0; expected queue yes; actual queue yes.


## Scenario 5: ALT-20260428-009

Internal IP and non-privileged user require manual review without isolation

**Command:**

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-009.json
```

**Actual stdout, unchanged:**

```text
[2026-11-10T10:33:44Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-009
Host       : WST-WS-041
User       : k.nguyen  Privilege: Standard user
Source IP  : 192.168.10.55  Verdict: ALLOW  Score: 0
MITRE      : T1550.002 Use Alternate Authentication Material: Pass the Hash
Verdict    : MANUAL_REVIEW
Case       : CASE-20261110-005  Severity: Medium  Status: open
Action     : Case recorded for analyst review; no isolation queued
```

**Actual stderr:** Empty.

**Case query:**

```bash
python3 case_manager.py get CASE-20261110-005
```

**Actual case query stdout, unchanged:**

```json
{
  "case_id": "CASE-20261110-005",
  "alert_id": "ALT-20260428-009",
  "severity": "Medium",
  "title": "Credential exposure: WST-WS-041",
  "description": "Use Alternate Authentication Material: Pass the Hash on WST-WS-041 from 192.168.10.55 (ALLOW) by Standard user k.nguyen",
  "status": "open",
  "created_at": "2026-11-10T10:33:44Z",
  "updated_at": "2026-11-10T10:33:44Z",
  "resolution": null,
  "notes": [
    {
      "note": "{\"enrichment\": {\"enriched_at\": \"2026-11-10T10:33:44Z\", \"feed_result\": {\"in_benign_list\": false, \"in_malicious_feed\": false}, \"ioc\": \"192.168.10.55\", \"ip_class\": \"private\", \"note\": \"Private address range; internal network traffic\", \"reverse_dns\": \"NXDOMAIN\", \"score\": 0, \"type\": \"ipv4\", \"verdict\": \"ALLOW\"}, \"human_authorization_required\": false, \"inventory_exported_at\": \"2026-04-28T08:00:00Z\", \"mitre_technique\": \"T1550.002\", \"playbook_verdict\": \"MANUAL_REVIEW\", \"privilege\": \"Standard user\", \"reason\": \"Use Alternate Authentication Material: Pass the Hash on WST-WS-041 from 192.168.10.55 (ALLOW) by Standard user k.nguyen\", \"source_event_time\": \"2026-04-28T15:07:44Z\", \"technique_name\": \"Use Alternate Authentication Material: Pass the Hash\"}",
      "created_at": "2026-11-10T10:33:44Z"
    }
  ],
  "iocs": [
    {
      "ioc_value": "192.168.10.55",
      "ioc_type": "ipv4",
      "verdict": "ALLOW",
      "score": 0
    }
  ]
}
```

**Expected versus actual:** PASS. Exit code 0; expected queue no; actual queue no.

## Final case listing

Exact output of `python3 case_manager.py list`:

```text
+-------------------+------------------+----------+-------------------------------------+-----------+
| Case ID           | Alert ID         | Severity | Title                               | Status    |
+-------------------+------------------+----------+-------------------------------------+-----------+
| CASE-20261110-001 | ALT-20260428-001 | Critical | Phishing: Known indicator escalated | escalated |
| CASE-20261110-002 | ALT-20260428-002 | High     | Phishing: Sender review             | open      |
| CASE-20261110-004 | ALT-20260428-007 | Critical | Credential exposure: WST-WS-031     | escalated |
| CASE-20261110-005 | ALT-20260428-009 | Medium   | Credential exposure: WST-WS-041     | open      |
+-------------------+------------------+----------+-------------------------------------+-----------+
4 cases (filter: open + escalated + investigating)
```

The default CLI lists actionable cases: open, escalated, and investigating.
The benign closed case remains in the database and is retrievable by ID or
`list --status closed`. The Python function `list_cases()` without a filter
returns every case, including closed cases.

## Final isolation queue

Exact output equivalent to `cat isolation_queue.json`:

```json
[
  {
    "queued_at": "2026-11-10T10:33:44Z",
    "host": "WST-WS-031",
    "alert_id": "ALT-20260428-007",
    "case_id": "CASE-20261110-004",
    "reason": "OS Credential Dumping: LSASS Memory on WST-WS-031 from 198.51.100.42 (BLOCK) by Domain Admin svc_helpdesk",
    "action_required": "Analyst must authorize isolation via EDR console before execution",
    "status": "pending_authorization"
  }
]
```

One host recommendation is pending authorization. This is a local queue entry,
not an isolation event or a delivered on-call notification. Case and queue identifiers
must stay linked when the package is copied or reviewed.

## Interpretation and remaining limits

All five canonical scenarios matched their expected results on the first canonical
run. No failing integration run or corrective patch is invented. Separate regression
checks exercise malformed input, uncertain enrichment, the additional privileged
internal alert, decision branches, and database behavior; see the saved regression
report. These checks are not additional entries in the five-case canonical database.

The phishing sample 001 contains four extracted indicator occurrences: sender IP,
sender domain, and two URL hostnames. After normalization, only two unique indicators
are enriched. This corrects contradictory illustrative sample counts without
changing the canonical verdict. Audit IOC counts are unique enriched counts.

The five fixtures do not measure real false-positive or false-negative rates,
clinical disruption risk, sustained throughput, or production readiness. Missing
cross-alert deduplication, TTL caching, privilege/feed freshness enforcement, and
notification delivery remain production gaps. Multi-file persistence is not one
transaction: a crash between database and file writes can leave partial evidence;
production requires durable outbox/retry and idempotency controls.
