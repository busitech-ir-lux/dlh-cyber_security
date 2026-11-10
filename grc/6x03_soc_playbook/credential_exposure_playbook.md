# Task 4: Credential exposure playbook

**Implementation:** [playbook_credential_exposure.py](playbook_credential_exposure.py)  
**Privilege source:** Unchanged [privileged_accounts.json](privileged_accounts.json)  
**Decision sources:** `credential_exposure_decision_logic.md` and
`privileged_account_context.md`

## Processing and decision rules

The script extracts source IP, username, host, and technique from `raw_log`.
It enriches the IP and compares the username, case-insensitively, with the supplied
Domain Admin and Server Admin lists. Domain Admin membership takes precedence
if an account is in both lists. Missing or malformed privilege inventory stops
processing rather than silently treating everyone as a standard user.

| IP verdict | Account | Playbook verdict | Severity / status | Queue isolation |
| --- | --- | --- | --- | --- |
| BLOCK | Any | ESCALATE | Critical / escalated | Yes |
| INVESTIGATE | Domain Admin | ESCALATE | Critical / escalated | Yes |
| INVESTIGATE | Server Admin or standard | MANUAL_REVIEW | High / open | No |
| ALLOW | Domain Admin | ESCALATE | High / escalated | No |
| ALLOW | Server Admin or standard | MANUAL_REVIEW | Medium / open | No |

An internal source IP therefore cannot close a credential-access case. The account
risk and observed technique remain relevant even when local-feed scoring returns
ALLOW. No judgment is taken from the fixtures' `expected` annotations.

The static technique dictionary covers T1003.001 LSASS Memory, T1550.002 Pass the
Hash, T1021.002 SMB/Windows Admin Shares, and T1059.001 PowerShell, using the supplied
MITRE descriptions. Unknown techniques are displayed as requiring verification.
The case note retains the technique, privilege, full enrichment, source event time,
and inventory export time, rather than storing only a final label.

## Human-authorization queue

A queue entry is written only after case creation so it can reference a real case.
It includes timestamp, host, alert ID, case ID, reason, the human authorization
instruction, and `pending_authorization` status. Existing list entries are retained;
an unreadable or non-list queue is not overwritten. A temporary file is atomically
renamed to avoid a half-written JSON file for a single writer.

This is not a concurrent queue or a transactional outbox. Multiple workers and
crash recovery need a stronger store, deduplication, and retry reconciliation.
The script never calls an EDR API, isolates a host, or disables an account.

## Actual execution

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json
```

That command appends evidence, so use a fresh test workspace for another run.
The canonical results are saved in [integration_test_results.md](integration_test_results.md):

- Alert 007: Critical escalation, with WST-WS-031 pending analyst authorization.
- Alert 009: Medium manual review, open, with no isolation entry.

The additional alert 008 is checked in the isolated regression suite: the internal
IP with Domain Admin `admin.legacy` becomes High/escalated without isolation.
The regression suite also checks every branch of the decision table and verifies
that a later no-isolation result preserves an existing queue entry.

The account inventory is an April snapshot and no freshness limit is enforced.
Production needs a trusted current identity export and explicit behavior when
membership is stale or unavailable. There is no claim that listed dormant accounts
have been removed, disabled, or remediated by this playbook.
