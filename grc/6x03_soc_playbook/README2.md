# SOC Playbook task package

Prepared on **2026-11-10**. These answers use the README, task instructions, and all
supplied MedDefense materials. Source files remain unchanged. The quiz is labeled
Task 0 in the source; study notes replace answers to unseen quiz questions.

| Task | Answer | Executable or evidence |
| --- | --- | --- |
| 0: Concepts quiz | [Study notes](quiz_study_notes.md) | No platform quiz submitted. |
| 1: IOC enrichment | [Engine explanation](ioc_enrichment_engine.md) | [enrich_ioc.py](enrich_ioc.py), [feed](ioc_feed.json), [validation](evidence/enrichment_validation_results.json) |
| 2: Case manager | [Case management](case_manager.md) | [case_manager.py](case_manager.py), [cases.db](cases.db) |
| 3: Phishing | [Phishing playbook](phishing_triage_playbook.md) | [playbook_phishing_triage.py](playbook_phishing_triage.py) |
| 4: Credential exposure | [Credential playbook](credential_exposure_playbook.md) | [playbook_credential_exposure.py](playbook_credential_exposure.py), [account inventory](privileged_accounts.json) |
| 5: Integration | [Actual results](integration_test_results.md) | [Audit log](playbook_audit.log), [human queue](isolation_queue.json) |
| 6: Strategy | [Automation strategy](automation_strategy.md) | Proposed rollout; no production authorization. |
| 7: Leadership brief | [SOC lead brief](soc_automation_brief.md) | For James Chen; no message sent. |

[LEARNING_OBJECTIVES.md](../LEARNING_OBJECTIVES.md) answers every README objective.
The shared [playbook_common.py](playbook_common.py) module keeps validation, audit,
and queue handling consistent across the two playbooks.

## Running the tools

The task folder is the execution root so each task's code, input copies, and
outputs stay together. Run commands from this directory:

```bash
python3 enrich_ioc.py 198.51.100.42
python3 case_manager.py list
python3 case_manager.py list --status closed
python3 case_manager.py get CASE-20261110-001
```

Running a playbook again appends a new case and audit entry; cross-alert replay
protection is not implemented. Preserve the canonical evidence. For a new run,
use a fresh working directory instead of deleting the supplied database or logs:

```bash
python3 run_integration_tests.py --workdir /tmp/meddefense-soc-new-run
python3 test_soc_automation.py
```

The integration runner reads original inputs at `../opt/meddefense/materials`
relative to the script location. Use `--materials PATH` for another material
location. It copies the supplied feed, account list, and alerts without changing
them, and refuses to overwrite an existing run. Regression tests use isolated
temporary directories and leave the five-case evidence database unchanged.

## What actually ran

Python 3.14.10 executed the tools locally. The prescribed SSH training container
was not connected, so this package does not claim container execution. Core code
uses only the permitted standard-library modules and local sibling modules;
Python 3.8 syntax compatibility was checked, but no Python 3.8 runtime was present.
Test helpers use additional standard-library testing/process modules, not external
packages. No packages were installed.

All ten enrichment CSV rows matched their expected type, address class, score,
and verdict. All five canonical playbook scenarios matched expected results,
creating five cases, five audit entries, and one pending isolation recommendation.
Nineteen regression tests passed, including malformed input, DNS failure, uncertain
enrichment, case rollback, and the additional privileged internal alert 008.
[Saved test output](evidence/regression_tests.stderr.txt) contains the actual run.

The first regression attempt had two setup errors because reference materials had
not yet been copied into the temporary staging layout. Its output is preserved in
[evidence/regression_tests.initial.stderr.txt](evidence/regression_tests.initial.stderr.txt).
The staging setup was corrected and test resource handling improved before the
successful 19-test run. The canonical five-case run passed on its first attempt;
no playbook correction or failed integration result is invented.

## Boundaries and source inconsistencies

`BLOCK` is an indicator verdict, not an instruction to change a firewall. Phishing
closure affects only the local simulated case. The isolation queue requires a
human; there is no EDR call, account disablement, mailbox quarantine, or delivered
notification. The scripts are lab prototypes; do not connect them directly to a
production input feed before the strategy's approval gates are implemented.

The supplied materials use 150 total alerts/day as the planning midpoint, while
Task 6 describes 150 phishing alerts/day. The strategy shows both the required
150-alert illustration and the source-based 90-phishing-alert scenario. The
README's 18-hour and 68% examples are not combined with the canonical 20-hour,
67% planning calculation. Monthly estimates are assumptions, not measured savings.

Task 6 explicitly requires enrichment-only, then benign auto-close, then
conditional escalation in three 90-day phases. That order takes precedence over
the brief template's different sequence. Sample phishing counts are also
inconsistent: alert 001 actually has four IOC occurrences and two unique hosts,
not three enriched IOCs. Audit counts record unique enriched indicators.

The five required integration scenarios omit alert 008, which is additionally
checked in the isolated regression suite. Source event dates are in April; case
IDs and audit timestamps reflect November execution. Fixed-feed verdicts are
repeatable, but timestamps and reverse-DNS names may differ. The feed and privilege
inventory are historical snapshots; freshness enforcement is not implemented.

## Public references and validation

The README links were reviewed for background. Its NIST SP 800-61r2 is archived
and was superseded in April 2025 by
[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
The IBM page returned access denied, so no claim relies on its unseen content.
Relevant implementation references are the official
[sqlite3](https://docs.python.org/3/library/sqlite3.html),
[ipaddress](https://docs.python.org/3/library/ipaddress.html), and
[socket](https://docs.python.org/3/library/socket.html) documentation.
The [MITRE LSASS technique](https://attack.mitre.org/techniques/T1003/001/)
provides context; no credential extraction is performed.

Markdownlint is unavailable. Local checks cover document structure, links,
source-copy identity, calculations, schema, actual CLI behavior, and database
integrity. Page limits are addressed through concise prose; exact rendered page
counts depend on the viewer and were not measured.
