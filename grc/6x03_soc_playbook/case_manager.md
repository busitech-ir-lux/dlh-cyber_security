# Task 2: SQLite case manager

**Implementation:** [case_manager.py](case_manager.py)  
**Database:** [cases.db](cases.db)  
**Schema source:** `case_management/case_schema_reference.sql`

## Storage and functions

The three tables match the supplied schema: `cases` stores the main record,
`case_notes` stores timestamped comments, and `case_iocs` stores indicator links.
Keeping notes and indicators in separate linked tables avoids repeating the whole
case for every observation. Each connection enables foreign-key enforcement and
uses SQL parameters for data values.

The module initializes `cases.db` in the current working directory on import.
`init_db(path)` can select a different store. The required functions create a case,
append a note, update status, close with a resolution, retrieve a complete nested
case, and list summary records. Invalid status changes and missing cases return
False as required; a missing case lookup returns None.

`generate_case_id()` derives a candidate from the current UTC date and count of
existing daily cases. Creation allocates and inserts the ID inside a SQLite
`BEGIN IMMEDIATE` transaction, preventing two ordinary writers from taking the
same ID during creation. The helper by itself does not reserve an ID. Allocation
also skips an existing candidate if earlier rows were deleted; the application
provides no evidence-deletion command.

Case and IOC inserts share one transaction. An invalid IOC aborts the entire
creation rather than leaving a partial case. Note insertion updates the parent
record's modification time. Reopening clears a previous closure resolution to
avoid showing an obsolete disposition.

## Commands and actual results

```bash
python3 case_manager.py list
python3 case_manager.py list --status escalated
python3 case_manager.py list --status closed
python3 case_manager.py get CASE-20261110-001
```

Closing a case intentionally changes its evidence record:

```bash
python3 case_manager.py close CASE-20261110-001 "benign; confirmed newsletter sender"
```

That last example was not run against the supplied canonical cases. Use a separate
test database for experiments. The canonical run contains five cases: two Critical
escalated cases, one High open case, one Low closed case, and one Medium open case.
The [integration report](integration_test_results.md) includes exact CLI output and
the full retrieved record for each case.

The Python `list_cases()` function returns all summaries without a filter. The
CLI's default listing shows actionable open, investigating, and escalated cases,
matching the sample's intent to exclude closed records. Use `--status closed` to
inspect the benign case. IDs use actual execution dates, not source alert dates.

## Verification and limits

The regression suite compares table columns and foreign keys against the reference
SQL, tests lifecycle operations and parameterized text, and confirms rollback on
a malformed IOC. The final database passes SQLite integrity and foreign-key checks.

This is a local prototype without authentication, role controls, encryption,
cross-alert correlation, or immutable audit storage. Separate case updates, audit
file writes, and queue writes are not one transaction. Production needs protected
storage, backed-up evidence, idempotent event handling, and an outbox/retry design;
SQLite ID allocation alone does not solve ticket storms or distributed delivery.
