# When Everything Fails: completed task package

This folder answers all written tasks in `tasks.md` and provides study notes for
the quiz labeled Task 0. Source files remain unchanged. Prepared on 2026-11-10;
all BIA targets, architecture changes, and governance decisions are proposals
until authorized and tested. No CISO signature or clinical acceptance is invented.

| Task | Deliverable |
| --- | --- |
| 0: Quiz | [Study notes](quiz_study_notes.md) |
| 1: Business impact | [Business Impact Analysis](business_impact_analysis.md) |
| 2: Backup design | [Backup architecture](backup_architecture.md) |
| 3: Technical procedures | [Recovery runbooks](recovery_runbooks.md) |
| 4: Clinical procedures | [Two quick references](clinical_downtime_procedures.md) |
| 5: Timed test | [Test record](recovery_test_record.md), [timer](recovery_timer.sh), [step log](recovery_test_log.txt) |
| 6: Test findings | [Gap analysis and corrected runbook](gap_analysis.md) |
| 7: Program package | [Master plan](dr_plan_master.md), [board brief](ciso_dr_brief.md) |

[Learning objectives](../LEARNING_OBJECTIVES.md) are answered separately.

## What was actually tested

A local SQLite restore used copies of the supplied backup and configuration at
`/tmp/meddefense-dr-test`. No SSH session or prescribed training container was
available. The supplied SQL contains five simulated patient orders. The timer ran
all ten recovery steps, including integrity checks and two critical-record checks;
no internet was used during execution. AD is documentation-only, as required.

The measured local interval was 245,711,516 nanoseconds, approximately 0.246 seconds,
reported conservatively as 0m 01s. This tests a tiny database restoration workflow,
not hospital service recovery, clinical notification delivery, an RPO, or a full
site loss. The result is CONDITIONAL PASS for this limited exercise, not evidence
that production LIS meets 30 minutes. The historical April backup cannot establish
a current one-hour recovery point.

## Evidence and execution paths

The extracted material path here is `../opt/`, relative to this task folder,
rather than `/opt/meddefense/materials`. The test used the supplied
`opt/recovery_test/lab_config.env` without changing its absolute workspace paths.
The `tmp/meddefense-dr-test/config/app_config.env` copy differs from the example
in `opt/recovery_test/app_config.env`; the executed workspace copy is recorded in
the evidence. Both contain the production hostname, which was never contacted.

Raw commands, stdout, stderr, and high-resolution step metadata are in
[evidence/](evidence/). The failed original manifest check is retained. The source
manifest starts with a UTF-8 byte-order marker; a separate normalized copy removes
only those bytes before successful SHA-256 validation. No source checksum or SQL
content was changed to force a successful check.

The recovered database and staged SQL are copied under the project's
`tmp/meddefense-dr-test/recovery/` for submission. Raw `ls` output records the
original execution path under `/tmp`, not the copied submission path.

## Running the timer safely

Run the executable timer from a dedicated new exercise directory. It writes
`./recovery_test_log.txt` and `./tmp/rtest_state` relative to that working directory.
Use `START`, then `PASS` or `FAIL` with exactly the same step name, then `SUMMARY`.
It serializes concurrent calls, refuses overlapping steps and accidental reuse of
a completed run, and preserves existing evidence. Archive a run by choosing a new
working directory, not by deleting its state. Keep the completed supplied run
unchanged when testing the script.

## Sources and validation limits

BIA values and hourly revenue amounts are explicitly modeled assumptions because
the materials provide no financial ledger or approved tolerances. The master plan
maps evidence to all five HIPAA contingency specifications without declaring the
program fully implemented. Clinical approval, staffing, costs, and production
verification remain open.

The public README references were reviewed before the timed exercise. The FEMA
training-platform redirect could not be accessed; no claim relies on reading it.
Useful accessible references include [NIST contingency planning](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-34r1.pdf),
[CIS recovery safeguards](https://www.cisecurity.org/controls/data-recovery),
[AWS recovery guidance](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-workloads-on-aws.html),
and [HHS security guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html).
No extra packages were installed. Markdownlint is unavailable; local structural,
link, evidence, arithmetic, word-count, and script behavior checks are used instead.
Rendered page counts depend on the viewer; the brief is kept short and clinical
quick references have 350–500 words each. Print each clinical reference separately.
