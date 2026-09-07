# MedDefense Detection Engineering Specification

## Purpose

This specification defines how MedDefense detection rules are authored, executed, measured, tuned, prioritized, and delivered to the SOC. It is the operating contract between the 3x02 detection catalog and the 3x03 Triage Shift.

## Inputs

Detection processing uses these dependencies:

* `$HANDOFF_DIR/data/normalized_events.json` — normalized evidence
* `$HANDOFF_DIR/context/asset_inventory.json` — asset context
* `$BASELINE_PKG/baselines/baseline_summary.json` — baseline and evaluation windows
* `$BASELINE_PKG/baselines/baseline_process.json` — process baseline
* `$BASELINE_PKG/anomalies/ranked_anomalies.json` — anomaly ground truth
* `$BASELINE_PKG/taxonomy/labeled_events.json` — labeled events
* `$ASSETS_DIR/risk_register.json` — organizational risk scenarios
* `$ASSETS_DIR/attack_taxonomy.json` — ATT&CK reference data

Environment defaults:

* `HANDOFF_DIR=~/3x00_handoff/evidence_handoff`
* `BASELINE_PKG=~/3x01_package/baseline_package`
* `ASSETS_DIR=~/3x02_assets`
* `CATALOG_DIR=~/3x02_package/detection_catalog`

## Rule Authoring Standard

Rules use Sigma YAML and must contain:

* `title`
* `id` using UUID v4
* `status`
* `description`
* `logsource`
* `detection`
* `condition`
* `falsepositives`
* `level`
* `tags`

Rule filenames follow `NNN_short_name.yml`.

Levels are limited to `informational`, `low`, `medium`, `high`, or `critical`.

Every rule must contain at least one ATT&CK technique tag such as `attack.t1110.001`. Detection logic should use precise structured fields rather than free-text matching whenever possible.

## Execution Model

`3-sigma_runner.sh` executes Sigma rules directly against normalized JSON evidence.

The runner supports selections, boolean logic, field comparisons, time windows, and aggregation such as:

`selection | count() by src_ip > 5`

Project-specific fields such as `hour_of_day` and `baseline_seen` may be calculated before evaluation.

Baseline and evaluation boundaries come from `baseline_summary.json` and must never be hardcoded.

## Quality Thresholds

Every shipped rule must have measured:

* `tp_count`
* `fp_count`
* `precision`
* `recall`
* `f1`

Rules producing more than **10 false positives during the seven-day clean baseline** must be tuned before shipping.

Rules with `f1 < 0.30` are considered **WEAK** and should not ship without review. Rules with `f1 >= 0.70` are considered **STRONG**.

Precision and recall must both be reported and must not be zero for a rule expected to detect labeled malicious activity.

## Tuning Protocol

A noisy rule is first measured against the clean baseline to identify legitimate activity causing matches.

Tuning should add the narrowest defensible filter, such as:

* known administrative accounts
* approved hosts
* expected parent processes
* trusted destinations
* normal time windows

The tuned rule must then be rerun against both baseline and evaluation windows. Tuning is accepted only when false positives decrease without removing the intended true-positive behavior.

## Risk Ranking Model

Each rule inherits risk from scenarios in `risk_register.json` whose ATT&CK techniques intersect the rule's ATT&CK tags.

For each matching scenario:

`scenario risk = likelihood × impact`

Then:

`risk_score = sum of matching scenario risks`

`priority_score = risk_score × f1`

When `f1 = 0`, the minimum multiplier is `0.1`.

Rules with no matching risk scenario receive priority score `0` and are marked as orphan detections.

## Outputs

The primary downstream contract is `alert_queue.json`.

Each alert contains:

* deterministic `alert_id`
* `generated_at`
* rule ID, title, and level
* `priority_score`
* `event_ref`
* flattened `event_summary`
* `asset_context`
* ATT&CK techniques
* `status`
* `evidence_hash`

Alerts are deduplicated within 60 seconds using `(rule_id, hostname, user)` and ranked by priority score.

`alert_queue_schema.json` defines the fixed schema consumed by 3x03. Schema changes require coordination because incompatible changes can break triage processing.

## Failure Modes

**Missing dependency file:** scripts stop with an input-file error and no valid catalog output is produced.

**Invalid Sigma YAML:** the runner fails validation or returns `INVALID`.

**Incorrect window boundaries:** baseline activity may be counted as attacks or evaluation attacks may be missed.

**Broken event references:** alerts cannot be linked back to `normalized_events.json`.

**Excessive false positives:** baseline evaluation produces more than 10 matches and the rule is marked for tuning.

**Missing ATT&CK mapping:** the rule may receive no risk score and appear as an orphan.

## Reviewer Checklist

Before merging a rule:

* YAML parses successfully.
* UUID is valid version 4.
* Required Sigma fields are present.
* Filename follows `NNN_short_name.yml`.
* ATT&CK technique mapping is justified.
* Detection uses structured fields.
* Runner executes without error.
* Baseline FP count is measured.
* TP, precision, recall, and F1 are measured.
* No unacceptable false-positive behavior remains.
* Risk ranking is present.
* Alert output preserves the 3x03 schema contract.

