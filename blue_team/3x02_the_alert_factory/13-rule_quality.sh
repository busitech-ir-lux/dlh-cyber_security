#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# 13-rule_quality.sh
#
# Measure detection quality for every Sigma rule using:
#
#   - confirmed malicious ground truth from 3x01
#   - evaluation-window matches from 3-sigma_runner.sh
#   - baseline false positives from T10
#
# Metrics:
#   precision = TP / (TP + FP)
#   recall    = TP / (TP + FN)
#   F1        = 2 * precision * recall / (precision + recall)
#
# Output:
#   rule_quality.json
# ------------------------------------------------------------


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUNNER="$SCRIPT_DIR/3-sigma_runner.sh"

RULE_DIR="$SCRIPT_DIR/rules/sigma"
TUNED_DIR="$RULE_DIR/tuned"

RANKED_ANOMALIES="$BASELINE_PKG/anomalies/ranked_anomalies.json"
LABELED_EVENTS="$BASELINE_PKG/taxonomy/labeled_events.json"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

FP_BASELINE="$SCRIPT_DIR/fp_baseline.json"
OUTPUT="$SCRIPT_DIR/rule_quality.json"


# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required" >&2
    exit 1
}


# ------------------------------------------------------------
# Required input checks
# ------------------------------------------------------------

for file in \
    "$RANKED_ANOMALIES" \
    "$LABELED_EVENTS" \
    "$BASELINE_SUMMARY" \
    "$FP_BASELINE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: required file not found: $file" >&2
        exit 1
    fi
done

if [[ ! -x "$RUNNER" ]]; then
    echo "ERROR: runner not found or not executable: $RUNNER" >&2
    exit 1
fi

if [[ ! -d "$RULE_DIR" ]]; then
    echo "ERROR: Sigma rule directory not found: $RULE_DIR" >&2
    exit 1
fi


# ------------------------------------------------------------
# Run Python quality analysis
# ------------------------------------------------------------

python3 -W error - \
    "$RUNNER" \
    "$RULE_DIR" \
    "$TUNED_DIR" \
    "$RANKED_ANOMALIES" \
    "$LABELED_EVENTS" \
    "$BASELINE_SUMMARY" \
    "$FP_BASELINE" \
    "$OUTPUT" <<'PY'

import json
import subprocess
import sys
from pathlib import Path

import yaml


# ------------------------------------------------------------
# Arguments from Bash
# ------------------------------------------------------------

RUNNER = Path(sys.argv[1])
RULE_DIR = Path(sys.argv[2])
TUNED_DIR = Path(sys.argv[3])

RANKED_ANOMALIES = Path(sys.argv[4])
LABELED_EVENTS = Path(sys.argv[5])
BASELINE_SUMMARY = Path(sys.argv[6])
FP_BASELINE = Path(sys.argv[7])

OUTPUT = Path(sys.argv[8])


# ------------------------------------------------------------
# Ground-truth labels considered explicitly malicious
#
# Do not treat every anomaly as malicious automatically.
# ------------------------------------------------------------

POSITIVE_LABELS = {
    "malicious",
    "true_positive",
    "true positive",
    "tp",
    "attack",
    "confirmed_attack",
    "confirmed attack",
    "confirmed_malicious",
    "confirmed malicious",
    "positive",
}


# ------------------------------------------------------------
# Load JSON or NDJSON
# ------------------------------------------------------------

def load_json_or_ndjson(path):
    text = path.read_text(
        encoding="utf-8",
    ).strip()

    if not text:
        return []

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        records = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}: invalid JSON on "
                    f"line {line_number}: {exc}"
                ) from exc

        return records


# ------------------------------------------------------------
# Flatten common wrapper structures
# ------------------------------------------------------------

def record_list(data):
    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    possible_lists = (
        "events",
        "labeled_events",
        "anomalies",
        "ranked_anomalies",
        "results",
        "items",
    )

    for key in possible_lists:
        value = data.get(key)

        if isinstance(value, list):
            return value

    # A single event object is still usable.
    return [data]


# ------------------------------------------------------------
# Extract event reference
# ------------------------------------------------------------

def event_ref(record):
    if not isinstance(record, dict):
        return None

    possible_fields = (
        "event_ref",
        "event_reference",
        "record_ref",
    )

    for field in possible_fields:
        value = record.get(field)

        if value is not None:
            return str(value)

    return None


# ------------------------------------------------------------
# Extract explicit event-reference lists that may exist at
# top-level in the ground-truth artifacts.
# ------------------------------------------------------------

def explicit_positive_refs(data):
    refs = set()

    if not isinstance(data, dict):
        return refs

    possible_fields = (
        "true_positive_event_refs",
        "malicious_event_refs",
        "positive_event_refs",
    )

    for field in possible_fields:
        value = data.get(field)

        if not isinstance(value, list):
            continue

        for item in value:
            if item is not None:
                refs.add(str(item))

    return refs


# ------------------------------------------------------------
# Determine whether a record is explicitly labeled malicious.
# ------------------------------------------------------------

def is_positive(record):
    if not isinstance(record, dict):
        return False

    boolean_fields = (
        "malicious",
        "is_malicious",
        "true_positive",
        "is_true_positive",
    )

    for field in boolean_fields:
        if record.get(field) is True:
            return True

    text_fields = (
        "label",
        "classification",
        "ground_truth",
        "verdict",
        "status",
    )

    for field in text_fields:
        value = record.get(field)

        if not isinstance(value, str):
            continue

        if value.strip().casefold() in POSITIVE_LABELS:
            return True

    return False


# ------------------------------------------------------------
# Category tokens
#
# T13 requires FN to consider ground-truth events from the
# same category as the rule.
#
# We preserve the category information supplied by 3x01
# instead of inventing categories from filenames.
# ------------------------------------------------------------

def category_tokens(record):
    if not isinstance(record, dict):
        return set()

    fields = (
        "event_category",
        "canonical_label",
        "anomaly_type",
        "category",
    )

    tokens = set()

    for field in fields:
        value = record.get(field)

        if isinstance(value, str) and value:
            tokens.add(
                value.strip().casefold()
            )

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    tokens.add(
                        item.strip().casefold()
                    )

    return tokens


# ------------------------------------------------------------
# Build labeled-event lookup
# ------------------------------------------------------------

ranked_data = load_json_or_ndjson(
    RANKED_ANOMALIES
)

labeled_data = load_json_or_ndjson(
    LABELED_EVENTS
)

ranked_records = record_list(
    ranked_data
)

labeled_records = record_list(
    labeled_data
)


labeled_by_ref = {}

for record in labeled_records:
    ref = event_ref(record)

    if ref is not None:
        labeled_by_ref[ref] = record


# ------------------------------------------------------------
# Build true_positive_event_refs
#
# Sources:
#
# 1. Explicit positive-ref arrays.
# 2. Explicitly malicious labeled events.
# 3. Ranked anomalies explicitly confirmed malicious.
# 4. Ranked anomalies whose matching labeled event is
#    explicitly confirmed malicious.
#
# We do NOT automatically treat every anomaly as malicious.
# ------------------------------------------------------------

true_positive_event_refs = set()

true_positive_event_refs.update(
    explicit_positive_refs(ranked_data)
)

true_positive_event_refs.update(
    explicit_positive_refs(labeled_data)
)


for record in labeled_records:
    ref = event_ref(record)

    if ref is not None and is_positive(record):
        true_positive_event_refs.add(ref)


for record in ranked_records:
    ref = event_ref(record)

    if ref is None:
        continue

    if is_positive(record):
        true_positive_event_refs.add(ref)
        continue

    labeled_record = labeled_by_ref.get(ref)

    if (
        labeled_record is not None
        and is_positive(labeled_record)
    ):
        true_positive_event_refs.add(ref)


if not true_positive_event_refs:
    raise SystemExit(
        "ERROR: no explicitly malicious event references "
        "could be identified from ranked_anomalies.json "
        "and labeled_events.json"
    )


# ------------------------------------------------------------
# Build category lookup for ground-truth events
# ------------------------------------------------------------

ground_truth_categories = {}

for ref in true_positive_event_refs:
    tokens = set()

    labeled_record = labeled_by_ref.get(ref)

    if labeled_record is not None:
        tokens.update(
            category_tokens(labeled_record)
        )

    for ranked_record in ranked_records:
        if event_ref(ranked_record) == ref:
            tokens.update(
                category_tokens(ranked_record)
            )

    ground_truth_categories[ref] = tokens


# ------------------------------------------------------------
# Read evaluation window from baseline_summary.json
# ------------------------------------------------------------

summary = load_json_or_ndjson(
    BASELINE_SUMMARY
)


def first_string(values):
    for value in values:
        if isinstance(value, str) and value:
            return value

    return None


if not isinstance(summary, dict):
    raise SystemExit(
        "ERROR: baseline_summary.json must be an object"
    )


evaluation = summary.get("evaluation_window")
evaluation_obj = (
    evaluation
    if isinstance(evaluation, dict)
    else {}
)

evaluation_alt = summary.get("evaluation")
evaluation_alt_obj = (
    evaluation_alt
    if isinstance(evaluation_alt, dict)
    else {}
)


evaluation_start = first_string(
    (
        summary.get("evaluation_window_start"),
        summary.get("evaluation_start"),
        evaluation_obj.get("start"),
        evaluation_alt_obj.get("start"),
        evaluation_alt_obj.get("window_start"),
    )
)

evaluation_end = first_string(
    (
        summary.get("evaluation_window_end"),
        summary.get("evaluation_end"),
        evaluation_obj.get("end"),
        evaluation_alt_obj.get("end"),
        evaluation_alt_obj.get("window_end"),
    )
)


if evaluation_start is None or evaluation_end is None:
    raise SystemExit(
        "ERROR: evaluation window not found in "
        "baseline_summary.json"
    )


# ------------------------------------------------------------
# Expand date-only values for the runner
# ------------------------------------------------------------

def runner_boundary(value, is_end=False):
    if (
        len(value) == 10
        and value[4] == "-"
        and value[7] == "-"
    ):
        if is_end:
            return value + "T23:59:59Z"

        return value + "T00:00:00Z"

    return value


runner_start = runner_boundary(
    evaluation_start
)

runner_end = runner_boundary(
    evaluation_end,
    is_end=True,
)

runner_window = (
    f"{runner_start},{runner_end}"
)


# ------------------------------------------------------------
# Load baseline false-positive measurements from T10
# ------------------------------------------------------------

fp_data = load_json_or_ndjson(
    FP_BASELINE
)

fp_records = record_list(
    fp_data
)

fp_by_rule = {}

for record in fp_records:
    if not isinstance(record, dict):
        continue

    rule_id = record.get("rule_id")
    fp_count = record.get("fp_count")

    if rule_id is None:
        continue

    try:
        fp_by_rule[str(rule_id)] = int(
            fp_count
        )

    except (TypeError, ValueError):
        raise SystemExit(
            f"ERROR: invalid fp_count for rule {rule_id}"
        )


# ------------------------------------------------------------
# Enumerate Sigma rules
#
# rules/sigma/*.yml
# rules/sigma/tuned/*.yml
#
# Using max-directory behavior avoids accidentally evaluating
# tuned rules twice.
# ------------------------------------------------------------

rules = []

for suffix in ("*.yml", "*.yaml"):
    rules.extend(
        RULE_DIR.glob(suffix)
    )

if TUNED_DIR.is_dir():
    for suffix in ("*.yml", "*.yaml"):
        rules.extend(
            TUNED_DIR.glob(suffix)
        )

rules = sorted(
    set(rules),
    key=lambda path: str(path),
)


if not rules:
    raise SystemExit(
        "ERROR: no Sigma rules found"
    )


print(
    f"evaluating {len(rules)} rules "
    "against labeled ground truth"
)


# ------------------------------------------------------------
# Load rule
# ------------------------------------------------------------

def load_rule(path):
    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        rule = yaml.safe_load(handle)

    if not isinstance(rule, dict):
        raise ValueError(
            f"{path}: Sigma rule is not a mapping"
        )

    return rule


# ------------------------------------------------------------
# Infer category tokens explicitly encoded by the rule.
#
# We only use:
#
#   event_category
#   canonical_label
#   anomaly_type
#   category
#
# plus logsource.category.
#
# This avoids guessing category from rule title or filename.
# ------------------------------------------------------------

CATEGORY_FIELDS = {
    "event_category",
    "canonical_label",
    "anomaly_type",
    "category",
}


def values_as_tokens(value):
    values = set()

    if isinstance(value, str):
        values.add(
            value.strip().casefold()
        )

    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                values.add(
                    item.strip().casefold()
                )

    return values


def rule_category_tokens(rule):
    tokens = set()

    logsource = rule.get("logsource")

    if isinstance(logsource, dict):
        value = logsource.get("category")

        if isinstance(value, str):
            tokens.add(
                value.strip().casefold()
            )

    detection = rule.get("detection")

    if not isinstance(detection, dict):
        return tokens

    for name, selection in detection.items():

        if name in {
            "condition",
            "timeframe",
        }:
            continue

        selections = (
            selection
            if isinstance(selection, list)
            else [selection]
        )

        for item in selections:
            if not isinstance(item, dict):
                continue

            for field, value in item.items():
                base_field = field.split("|")[0]

                if base_field in CATEGORY_FIELDS:
                    tokens.update(
                        values_as_tokens(value)
                    )

    return tokens


# ------------------------------------------------------------
# Execute one rule using the project runner
# ------------------------------------------------------------

def run_rule(path):
    command = [
        str(RUNNER),
        str(path),
        "--window",
        runner_window,
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if process.returncode != 0:
        raise RuntimeError(
            f"runner failed for {path}:\n"
            f"{process.stderr.strip()}"
        )

    try:
        result = json.loads(
            process.stdout
        )

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"runner returned invalid JSON for {path}"
        ) from exc

    return result


# ------------------------------------------------------------
# Metric helpers
# ------------------------------------------------------------

def ratio(numerator, denominator):
    if denominator == 0:
        return 0.0

    return numerator / denominator


def rounded(value):
    return round(
        value,
        6,
    )


# ------------------------------------------------------------
# Evaluate every rule
# ------------------------------------------------------------

quality_results = []


for rule_path in rules:

    rule = load_rule(
        rule_path
    )

    rule_id = str(
        rule.get("id", "")
    )

    rule_title = str(
        rule.get("title", "")
    )

    level = str(
        rule.get("level", "")
    )

    if rule_id not in fp_by_rule:
        raise SystemExit(
            "ERROR: no baseline fp_count exists for "
            f"{rule_path} (rule id {rule_id}). "
            "Run T10 for this rule before T13."
        )

    baseline_fp = fp_by_rule[
        rule_id
    ]

    result = run_rule(
        rule_path
    )

    matches = result.get(
        "matches",
        [],
    )

    if not isinstance(matches, list):
        raise SystemExit(
            f"ERROR: runner matches is not a list for "
            f"{rule_path}"
        )

    matched_refs = set()

    for match in matches:
        if not isinstance(match, dict):
            continue

        ref = match.get("event_ref")

        if ref is not None:
            matched_refs.add(
                str(ref)
            )


    # --------------------------------------------------------
    # True positives:
    # evaluation matches that intersect confirmed malicious
    # ground truth.
    # --------------------------------------------------------

    tp_refs = (
        matched_refs
        & true_positive_event_refs
    )

    tp_count = len(
        tp_refs
    )


    # --------------------------------------------------------
    # Evaluation false positives:
    # anything matched in evaluation that is not ground truth.
    # --------------------------------------------------------

    evaluation_fp_refs = (
        matched_refs
        - true_positive_event_refs
    )

    evaluation_fp_count = len(
        evaluation_fp_refs
    )


    # --------------------------------------------------------
    # Total FP:
    #
    # clean baseline matches
    # +
    # non-malicious evaluation matches
    # --------------------------------------------------------

    fp_count = (
        baseline_fp
        + evaluation_fp_count
    )


    # --------------------------------------------------------
    # Determine this rule's category.
    #
    # Start with category information encoded directly in
    # the Sigma rule.
    # --------------------------------------------------------

    categories = rule_category_tokens(
        rule
    )


    # --------------------------------------------------------
    # Add category information from labeled events that this
    # rule actually matched.
    #
    # This is useful for rules such as process detections that
    # do not contain event_category directly.
    # --------------------------------------------------------

    for ref in matched_refs:

        labeled_record = labeled_by_ref.get(
            ref
        )

        if labeled_record is not None:
            categories.update(
                category_tokens(
                    labeled_record
                )
            )


    # --------------------------------------------------------
    # Add categories of true-positive events detected by the
    # rule.
    # --------------------------------------------------------

    for ref in tp_refs:
        categories.update(
            ground_truth_categories.get(
                ref,
                set(),
            )
        )


    # --------------------------------------------------------
    # Ground truth for the same category.
    #
    # Only ground-truth events sharing one of the rule's
    # explicit/data-derived category tokens belong in the
    # recall denominator.
    # --------------------------------------------------------

    same_category_gt = set()

    if categories:

        for ref in true_positive_event_refs:

            gt_categories = (
                ground_truth_categories.get(
                    ref,
                    set(),
                )
            )

            if categories & gt_categories:
                same_category_gt.add(ref)

    else:
        # If the category cannot be established from either
        # the rule or labeled evidence, do not invent one.
        #
        # TP events themselves remain part of the category
        # set so that recall does not become inconsistent.
        same_category_gt.update(
            tp_refs
        )


    # A detected TP must always be in the recall universe.
    same_category_gt.update(
        tp_refs
    )


    # --------------------------------------------------------
    # False negatives:
    # malicious events in this rule's category that the rule
    # did not match.
    # --------------------------------------------------------

    fn_refs = (
        same_category_gt
        - tp_refs
    )

    fn_count = len(
        fn_refs
    )


    # --------------------------------------------------------
    # Precision / Recall / F1
    # --------------------------------------------------------

    precision = ratio(
        tp_count,
        tp_count + fp_count,
    )

    recall = ratio(
        tp_count,
        tp_count + fn_count,
    )

    if precision + recall == 0:
        f1 = 0.0

    else:
        f1 = (
            2
            * precision
            * recall
            / (precision + recall)
        )


    # --------------------------------------------------------
    # Store relative path for readable deterministic output.
    # --------------------------------------------------------

    try:
        relative_rule = rule_path.relative_to(
            RULE_DIR.parent.parent
        )

    except ValueError:
        relative_rule = rule_path


    quality_results.append(
        {
            "rule_id": rule_id,
            "rule_title": rule_title,
            "rule_file": str(relative_rule),
            "level": level,
            "tp_count": tp_count,
            "fp_count": fp_count,
            "baseline_fp_count": baseline_fp,
            "evaluation_fp_count": evaluation_fp_count,
            "fn_count": fn_count,
            "precision": rounded(precision),
            "recall": rounded(recall),
            "f1": rounded(f1),
            "evaluation_window_start": evaluation_start,
            "evaluation_window_end": evaluation_end,
            "category_ground_truth_count": len(
                same_category_gt
            ),
            "categories": sorted(
                categories
            ),
        }
    )


# ------------------------------------------------------------
# Deterministic JSON output
#
# Keep normal catalog/file order in the artifact itself.
# ------------------------------------------------------------

quality_results.sort(
    key=lambda item: item["rule_file"]
)

with OUTPUT.open(
    "w",
    encoding="utf-8",
) as handle:
    json.dump(
        quality_results,
        handle,
        indent=2,
        ensure_ascii=False,
    )

    handle.write("\n")


# ------------------------------------------------------------
# Console presentation
# ------------------------------------------------------------

def short_name(entry):
    stem = Path(
        entry["rule_file"]
    ).stem

    if "_" in stem:
        number, name = stem.split(
            "_",
            1,
        )

        return number, name

    return "", stem


def quality_mark(f1):
    if f1 >= 0.7:
        return "[STRONG]"

    if f1 < 0.3:
        return "[WEAK]"

    return ""


# Highest F1 first.
strongest = sorted(
    quality_results,
    key=lambda item: (
        -item["f1"],
        -item["precision"],
        -item["recall"],
        item["rule_file"],
    ),
)[:5]


# Lowest F1 first.
weakest = sorted(
    quality_results,
    key=lambda item: (
        item["f1"],
        item["precision"],
        item["recall"],
        item["rule_file"],
    ),
)[:5]


print("strongest")

for entry in strongest:

    number, name = short_name(
        entry
    )

    mark = quality_mark(
        entry["f1"]
    )

    print(
        f"  {number:<3} "
        f"{name:<30} "
        f"f1={entry['f1']:.2f}  "
        f"p={entry['precision']:.2f} "
        f"r={entry['recall']:.2f}"
        + (
            f"  {mark}"
            if mark
            else ""
        )
    )


print("weakest")

for entry in weakest:

    number, name = short_name(
        entry
    )

    mark = quality_mark(
        entry["f1"]
    )

    print(
        f"  {number:<3} "
        f"{name:<30} "
        f"f1={entry['f1']:.2f}  "
        f"p={entry['precision']:.2f} "
        f"r={entry['recall']:.2f}"
        + (
            f"  {mark}"
            if mark
            else ""
        )
    )


print("rule_quality.json written")

PY
