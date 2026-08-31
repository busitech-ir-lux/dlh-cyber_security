#!/bin/bash
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

SCHEMA_FILE="$WORKDIR/event_schema.json"
EVENTS_FILE="$WORKDIR/normalized_events.json"
REPORT_FILE="$WORKDIR/validation_report.json"

for file in "$SCHEMA_FILE" "$EVENTS_FILE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file: $file" >&2
        exit 1
    fi
done


python3 - \
    "$SCHEMA_FILE" \
    "$EVENTS_FILE" \
    "$REPORT_FILE" <<'PYTHON'

import json
import sys
from datetime import datetime


schema_file = sys.argv[1]
events_file = sys.argv[2]
report_file = sys.argv[3]


# ------------------------------------------------------------
# Load schema
# ------------------------------------------------------------

with open(
    schema_file,
    "r",
    encoding="utf-8"
) as f:
    schema = json.load(f)

fields = schema["fields"]


# ------------------------------------------------------------
# Type validation
# ------------------------------------------------------------

def valid_timestamp(value):
    if not isinstance(value, str):
        return False

    try:
        text = value

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        datetime.fromisoformat(text)
        return True

    except ValueError:
        return False


def matches_type(value, declared_type):
    if value is None:
        return True

    if declared_type == "string":
        return isinstance(value, str)

    if declared_type == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
        )

    if declared_type == "float":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )

    if declared_type == "boolean":
        return isinstance(value, bool)

    if declared_type == "timestamp":
        return valid_timestamp(value)

    if declared_type == "object":
        return isinstance(value, dict)

    if declared_type == "array":
        return isinstance(value, list)

    return False


# ------------------------------------------------------------
# Counters
# ------------------------------------------------------------

total = 0
compliant = 0
non_compliant = 0

field_present = {
    field["name"]: 0
    for field in fields
}

examples = []


# ------------------------------------------------------------
# Validate normalized NDJSON
# ------------------------------------------------------------

with open(
    events_file,
    "r",
    encoding="utf-8",
    errors="replace"
) as f:

    for line_number, line in enumerate(
        f,
        start=1
    ):

        line = line.strip()

        if not line:
            continue

        total += 1

        reasons = []


        # ----------------------------------------------------
        # Parse record
        # ----------------------------------------------------

        try:
            record = json.loads(line)

        except json.JSONDecodeError:

            reasons.append("invalid JSON")

            non_compliant += 1

            if len(examples) < 20:
                examples.append({
                    "line": line_number,
                    "reason": reasons,
                    "record": line
                })

            continue


        if not isinstance(record, dict):
            reasons.append("record is not an object")


        # ----------------------------------------------------
        # Validate fields
        # ----------------------------------------------------

        if isinstance(record, dict):

            for field in fields:

                name = field["name"]
                declared_type = field["type"]
                required = field["required"]

                value = record.get(name)


                # Completeness means present and non-null.
                if name in record and value is not None:
                    field_present[name] += 1


                # Required fields must exist and be non-null.
                if required:

                    if name not in record:
                        reasons.append(
                            f"missing required field: {name}"
                        )
                        continue

                    if value is None:
                        reasons.append(
                            f"required field is null: {name}"
                        )
                        continue


                # Optional null is allowed.
                if value is None:
                    continue


                # Type check.
                if not matches_type(
                    value,
                    declared_type
                ):
                    reasons.append(
                        f"type mismatch for {name}: "
                        f"expected {declared_type}"
                    )


        # ----------------------------------------------------
        # Record result
        # ----------------------------------------------------

        if reasons:
            non_compliant += 1

            if len(examples) < 20:
                examples.append({
                    "line": line_number,
                    "reason": reasons,
                    "record": record
                })

        else:
            compliant += 1


# ------------------------------------------------------------
# Completeness percentages
# ------------------------------------------------------------

completeness = {}

for field in fields:

    name = field["name"]

    if total == 0:
        percentage = 0.0
    else:
        percentage = (
            field_present[name] / total
        ) * 100

    completeness[name] = round(
        percentage,
        2
    )


# ------------------------------------------------------------
# Overall compliance
# ------------------------------------------------------------

if total == 0:
    compliance_percent = 0.0
else:
    compliance_percent = (
        compliant / total
    ) * 100


# ------------------------------------------------------------
# Write validation report
# ------------------------------------------------------------

report = {
    "records_checked": total,
    "fully_compliant": compliant,
    "non_compliant": non_compliant,
    "compliance_percent": round(
        compliance_percent,
        2
    ),
    "per_field_completeness": completeness,
    "non_compliant_examples": examples
}

with open(
    report_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=2
    )

    f.write("\n")


# ------------------------------------------------------------
# Human-readable output
# ------------------------------------------------------------

print(
    f"records checked       : {total}"
)

print(
    f"fully compliant       : "
    f"{compliant} "
    f"({compliance_percent:.2f}%)"
)

print(
    f"non-compliant         : "
    f"{non_compliant}"
)

print("per-field completeness:")

for field in fields:

    name = field["name"]

    print(
        f"  {name:<16} "
        f"{completeness[name]:6.2f}%"
    )

print("validation_report.json written")


# ------------------------------------------------------------
# Exit code
#
# Above 99% = pass.
# Exactly 99% or lower = fail.
# ------------------------------------------------------------

if compliance_percent > 99.0:
    sys.exit(0)

sys.exit(1)

PYTHON
