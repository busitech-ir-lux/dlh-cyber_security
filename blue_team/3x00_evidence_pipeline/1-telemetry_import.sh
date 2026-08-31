#!/bin/bash
set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
TELEMETRY_DIR="$EVIDENCE_PACK/student_telemetry"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/import_validation.json}"

python3 - "$TELEMETRY_DIR" "$OUTPUT_FILE" <<'PYTHON'
import json
import os
import sys


telemetry_dir = sys.argv[1]
output_file = sys.argv[2]

required_files = [
    "windows_events.json",
    "linux_events.json",
    "attack_ground_truth.json"
]

required_fields = [
    "timestamp",
    "hostname",
    "source_type",
    "event_category"
]


# ------------------------------------------------------------
# Parse JSON array, single object, or NDJSON.
# Any malformed JSON causes validation failure.
# ------------------------------------------------------------

def read_records(path):
    with open(
        path,
        "r",
        encoding="utf-8",
        errors="strict"
    ) as f:
        content = f.read()

    if not content.strip():
        raise ValueError("file is empty")

    # Normal JSON first.
    try:
        data = json.loads(content)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

        raise ValueError("JSON does not contain records")

    except json.JSONDecodeError:
        pass

    # NDJSON fallback.
    records = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1
    ):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON on line {line_number}"
            ) from exc

        if not isinstance(record, dict):
            raise ValueError(
                f"record on line {line_number} is not an object"
            )

        records.append(record)

    if not records:
        raise ValueError("file contains no records")

    return records


# ------------------------------------------------------------
# Validate one telemetry file.
# ------------------------------------------------------------

def validate_file(filename):
    path = os.path.join(
        telemetry_dir,
        filename
    )

    result = {
        "file": filename,
        "status": "fail",
        "record_count": 0,
        "source_types": []
    }

    if not os.path.isfile(path):
        result["reason"] = "file not found"
        return result

    try:
        records = read_records(path)
    except (ValueError, UnicodeError) as exc:
        result["reason"] = str(exc)
        return result

    result["record_count"] = len(records)

    # Windows and Linux telemetry have the required contract.
    if filename in (
        "windows_events.json",
        "linux_events.json"
    ):
        for index, record in enumerate(
            records,
            start=1
        ):
            if not isinstance(record, dict):
                result["reason"] = (
                    f"record {index} is not an object"
                )
                return result

            missing = [
                field
                for field in required_fields
                if field not in record
            ]

            if missing:
                result["reason"] = (
                    f"record {index} missing fields: "
                    + ", ".join(missing)
                )
                return result

        result["source_types"] = sorted({
            str(record["source_type"])
            for record in records
        })

    result["status"] = "pass"
    return result


# ------------------------------------------------------------
# Validate all three required files.
# ------------------------------------------------------------

results = []

for filename in required_files:
    results.append(
        validate_file(filename)
    )


passed = sum(
    1
    for result in results
    if result["status"] == "pass"
)

overall_pass = passed == len(required_files)


# ------------------------------------------------------------
# Write machine-readable report.
# ------------------------------------------------------------

report = {
    "status": "pass" if overall_pass else "fail",
    "files_validated": passed,
    "files_required": len(required_files),
    "files": results
}

with open(
    output_file,
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
# Human-readable output.
# ------------------------------------------------------------

for result in results:
    filename = result["file"]
    count = result["record_count"]

    if result["status"] == "pass":
        if result["source_types"]:
            sources = ", ".join(
                result["source_types"]
            )

            print(
                f"[OK] {filename:<25} "
                f"{count} records    "
                f"sources: {sources}"
            )
        else:
            print(
                f"[OK] {filename:<25} "
                f"{count} records"
            )

    else:
        print(
            f"[FAIL] {filename:<23} "
            f"{result.get('reason', 'validation failed')}"
        )


if overall_pass:
    print(
        f"{passed}/{len(required_files)} files validated. "
        "Import OK."
    )
    sys.exit(0)

print(
    f"{passed}/{len(required_files)} files validated. "
    "Import FAILED."
)
sys.exit(1)

PYTHON
