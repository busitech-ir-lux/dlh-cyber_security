#!/bin/bash

# ============================================================
# Task 16 - Baseline Package Assembly
#
# Builds the final self-contained baseline_package/ directory.
#
# The package contains exactly:
#   6 baseline files
#   5 anomaly files
#   2 taxonomy files
#   3 report files
#   13 toolkit scripts
#
# Total manifest entries: 29
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package/}"

# Resolve the directory containing this script.
# This lets the script work even when launched from another
# current working directory.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

FINAL_PKG="${BASELINE_PKG%/}"


# Protect against an unsafe package path.
if [ -z "$FINAL_PKG" ] || [ "$FINAL_PKG" = "/" ]; then
    echo "Error: unsafe BASELINE_PKG path" >&2
    exit 1
fi


# ============================================================
# 2. Exact package file lists
# ============================================================

BASELINE_FILES=(
    "baseline_auth.json"
    "baseline_process.json"
    "baseline_network.json"
    "baseline_file.json"
    "temporal_profile.json"
    "baseline_summary.json"
)

ANOMALY_FILES=(
    "anomalies_auth.json"
    "anomalies_process.json"
    "anomalies_network.json"
    "correlated_anomalies.json"
    "ranked_anomalies.json"
)

TAXONOMY_FILES=(
    "event_taxonomy.json"
    "labeled_events.json"
)

REPORT_FILES=(
    "format_analysis.json"
    "field_index.json"
    "baseline_validation.json"
)

TOOLKIT_FILES=(
    "2-query_toolkit.sh"
    "4-baseline_auth.sh"
    "5-baseline_process.sh"
    "6-baseline_network.sh"
    "7-baseline_file.sh"
    "8-temporal_profile.sh"
    "9-baseline_summary.sh"
    "10-anomalies_auth.sh"
    "11-anomalies_process.sh"
    "12-anomalies_network.sh"
    "13-correlate_anomalies.sh"
    "14-rank_anomalies.sh"
    "15-baseline_validation.sh"
)


# ============================================================
# 3. Verify every required source file exists
#
# Do this BEFORE modifying the existing package.
# ============================================================

missing_files=0


check_files() {
    local file

    for file in "$@"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            echo "Error: required file missing: $file" >&2
            missing_files=$((missing_files + 1))
        fi
    done
}


check_files "${BASELINE_FILES[@]}"
check_files "${ANOMALY_FILES[@]}"
check_files "${TAXONOMY_FILES[@]}"
check_files "${REPORT_FILES[@]}"
check_files "${TOOLKIT_FILES[@]}"


if [ "$missing_files" -ne 0 ]; then
    echo "Error: $missing_files required file(s) missing" >&2
    exit 1
fi


# ============================================================
# 4. Prepare a temporary package directory
#
# We build everything here first.
#
# The existing baseline_package is only replaced after the new
# package passes all sanity checks.
# ============================================================

PARENT_DIR="$(dirname -- "$FINAL_PKG")"
STAGING_DIR="${FINAL_PKG}.tmp.$$"

mkdir -p -- "$PARENT_DIR"

rm -rf -- "$STAGING_DIR"

mkdir -p \
    "$STAGING_DIR/baselines" \
    "$STAGING_DIR/anomalies" \
    "$STAGING_DIR/taxonomy" \
    "$STAGING_DIR/reports" \
    "$STAGING_DIR/toolkit"


# Remove temporary directory if the script fails.
cleanup() {
    rm -rf -- "$STAGING_DIR"
}

trap cleanup EXIT


# ============================================================
# 5. Copy helper
# ============================================================

copy_group() {
    local destination="$1"
    shift

    local files=("$@")
    local file

    for file in "${files[@]}"; do
        cp -- \
            "$SCRIPT_DIR/$file" \
            "$STAGING_DIR/$destination/$file"
    done

    printf "copying %-11s ... %d files\n" \
        "$destination" \
        "${#files[@]}"
}


# ============================================================
# 6. Copy all required artifacts
# ============================================================

copy_group \
    "baselines" \
    "${BASELINE_FILES[@]}"

copy_group \
    "anomalies" \
    "${ANOMALY_FILES[@]}"

copy_group \
    "taxonomy" \
    "${TAXONOMY_FILES[@]}"

copy_group \
    "reports" \
    "${REPORT_FILES[@]}"

copy_group \
    "toolkit" \
    "${TOOLKIT_FILES[@]}"


# Ensure toolkit scripts are directly executable.
chmod +x "$STAGING_DIR"/toolkit/*.sh


# ============================================================
# 7. Generate MANIFEST.json
#
# Important:
# MANIFEST.json does NOT hash itself.
#
# Therefore:
#
#   6 + 5 + 2 + 3 + 13 = 29 entries
#
# No creation timestamp is included because that would make
# repeated runs produce different output.
# ============================================================

python3 -W error - "$STAGING_DIR" <<'PYTHON'

import hashlib
import json
import os
import sys


package_dir = sys.argv[1]
manifest_path = os.path.join(
    package_dir,
    "MANIFEST.json"
)


# ============================================================
# Calculate SHA-256
# ============================================================

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


# ============================================================
# Discover package files
#
# MANIFEST.json itself is deliberately excluded.
# ============================================================

entries = []


for root, directories, files in os.walk(package_dir):

    # Deterministic traversal.
    directories.sort()
    files.sort()

    for filename in files:

        full_path = os.path.join(
            root,
            filename
        )

        relative_path = os.path.relpath(
            full_path,
            package_dir
        )

        # Always use forward slashes in the manifest.
        relative_path = relative_path.replace(
            os.sep,
            "/"
        )

        if relative_path == "MANIFEST.json":
            continue

        entries.append(
            {
                "path": relative_path,
                "size": os.path.getsize(
                    full_path
                ),
                "sha256": sha256_file(
                    full_path
                ),
            }
        )


# Sort explicitly by path.
entries.sort(
    key=lambda item: item["path"]
)


manifest = {
    "entry_count": len(entries),
    "files": entries,
}


# ============================================================
# Write deterministic manifest
# ============================================================

temporary_manifest = (
    manifest_path + ".tmp"
)


with open(
    temporary_manifest,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        manifest,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Project requirement: every file ends with newline.
    handle.write("\n")


os.replace(
    temporary_manifest,
    manifest_path
)

PYTHON


printf "MANIFEST.json       : %d entries\n" 29


# ============================================================
# 8. Validate shell syntax of every packaged toolkit script
# ============================================================

for script in "$STAGING_DIR"/toolkit/*.sh; do
    bash -n "$script"
done


# ============================================================
# 9. Final package sanity check
#
# Checks:
#   - exactly 29 files are represented
#   - no expected file is missing
#   - no unexpected package file is present
#   - file sizes match the manifest
#   - SHA-256 hashes match
#   - JSON/NDJSON artifacts are parseable
# ============================================================

python3 -W error - "$STAGING_DIR" <<'PYTHON'

import hashlib
import json
import os
import sys


package_dir = sys.argv[1]


EXPECTED_PATHS = {
    # Baselines
    "baselines/baseline_auth.json",
    "baselines/baseline_process.json",
    "baselines/baseline_network.json",
    "baselines/baseline_file.json",
    "baselines/temporal_profile.json",
    "baselines/baseline_summary.json",

    # Anomalies
    "anomalies/anomalies_auth.json",
    "anomalies/anomalies_process.json",
    "anomalies/anomalies_network.json",
    "anomalies/correlated_anomalies.json",
    "anomalies/ranked_anomalies.json",

    # Taxonomy
    "taxonomy/event_taxonomy.json",
    "taxonomy/labeled_events.json",

    # Reports
    "reports/format_analysis.json",
    "reports/field_index.json",
    "reports/baseline_validation.json",

    # Toolkit
    "toolkit/2-query_toolkit.sh",
    "toolkit/4-baseline_auth.sh",
    "toolkit/5-baseline_process.sh",
    "toolkit/6-baseline_network.sh",
    "toolkit/7-baseline_file.sh",
    "toolkit/8-temporal_profile.sh",
    "toolkit/9-baseline_summary.sh",
    "toolkit/10-anomalies_auth.sh",
    "toolkit/11-anomalies_process.sh",
    "toolkit/12-anomalies_network.sh",
    "toolkit/13-correlate_anomalies.sh",
    "toolkit/14-rank_anomalies.sh",
    "toolkit/15-baseline_validation.sh",
}


# ============================================================
# SHA-256 helper
# ============================================================

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


# ============================================================
# JSON / NDJSON validation helper
# ============================================================

def validate_json_file(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as handle:
        text = handle.read().strip()

    if not text:
        raise ValueError(
            f"empty JSON file: {path}"
        )

    # First try standard JSON.
    try:
        json.loads(text)
        return

    except json.JSONDecodeError:
        pass


    # If standard JSON fails, accept valid NDJSON.
    valid_records = 0

    for line_number, line in enumerate(
        text.splitlines(),
        start=1
    ):
        line = line.strip()

        if not line:
            continue

        try:
            json.loads(line)

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON in {path} "
                f"line {line_number}: {exc}"
            ) from exc

        valid_records += 1


    if valid_records == 0:
        raise ValueError(
            f"no valid records in {path}"
        )


# ============================================================
# Read manifest
# ============================================================

manifest_path = os.path.join(
    package_dir,
    "MANIFEST.json"
)


with open(
    manifest_path,
    "r",
    encoding="utf-8"
) as handle:
    manifest = json.load(handle)


entries = manifest.get(
    "files"
)


if not isinstance(entries, list):
    raise ValueError(
        "MANIFEST.json files field must be a list"
    )


if manifest.get("entry_count") != 29:
    raise ValueError(
        "MANIFEST.json entry_count must be 29"
    )


if len(entries) != 29:
    raise ValueError(
        "MANIFEST.json must contain exactly 29 entries"
    )


# ============================================================
# Compare manifest paths with exact required layout
# ============================================================

manifest_paths = {
    entry.get("path")
    for entry in entries
}


if manifest_paths != EXPECTED_PATHS:

    missing = sorted(
        EXPECTED_PATHS - manifest_paths
    )

    unexpected = sorted(
        manifest_paths - EXPECTED_PATHS
    )

    if missing:
        raise ValueError(
            "manifest missing required files: "
            + ", ".join(missing)
        )

    if unexpected:
        raise ValueError(
            "manifest contains unexpected files: "
            + ", ".join(unexpected)
        )


# ============================================================
# Verify every manifest entry
# ============================================================

for entry in entries:

    relative_path = entry.get(
        "path"
    )

    expected_size = entry.get(
        "size"
    )

    expected_hash = entry.get(
        "sha256"
    )


    full_path = os.path.join(
        package_dir,
        relative_path
    )


    if not os.path.isfile(full_path):
        raise ValueError(
            f"missing package file: {relative_path}"
        )


    actual_size = os.path.getsize(
        full_path
    )


    if actual_size != expected_size:
        raise ValueError(
            f"size mismatch: {relative_path}"
        )


    actual_hash = sha256_file(
        full_path
    )


    if actual_hash != expected_hash:
        raise ValueError(
            f"sha256 mismatch: {relative_path}"
        )


    # Validate all JSON artifacts.
    if relative_path.endswith(".json"):
        validate_json_file(
            full_path
        )


# ============================================================
# Check that there are no extra non-manifest files
# ============================================================

actual_paths = set()


for root, directories, files in os.walk(
    package_dir
):
    directories.sort()
    files.sort()

    for filename in files:

        full_path = os.path.join(
            root,
            filename
        )

        relative_path = os.path.relpath(
            full_path,
            package_dir
        ).replace(
            os.sep,
            "/"
        )

        if relative_path == "MANIFEST.json":
            continue

        actual_paths.add(
            relative_path
        )


if actual_paths != EXPECTED_PATHS:
    raise ValueError(
        "package layout does not exactly match specification"
    )

PYTHON


printf "sanity check        : ok\n"


# ============================================================
# 10. Replace the final package
#
# Only do this after all sanity checks pass.
# ============================================================

rm -rf -- "$FINAL_PKG"

mv -- \
    "$STAGING_DIR" \
    "$FINAL_PKG"


# Staging directory no longer exists, so disable cleanup trap.
trap - EXIT


# ============================================================
# 11. Final message
# ============================================================

printf "baseline_package/ ready\n"
