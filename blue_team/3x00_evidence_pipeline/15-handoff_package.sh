#!/bin/bash
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="$HANDOFF_DIR/MANIFEST.json"
MANIFEST_TMP=$(mktemp)

trap 'rm -f "$MANIFEST_TMP"' EXIT


# ------------------------------------------------------------
# Required files
# ------------------------------------------------------------

DATA_FILES=(
    normalized_events.json
    enriched_events.json
    timeline_index.json
    network_events.json
    quarantine.json
)

REPORT_FILES=(
    source_inventory.json
    validation_report.json
    cleaning_log.json
    source_stats.json
    pipeline_test_report.json
)

PIPELINE_FILES=(
    evidence_pipeline.sh
    0-source_inventory.sh
    1-telemetry_import.sh
    2-windows_parse.sh
    3-linux_parse.sh
    5-normalize.sh
    6-network_normalize.sh
    7-schema_validate.sh
    8-data_quality.sh
    9-enrich.sh
    10-timeline.sh
    11-source_stats.sh
)


# ------------------------------------------------------------
# Rebuild handoff directory
# ------------------------------------------------------------

rm -rf "$HANDOFF_DIR"

mkdir -p \
    "$HANDOFF_DIR/data" \
    "$HANDOFF_DIR/context" \
    "$HANDOFF_DIR/reports" \
    "$HANDOFF_DIR/schema" \
    "$HANDOFF_DIR/pipeline"


# ------------------------------------------------------------
# Copy helper
# ------------------------------------------------------------

copy_required() {
    src="$1"
    dst="$2"

    if [[ ! -s "$src" ]]; then
        echo "ERROR: Missing or empty file: $src" >&2
        exit 1
    fi

    cp "$src" "$dst"
}


# ------------------------------------------------------------
# Copy data files
# ------------------------------------------------------------

for file in "${DATA_FILES[@]}"
do
    copy_required \
        "$WORKDIR/$file" \
        "$HANDOFF_DIR/data/$file"
done

echo "copying data/       ... ${#DATA_FILES[@]} files"


# ------------------------------------------------------------
# Copy context files
# ------------------------------------------------------------

copy_required \
    "$EVIDENCE_PACK/context/asset_inventory.json" \
    "$HANDOFF_DIR/context/asset_inventory.json"

copy_required \
    "$EVIDENCE_PACK/context/network_zones.json" \
    "$HANDOFF_DIR/context/network_zones.json"

echo "copying context/    ... 2 files"


# ------------------------------------------------------------
# Copy reports
# ------------------------------------------------------------

for file in "${REPORT_FILES[@]}"
do
    copy_required \
        "$WORKDIR/$file" \
        "$HANDOFF_DIR/reports/$file"
done

echo "copying reports/    ... ${#REPORT_FILES[@]} files"


# ------------------------------------------------------------
# Copy schema
# ------------------------------------------------------------

copy_required \
    "$WORKDIR/event_schema.json" \
    "$HANDOFF_DIR/schema/event_schema.json"

echo "copying schema/     ... 1 file"


# ------------------------------------------------------------
# Copy pipeline scripts
# ------------------------------------------------------------

for file in "${PIPELINE_FILES[@]}"
do
    copy_required \
        "$WORKDIR/$file" \
        "$HANDOFF_DIR/pipeline/$file"
done

echo "copying pipeline/   ... ${#PIPELINE_FILES[@]} files"


# ------------------------------------------------------------
# Copy specification
# ------------------------------------------------------------

copy_required \
    "$WORKDIR/pipeline_spec.md" \
    "$HANDOFF_DIR/pipeline_spec.md"

echo "copying spec        ... 1 file"


# ------------------------------------------------------------
# Generate MANIFEST.json
#
# MANIFEST contains the 26 handoff files, excluding itself.
# ------------------------------------------------------------

while IFS= read -r file
do
    relative="${file#"$HANDOFF_DIR"/}"
    size=$(stat -c '%s' "$file")
    hash=$(sha256sum "$file" | awk '{print $1}')

    jq -n \
        --arg path "$relative" \
        --argjson size "$size" \
        --arg sha256 "$hash" \
        '{
            path: $path,
            size_bytes: $size,
            sha256: $sha256
        }' >> "$MANIFEST_TMP"

done < <(
    find "$HANDOFF_DIR" \
        -type f \
        ! -name MANIFEST.json \
        | sort
)

jq -s '.' "$MANIFEST_TMP" > "$MANIFEST"

MANIFEST_COUNT=$(jq 'length' "$MANIFEST")

echo "MANIFEST.json       : $MANIFEST_COUNT entries"


# ------------------------------------------------------------
# Sanity check
#
# All expected files plus MANIFEST must exist and be non-empty.
# ------------------------------------------------------------

EXPECTED_FILES=(
    data/normalized_events.json
    data/enriched_events.json
    data/timeline_index.json
    data/network_events.json
    data/quarantine.json

    context/asset_inventory.json
    context/network_zones.json

    reports/source_inventory.json
    reports/validation_report.json
    reports/cleaning_log.json
    reports/source_stats.json
    reports/pipeline_test_report.json

    schema/event_schema.json

    pipeline/evidence_pipeline.sh
    pipeline/0-source_inventory.sh
    pipeline/1-telemetry_import.sh
    pipeline/2-windows_parse.sh
    pipeline/3-linux_parse.sh
    pipeline/5-normalize.sh
    pipeline/6-network_normalize.sh
    pipeline/7-schema_validate.sh
    pipeline/8-data_quality.sh
    pipeline/9-enrich.sh
    pipeline/10-timeline.sh
    pipeline/11-source_stats.sh

    pipeline_spec.md
    MANIFEST.json
)

for file in "${EXPECTED_FILES[@]}"
do
    if [[ ! -s "$HANDOFF_DIR/$file" ]]; then
        echo "handoff sanity check: FAILED"
        echo "missing or empty: $file"
        exit 1
    fi
done


# Manifest should contain exactly 26 entries.
if [[ "$MANIFEST_COUNT" -ne 26 ]]; then
    echo "handoff sanity check: FAILED"
    echo "expected 26 manifest entries, found $MANIFEST_COUNT"
    exit 1
fi

echo "handoff sanity check: ok"
echo "evidence_handoff/ ready"
