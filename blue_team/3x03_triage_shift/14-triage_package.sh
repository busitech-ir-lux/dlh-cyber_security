#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# Package location
# ------------------------------------------------------------

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
TRIAGE_PKG="${TRIAGE_PKG%/}"

# Safety check before removing an old package.
[[ -n "$TRIAGE_PKG" && "$TRIAGE_PKG" != "/" ]] || {
    echo "ERROR: invalid TRIAGE_PKG" >&2
    exit 1
}

# ------------------------------------------------------------
# Required source files
# ------------------------------------------------------------

tickets=(
    "tickets/batch1_clearcut_tp.json"
    "tickets/batch2_clearcut_fp.json"
    "tickets/batch3_benign.json"
    "tickets/batch4_auth.json"
    "tickets/batch5_proc_net.json"
    "tickets/batch6_incidents.json"
    "tickets/batch7_overrides.json"
)

runtime=(
    "0-queue_assessment.sh"
    "2-context_assembly.sh"
    "3-triage_clearcut_tp.sh"
    "4-triage_clearcut_fp.sh"
    "5-triage_benign.sh"
    "6-triage_ambiguous_auth.sh"
    "7-triage_ambiguous_proc_net.sh"
    "8-triage_correlation.sh"
    "9-triage_priority_conflicts.sh"
    "10-fp_tuning.sh"
    "11-incident_assembly.sh"
    "12-shift_metrics.sh"
)

other_files=(
    "incidents.json"
    "tuning_recommendations.json"
    "queue_assessment.json"
    "shift_metrics.json"
    "shift_report.md"
    "triage_methodology.md"
)

# ------------------------------------------------------------
# Verify everything exists before copying
# ------------------------------------------------------------

for file in "${tickets[@]}" "${runtime[@]}" "${other_files[@]}"; do
    [[ -s "$file" ]] || {
        echo "ERROR: required file missing or empty: $file" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Create clean package structure
# ------------------------------------------------------------

rm -rf "$TRIAGE_PKG"

mkdir -p \
    "$TRIAGE_PKG/tickets" \
    "$TRIAGE_PKG/incidents" \
    "$TRIAGE_PKG/tuning" \
    "$TRIAGE_PKG/metrics" \
    "$TRIAGE_PKG/reports" \
    "$TRIAGE_PKG/spec" \
    "$TRIAGE_PKG/runtime"

# ------------------------------------------------------------
# Copy tickets
# ------------------------------------------------------------

for file in "${tickets[@]}"; do
    cp "$file" "$TRIAGE_PKG/tickets/"
done

echo "copying tickets     ... ${#tickets[@]} files"

# ------------------------------------------------------------
# Copy incidents
# ------------------------------------------------------------

cp "incidents.json" \
    "$TRIAGE_PKG/incidents/incidents.json"

echo "copying incidents   ... 1 file"

# ------------------------------------------------------------
# Copy tuning recommendations
# ------------------------------------------------------------

cp "tuning_recommendations.json" \
    "$TRIAGE_PKG/tuning/tuning_recommendations.json"

echo "copying tuning      ... 1 file"

# ------------------------------------------------------------
# Copy metrics
# ------------------------------------------------------------

cp "queue_assessment.json" \
    "$TRIAGE_PKG/metrics/queue_assessment.json"

cp "shift_metrics.json" \
    "$TRIAGE_PKG/metrics/shift_metrics.json"

echo "copying metrics     ... 2 files"

# ------------------------------------------------------------
# Copy report
# ------------------------------------------------------------

cp "shift_report.md" \
    "$TRIAGE_PKG/reports/shift_report.md"

echo "copying reports     ... 1 file"

# ------------------------------------------------------------
# Copy methodology
# ------------------------------------------------------------

cp "triage_methodology.md" \
    "$TRIAGE_PKG/spec/triage_methodology.md"

echo "copying spec        ... 1 file"

# ------------------------------------------------------------
# Copy runtime scripts
# ------------------------------------------------------------

for file in "${runtime[@]}"; do
    cp "$file" "$TRIAGE_PKG/runtime/"
done

echo "copying runtime     ... ${#runtime[@]} files"

# ------------------------------------------------------------
# Sanity check copied files
# ------------------------------------------------------------

required_package_files=(
    "tickets/batch1_clearcut_tp.json"
    "tickets/batch2_clearcut_fp.json"
    "tickets/batch3_benign.json"
    "tickets/batch4_auth.json"
    "tickets/batch5_proc_net.json"
    "tickets/batch6_incidents.json"
    "tickets/batch7_overrides.json"
    "incidents/incidents.json"
    "tuning/tuning_recommendations.json"
    "metrics/queue_assessment.json"
    "metrics/shift_metrics.json"
    "reports/shift_report.md"
    "spec/triage_methodology.md"
)

for file in "${runtime[@]}"; do
    required_package_files+=("runtime/$file")
done

for file in "${required_package_files[@]}"; do
    [[ -s "$TRIAGE_PKG/$file" ]] || {
        echo "ERROR: package file missing or empty: $file" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Generate MANIFEST.json
# ------------------------------------------------------------

MANIFEST_TMP="$TRIAGE_PKG/.manifest.tmp"
: > "$MANIFEST_TMP"

for file in "${required_package_files[@]}"; do
    full_path="$TRIAGE_PKG/$file"

    size="$(stat -c '%s' "$full_path")"
    sha256="$(sha256sum "$full_path" | awk '{print $1}')"

    jq -n \
        --arg path "$file" \
        --argjson size "$size" \
        --arg sha256 "$sha256" \
        '{
            path: $path,
            size: $size,
            sha256: $sha256
        }' >> "$MANIFEST_TMP"
done

jq -s '.' "$MANIFEST_TMP" > "$TRIAGE_PKG/MANIFEST.json"
rm -f "$MANIFEST_TMP"

# ------------------------------------------------------------
# Final validation
# ------------------------------------------------------------

MANIFEST_COUNT="$(jq 'length' "$TRIAGE_PKG/MANIFEST.json")"

if [[ "$MANIFEST_COUNT" -ne 25 ]]; then
    echo "ERROR: expected 25 manifest entries, found $MANIFEST_COUNT" >&2
    exit 1
fi

printf "MANIFEST.json       : %s entries\n" "$MANIFEST_COUNT"
echo "sanity check        : ok"
echo "triage_package/ ready"
