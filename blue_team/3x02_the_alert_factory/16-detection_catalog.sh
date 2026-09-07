#!/bin/bash
set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

RULES=(
001_ssh_brute_force.yml
002_windows_offhours_privileged_logon.yml
003_interpreter_abuse.yml
004_recon_tool_execution.yml
005_scheduled_task_creation.yml
006_registry_autorun_modify.yml
007_unknown_outbound_destination.yml
008_uncommon_port_outbound.yml
009_lateral_movement_smb.yml
010_credential_theft_chain.yml
011_patient_data_access.yml
012_medical_segment_egress.yml
013_privileged_account_shift_violation.yml
)

METRICS=(
detection_matrix.json
fp_baseline.json
tuning_report.json
rule_quality.json
)

COVERAGE=(
attack_coverage.json
rule_prioritization.json
)

ALERTS=(
alert_queue.json
alert_queue_schema.json
)

RUNTIME=(
3-sigma_runner.sh
8-correlation_primitives.py
10-fp_baseline.sh
11-tune_rules.sh
12-attack_coverage.sh
13-rule_quality.sh
14-rule_prioritization.sh
15-generate_alerts.sh
)

# ------------------------------------------------------------
# Check files first
# ------------------------------------------------------------

for file in "${RULES[@]}"; do
    [[ -s "rules/sigma/$file" ]] || {
        echo "ERROR: missing rules/sigma/$file" >&2
        exit 1
    }
done

for file in "${METRICS[@]}" "${COVERAGE[@]}" "${ALERTS[@]}" "${RUNTIME[@]}"; do
    [[ -s "$file" ]] || {
        echo "ERROR: missing $file" >&2
        exit 1
    }
done

[[ -s detection_spec.md ]] || {
    echo "ERROR: detection_spec.md missing - run T17 first" >&2
    exit 1
}

# ------------------------------------------------------------
# Rebuild catalog
# ------------------------------------------------------------

rm -rf "$CATALOG_DIR"

mkdir -p \
    "$CATALOG_DIR/rules/sigma" \
    "$CATALOG_DIR/rules/tuned" \
    "$CATALOG_DIR/metrics" \
    "$CATALOG_DIR/coverage" \
    "$CATALOG_DIR/alerts" \
    "$CATALOG_DIR/runtime" \
    "$CATALOG_DIR/spec"

for file in "${RULES[@]}"; do
    cp "rules/sigma/$file" "$CATALOG_DIR/rules/sigma/"
done

TUNED_COUNT=0

if compgen -G 'rules/sigma/tuned/*.yml' >/dev/null; then
    cp rules/sigma/tuned/*.yml "$CATALOG_DIR/rules/tuned/"
    TUNED_COUNT="$(find rules/sigma/tuned -name '*.yml' | wc -l)"
fi

for file in "${METRICS[@]}"; do
    cp "$file" "$CATALOG_DIR/metrics/"
done

for file in "${COVERAGE[@]}"; do
    cp "$file" "$CATALOG_DIR/coverage/"
done

for file in "${ALERTS[@]}"; do
    cp "$file" "$CATALOG_DIR/alerts/"
done

for file in "${RUNTIME[@]}"; do
    cp "$file" "$CATALOG_DIR/runtime/"
done

cp detection_spec.md "$CATALOG_DIR/spec/"

echo "copying rules/sigma   ... 13 files"
printf "copying rules/tuned   ... %2d files\n" "$TUNED_COUNT"
echo "copying metrics       ...  4 files"
echo "copying coverage      ...  2 files"
echo "copying alerts        ...  2 files"
echo "copying runtime       ...  8 files"
echo "copying spec          ...  1 file"

# ------------------------------------------------------------
# MANIFEST.json
# ------------------------------------------------------------

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

while read -r file; do

    path="${file#"$CATALOG_DIR/"}"
    size="$(stat -c '%s' "$file")"
    hash="$(sha256sum "$file" | awk '{print $1}')"

    jq -n \
        --arg path "$path" \
        --argjson size "$size" \
        --arg hash "$hash" '
        {
          path: $path,
          size: $size,
          sha256: $hash
        }
    ' >> "$TMP"

done < <(
    find "$CATALOG_DIR" -type f ! -name MANIFEST.json | sort
)

jq -s '.' "$TMP" > "$CATALOG_DIR/MANIFEST.json"

COUNT="$(jq 'length' "$CATALOG_DIR/MANIFEST.json")"

# ------------------------------------------------------------
# Final sanity check
# ------------------------------------------------------------

while read -r file; do
    [[ -s "$file" ]] || {
        echo "ERROR: empty file: $file" >&2
        exit 1
    }
done < <(find "$CATALOG_DIR" -type f)

echo "MANIFEST.json         : $COUNT entries"
echo "sanity check          : ok"
echo "detection_catalog/ ready"
