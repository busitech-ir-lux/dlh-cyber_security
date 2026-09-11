#!/bin/bash

set -u

OUT="tool_evaluation"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_file() {
    [ -s "$1" ] || die "required file missing or empty: $1"
}

# ------------------------------------------------------------
# Validate source files
# ------------------------------------------------------------

FINDINGS=(
    findings/anchor_cli.json
    findings/anchor_export.json
    findings/scenario_a_cli.json
    findings/scenario_a_export.json
    findings/scenario_b_cli.json
    findings/scenario_b_export.json
    findings/scenario_c_cli.json
    findings/scenario_c_export.json
)

RULES=(
    rules/wazuh/001_ssh_brute_force.xml
    rules/wazuh/003_interpreter_abuse.xml
    rules/wazuh/010_credential_theft_chain.xml
    rules/wazuh/translation_report.json
)

QUESTIONS=(
    comparison/questions/q1.yml
    comparison/questions/q2.yml
    comparison/questions/q3.yml
    comparison/questions/q4.yml
)

COMPARISON=(
    comparison/query_comparison.json
    comparison/tradeoff_table.json
    comparison/tradeoff_table.md
    comparison/workflow_comparison.json
)

PLAYBOOK="playbook/tool_agnostic_playbook.md"
BRIEF="brief/vendor_brief.md"
WORKSPACE="workspace/workspace_init.json"

for f in "${FINDINGS[@]}" \
         "${RULES[@]}" \
         "${QUESTIONS[@]}" \
         "${COMPARISON[@]}" \
         "$PLAYBOOK" \
         "$BRIEF" \
         "$WORKSPACE"
do
    require_file "$f"
done

# Require one script for every task 0-13.
RUNTIME=()

for n in $(seq 0 13)
do
    MATCH=$(find . -maxdepth 1 -type f -name "${n}-*.sh" | head -1)

    [ -n "$MATCH" ] || die "task $n runtime script not found"

    require_file "$MATCH"
    RUNTIME+=("$MATCH")
done

# ------------------------------------------------------------
# Create clean package
# ------------------------------------------------------------

rm -rf "$OUT"

mkdir -p \
    "$OUT/findings" \
    "$OUT/rules/wazuh" \
    "$OUT/comparison/questions" \
    "$OUT/comparison" \
    "$OUT/playbook" \
    "$OUT/brief" \
    "$OUT/workspace" \
    "$OUT/runtime"

cp "${FINDINGS[@]}" "$OUT/findings/"
echo "copying findings   ... ${#FINDINGS[@]} files"

cp "${RULES[@]}" "$OUT/rules/wazuh/"
echo "copying rules      ... ${#RULES[@]} files"

cp "${QUESTIONS[@]}" "$OUT/comparison/questions/"

cp "${COMPARISON[@]}" "$OUT/comparison/"
echo "copying comparison ... $((${#QUESTIONS[@]} + ${#COMPARISON[@]})) files"

cp "$PLAYBOOK" "$OUT/playbook/"
echo "copying playbook   ... 1 file"

cp "$BRIEF" "$OUT/brief/"
echo "copying brief      ... 1 file"

cp "$WORKSPACE" "$OUT/workspace/"
echo "copying workspace  ... 1 file"

for script in "${RUNTIME[@]}"
do
    cp "$script" "$OUT/runtime/"
done

echo "copying runtime    ... ${#RUNTIME[@]} files"

# ------------------------------------------------------------
# Generate MANIFEST.json
# ------------------------------------------------------------

TMP_MANIFEST=$(mktemp)
trap 'rm -f "$TMP_MANIFEST"' EXIT

find "$OUT" \
    -type f \
    ! -name MANIFEST.json \
    -print0 |
sort -z |
while IFS= read -r -d '' file
do
    REL="${file#"$OUT"/}"
    SIZE=$(stat -c '%s' "$file")
    HASH=$(sha256sum "$file" | awk '{print $1}')

    jq -n \
        --arg path "$REL" \
        --argjson size "$SIZE" \
        --arg sha256 "$HASH" \
        '{
            path: $path,
            size: $size,
            sha256: $sha256
        }'
done |
jq -s '{
    generated_at: (now | todateiso8601),
    entries: .
}' > "$OUT/MANIFEST.json"

ENTRY_COUNT=$(jq '.entries | length' "$OUT/MANIFEST.json")

printf '%-20s: %s entries\n' "MANIFEST.json" "$ENTRY_COUNT"

# ------------------------------------------------------------
# Final sanity check
# ------------------------------------------------------------

jq -e '.entries | length > 0' "$OUT/MANIFEST.json" >/dev/null ||
    die "manifest is empty"

while IFS= read -r path
do
    require_file "$OUT/$path"
done < <(jq -r '.entries[].path' "$OUT/MANIFEST.json")

echo "sanity check       : ok"
echo "tool_evaluation/ ready"
