#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
TAXONOMY="$ASSETS_DIR/attack_taxonomy.json"
OUTPUT="attack_coverage.json"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TACTICS=(
    initial_access
    execution
    persistence
    privilege_escalation
    defense_evasion
    credential_access
    discovery
    lateral_movement
    collection
    command_and_control
    exfiltration
    impact
)

# ------------------------------------------------------------
# Collect ATT&CK techniques from all Sigma rules
# ------------------------------------------------------------

find rules/sigma -type f -name '*.yml' | sort |
while read -r rule; do

    yq -r '.tags[]? | select(test("^attack\\.t"))' "$rule" |
        sed 's/attack\.//' |
        tr '[:lower:]' '[:upper:]'

done | sort -u > "$TMP/covered.txt"

# ------------------------------------------------------------
# Build coverage for each tactic
# ------------------------------------------------------------

for tactic in "${TACTICS[@]}"; do

    # Techniques belonging to this tactic.
    jq -r --arg tactic "$tactic" '
        .techniques[]
        | select((.tactics // []) | index($tactic))
        | .id
    ' "$TAXONOMY" > "$TMP/tactic.txt"

    # Keep only techniques that our rules cover.
    grep -Fxf "$TMP/covered.txt" "$TMP/tactic.txt" \
        > "$TMP/current.txt" || true

    count="$(wc -l < "$TMP/current.txt")"

    techniques="$(
        jq -R . < "$TMP/current.txt" | jq -s .
    )"

    jq -n \
        --arg tactic "$tactic" \
        --argjson techniques "$techniques" '
        {
            tactic: $tactic,
            techniques: $techniques
        }
    ' >> "$TMP/matrix.jsonl"

    if (( count == 0 )); then
        printf "%-22s %d techniques  [GAP]\n" "$tactic" "$count"
    elif (( count == 1 )); then
        printf "%-22s %d technique\n" "$tactic" "$count"
    else
        printf "%-22s %d techniques\n" "$tactic" "$count"
    fi
done

# ------------------------------------------------------------
# Convert JSONL to a normal JSON array
# ------------------------------------------------------------

jq -s '.' "$TMP/matrix.jsonl" > "$TMP/matrix.json"

# ------------------------------------------------------------
# Create final output
# ------------------------------------------------------------

jq '
{
    matrix:
        (
            map({
                key: .tactic,
                value: .techniques
            })
            | from_entries
        ),

    uncovered_tactics:
        [
            .[]
            | select(.techniques | length == 0)
            | .tactic
        ]
}
' "$TMP/matrix.json" > "$OUTPUT"

echo "attack_coverage.json written"
