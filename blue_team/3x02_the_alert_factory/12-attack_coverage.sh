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

find rules/sigma -type f -name '*.yml' | sort |
while read -r rule; do

    id="$(yq -r '.id' "$rule")"
    title="$(yq -r '.title' "$rule")"

    techniques="$(
        yq -r '.tags[]? | select(test("^attack\\.t"))' "$rule" |
        sed 's/attack\.//' |
        tr '[:lower:]' '[:upper:]' |
        jq -R . |
        jq -s .
    )"

    jq -n \
        --arg id "$id" \
        --arg title "$title" \
        --argjson techniques "$techniques" '
        {
          rule_id: $id,
          rule_title: $title,
          techniques: $techniques
        }
    ' >> "$TMP/rules.jsonl"

done

jq -s '.' "$TMP/rules.jsonl" > "$TMP/rules.json"

for tactic in "${TACTICS[@]}"; do

    techniques="$(
        jq -r --arg tactic "$tactic" '
            .techniques[]
            | select((.tactics // []) | index($tactic))
            | .id
        ' "$TAXONOMY" |
        sort -u
    )"

    covered=""

    while read -r technique; do
        [[ -n "$technique" ]] || continue

        if jq -e --arg t "$technique" '
            any(.[]; (.techniques // []) | index($t))
        ' "$TMP/rules.json" >/dev/null; then
            covered+="$technique"$'\n'
        fi
    done <<<"$techniques"

    count="$(printf '%s' "$covered" | sed '/^$/d' | wc -l)"

    printf '%s\n' "$covered" |
        sed '/^$/d' |
        jq -R . |
        jq -s \
            --arg tactic "$tactic" \
            '{tactic:$tactic, techniques:.}' \
            >> "$TMP/matrix.jsonl"

    if (( count == 0 )); then
        printf "%-22s %d techniques  [GAP]\n" "$tactic" "$count"
    elif (( count == 1 )); then
        printf "%-22s %d technique\n" "$tactic" "$count"
    else
        printf "%-22s %d techniques\n" "$tactic" "$count"
    fi

done

jq -n \
    --slurpfile rules "$TMP/rules.json" \
    --slurpfile matrix "$TMP/matrix.jsonl" '
    {
      rules: $rules[0],
      matrix:
        ($matrix | map({key:.tactic, value:.techniques}) | from_entries),
      uncovered_tactics:
        [$matrix[] | select(.techniques | length == 0) | .tactic]
    }
' > "$OUTPUT"

echo "attack_coverage.json written"
