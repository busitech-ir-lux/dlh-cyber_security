#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"

RISK="$ASSETS_DIR/risk_register.json"
QUALITY="rule_quality.json"
COVERAGE="attack_coverage.json"
OUTPUT="rule_prioritization.json"

# Check required files.
for file in "$RISK" "$QUALITY" "$COVERAGE"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

jq -n \
    --slurpfile risk "$RISK" \
    --slurpfile quality "$QUALITY" \
    --slurpfile coverage "$COVERAGE" '
    
    # Normalize ATT&CK technique names:
    # attack.t1110.001 -> t1110.001
    def tech:
        tostring
        | ascii_downcase
        | sub("^attack\\."; "");

    # Support either plain arrays or {"rules": [...]}.
    ($quality[0].rules // $quality[0]) as $rules |
    ($coverage[0].rules // $coverage[0]) as $coverage_rules |
    ($risk[0].threat_scenarios //
     $risk[0].scenarios //
     $risk[0]) as $scenarios |

    [
        $rules[] as $rule |

        # Find ATT&CK techniques for this rule.
        (
            $coverage_rules[]
            | select(.rule_id == $rule.rule_id)
            | (.techniques // .attack_techniques // .tags // [])
            | map(tech)
        ) as $rule_techniques |

        # Find risk scenarios sharing at least one technique.
        [
            $scenarios[]
            | (
                .detection_relevant_techniques //
                .techniques //
                .attack_techniques //
                .covered_techniques //
                []
              | map(tech)
            ) as $scenario_techniques

            | select(
                [
                    $rule_techniques[]
                    | select(. as $t | $scenario_techniques | index($t))
                ]
                | length > 0
            )
        ] as $matching |

        ($matching
            | map((.likelihood // 0) * (.impact // 0))
            | add // 0
        ) as $risk_score |

        ($rule.f1 // 0) as $f1 |

        {
            rule_id: $rule.rule_id,
            rule_title: $rule.rule_title,
            risk_score: $risk_score,
            f1: $f1,
            priority_score:
                (
                    $risk_score *
                    (if $f1 == 0 then 0.1 else $f1 end)
                    | . * 100
                    | round
                    | . / 100
                ),
            covering_scenarios:
                [
                    $matching[]
                    | (.id // .scenario_id // .name // .title // "unknown")
                ],
            level: $rule.level
        }
    ]
    | sort_by(-.priority_score)
' > "$OUTPUT"

echo "top 10 rules by priority_score"

jq -r '
    [.[] | select(.priority_score > 0)]
    | .[:10]
    | to_entries[]
    | "\(.key + 1)\t\(.value.priority_score)\t\(.value.rule_title)"
' "$OUTPUT" |
while IFS=$'\t' read -r rank score title; do
    printf "%2d  %5.1f  %s\n" "$rank" "$score" "$title"
done

ORPHANS="$(jq '[.[] | select(.priority_score == 0)] | length' "$OUTPUT")"

echo "orphan rules (no risk scenario covers) : $ORPHANS"

jq -r '
    .[]
    | select(.priority_score == 0)
    | "  ORPHAN  \(.rule_title)"
' "$OUTPUT"

echo "rule_prioritization.json written"
