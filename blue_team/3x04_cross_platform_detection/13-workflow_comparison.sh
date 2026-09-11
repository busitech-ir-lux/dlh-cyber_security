#!/bin/bash

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
OUT_DIR="comparison"
OUT="$OUT_DIR/workflow_comparison.json"

mkdir -p "$OUT_DIR"

FILES=(
    "$FINDINGS_DIR/anchor_cli.json"
    "$FINDINGS_DIR/anchor_export.json"
    "$FINDINGS_DIR/scenario_a_cli.json"
    "$FINDINGS_DIR/scenario_a_export.json"
    "$FINDINGS_DIR/scenario_b_cli.json"
    "$FINDINGS_DIR/scenario_b_export.json"
    "$FINDINGS_DIR/scenario_c_cli.json"
    "$FINDINGS_DIR/scenario_c_export.json"
)

for file in "${FILES[@]}"
do
    [ -s "$file" ] || {
        echo "ERROR: missing finding: $file" >&2
        exit 1
    }
done

jq -s '

    def median:
        sort as $a |
        ($a | length) as $n |
        if $n == 0 then 0
        elif ($n % 2) == 1 then
            $a[($n / 2 | floor)]
        else
            (($a[$n/2 - 1] + $a[$n/2]) / 2)
        end;

    def interface_stats($name):
        [.[] | select(.interface == $name)] as $x |

        {
            finding_count: ($x | length),

            time_to_first_answer_seconds: {
                total: ([$x[].time_to_first_answer_seconds] | add),
                average: (
                    ([$x[].time_to_first_answer_seconds] | add) /
                    ($x | length)
                ),
                median: ([$x[].time_to_first_answer_seconds] | median)
            },

            action_count: {
                total: ([$x[] | (.actions | length)] | add),
                average: (
                    ([$x[] | (.actions | length)] | add) /
                    ($x | length)
                )
            },

            fields_touched_count: {
                total: ([$x[] | (.fields_touched | length)] | add),
                average: (
                    ([$x[] | (.fields_touched | length)] | add) /
                    ($x | length)
                )
            },

            event_refs_count: {
                total: ([$x[] | (.event_refs | length)] | add),
                average: (
                    ([$x[] | (.event_refs | length)] | add) /
                    ($x | length)
                )
            }
        };

    def scenario($id):
        ([.[] | select(.scenario_id == $id and .interface == "cli")][0]) as $c |
        ([.[] | select(.scenario_id == $id and .interface == "wazuh_export")][0]) as $w |

        {
            scenario_id: $id,
            cli_seconds: $c.time_to_first_answer_seconds,
            wazuh_export_seconds: $w.time_to_first_answer_seconds,
            delta_wazuh_export_minus_cli:
                ($w.time_to_first_answer_seconds - $c.time_to_first_answer_seconds),

            cli_actions: ($c.actions | length),
            wazuh_export_actions: ($w.actions | length)
        };

    {
        per_interface: {
            cli: interface_stats("cli"),
            wazuh_export: interface_stats("wazuh_export")
        },

        per_scenario: [
            scenario("anchor"),
            scenario("scenario_a"),
            scenario("scenario_b"),
            scenario("scenario_c")
        ],

        confidence_distribution: {
            cli: {
                low: ([.[] | select(.interface=="cli" and .confidence=="low")] | length),
                medium: ([.[] | select(.interface=="cli" and .confidence=="medium")] | length),
                high: ([.[] | select(.interface=="cli" and .confidence=="high")] | length)
            },

            wazuh_export: {
                low: ([.[] | select(.interface=="wazuh_export" and .confidence=="low")] | length),
                medium: ([.[] | select(.interface=="wazuh_export" and .confidence=="medium")] | length),
                high: ([.[] | select(.interface=="wazuh_export" and .confidence=="high")] | length)
            }
        },

        generated_at: (now | todateiso8601)
    }

' "${FILES[@]}" > "$OUT"

echo "findings loaded       : 8 (4 cli + 4 wazuh_export)"
echo "per interface totals:"

jq -r '
    .per_interface
    | to_entries[]
    | "  \(.key) : \(.value.time_to_first_answer_seconds.total)s total, avg \(.value.time_to_first_answer_seconds.average | floor)s, median \(.value.time_to_first_answer_seconds.median)s, \(.value.action_count.total) actions"
' "$OUT"

echo "per interface confidence:"

jq -r '
    .confidence_distribution
    | to_entries[]
    | "  \(.key) : high=\(.value.high) medium=\(.value.medium) low=\(.value.low)"
' "$OUT"

echo "per scenario deltas (wazuh_export - cli):"

jq -r '
    .per_scenario[]
    | "  \(.scenario_id) : \(.delta_wazuh_export_minus_cli)s"
' "$OUT"

echo "$OUT written"
