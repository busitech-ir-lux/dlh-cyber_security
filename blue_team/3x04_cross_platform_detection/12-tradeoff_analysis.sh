#!/bin/bash

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
OUT_DIR="comparison"

mkdir -p "$OUT_DIR"

JSON_OUT="$OUT_DIR/tradeoff_table.json"
MD_OUT="$OUT_DIR/tradeoff_table.md"

for scenario in anchor scenario_a scenario_b scenario_c
do
    for interface in cli export
    do
        if [ "$interface" = "cli" ]; then
            FILE="$FINDINGS_DIR/${scenario}_cli.json"
        else
            FILE="$FINDINGS_DIR/${scenario}_export.json"
        fi

        [ -s "$FILE" ] || {
            echo "ERROR: missing finding: $FILE" >&2
            exit 1
        }
    done
done

jq -n \
    --slurpfile anchor_cli "$FINDINGS_DIR/anchor_cli.json" \
    --slurpfile anchor_exp "$FINDINGS_DIR/anchor_export.json" \
    --slurpfile a_cli "$FINDINGS_DIR/scenario_a_cli.json" \
    --slurpfile a_exp "$FINDINGS_DIR/scenario_a_export.json" \
    --slurpfile b_cli "$FINDINGS_DIR/scenario_b_cli.json" \
    --slurpfile b_exp "$FINDINGS_DIR/scenario_b_export.json" \
    --slurpfile c_cli "$FINDINGS_DIR/scenario_c_cli.json" \
    --slurpfile c_exp "$FINDINGS_DIR/scenario_c_export.json" '

    def row($name; $cli; $exp; $cause_cli; $cause_exp):
        ($cli.time_to_first_answer_seconds) as $ct |
        ($exp.time_to_first_answer_seconds) as $et |
        ($cli.actions | length) as $ca |
        ($exp.actions | length) as $ea |

        {
            scenario_id: $name,
            cli_time_seconds: $ct,
            wazuh_export_time_seconds: $et,
            time_delta_export_minus_cli: ($et - $ct),

            cli_actions: $ca,
            wazuh_export_actions: $ea,
            action_delta_export_minus_cli: ($ea - $ca),

            faster_interface:
                if $ct < $et then "cli"
                elif $et < $ct then "wazuh_export"
                else "tie"
                end,

            advantage_cause:
                if $ct < $et then $cause_cli
                elif $et < $ct then $cause_exp
                else "reproducibility"
                end
        };

    [
        row(
            "anchor";
            $anchor_cli[0];
            $anchor_exp[0];
            "text_speed_iteration";
            "filter_bar_efficiency"
        ),

        row(
            "scenario_a";
            $a_cli[0];
            $a_exp[0];
            "pipeline_expressiveness";
            "timeline_visualization"
        ),

        row(
            "scenario_b";
            $b_cli[0];
            $b_exp[0];
            "context_join_ergonomics";
            "native_field_surface"
        ),

        row(
            "scenario_c";
            $c_cli[0];
            $c_exp[0];
            "pipeline_expressiveness";
            "native_field_surface"
        )
    ]
' > "$JSON_OUT"

{
    echo "# Cross-Platform Trade-off Table"
    echo
    echo "| Scenario | CLI time | Export time | Delta | CLI actions | Export actions | Faster | Cause |"
    echo "|---|---:|---:|---:|---:|---:|---|---|"

    jq -r '
        .[]
        | "| \(.scenario_id) | \(.cli_time_seconds)s | \(.wazuh_export_time_seconds)s | \(.time_delta_export_minus_cli)s | \(.cli_actions) | \(.wazuh_export_actions) | \(.faster_interface) | \(.advantage_cause) |"
    ' "$JSON_OUT"

} > "$MD_OUT"

SCENARIOS=$(jq 'length' "$JSON_OUT")
EXPORT_WINS=$(jq '[.[] | select(.faster_interface=="wazuh_export")] | length' "$JSON_OUT")
CLI_WINS=$(jq '[.[] | select(.faster_interface=="cli")] | length' "$JSON_OUT")

printf 'scenarios analyzed   : %s (anchor + 3)\n' "$SCENARIOS"
printf 'export advantages    : %s\n' "$EXPORT_WINS"
printf 'cli advantages       : %s\n' "$CLI_WINS"
echo "$JSON_OUT written"
echo "$MD_OUT written"
