# MedDefense SIEM Interface Evaluation Brief

## Purpose

This brief evaluates the CLI evidence workflow and the Wazuh export workflow using the same four security investigations. The recommendation is based on measured investigation time, action count, evidence access, and context lookup cost rather than vendor feature claims.

## Evaluation Methodology

The evaluation used the anchor investigation and Scenarios A, B, and C. Each scenario was investigated once through the CLI evidence pipeline and once through the Wazuh export interface using the same underlying evidence.

Each finding recorded time to first answer, actions performed, fields inspected, evidence references, ATT&CK techniques, hypothesis, and confidence. The final comparison was calculated automatically from the eight findings.

## Findings Summary

The CLI workflow completed four investigations in **[CLI_TOTAL_SECONDS] seconds**, with an average of **[CLI_AVERAGE_SECONDS] seconds** and **[CLI_ACTIONS] total actions**.

The Wazuh export workflow completed four investigations in **[EXPORT_TOTAL_SECONDS] seconds**, with an average of **[EXPORT_AVERAGE_SECONDS] seconds** and **[EXPORT_ACTIONS] total actions**.

The scenario-level results are stored in `comparison/tradeoff_table.json` and the aggregate results are stored in `comparison/workflow_comparison.json`.

## Strengths and Weaknesses per Interface

The CLI interface performs well when an analyst already knows the normalized schema and needs fast filtering, iteration, joins, or custom processing. The trade-off analysis should cite the scenarios where `text_speed_iteration`, `pipeline_expressiveness`, `context_join_ergonomics`, or `reproducibility` produced a measurable advantage. Its main weakness is that the analyst must know field names and manually build context that a SIEM may surface directly.

The Wazuh export interface performs well when useful fields and context are already indexed and visible. The trade-off analysis should cite scenarios where `native_field_surface`, `timeline_visualization`, or `filter_bar_efficiency` reduced investigation cost. Its main weakness is that missing asset or zone context can require a secondary lookup and remove some of the interface advantage.

## Recommendation

**Primary interface:** [PRIMARY_INTERFACE based on measured T13 results].

**Secondary interface:** Use [SECONDARY_INTERFACE] when its measured strengths match the investigation shape or when the primary interface does not expose required context efficiently.

## Operational Risks of Being Wrong

1. **Higher investigation time:** An unsuitable primary interface may add approximately **[X] analyst hours per week** based on the measured per-finding time difference multiplied by expected weekly alert volume.
2. **Extra context lookups:** Missing asset or zone fields may add **[X] analyst hours per week** through repeated secondary searches.
3. **Platform dependency:** Over-reliance on one interface may add **[X] analyst hours per week** during migration, maintenance, or access outages because analysts cannot reproduce investigations elsewhere.

## Security+ 4.7 Considerations

Automation and reusable structured findings reduce repeated manual work and improve scaling. The preferred platform should therefore minimize operational complexity without creating technical debt or preventing investigations from being reproduced through another interface.

## Next Steps

1. Detection engineering: validate rule behavior and field mappings across both interfaces.
2. Compliance: retain the findings, comparison data, brief, and manifest as evaluation evidence.
3. SOC manager: select the primary analyst surface using the measured workflow results and define when the secondary interface should be used.
