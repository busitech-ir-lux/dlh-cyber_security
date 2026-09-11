# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

This playbook defines a repeatable security investigation workflow that does not depend on one SIEM or interface. It allows a Tier 1 analyst to reach and document the same conclusion through CLI evidence or a dashboard/export interface.

## Scope

This playbook covers investigation of authentication, process, network, file, and correlated security events. It covers event filtering, context lookup, timeline building, ATT&CK mapping, hypothesis formation, and structured findings.

It does not replace incident response, malware analysis, forensic imaging, or Tier 2 investigation.

## Inputs

The analyst must have access to:

- enriched events
- asset inventory
- baseline package
- detection catalog
- triage package
- IOC context

## Workflow Steps

| Step | CLI action | Export/dashboard action |
|---|---|---|
| 1. Define scope | Read scenario/alert and identify host, time window, IPs, users, and event IDs | Open alert/search context and identify the same scope |
| 2. Filter evidence | Use `jq` to filter events | Use KQL/Lucene or exported search results |
| 3. Build timeline | Sort matching events by timestamp | Sort dashboard results by `@timestamp` |
| 4. Inspect fields | Read normalized fields and source-specific fields | Expand documents and inspect mapped Wazuh fields |
| 5. Add context | Join asset, zone, baseline, and IOC data | Use indexed labels or perform secondary context lookup |
| 6. Test hypothesis | Check whether ordered events support one explanation | Review the same event chain in the dashboard/export |
| 7. Map techniques | Match observed activity to ATT&CK techniques | Record the same technique IDs |
| 8. Write finding | Write the locked JSON finding | Write the same locked JSON finding |

## Field Name Translation Table

| Normalized field | Wazuh field |
|---|---|
| `timestamp` | `@timestamp` |
| `hostname` | `agent.name` |
| `src_ip` | `source.ip` |
| `src_port` | `source.port` |
| `dst_ip` | `destination.ip` |
| `dst_port` | `destination.port` |
| `user` | `user.name` |
| `event_id` | `winlog.event_id` |
| `event_ref` | `_id` |
| `raw_message` | `full_log` |

## Query Decomposition Rule

Every investigation query should be divided into three parts:

1. **Filter** — which events should match?
2. **Aggregation** — how should matches be counted or grouped?
3. **Time window** — during what period?

`jq` expresses these directly using `select`, arrays, grouping, sorting, and timestamp comparisons.

Sigma expresses the filter in the detection section and may describe counting or correlation depending on the rule design.

KQL expresses field filters such as `agent.name:"clin-ws-12"` and relies on the dashboard for time range and many aggregations.

Lucene also expresses field filters but uses Lucene query syntax and operators.

The investigative question must remain the same even when syntax changes.

## Finding Schema

Every finding contains:

- `finding_id`
- `scenario_id`
- `interface`
- `investigation_start`
- `investigation_end`
- `time_to_first_answer_seconds`
- `actions`
- `fields_touched`
- `event_refs`
- `attack_techniques`
- `hypothesis`
- `confidence`
- `created_at`

The schema must not change between interfaces.

## Exit Criteria

An investigation is complete when:

- the relevant event scope has been searched;
- important events are ordered into a timeline;
- required asset, baseline, zone, or IOC context has been checked;
- the hypothesis is supported by referenced events;
- ATT&CK techniques are recorded;
- uncertainty is reflected in the confidence value;
- the finding passes the locked schema.

## Known Pitfalls

Field names differ between the normalized dataset and Wazuh documents, so always use the field mapping.

Important asset context may not be indexed in the SIEM and may require a secondary inventory lookup.

A narrow network signal can be easy to miss if zone information is not immediately visible.

A known or authorized username does not automatically make suspicious activity benign.

Fast investigation is useful only when the same evidence and conclusion are preserved.
