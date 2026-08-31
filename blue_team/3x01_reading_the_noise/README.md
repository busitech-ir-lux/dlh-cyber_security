## Introduction

> _"Before you can spot an intruder, you must know what normal looks like."_ - **James Chen, SOC Lead**

Last week you built the evidence pipeline. Today you become the first person inside MedDefense who knows how to read what that pipeline produces. Forty thousand enriched events, eight days of activity, twelve hosts, six source types, one timeline. Most of it is noise. Most of the noise is **normal noise** — the heartbeat of a working hospital infrastructure. Somewhere inside it there are signals that matter, and nobody at MedDefense has ever taken the time to write down what normal sounds like here.

That is the work this week. You are going to take your 3x00 handoff, split it into a baseline window and an evaluation window, and build the first behavioral baselines MedDefense has ever had. Authentication patterns. Process inventories. Network destinations. File access footprints. Hourly and daily activity profiles. Each one a machine-readable reference that says, for this infrastructure, this is normal. Then you are going to hunt the evaluation window for everything that **does not** match those references, correlate the findings across sources, and rank them so the Tier 1 analyst who runs your toolkit on Monday morning sees the most dangerous thing first.

This project does not ask you to click buttons in a dashboard. It asks you to write the analytical scripts that the dashboard would run behind the scenes if you had one. The dataset is the one your own pipeline produced in 3x00. The tools are `jq`, `python3`, and a handful of bash. The output is a `baseline_package/` directory that will be loaded as a dependency by every downstream project in this module and reused as the ground truth reference in the capstone.

### Why this matters

A Tier 1 analyst stares at a queue of alerts and has to decide, in under two minutes, whether each alert is worth waking somebody up at 3 AM. That decision is only possible if the analyst has a reference for what the same alert looks like on a quiet Tuesday. Without a baseline, every alert is equally suspicious or equally boring, and the analyst guesses. With a baseline, the analyst compares. The baseline is the analyst's intuition, externalized into a JSON file that does not care about coffee or fatigue.

The 2020 SolarWinds campaign stayed undetected for nine months inside thousands of organizations. The malicious activity was designed to blend: legitimate protocols, legitimate tools, legitimate account names, legitimate traffic volumes. The victims who eventually caught it were the ones who had written down, ahead of time, the minor behavioral fingerprints of their own environments and noticed subtle shifts no human would have spotted in a dashboard review. That is what you are building this week, at the scale of one hospital group. And everything you build feeds directly into 3x02, where the deviations you identify here become the detection rules that fire in production.

Security+ domain 4.9 expects you to understand the mitigation and risk-reduction value of monitoring and baselining; domain 4.4 expects you to know log aggregation, correlation, and monitoring. This project exercises both at the same time, against data you produced yourself.

---

## Context

You are currently working as a **SOC Analyst** for **MedDefense Health Systems**.

### The Scenario: "What Normal Sounds Like"

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Analyst (You)

**SUBJECT:** First assignment now that your pipeline is live

**PRIORITY:** High

Good work on the pipeline. `evidence_handoff/` is sitting on your workstation, schema-valid, enriched, timeline-indexed. I have already pulled it into my review environment.

Here is the problem nobody at MedDefense has ever solved. **We have no baselines.** Three sites, two thousand employees, a dozen production servers, and nobody can tell me how many failed logins are normal on a Tuesday morning, which processes are supposed to run on the patient portal, which external destinations the billing server is supposed to contact, or whether a spike of auditd events at 02:00 on Saturday is routine backup activity or a lateral movement attempt. When Dr. Morales asks whether we are safe, the honest answer is "I do not know, because I have nothing to compare today against."

Your handoff covers eight days of activity. I want you to treat the first seven as your clean baseline window and the last day as your evaluation window. Infrastructure has confirmed the first seven days contain only authorized administration and normal clinical operations. The last day contains real activity that we have not reviewed yet, and I have reason to believe something slipped through. **Do not tell me what to look for. Your baselines should tell me.**

Build the baselines. Build the anomaly detection. Correlate findings across sources so if something touches both the endpoint and the network on the same host in the same minute, I see it as one thing, not two. Rank the output so the worst item is at the top, not buried in a list of low-severity noise.

Last thing. The scripts you write become the MedDefense SOC reference toolkit. Whatever Tier 1 analyst picks up this keyboard on Monday should be able to run your `baseline_package/` against any new evidence drop and get the same analytical quality you produced today. I expect that directory to be the most reused artifact in this department.

-- James Chen


#####################################################################
#######                                              TASKS                                                                     ######
#####################################################################

0-
[1-]()
[2-Reusable Query Toolkit](#reusable-query-toolkit)
### Reusable Query Toolkit

**Goal:** _Build a reusable CLI query toolkit that filters, projects, and aggregates events from the handoff dataset without a SIEM._

---

**Context:** Every baseline and anomaly task in this project will need to answer small pointed questions against the dataset. Rather than reimplement that logic in every script, you build the toolkit once. Every downstream task calls it.

---

**Instructions:** Write a script `2-query_toolkit.sh` that dispatches sub-commands against the enriched dataset. It must support at minimum:

- `filter --source <type> --host <h> --from <iso> --to <iso> --category <c>`: emits newline-delimited JSON of matching records to stdout
    
- `top --field <name> --limit <n> [filters]`: emits a two-column table of the top N values of a field, sorted desc by count
    
- `distinct --field <name> [filters]`: emits the distinct values of a field one per line
    
- `count [filters]`: emits a single integer with the record count matching the filters
    
- `window --field <name> --bucket <hour|day> [filters]`: emits a two-column table of bucket to count
    
- `help`: prints the usage
    

The toolkit must accept filters in any combination, must read from `$HANDOFF_DIR/data/enriched_events.json`, and must default `HANDOFF_DIR` to `~/3x00_handoff/evidence_handoff` if not set.

**Expected Output:**

```sql
$ ./2-query_toolkit.sh help
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message
```

[View the script](2-query_toolkit.sh)

