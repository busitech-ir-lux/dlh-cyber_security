## Introduction

> _"Before you can spot an intruder, you must know what normal looks like."_ - **James Chen, SOC Lead**

Last week you built the evidence pipeline. Today you become the first person inside MedDefense who knows how to read what that pipeline produces. Forty thousand enriched events, eight days of activity, twelve hosts, six source types, one timeline. Most of it is noise. Most of the noise is **normal noise** — the heartbeat of a working hospital infrastructure. Somewhere inside it there are signals that matter, and nobody at MedDefense has ever taken the time to write down what normal sounds like here.

That is the work this week. You are going to take your 3x00 handoff, split it into a baseline window and an evaluation window, and build the first behavioral baselines MedDefense has ever had. Authentication patterns. Process inventories. Network destinations. File access footprints. Hourly and daily activity profiles. Each one a machine-readable reference that says, for this infrastructure, this is normal. Then you are going to hunt the evaluation window for everything that **does not** match those references, correlate the findings across sources, and rank them so the Tier 1 analyst who runs your toolkit on Monday morning sees the most dangerous thing first.

This project does not ask you to click buttons in a dashboard. It asks you to write the analytical scripts that the dashboard would run behind the scenes if you had one. The dataset is the one your own pipeline produced in 3x00. The tools are `jq`, `python3`, and a handful of bash. The output is a `baseline_package/` directory that will be loaded as a dependency by every downstream project in this module and reused as the ground truth reference in the capstone.

## Why this matters

A Tier 1 analyst stares at a queue of alerts and has to decide, in under two minutes, whether each alert is worth waking somebody up at 3 AM. That decision is only possible if the analyst has a reference for what the same alert looks like on a quiet Tuesday. Without a baseline, every alert is equally suspicious or equally boring, and the analyst guesses. With a baseline, the analyst compares. The baseline is the analyst's intuition, externalized into a JSON file that does not care about coffee or fatigue.

The 2020 SolarWinds campaign stayed undetected for nine months inside thousands of organizations. The malicious activity was designed to blend: legitimate protocols, legitimate tools, legitimate account names, legitimate traffic volumes. The victims who eventually caught it were the ones who had written down, ahead of time, the minor behavioral fingerprints of their own environments and noticed subtle shifts no human would have spotted in a dashboard review. That is what you are building this week, at the scale of one hospital group. And everything you build feeds directly into 3x02, where the deviations you identify here become the detection rules that fire in production.

Security+ domain 4.9 expects you to understand the mitigation and risk-reduction value of monitoring and baselining; domain 4.4 expects you to know log aggregation, correlation, and monitoring. This project exercises both at the same time, against data you produced yourself.

---

## Context

You are currently working as a **SOC Analyst** for **MedDefense Health Systems**.

## The Scenario: "What Normal Sounds Like"

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


---

######### TASKS INTERLINK

---

- 0-
- [1-]()
- [2-Reusable Query Toolkit](#reusable-query-toolkit)
- [3-Event Type Taxonomy](#event-type-taxonomy)
- [4-Authentication Baseline](#authentication-baseline)
- [5-Process Execution Baseline](#process-execution-baseline)
- [9-Cross-Source Baseline Summary](#cross-source-baseline-summary)
- [10-Authentication Anomalies](#authentication-anomalies)
- [11-Process Anomalies](#process-anomalies)
- [13-Cross-Source Correlation](#cross-source-correlation)
- [15-Baseline Validation](#baseline-validation)


---
## Reusable Query Toolkit

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

---
## Event Type Taxonomy

**Goal:** _Build the MedDefense event type taxonomy that maps every observed source-specific event into a canonical analytical label._

---

**Context:** The schema gives you `event_category` at a coarse grain. For baselining and anomaly analysis you need finer granularity. The taxonomy is the deterministic mapping from raw source fields to canonical labels. Every downstream script in this project labels events through the taxonomy instead of interpreting source fields directly.

---

**Instructions:** Write a script `3-event_taxonomy.sh` that reads `$HANDOFF_DIR/data/enriched_events.json` and produces `event_taxonomy.json`. The taxonomy must contain, for each canonical label, the list of rules that identify it. A rule is a record `{source_type, match: {field: value, ...}, label}`.

At minimum the taxonomy must cover:

- `login_success`, `login_failure`, `logout`, `account_lockout`, `privilege_escalation`
    
- `process_start`, `process_stop`, `child_process_spawn`
    
- `file_read_sensitive`, `file_write_sensitive`, `file_permission_change`
    
- `network_connection_outbound`, `network_connection_inbound`, `network_alert`, `network_blocked`
    

The script must also write the labeled dataset to `labeled_events.json` (newline-delimited JSON) with a new `canonical_label` field. Records whose label cannot be determined are assigned `unlabeled`.

The script must default `HANDOFF_DIR` to `~/3x00_handoff/evidence_handoff` if not set.

**Expected Output:**

```php-template
$ source ~/m3_env.sh && ./3-event_taxonomy.sh
taxonomy rules         : <N>
records labeled        : <N>
records unlabeled      : <N>
canonical label distribution (top 10):
  process_start              <N>
  login_success              <N>
  ...
event_taxonomy.json written
labeled_events.json written
```


[View the script](3-event_taxonomy.sh)

---
## Authentication Baseline

**Goal:** _Compute the authentication baseline over the clean window: per-host, per-user, per-time-of-day success and failure patterns._

---

**Context:** Authentication is the most frequently queried log category in a SOC. The baseline must answer: who logs in where, when do they log in, what is the normal success-to-failure ratio, what is the largest failure burst from a single source that is considered normal. Every number in this baseline will be compared against day 8 by the anomaly script in T10.

---

**Instructions:** Write a script `4-baseline_auth.sh` that reads `labeled_events.json`, restricts to the baseline window (first seven days by default, overridable by `$BASELINE_DAYS`), and produces `baseline_auth.json` containing:

- `window`: the baseline window start and end timestamps
    
- `per_host`: for each host, the counts of `login_success`, `login_failure`, `logout`, `account_lockout`, `privilege_escalation`
    
- `per_user`: list of accounts observed with per-account success and failure counts
    
- `known_accounts`: the deduplicated list of usernames that appear at least once
    
- `business_hours_avg`: average successes and failures per hour during 06:00 to 17:59
    
- `offhours_avg`: average successes and failures per hour during 18:00 to 05:59
    
- `max_failures_1h_window`: the maximum number of failures observed in any 1-hour window from a single `src_ip` during the baseline
    

**Expected Output:**

```php-template
$ ./4-baseline_auth.sh
baseline window : <start> -> <end>
hosts           : <N>
known accounts  : <N>
business hours  : <N> success/h  |  <N> failure/h
off hours       : <N> success/h  |  <N> failure/h
max 1h src_ip failures : <N>
baseline_auth.json written
```

[View the script](4-baseline_auth.sh)

---
## Process Execution Baseline

**Goal:** _Compute the per-host process execution baseline: which processes are expected on which host and with what frequency._

---

**Context:** A process that has never been seen on a host is an investigation trigger in almost every SOC playbook. The baseline is the authoritative list of "expected" processes per host. The key distinction is **per host, not global**: `python3` may be normal on a data analyst workstation and deeply abnormal on a clinical imaging server. A global baseline erases that distinction and produces useless noise.

---

**Instructions:** Write a script `5-baseline_process.sh` that reads `labeled_events.json`, restricts to the baseline window, and produces `baseline_process.json` containing:

- `per_host`: for each host, the list of expected process names with execution count, first and last seen timestamps, and distinct executing users
    
- `global_top`: the 50 most executed processes across the whole baseline
    
- `rare_processes`: processes that appear on only one host or run fewer than five times total during the baseline
    
- `parent_child_pairs`: for process start events with parent-child information, the set of observed `parent -> child` pairs per host
    

**Expected Output:**

```php-template
$ ./5-baseline_process.sh
baseline window : <start> -> <end>
processes indexed by host: <N> hosts
global top process    : <name> (<N> executions)
rare processes        : <N>
parent->child pairs   : <N>
baseline_process.json written
```


[View the script](5-baseline_process.sh)

---

### Cross-Source Baseline Summary

**Goal:** _Combine all baselines into a single machine-readable baseline summary consumed by the anomaly detection block._

---

**Context:** Each previous task produced one slice of the baseline. The anomaly scripts in the next block should not have to open four separate files and cross-reference them. The summary is the single input contract: one file that contains everything an anomaly detector needs, with clear section boundaries and a version number. It is also the artifact Tier 1 analysts will load on Monday morning.

---

**Instructions:** Write a script `9-baseline_summary.sh` that reads `baseline_auth.json`, `baseline_process.json`, `baseline_network.json`, `baseline_file.json`, and `temporal_profile.json`, and produces `baseline_summary.json` containing:

- `version`
    
- `generated_at` (ISO 8601 UTC)
    
- `baseline_window` (start, end, duration in days)
    
- `evaluation_window` (start, end, duration in hours)
    
- `host_inventory`: the set of hosts present in the baseline
    
- `auth`, `process`, `network`, `file`, `temporal`: the respective sub-documents from the prior tasks, nested
    
- `thresholds`: a derived object containing the numeric thresholds anomaly scripts will apply (for example, `failure_rate_multiplier: 3`, `unknown_process_penalty: 5`, `unknown_port_penalty: 4`). Each threshold must include a short comment explaining how it was derived
    

**Expected Output:**

```php-template
$ ./9-baseline_summary.sh
version           : 1.0
baseline window   : <start> -> <end>  (<N> days)
evaluation window : <start> -> <end>  (24h)
hosts             : <N>
sections included : auth, process, network, file, temporal, thresholds
baseline_summary.json written
```

[View the script](9-baseline_summary.sh)

---

### Authentication Anomalies

**Goal:** _Scan the evaluation window for authentication anomalies using thresholds derived from the baseline summary._

---

**Context:** This is where the baseline pays off. Every deviation you flag is a potential signal that has to be credible enough to justify an analyst's time. The script must detect the categories that matter most in practice: accounts that do not exist in the baseline, failure bursts that exceed baseline expectations, logins at unusual hours, and privilege escalations that did not appear during the baseline.

---

**Instructions:** Write a script `10-anomalies_auth.sh` that reads `baseline_summary.json` and `labeled_events.json`, restricts to the evaluation window, and writes `anomalies_auth.json` containing one entry per anomaly with at minimum these fields: `timestamp`, `host`, `user`, `src_ip`, `anomaly_type`, `baseline_value`, `observed_value`, `severity`, `event_refs`.

The script must detect at minimum:

- `unknown_account`: a `user` value not present in the baseline `known_accounts`
    
- `failure_rate_burst`: any 1-hour window where the failure rate from a single `src_ip` exceeds the baseline `max_failures_1h_window` multiplied by the `failure_rate_multiplier` threshold
    
- `offhours_login`: a `login_success` event outside business hours for a user that has only ever logged in during business hours in the baseline
    
- `privilege_escalation_surge`: more than N `privilege_escalation` events on a host where the baseline has zero such events
    

**Expected Output:**

```php-template
$ ./10-anomalies_auth.sh
evaluation window  : <start> -> <end>
unknown_account           : <N>
failure_rate_burst        : <N>
offhours_login            : <N>
privilege_escalation_surge: <N>
total anomalies           : <N>
anomalies_auth.json written
```

[View the script](10-anomalies_auth.sh)

---

### Process Anomalies

**Goal:** _Scan the evaluation window for process execution anomalies relative to the per-host process baseline._

---

**Context:** Process anomalies are the highest signal-to-noise category when the baseline is computed per host. A process that has never run on a specific host during the baseline and shows up on day 8 is, at minimum, a note in the analyst's notebook. If it is a process with a reputation for misuse (scripting interpreters, network tools, archivers), it is already a medium-severity item.

---

**Instructions:** Write a script `11-anomalies_process.sh` that reads `baseline_summary.json` and `labeled_events.json`, restricts to the evaluation window, and writes `anomalies_process.json` containing one entry per anomaly with `timestamp`, `host`, `user`, `process_name`, `parent_process_name`, `anomaly_type`, `severity`, `event_refs`.

The script must detect at minimum:

- `unknown_process_for_host`: a process name that never appeared on that host in the baseline
    
- `unknown_parent_child`: a parent-child pair that never appeared on that host in the baseline
    
- `rare_process_spike`: a process that ran fewer than five times in the whole baseline but runs more than ten times in the evaluation window on a single host
    
- `high_risk_process`: hits on a watchlist of interpreters and tooling (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `nc`, `nmap`, `wget`, `curl`, `python3`, `bash`) running on a host where they did not run during the baseline
    

Severity is assigned from a rubric declared at the top of the script.

**Expected Output:**

```php-template
$ ./11-anomalies_process.sh
evaluation window : <start> -> <end>
unknown_process_for_host : <N>
unknown_parent_child     : <N>
rare_process_spike       : <N>
high_risk_process        : <N>
total anomalies          : <N>
anomalies_process.json written
```


[View the script](11-anomalies_process.sh)

---
### Cross-Source Correlation

**Goal:** _Correlate anomalies from multiple sources that share a host and a time window to produce higher confidence findings._

---

**Context:** A single unknown process on a clinical workstation might be a developer running a one-off script. The same unknown process happening one minute before an `unknown_destination_for_host` anomaly on the same host is a very different story. Correlation is what turns three low-value single-source items into one high-value multi-source finding. Triage in 3x03 will consume the output of this task directly.

---

**Instructions:** Write a script `13-correlate_anomalies.sh` that reads `anomalies_auth.json`, `anomalies_process.json`, and `anomalies_network.json`, and writes `correlated_anomalies.json`. A correlated finding groups any two or more single-source anomalies that share the same `host` and whose timestamps fall within a configurable correlation window (default: 300 seconds).

Each correlated finding must contain:

- `correlation_id` (a short deterministic identifier)
    
- `host`
    
- `window_start` and `window_end`
    
- `sources_involved` (the set of source categories: auth, process, network)
    
- `anomaly_types` (the set of anomaly types from the involved items)
    
- `member_refs` (list of references back to the individual anomaly entries)
    
- `score` (an integer composite score: 1 per involved source, plus a bonus for each distinct anomaly type, plus an asset criticality multiplier)
    

**Expected Output:**

```php-template
$ ./13-correlate_anomalies.sh
single-source anomalies  : <N>
correlated findings      : <N>
multi-host findings      : <N>
max score                : <N>
correlated_anomalies.json written
```

[View the script](13-correlate_anomalies.sh)

---
### 15. Baseline Validation

**Goal:** _Validate the baseline by running the anomaly scripts against the baseline window itself and then against the evaluation window, then checking that the results match expectations._

---

**Context:** An unvalidated baseline is guesswork. The only honest way to know whether your baseline produces useful output is to run the same anomaly logic over the baseline window (where you expect almost no findings) and over the evaluation window (where you expect the planted anomalies). The gap between the two tells you whether your baseline has any signal at all. This step is the equivalent of a backtest in quantitative analysis: it is what separates a baseline you can trust from a baseline you hope works.

---

**Instructions:** Write a script `15-baseline_validation.sh` that:

1. Re-runs the three single-source anomaly scripts (T10, T11, T12) once with the evaluation window set to the **baseline window itself**, capturing output as `self_check_*.json`
    
2. Re-runs them once with the **normal evaluation window** (day 8), capturing output as `live_check_*.json`
    
3. Produces `baseline_validation.json` containing:
    
    - `self_check_total` (expected to be very small)
        
    - `live_check_total`
        
    - `signal_to_noise_ratio = live_check_total / max(self_check_total, 1)`
        
    - per-type breakdown for both runs
        
    - a `verdict`: `pass` if `self_check_total` is under a declared acceptable threshold (default: 5) and `signal_to_noise_ratio` is at least 3.0, `fail` otherwise
        

The script must exit `0` on `pass` and `1` on `fail`.

**Expected Output:**

```php-template
$ ./15-baseline_validation.sh
self-check anomalies (baseline window): <N>
live-check anomalies (evaluation win ): <N>
signal-to-noise ratio                : <X>
verdict                              : pass
baseline_validation.json written
```

[View the script](15-baseline_validation.sh)

---

# Review 

[Checkout the review questions](Review.md)

