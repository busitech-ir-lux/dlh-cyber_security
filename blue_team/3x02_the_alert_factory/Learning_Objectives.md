
## Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, **without the help of Google**:

### Detection Engineering Fundamentals

- The four detection types (signature, anomaly, behavioral, correlation) and which data source and rule structure supports each
    
- The difference between a true positive, false positive, true negative, and false negative, and why each matters for SOC workload and detection confidence
    
- Why every detection rule must be expressible as a precise predicate against specific fields and why free-text matching is a last resort
    

### Sigma Rule Authoring

- The full Sigma rule structure: `title`, `id`, `status`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, and `tags`
    
- How to express selection, count, timeframe, and boolean logic in Sigma detection blocks
    
- How to map a rule to one or more MITRE ATT&CK techniques and why the mapping is not cosmetic
    
- Why vendor-neutral detection authoring outlives any specific SIEM and why Sigma became the industry reference
    

### Detection Quality and Tuning

- How to measure precision, recall, and false positive rate for an individual detection rule against labeled evidence
    
- How to tune a rule that fires too often without losing its ability to catch the targeted behavior
    
- How to assess detection coverage across the MITRE ATT&CK matrix and identify gaps
    
- Why rule prioritization must be driven by organizational risk, not by technical novelty
    

### Cross-Source Detection

- Why multi-source correlation rules produce higher confidence findings than single-source rules
    
- How a correlation rule is structured in Sigma and what the limits of pure Sigma correlation are
    
- When to preprocess evidence into correlation primitives before rule evaluation
    

---

## Resources

_Read or watch:_

### Sigma Format and Authoring

- [Sigma GitHub Repository](https://intranet.hbtn.io/rltoken/QAFsKpL-KeNMpEqJYP9bQQ) - Official Sigma specification, rule library, and tooling
    
- [Sigma Rule Specification](https://intranet.hbtn.io/rltoken/MkUtx89K8jWLzq7DyGdstQ) - Canonical YAML format reference
    
- [How to Write Sigma Rules](https://intranet.hbtn.io/rltoken/huk8CpRxZuMSGMTYNLF17w) - Authoring best practices from the Sigma creator
    

### Detection Engineering Theory

- [Palantir: Alerting and Detection Strategy Framework](https://intranet.hbtn.io/rltoken/kR0Q1ZyaN-v897UO2E1fAA) - Structured approach to writing and measuring detections
    
- [David Bianco: The Pyramid of Pain](https://intranet.hbtn.io/rltoken/-YHv4x6uupldtkLZOv98mw) - Why behavioral detection outlives IOC detection
    
- [MITRE ATT&CK: Techniques Matrix](https://intranet.hbtn.io/rltoken/LMMhIhhmKYt8XboJNHJ3CQ) - Technique reference for rule mapping
    

### Detection Tooling

- [sigma-cli Documentation](https://intranet.hbtn.io/rltoken/V_cCCO3vEf_CRCJMbdak_g) - Command-line rule validation and conversion
    
- [pySigma Reference](https://intranet.hbtn.io/rltoken/oGfL9YeqXG5eF2v4GcghLA) - Python library behind sigma-cli and the Sigma ecosystem
    

### Man Pages

- `man jq`
    
- `man yq`
    
- `man sigma`
    
- `man python3`


----
# Detection Engineering Fundamentals

### The four detection types (signature, anomaly, behavioral, correlation) and which data source and rule structure supports each

There are four main detection types in this project.

**1. Signature detection**

Signature detection looks for a **known and specific pattern**. The rule already knows what suspicious activity looks like and checks whether an event matches it.

Example:

```text
event_id = 4698
```

Windows Event ID `4698` means a scheduled task was created. A rule can use that exact value as part of a detection.

Another example is Suricata matching a known malicious network pattern.

Signature detection works best with structured data where fields have clear and stable meanings, such as:

- Windows Event Logs
    
- Sysmon
    
- Linux authentication logs
    
- Suricata alerts
    

The advantage is that it is precise and easy to understand. The weakness is that attackers can sometimes change indicators such as IP addresses, hashes, or commands.

---

**2. Anomaly detection**

Anomaly detection asks:

> Is this activity different from what is normally seen?

It needs a **baseline** of normal activity.

For example, if a server normally communicates only with five external IP addresses and suddenly connects to a new destination:

```text
baseline_known_destination = false
```

that connection can be considered anomalous.

Anomaly detection is useful for:

- authentication patterns
    
- network destinations
    
- ports
    
- process activity
    
- working hours
    

It is especially useful when there is no single known malicious signature.

---

**3. Behavioral detection**

Behavioral detection focuses on **what the attacker is doing**, rather than one specific indicator.

For example:

```text
unusual parent process
→ powershell.exe
→ suspicious command execution
```

The exact command may change, but the behavior of abusing an interpreter can remain similar.

Behavioral detection is useful with endpoint and process telemetry because attacker techniques such as command execution, discovery, credential access, and lateral movement usually produce recognizable actions.

This relates to the Pyramid of Pain: indicators such as IP addresses are easy for attackers to change, while changing their overall techniques and behaviors is harder.

---

**4. Correlation detection**

Correlation combines multiple related events.

For example:

```text
multiple failed logins
→ successful login from another IP
→ privilege escalation
```

Each event alone may have a legitimate explanation. Together they form a much stronger signal.

Correlation works best when events contain fields that allow them to be connected, such as:

- `timestamp`
    
- `user`
    
- `hostname`
    
- `src_ip`
    
- `dst_ip`
    

It may also combine information from different data sources.

---

### The difference between a true positive, false positive, true negative, and false negative, and why each matters for SOC workload and detection confidence

These terms describe whether the rule's decision was correct.

|Situation|Meaning|
|---|---|
|True Positive|Attack happened and the rule alerted|
|False Positive|No attack happened but the rule alerted|
|True Negative|No attack happened and the rule stayed quiet|
|False Negative|Attack happened but the rule missed it|

**True Positive (TP)** is what we want. The detection correctly finds malicious activity.

**False Positive (FP)** creates unnecessary work. An analyst must investigate an alert even though nothing malicious happened.

If a rule produces hundreds of false positives every day, analysts may stop trusting it.

**True Negative (TN)** means normal activity was correctly ignored.

**False Negative (FN)** is dangerous because malicious activity exists but the detection does not find it.

A good detection therefore tries to:

```text
increase TP
reduce FP
reduce FN
```

This gives analysts useful alerts without overwhelming them.

---

### Why every detection rule must be expressible as a precise predicate against specific fields and why free-text matching is a last resort

A detection should be something that a computer can evaluate clearly as **true or false**.

For example:

```text
event_id = 4624
AND LogonType = 3
AND hour_of_day >= 18
```

This is a precise predicate.

We know exactly:

- which fields are checked
    
- which values are required
    
- when the rule should match
    

This makes the rule easier to test, tune, measure, and reproduce.

Free-text detection is weaker.

For example:

```text
message contains "login failed"
```

Different systems may write:

```text
Login failed
Authentication failure
Invalid credentials
User authentication unsuccessful
```

The meaning is similar, but the text is different.

Structured fields such as:

```text
canonical_label = login_failure
```

are therefore much more reliable.

Free-text matching should mainly be used when structured fields are not available.

---

# Sigma Rule Authoring

### The full Sigma rule structure: `title`, `id`, `status`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, and `tags`

Sigma rules are written in YAML.

A basic rule contains information about **what the rule is, what data it needs, what it detects, and how important the alert is**.

Example:

```yaml
title: SSH Repeated Authentication Failures
id: 7b8f2b9a-53fd-4e81-9b35-62d8bc1c972a
status: experimental
description: Detects repeated SSH authentication failures.

logsource:
  product: linux
  service: auth

detection:
  selection:
    canonical_label: login_failure
  condition: selection

falsepositives:
  - Administrator typing the wrong password

level: high

tags:
  - attack.credential_access
  - attack.t1110.001
```

The important fields are:

- `title` — readable name
    
- `id` — unique UUID for the rule
    
- `status` — development state
    
- `description` — what it detects and why
    
- `logsource` — required log source
    
- `detection` — matching logic
    
- `condition` — how the selections are combined
    
- `falsepositives` — expected legitimate causes
    
- `level` — severity
    
- `tags` — ATT&CK mapping
    

In this project, every rule must contain all required fields and at least one `attack.tXXXX` tag.

---

### How to express selection, count, timeframe, and boolean logic in Sigma detection blocks

A **selection** defines the events we want.

Example:

```yaml
selection:
  event_id: 4624
  LogonType: '3'
```

Both fields must match.

A **filter** usually describes activity we want to exclude:

```yaml
filter:
  user: SYSTEM
```

Then we combine them:

```yaml
condition: selection and not filter
```

Sigma can also use:

```text
and
or
not
```

For example:

```yaml
condition: selection_a or selection_b
```

A `timeframe` limits a detection to a time period:

```yaml
timeframe: 120s
```

Aggregation allows us to count events:

```yaml
condition: selection | count() by src_ip > 5
```

This means:

> Find matching events, group them by source IP, and alert when one source produces more than five matches.

Together, selections, filters, boolean logic, aggregation, and timeframes allow more useful detections than simple one-event matching.

---

### How to map a rule to one or more MITRE ATT&CK techniques and why the mapping is not cosmetic

MITRE ATT&CK describes common attacker behaviors.

For example:

```yaml
tags:
  - attack.credential_access
  - attack.t1110.001
```

`T1110.001` represents Password Guessing.

The mapping tells us **what attacker behavior the rule is intended to detect**.

It is useful because it allows the SOC to answer questions such as:

- Which ATT&CK techniques can we detect?
    
- Which tactics have no coverage?
    
- Are several rules detecting the same technique?
    
- Which important techniques need new detections?
    

In this project, T12 collects ATT&CK tags from the rules and builds the coverage map.

So ATT&CK tags are not decoration. They connect individual rules to the overall detection strategy.

---

### Why vendor-neutral detection authoring outlives any specific SIEM and why Sigma became the industry reference

Different SIEM products have different query languages.

For example, one platform may use one search syntax while another uses something completely different.

If the entire detection is written directly in one vendor's language, moving to another SIEM can require rewriting the rules.

Sigma separates the **detection idea** from the SIEM implementation.

For example, Sigma describes:

```text
event_id = 4624
AND LogonType = 3
```

in a common YAML format.

Tools such as `sigma-cli` and pySigma can then convert the rule into supported backend formats.

This makes Sigma rules:

- easier to share
    
- easier to review
    
- easier to migrate
    
- less dependent on one vendor
    

That portability is one reason Sigma has become a common standard for detection-rule sharing.

---

# Detection Quality and Tuning

### How to measure precision, recall, and false positive rate for an individual detection rule against labeled evidence

We compare rule alerts with known ground truth.

**Precision** answers:

> When my rule alerts, how often is it correct?

```text
Precision = TP / (TP + FP)
```

Example:

```text
8 true alerts
2 false alerts
```

Then:

```text
Precision = 8 / 10 = 0.80
```

So 80% of the alerts were correct.

---

**Recall** answers:

> How much of the malicious activity did my rule detect?

```text
Recall = TP / (TP + FN)
```

If there were 10 malicious events and the rule found 8:

```text
Recall = 8 / 10 = 0.80
```

---

**False Positive Rate** measures incorrect alerts against legitimate activity:

```text
FPR = FP / (FP + TN)
```

In this project, we also use the seven-day clean baseline to measure how many false alerts a rule produces during normal activity.

A useful rule needs both good detection coverage and manageable false positives.

---

### How to tune a rule that fires too often without losing its ability to catch the targeted behavior

First, examine the false-positive events.

Look for patterns such as:

```text
same user
same hostname
same process
same destination
same parent process
```

Suppose most false positives come from an approved automation account:

```text
svc_backup
```

We can add:

```yaml
filter:
  user: svc_backup

condition: selection and not filter
```

This removes known legitimate activity.

But tuning must be careful.

A filter that is too broad could remove the malicious event too.

Therefore, after tuning we test the rule again against:

1. the clean baseline
    
2. the malicious evaluation window
    

The project accepts tuning only when false positives decrease significantly **without reducing true positives**.

---

### How to assess detection coverage across the MITRE ATT&CK matrix and identify gaps

Every Sigma rule contains ATT&CK technique tags.

T12 collects these tags and groups them by tactic.

Example:

```text
initial_access        1
execution             2
persistence           2
credential_access     2
exfiltration          0 [GAP]
impact                0 [GAP]
```

A tactic with zero techniques has no detection coverage in the current catalog.

This does not automatically mean the SOC must immediately write a rule for everything.

The coverage map helps identify gaps, and then risk prioritization determines which gaps matter most to MedDefense.

---

### Why rule prioritization must be driven by organizational risk, not by technical novelty

A detection rule can be technically impressive but still have little value to the organization.

MedDefense should prioritize threats according to its own risk register.

Each risk scenario has:

```text
likelihood
impact
ATT&CK techniques
```

The project calculates:

```text
risk_score =
sum of (likelihood × impact)
```

for scenarios connected to the rule.

Then:

```text
priority_score = risk_score × F1
```

So priority combines two questions:

> How important is this threat to MedDefense?

and:

> How well does our rule detect it?

For example, a patient-data access rule may have slightly lower F1 than another rule but still rank higher because patient-data compromise has much greater organizational impact.

---

# Cross-Source Detection

### Why multi-source correlation rules produce higher confidence findings than single-source rules

One suspicious event often does not prove an attack.

For example:

```text
failed login
```

could simply be a user entering the wrong password.

But imagine this sequence:

```text
5 failed logins from IP A
↓
successful login from IP B
↓
privilege escalation
```

Now the activity is much harder to explain as normal behavior.

Correlation increases confidence because several related signals support the same conclusion.

It can also connect different telemetry sources, such as:

```text
authentication logs
+
process events
+
network activity
```

This gives analysts more context than one isolated alert.

---

### How a correlation rule is structured in Sigma and what the limits of pure Sigma correlation are

Simple correlations can use Sigma aggregation:

```yaml
timeframe: 120s
condition: selection | count() by src_ip > 5
```

But complex chains are harder.

For example:

```text
3 failures from IP A
then
success from IP B
then
privilege escalation
```

requires the system to:

- group events by user
    
- compare two different source IPs
    
- preserve event order
    
- check multiple time windows
    
- connect authentication and privilege events
    

That is beyond a simple selection against one event.

For this project, the complex logic is handled before Sigma evaluation.

The resulting event can contain:

```yaml
correlation_primitive: credential_compromise_chain
```

The Sigma rule then checks that field.

---

### When to preprocess evidence into correlation primitives before rule evaluation

Preprocessing should be used when several raw events must first be combined before a meaningful detection can be made.

For example:

```text
login_failure
login_failure
login_failure
login_success
privilege_escalation
```

The preprocessing helper checks:

- same user
    
- different source IP
    
- correct order
    
- correct time limits
    
- same destination host where required
    

If the complete pattern exists, it creates a simpler event:

```json
{
  "correlation_primitive": "credential_compromise_chain"
}
```

The Sigma rule can then evaluate:

```yaml
selection:
  correlation_primitive: credential_compromise_chain
```

This keeps the Sigma rule simple while allowing more complex multi-source detection logic.

A good rule of thumb is:

> Use normal Sigma for clear event predicates and simple aggregation. Use preprocessing when you need event sequences, multiple sources, changing values, or several related time windows.

# Detection Engineering Fundamentals

### The four detection types (signature, anomaly, behavioral, correlation) and which data source and rule structure supports each

**Signature detection** looks for a known indicator or exact pattern.

Example:

```text
event_id = 4698
process_name = schtasks.exe
```

Best for structured logs such as Windows events, Linux authentication logs, Sysmon, and Suricata alerts.

**Anomaly detection** looks for activity that differs from an established baseline.

Example:

```text
baseline_known_destination = false
```

It works well with authentication, process, firewall, and network data when historical baseline data exists.

**Behavioral detection** looks for suspicious actions or sequences rather than one exact indicator.

Example:

```text
PowerShell launched by an unusual parent process
```

This is useful for endpoint/process and network-flow telemetry.

**Correlation detection** combines multiple events, often from different sources.

Example:

```text
failed login
→ successful login from another IP
→ privilege escalation
```

It usually needs timestamps, users, hosts, IP addresses, or other fields that can connect the events.

---

### The difference between a true positive, false positive, true negative, and false negative, and why each matters for SOC workload and detection confidence

**True Positive (TP):**  
The rule alerts and malicious activity really happened.

Good because the rule correctly detected a threat.

**False Positive (FP):**  
The rule alerts, but the activity is legitimate.

Too many FPs increase SOC workload and cause alert fatigue.

**True Negative (TN):**  
The rule does not alert and the activity is legitimate.

This means normal activity is correctly ignored.

**False Negative (FN):**  
Malicious activity happens but the rule does not alert.

This is dangerous because the attack may remain undetected.

A good detection tries to keep **TP high** while keeping both **FP and FN low**.

---

### Why every detection rule must be expressible as a precise predicate against specific fields and why free-text matching is a last resort

A detection rule should clearly say exactly what must be true.

For example:

```text
event_id = 4624
AND LogonType = 3
AND hour_of_day >= 18
```

This is easier to test, measure, tune, and reproduce.

Free-text matching such as:

```text
message contains "failed login"
```

is weaker because wording can change between products, versions, or log formats.

Structured fields are therefore preferred whenever available.

---

# Sigma Rule Authoring

### The full Sigma rule structure: `title`, `id`, `status`, `logsource`, `detection`, `condition`, `falsepositives`, `level`, and `tags`

A Sigma rule is a YAML detection description.

Main fields:

- `title` — human-readable rule name
    
- `id` — unique UUID
    
- `status` — for example `experimental`
    
- `description` — what the rule detects
    
- `logsource` — where the events come from
    
- `detection` — selections and filters
    
- `condition` — how selections are combined
    
- `falsepositives` — expected legitimate causes
    
- `level` — severity
    
- `tags` — ATT&CK mappings
    

Example structure:

```yaml
title: SSH Brute Force
id: UUID
status: experimental

logsource:
  product: linux
  service: auth

detection:
  selection:
    canonical_label: login_failure
  condition: selection

falsepositives:
  - Administrator mistyping password

level: high

tags:
  - attack.t1110.001
```

---

### How to express selection, count, timeframe, and boolean logic in Sigma detection blocks

A **selection** defines the events you want:

```yaml
selection:
  event_id: 4624
  LogonType: '3'
```

Boolean logic combines selections:

```yaml
condition: selection and not filter
```

or:

```yaml
condition: selection_a or selection_b
```

A timeframe limits events to a period:

```yaml
timeframe: 120s
```

Aggregation can detect repeated activity:

```yaml
condition: selection | count() by src_ip > 5
```

This means repeated matching events from the same source IP.

---

### How to map a rule to one or more MITRE ATT&CK techniques and why the mapping is not cosmetic

Each Sigma rule should include the ATT&CK technique that describes the attacker behavior.

Example:

```yaml
tags:
  - attack.credential_access
  - attack.t1110.001
```

`T1110.001` represents Password Guessing.

ATT&CK mapping matters because it helps the SOC:

- understand what attacker behavior is covered
    
- find detection gaps
    
- group rules by attack tactic
    
- explain coverage to management
    

So the tag describes what security behavior the rule actually detects.

---

### Why vendor-neutral detection authoring outlives any specific SIEM and why Sigma became the industry reference

Different SIEM products use different query languages.

A rule written only for one SIEM may need to be rewritten when the organization changes platforms.

Sigma describes the detection in a **vendor-neutral YAML format**.

Tools such as `sigma-cli` and pySigma can then convert Sigma rules into supported SIEM query formats.

This makes the detection logic more portable and reusable.

---

# Detection Quality and Tuning

### How to measure precision, recall, and false positive rate for an individual detection rule against labeled evidence

The project uses labeled evidence to compare rule matches with known malicious activity.

**Precision** asks:

> Of all alerts produced, how many were really malicious?

```text
precision = TP / (TP + FP)
```

**Recall** asks:

> Of all malicious events we wanted to detect, how many did we catch?

```text
recall = TP / (TP + FN)
```

**False positive rate** shows how often legitimate activity creates alerts.

In this project, the clean seven-day baseline is especially useful for measuring false positives.

---

### How to tune a rule that fires too often without losing its ability to catch the targeted behavior

First inspect the false-positive events.

Look for common legitimate values such as:

- users
    
- hosts
    
- processes
    
- destinations
    
- parent processes
    

Then add a narrow exclusion.

Example:

```yaml
filter_admin:
  user: approved_admin

condition: selection and not filter_admin
```

After tuning, run the rule again against both:

- clean baseline
    
- malicious evaluation window
    

The tuning is useful only if false positives decrease **without losing the true positive**.

---

### How to assess detection coverage across the MITRE ATT&CK matrix and identify gaps

Collect the `attack.tXXXX` tags from every rule.

Then group those techniques by ATT&CK tactic.

Example:

```text
execution            2 techniques
persistence          2 techniques
credential_access    2 techniques
exfiltration         0 techniques [GAP]
```

A tactic with zero covered techniques is a detection gap.

This helps the SOC see which attacker behaviors are well covered and which need new rules.

---

### Why rule prioritization must be driven by organizational risk, not by technical novelty

A technically interesting rule is not automatically important.

The rule should protect against risks that matter to the organization.

In this project:

```text
risk_score = Σ(likelihood × impact)
```

Then:

```text
priority_score = risk_score × F1
```

This combines:

- how important the threat is to MedDefense
    
- how well the detection performs
    

For a healthcare organization, for example, detecting patient-data theft may deserve higher priority than detecting a rare technical behavior.

---

# Cross-Source Detection

### Why multi-source correlation rules produce higher confidence findings than single-source rules

One event can often have a legitimate explanation.

For example:

```text
failed login
```

alone may simply be a mistyped password.

But:

```text
many failed logins
→ login from a different IP
→ privilege escalation
```

is much more suspicious.

Combining multiple related signals reduces uncertainty and can produce higher-confidence alerts.

---

### How a correlation rule is structured in Sigma and what the limits of pure Sigma correlation are

In this project, Sigma can describe the final correlation condition:

```yaml
selection:
  correlation_primitive: credential_compromise_chain

condition: selection
```

But Sigma is mainly designed for describing detection logic, not for complex processing of many event streams.

Complex correlation may require:

- ordering events
    
- comparing different IPs
    
- grouping by user
    
- checking several time windows
    
- combining multiple log sources
    

That work may need to happen before the Sigma rule is evaluated.

---

### When to preprocess evidence into correlation primitives before rule evaluation

Preprocessing is useful when the detection cannot be expressed cleanly as one normal event predicate.

For example:

```text
3 failed logins from IP A
→ successful login from IP B
→ privilege escalation on the same host
```

A helper can first combine these related events into:

```json
{
  "correlation_primitive": "credential_compromise_chain"
}
```

The Sigma rule can then detect that primitive.

Use preprocessing when the rule requires **multiple sources, event ordering, grouping, or complex time relationships** that normal Sigma selection logic cannot easily represent.
