
# Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, **without the help of Google**:

### Log Reading and Format Literacy

- How to identify, enumerate, and profile every source type present in a normalized security dataset
    
- How field presence, field cardinality, and example values reveal the operational role of a log source
    
- How to build a reusable CLI query toolkit that filters, aggregates, and pivots across a flat JSON dataset without a SIEM
    

### Behavioral Baselining

- What a behavioral baseline is, why it is the foundation of anomaly detection, and how it differs from a static threshold
    
- How to compute authentication, process, network, file, and temporal baselines from historical normalized data
    
- Why baselines must be specific to host, role, and time of day or week to remain useful in production
    
- How to store a baseline in a machine-readable format that another script can consume without human interpretation
    

### Anomaly Detection and Correlation

- How to compare an evaluation window against a baseline to surface deviations in activity
    
- Why a single-source anomaly is rarely actionable and why correlating across sources multiplies signal confidence
    
- How to rank anomalies by a composite score that combines asset criticality, deviation magnitude, and cross-source confirmation
    

### Validation and Operational Reuse

- Why every baseline must be validated against a known-clean window to bound its false positive rate before production use
    
- How to package a reusable analytical toolkit that another analyst can run on a fresh dataset with zero configuration
    

---

# Resources

_Read or watch:_

### Baseline Analysis Foundations

- [SANS: Baseline Analysis of Network Traffic](https://www.sans.org/white-papers/1549) - Principles of baselining and deviation analysis
    
- [NIST SP 800-137: Information Security Continuous Monitoring](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf) - Continuous monitoring and baseline establishment
    

### Log Field Semantics

- [SANS: Windows Security Log Events Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) - Definitive Event ID reference
    
- [Linux Audit Framework Reference](https://github.com/linux-audit/audit-documentation/wiki) - auditd field semantics
    
- [Suricata EVE JSON Output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) - Network alert field reference
    

### Correlation and Detection Theory

- [MITRE ATT&CK: Data Sources](https://attack.mitre.org/datasources/) - Which techniques each data source reveals
    
- [David Bianco: The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) - Why behavioral detection outlives IOC detection
    

### Man Pages

- `man jq`
    
- `man awk`
    
- `man sort`
    
- `man date`
    
- `man python3`

---
# Learning Objectives

## Log Reading and Format Literacy

**How to identify, enumerate, and profile every source type present in a normalized security dataset**

**Answer:**  
First identify the unique `source_type` values in the dataset, then count how many events each source produces. After that, inspect a few records from every source and note which fields are commonly present. This tells you what telemetry you actually have before you start building detections.

---

**How field presence, field cardinality, and example values reveal the operational role of a log source**

**Answer:**  
The fields tell you what a source can observe. For example, usernames and login results suggest authentication telemetry, process and parent fields suggest endpoint execution data, while `src_ip`, `dst_ip`, ports and protocols suggest network telemetry. Cardinality also helps: a field with thousands of destination IPs behaves differently from a field with only twelve hostnames. Suricata EVE, for example, uses fields such as timestamp, event type, IPs, ports and protocol to describe network activity.

---

**How to build a reusable CLI query toolkit that filters, aggregates, and pivots across a flat JSON dataset without a SIEM**

**Answer:**  
Build one script that reads the normalized JSON and provides reusable commands such as `filter`, `count`, `distinct`, `top`, and time-window grouping. Tools such as `jq`, `sort`, `uniq` and `awk` can do most of this directly from the command line. The benefit is that later scripts reuse the same query logic instead of implementing it again.

---

# Behavioral Baselining

**What a behavioral baseline is, why it is the foundation of anomaly detection, and how it differs from a static threshold**

**Answer:**  
A behavioral baseline is a record of what **normal activity actually looks like** in your environment, based on historical data. Anomaly detection then asks whether new behavior differs from that normal pattern. A static threshold is just a fixed rule such as “more than 10 failures is suspicious,” while a baseline can learn that 10 failures may be normal on one system and highly unusual on another. This fits NIST's monitoring approach of continuously assessing actual system conditions and risk.

---

**How to compute authentication, process, network, file, and temporal baselines from historical normalized data**

**Answer:**  
Take a known-clean historical window and summarize each behavior separately. Authentication can track normal users, hosts, login times and failures; process baselines track expected processes and parent-child pairs; network baselines track normal destinations and ports; file baselines track normal file activity; and temporal baselines show when those activities normally happen. The result is a reference against which future events can be compared.

---

**Why baselines must be specific to host, role, and time of day or week to remain useful in production**

**Answer:**  
Normal behavior depends on context. `python3` may be completely normal on an analyst workstation but unusual on a clinical server, and a login at 03:00 may be normal for a backup account but strange for an office user. A global baseline removes these differences and creates too many false positives or misses important anomalies.

---

**How to store a baseline in a machine-readable format that another script can consume without human interpretation**

**Answer:**  
Store the baseline in structured JSON with predictable names and types, for example `per_host`, `known_accounts`, `expected_processes`, `window`, and numeric thresholds. Another script should be able to read those values directly with `jq` or Python without parsing sentences or analyst notes. This makes the baseline reusable and deterministic.

---

# Anomaly Detection and Correlation

**How to compare an evaluation window against a baseline to surface deviations in activity**

**Answer:**  
First separate new events into an evaluation window, then compare their behavior with the clean baseline. Examples include a new account, a process never seen on that host, an unusual network destination, or activity at a normally quiet time. The difference between the observed value and expected behavior becomes the anomaly.

---

**Why a single-source anomaly is rarely actionable and why correlating across sources multiplies signal confidence**

**Answer:**  
One unusual event may have an innocent explanation. But if an unusual login is followed by a new process and an unexpected network connection on the same host within a few minutes, the combined evidence is much stronger. Different telemetry sources observe different parts of attacker activity, which is why combining them increases confidence. MITRE ATT&CK likewise treats sources such as process, network traffic, logon sessions, files and user accounts as different observable areas of activity.

---

**How to rank anomalies by a composite score that combines asset criticality, deviation magnitude, and cross-source confirmation**

**Answer:**  
Not every anomaly deserves the same priority. A score can increase when the affected asset is more critical, the behavior differs greatly from its baseline, or several independent sources confirm the same activity. This pushes the findings with the strongest security impact and evidence to the top of the analyst's queue.

---

# Validation and Operational Reuse

**Why every baseline must be validated against a known-clean window to bound its false positive rate before production use**

**Answer:**  
Run the anomaly logic against data that is known to be clean. If it produces many findings there, the baseline or thresholds are too noisy and should not be trusted in production. Then compare this with the evaluation window: a useful baseline should produce relatively little noise on normal data but clearly surface abnormal activity. This is consistent with NIST's emphasis on monitoring whether security controls and monitoring processes remain effective.

---

**How to package a reusable analytical toolkit that another analyst can run on a fresh dataset with zero configuration**

**Answer:**  
Put the scripts, baselines, taxonomy, thresholds and required supporting files into one predictable package. Scripts should use environment variables and relative paths rather than student-specific hardcoded paths, validate their inputs, produce deterministic outputs, and run in the correct order. The goal is that another analyst can provide a fresh handoff dataset, run the toolkit, and get the same type of analysis without rewriting anything.
