## Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, **without the help of Google**:

### Evidence Engineering [read more](#evidence-engineering)

- What an evidence pipeline is, the stages it contains (intake, parse, normalize, clean, enrich, index, validate), and why each stage exists
    
- How raw log exports from `Windows`, `Linux`, and network devices differ in structure, and why those differences must be reconciled before analysis
    
- What a unified event schema is, what fields belong in it, and how to justify required versus optional fields
    
- Why data normalization is a trade-off between fidelity and searchability, and what is lost when you collapse source-specific fields into a common format
    

### Data Quality and Enrichment [read more](#data-quality-and-enrichment)

- What dirty data looks like in a security context (malformed timestamps, duplicates, encoding errors, timezone inconsistencies, missing hostnames) and why it arises in production logging
    
- How asset context and network zone information change the operational meaning of an otherwise-identical event
    
- Why a chronological timeline with source attribution is the primary lookup tool of a SOC analyst during an incident
    

### Operational Reproducibility [read more](#operational-reproducibility)

- Why an evidence pipeline must be runnable from a single command and must generalize to unseen data
    
- How to write a bounded technical specification for a data pipeline that another engineer can rebuild from
    
- How the evidence handoff package produced here feeds every downstream detection, triage, and investigation project in this module
    

---

## Resources

_Read or watch:_

### Log Formats and Parsing

- [NIST SP 800-92: Guide to Computer Security Log Management](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf) - Sections 2 to 4 on log sources, formats, and management
    
- [evtx_dump Documentation](https://github.com/omerbenamram/evtx) - Python and Rust library for parsing `Windows` Event Log files into JSON
    
- [Suricata EVE JSON Output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) - Schema reference for Suricata alert exports
    

### Unified Schemas

- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/docs/reference/ecs) - The industry reference for field naming across sources
    
- [OCSF: Open Cybersecurity Schema Framework](https://schema.ocsf.io/) - Vendor-neutral schema for security events
    

### Data Quality

- [Google SRE Book: Data Integrity](https://sre.google/sre-book/data-integrity/) - How production data pipelines handle corruption and quality
    
- [MITRE ATT&CK: Data Sources](https://attack.mitre.org/datasources/) - Which data sources detect which techniques
    

### Man Pages

- `man jq`
    
- `man date`
    
- `man awk`
    
- `man python3`
    
- `man sort`

---
### Evidence Engineering

**What an evidence pipeline is, the stages it contains (intake, parse, normalize, clean, enrich, index, validate), and why each stage exists**

---

An evidence pipeline is a repeatable process that turns raw security logs into data analysts can reliably search and investigate.

- **Intake:** identify what evidence was received and verify the files.
    
- **Parse:** turn different raw formats into structured records.
    
- **Normalize:** map those records into one common schema.
    
- **Clean:** repair or flag problems such as bad timestamps, duplicates, or encoding errors.
    
- **Enrich:** add useful context such as asset criticality and network zone.
    
- **Index:** organize events, especially by time, for fast investigation.
    
- **Validate:** check that the final records follow the schema and that the pipeline did not lose or corrupt important data.
    

Each stage has one clear responsibility, which makes problems easier to detect and the whole process reproducible.

---

**How raw log exports from `Windows`, `Linux`, and network devices differ in structure, and why those differences must be reconciled before analysis**

---

The sources describe similar activity in very different ways. Windows events are usually structured around fields such as Event ID, provider, channel, hostname, and event data. Linux logs may be plain syslog text or auditd key-value records, while network sources may use CSV, Suricata EVE JSON, or flow records with IP addresses, ports, protocols, and timestamps.

If these formats are analyzed directly, every query must understand every source format. Parsing and normalization solve this by putting equivalent concepts, such as time, user, source IP, and destination IP, into consistent fields. This is the basic idea behind standards such as ECS and OCSF.

---

**What a unified event schema is, what fields belong in it, and how to justify required versus optional fields**

---

A unified event schema defines the common structure that all normalized events follow. Useful fields include `timestamp`, `hostname`, `source_type`, `event_category`, `severity`, `user`, `process_name`, `src_ip`, `dst_ip`, and `raw_message`.

A field should be **required** when the pipeline or downstream analysis depends on every event having it, such as `timestamp` or `source_type`. A field should be **optional** when it is useful but does not exist for every source; for example, a firewall event may have IP addresses but no username or process name.

The goal is not to force every source to contain the same information, but to give the information that does exist a consistent meaning.

---

**Why data normalization is a trade-off between fidelity and searchability, and what is lost when you collapse source-specific fields into a common format**

---

Normalization makes searching easier because analysts can query one field such as `src_ip` instead of knowing every vendor's original field name. The trade-off is that source-specific details can be lost when many different formats are reduced to a small common schema.

For example, two products may provide different details about the same network connection that cannot all fit naturally into the same fields. A good pipeline therefore keeps normalized fields for searching while also preserving `raw_message` or original structured data for deeper investigation. This keeps both **searchability and evidence fidelity**.

---

### Data Quality and Enrichment

**What dirty data looks like in a security context (malformed timestamps, duplicates, encoding errors, timezone inconsistencies, missing hostnames) and why it arises in production logging**

---

Dirty security data is data that is technically present but unreliable or inconsistent. Examples include malformed timestamps, duplicated events, broken character encoding, different timezones, inconsistent hostname capitalization, and missing fields.

This happens because production logs come from different operating systems, applications, sensors, versions, time settings, export processes, and network conditions. For example, retransmissions may create duplicate network events and incorrectly configured clocks may shift events by several hours. If these problems are ignored, they can distort timelines, event counts, correlation, and detection results.

---

**How asset context and network zone information change the operational meaning of an otherwise-identical event**

---

The same event can have very different importance depending on where it happens. Ten failed logins against a test machine are usually less serious than the same activity against a critical patient database.

Asset enrichment adds information such as the system's **role, owner, OS, criticality, and zone**. Network enrichment identifies whether traffic is moving between areas such as an internal clinical network, DMZ, or the Internet. This context helps analysts decide which events need immediate attention rather than treating every technically identical event as equally important.

---

**Why a chronological timeline with source attribution is the primary lookup tool of a SOC analyst during an incident**

---

Incident investigation is largely about reconstructing **what happened, when, where, and in what order**. A chronological timeline puts Windows, Linux, firewall, IDS, and network events into one ordered view.

Source attribution is important because an analyst must know whether an observation came from Sysmon, Linux auditd, a firewall, Suricata, or another source. The timeline helps the analyst quickly find suspicious periods and related events, then use the full enriched records for deeper investigation. It is an index, not a replacement for the original evidence.

---

### Operational Reproducibility

**Why an evidence pipeline must be runnable from a single command and must generalize to unseen data**

---

A pipeline should not depend on someone remembering a long sequence of manual steps. A single command guarantees that stages run in the correct order, use the same configuration, stop on failures, and produce repeatable logs and outputs.

It must also work on an unseen evidence pack with different hosts, timestamps, addresses, and network ranges. If it only works on the dataset used during development, values were probably hardcoded and the result is a one-off parser rather than a reusable pipeline.

---

**How to write a bounded technical specification for a data pipeline that another engineer can rebuild from**

---

A useful pipeline specification should describe exactly what another engineer needs to reproduce the system: each stage, its script, its inputs, its outputs, the schema, execution commands, expected directory structure, and important failure conditions.

It should be short and precise rather than explaining the history of the project. The test is simple: another engineer should be able to understand the data contract and rebuild or operate the pipeline without needing a separate verbal explanation.

---

**How the evidence handoff package produced here feeds every downstream detection, triage, and investigation project in this module**

---

The handoff package is the contract between this pipeline and the rest of Module 3. It provides normalized and enriched events, the timeline index, network events, schema, context files, quality and validation reports, pipeline scripts, and integrity information.

Detection projects can query predictable normalized fields, triage can use enrichment such as asset criticality and network zones, and investigations can use the timeline to reconstruct activity before opening full records. Because every downstream project uses the same files and schema, an error introduced here can affect all later detections and investigations.

**Main references used:** NIST SP 800-92, Elastic Common Schema (ECS), Open Cybersecurity Schema Framework (OCSF), MITRE ATT&CK Data Sources, Google SRE guidance on data integrity, and the parsing/normalization work completed in this project.
