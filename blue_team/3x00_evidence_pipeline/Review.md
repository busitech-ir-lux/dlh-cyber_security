### Review: Evidence Chain Integrity

**Question:** An analyst finds an alert fired on an event whose `hostname` field is empty. The analyst traces back through the pipeline and discovers the original `Linux` log line had a valid hostname, but the normalization stage (T5) mapped the wrong intermediate field and the dirty data stage (T8) then silently assigned `null`. The analyst escalates to the pipeline owner.

**Answer:** This is an **evidence-chain integrity failure** because the original Linux event contained a valid hostname, but the pipeline altered that information during normalization. The pipeline owner should trace the event from the raw log through T3, T5, and T8, identify the incorrect field mapping in T5, and fix it so the original hostname is preserved. T8 should also be changed so that it does not silently replace required evidence fields with `null`; missing required data should instead be logged or quarantined. After fixing the pipeline, the affected data should be regenerated from the original evidence rather than manually editing the final event. The correction should be documented so analysts can prove what changed, why it changed, and maintain reproducibility and trust in the evidence chain.

---

### Review: Normalization Trade-offs

**Question:** A fellow student designs a schema with a single field called `message` into which the entire `raw_message` of every source is dumped. They argue this is simpler than mapping source-specific fields and that analysts can always `grep` the message. Their normalized dataset loads fine into 3x02 and Sigma rules still match on regex.

**Answer:** This design sacrifices **searchability, consistency, and semantic meaning** for simplicity. Keeping only a single `message` field forces analysts and detection rules to understand every vendor-specific log format and rely heavily on regex, which is fragile and can increase false positives or missed detections. Important concepts such as `user`, `src_ip`, `process_name`, `event_category`, and `severity` cannot be queried consistently across Windows, Linux, and network sources. A better schema should preserve `raw_message` for evidence fidelity while also extracting important values into normalized fields for reliable detection, correlation, and triage. Normalization therefore adds some implementation complexity, but it makes downstream analysis much more accurate and source-independent.

---

### Review: Data Quality Impact

**Question:** The primary evidence pack contains 127 duplicate events produced by a network retransmission. A student's pipeline deduplicates them silently during T8 with no entry in `cleaning_log.json`. Their `cleaned_events.json` is smaller and their downstream detection rules produce fewer false positives as a result.

**Answer:** Silently removing the 127 duplicate events is a **data-quality and evidence-integrity problem**, even if it reduces false positives. Deduplication is valid, but every removed event should be recorded in `cleaning_log.json` so analysts can distinguish intentional cleaning from accidental evidence loss. The investigation impact is important because removing events changes event counts and may affect timeline reconstruction, frequency analysis, correlation, and an analyst’s assessment of the scale or persistence of suspicious activity. Without a cleaning record, investigators cannot reliably explain why the cleaned dataset differs from the original evidence or reproduce the same findings. The correct approach is to keep the first occurrence, remove the retransmission duplicates, and log each removal with its record ID and reason.

---

### Review: Cross-Source Correlation

**Question:** An analyst will need to correlate a `Windows` Sysmon Event ID 3 (network connection) on a clinical workstation with a Suricata alert on a perimeter sensor fired within the same second on the same destination IP. In 4 to 6 sentences, explain which specific pipeline stages and schema fields from your 3x00 design make this correlation possible, what would happen if any one of those stages produced inconsistent output, and why the timeline index from T10 is not sufficient on its own to perform this correlation.

**Answer:** This correlation depends on **T5 normalization** and **T6 network normalization** producing consistent fields such as `timestamp`, `hostname`, `source_type`, `event_id`, `src_ip`, `dst_ip`, and `event_category` for both Sysmon and Suricata events. **T8 data quality** ensures timestamps and hostnames are consistent, while **T9 enrichment** adds asset criticality and network-zone context so the analyst can confirm that the Sysmon event came from a clinical workstation and understand where the Suricata traffic was observed. The analyst can then correlate Sysmon Event ID 3 and the Suricata alert by matching their normalized timestamps within the same second and comparing the same `dst_ip`. If any stage produces inconsistent timestamps, IP fields, hostnames, or source classifications, the two related events may appear unrelated and the correlation can be missed. **T10's timeline index alone is not sufficient** because chronological ordering only places events near each other in time; reliable cross-source correlation still requires consistently normalized fields and enrichment context to prove that the events refer to the same network activity.
