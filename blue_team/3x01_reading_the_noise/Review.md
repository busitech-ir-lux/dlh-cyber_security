## Review: Baseline Contamination

**Question:** A peer reviews your `baseline_auth.json` and points out that the baseline window might contain activity from a previously undetected intruder. If the attacker was already logging in as `svc_backup` during the baseline period, `svc_backup` will appear in your `known_accounts` list and your T10 script will never flag its activity on day 8.

**Answer:** If an attacker was already active during the baseline period, the baseline becomes **contaminated**. Malicious behavior such as logins by `svc_backup` may be learned as “normal,” so `svc_backup` enters `known_accounts` and the `unknown_account` detector will not flag it on day 8. This creates a **false negative** because the anomaly detector trusts a bad reference.

The correct response is to **question and revalidate the baseline window**, investigate suspicious baseline-period activity using other sources such as process and network events, and, if compromise is confirmed, rebuild the baseline from a period that is known to be clean. You should also avoid relying on only one feature such as account existence: unusual login time, abnormal processes, unexpected network activity, or cross-source correlations may still expose the compromised account. The project specifically emphasizes that baselines must be validated against a **known-clean window** and that cross-source correlation increases confidence.

**Simple answer:** A contaminated baseline teaches the detector that attacker behavior is normal. Therefore, the baseline must come from verified clean data and should be rebuilt if compromise is discovered.

---
### Review: Anomaly vs Incident

**Question:** Your T14 script produces a top item scoring 26: a correlated finding on `db-patient-01` combining an `unknown_process_for_host` (`/usr/bin/python3`), an `unknown_destination_for_host` on port 8443, and a `privilege_escalation_surge`. All three happened within 90 seconds.

**Answer:** This is a **high-confidence anomaly, but it is not automatically a confirmed security incident**. The three behaviors—an unknown `python3` process, a new outbound destination on port `8443`, and a privilege-escalation surge—occurred on the same host within 90 seconds, so the cross-source correlation makes the activity much more suspicious than any one anomaly alone. The project specifically emphasizes that single-source anomalies may be weak signals, while correlation across sources increases confidence.

A score of **26 should therefore trigger immediate Tier 1 escalation and investigation**, especially because `db-patient-01` appears to be a sensitive database asset. The analyst should review the underlying process, authentication, and network events to determine whether the activity was authorized or malicious. Only after investigation confirms unauthorized or harmful activity should it be classified as a **security incident**.

**Simple distinction:** an **anomaly** means _behavior differs from the established baseline_; an **incident** means _investigation has established that the activity represents an actual security compromise or policy violation_. The score prioritizes investigation—it does not by itself prove compromise.

---
### Review: Cross-Source Correlation Value

**Question:** During validation (T15) you notice that T10 alone produces 10 anomalies, T11 alone produces 15, T12 alone produces 13. After running T13 cross-source correlation, only 7 correlated findings emerge, and the top ranked item from T14 is a correlated one, not a single-source one.

**Answer:** This result shows why **cross-source correlation is valuable**. T10, T11, and T12 generate **38 individual anomalies** in total, but many of them may describe different parts of the same activity. T13 combines related authentication, process, and network anomalies occurring on the same host within a short time window, reducing those individual signals to **7 higher-confidence findings**. The project explicitly states that single-source anomalies are often less actionable, while correlation across sources increases signal confidence.

The fact that T14 ranks a correlated finding first is also expected. An activity supported by several independent telemetry sources is generally more useful for triage than an isolated deviation. For example, an unusual login followed by an unknown process and an unexpected network connection provides a stronger behavioral story than any of those events alone. The project specifically requires ranking to consider **cross-source confirmation together with factors such as asset criticality and deviation magnitude**.

**Simple answer:** Correlation reduces alert noise and increases confidence by connecting related anomalies into one finding. The 7 correlated findings should therefore receive greater analyst attention, especially the highest-ranked one. However, the remaining single-source anomalies should not be discarded, because some real attacks may appear in only one telemetry source.

---
### Review: Temporal Baseline Interpretation

**Question:** Your `temporal_profile.json` shows that `login_success` events on `clin-ws-07` have a business hours peak at 08:00, a smaller peak at 14:00, and a near-zero rate between 18:00 and 05:59. On day 8, at 03:17, a successful login occurs on `clin-ws-07` for an account that exists in `known_accounts` and has no other anomalies against it. In 4 to 6 sentences, explain why your T10 script should still flag this event, which baseline artifact from T4 or T8 carries the signal, what additional context from the 3x00 enrichment (asset inventory or network zones) would change your priority, and what the risk is of blindly suppressing this class of finding because the account is "known".

**Answer:** T10 should still flag the 03:17 login because it is far outside the normal temporal pattern for `clin-ws-07`; a known account can still behave abnormally if its credentials are compromised. The strongest signal comes from **T8 `temporal_profile.json`**, which shows that this host normally has almost no successful logins between 18:00 and 05:59; T4’s authentication baseline can support this with its business-hours versus off-hours rates. The 3x00 **asset inventory** could raise the priority if `clin-ws-07` is a sensitive clinical asset, while **network-zone enrichment** could raise it further if the login originates from an unexpected or less-trusted zone. Blindly suppressing the event because the username appears in `known_accounts` would create a false negative: attackers commonly use valid or stolen credentials specifically because the account itself looks legitimate. Therefore, “known account” should reduce only one type of anomaly—`unknown_account`—not override abnormal time, host, or network behavior.
