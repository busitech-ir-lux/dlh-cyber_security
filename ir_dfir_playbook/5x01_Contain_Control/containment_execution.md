# Containment Execution: IR-2026-0414-01

- host: `WST-WS-031` / `10.42.118.31`
- selected_strategy: A — quarantine VLAN with tightly controlled IR jumpbox access (see `containment_decision.md`)
- current_status: **NOT EXECUTED / EXECUTION NOT VERIFIED**
- source_records: `alert_A-20260414-9841.json`, `edr_wst_ws_031_24h.jsonl`, `containment_decision.md`, `evidence_preservation.md`
- evidence_limit: The source files show malicious-looking activity through `2026-04-14T02:47:30Z` but **do not contain switch, firewall, endpoint-containment, jumpbox-connectivity, or post-containment NetFlow/PCAP records**. No execution timestamps or observed results can be certified.

## Prerequisites (must be verified before execution)

- [ ] James Chen (IR Commander) explicitly approves the containment action; record actual UTC approval time.
- [ ] Evidence-preservation gate met, or an urgent-containment exception recorded (including what evidence may be lost).
- [ ] Laboratory owner confirms safe alternative clinical workflow; no spare workstation count is established.
- [ ] Network operator identifies the **actual** switch, switchport, existing VLAN, quarantine VLAN (999 is an **example**, not verified), and the IR jumpbox source IP; records pre-change configuration for rollback.
- [ ] Confirm quarantine access-control policy: deny patient/user VLAN, general egress, and lateral traffic; allow only approved forensic jumpbox and required management traffic. Validate IPv4 **and** IPv6 if enabled.
- [ ] Confirm actual enforcement-point CLI/API (switch vendor, firewall platform, EDR API) with authorized administrator; placeholders below are **not executable literal commands**.

## Step-by-step execution record

The steps below are **pending action records**, not claims that any action occurred. When executed, replace `PENDING` fields with the actual UTC time, named actor, exact device/console command, resulting transaction/record ID, and observation. Preserve the before/after switch and firewall configurations in the evidence store and SHA-256 hash the exports.

### 1. Quarantine VLAN / network isolation

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized network administrator`
- **command or console action:** Identify the live access port serving `WST-WS-031` (`10.42.118.31`) using approved NAC/switch inventory; export current port config; change its access VLAN to the approved quarantine VLAN **only after validating the approved ACL and jumpbox exception**. Example operational request: `Set <verified-switch>/<verified-port> access VLAN to <approved-quarantine-VLAN>; apply <approved-IR-quarantine-policy>` (vendor-neutral placeholder; not a shell command).
- **expected result:** Host loses ordinary clinical/internet access; permitted IR jumpbox can still reach host; no general egress.
- **observed result:** `NOT VERIFIED — no switch/NAC change log supplied`
- **deviation notes:** `PENDING`; record old/new VLAN, exact command or console audit-event ID, policy name, and evidence path.

### 2. Block attacker destination on egress firewall

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized firewall administrator`
- **command or console action:** On the **verified** egress firewall, add an explicit, logged deny rule for `source=10.42.118.31`, `destination=185.220.101.47`, `protocol=any`, `action=deny` (restrict scope as policy requires); commit/publish policy. Record rule ID and commit ID. Keep this defense in depth even if quarantine already denies general outbound traffic. Example console instruction: `Policy > Add rule > source 10.42.118.31 > destination 185.220.101.47 > deny > log > commit` (**UI flow illustrative; verify on actual product**).
- **expected result:** New outbound sessions or packets to this destination are denied, with matching firewall deny logs.
- **observed result:** `NOT VERIFIED — no rule/commit or firewall log supplied`
- **deviation notes:** `PENDING`; note policy propagation delay, existing session handling, and any alternate destinations.

### 3. Validate C2 network communication stopped

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — on-call SOC analyst / network operator`
- **command or console action:** Query firewall session/deny logs **and** NetFlow/PCAP for `src=10.42.118.31 AND dst=185.220.101.47 AND dport=443`, starting at the **actual** enforcement timestamp and extending across a documented observation interval. Export results as `network/post_containment_c2_validation.*` with timestamp range and collection details. If a packet capture is made at the enforcement point, use an approved capture invocation equivalent to `tcpdump -ni <verified-interface> -w <secure-output-path>.pcap 'host 10.42.118.31 and host 185.220.101.47 and tcp port 443'` (requires access and correct capture vantage point).
- **expected result:** No successful post-enforcement C2 sessions; allow/deny logs and packet observations corroborate block. Preexisting connections may need explicit termination at enforcement point.
- **observed result:** `NOT VERIFIED — no post-containment telemetry provided`; historical EDR confirms connections at `02:47:02Z` and `02:47:30Z`, **not** their subsequent cessation.
- **deviation notes:** `PENDING`; absence of flow records alone does not prove an effective block—check sensor health, logging completeness, and enforcement-policy hit counters.

### 4. Apply endpoint containment flag (if supported)

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized EDR operator`
- **command or console action:** Check actual EDR product and agent capabilities. If supported, select `WST-WS-031` by unique device ID and request `Isolate/Contain device`; record device ID, operation/job ID, policy exceptions, and console audit event. **Only enable if it preserves required forensic jumpbox access:** some endpoint products do not support this exception; if not supported, record `NOT APPLICABLE` and rely on VLAN-based isolation.
- **expected result:** Console reports containment enabled and endpoint agent acknowledges policy; authorized forensic channel remains usable or documented alternate forensic path works.
- **observed result:** `NOT VERIFIED — no containment console/action result provided`
- **deviation notes:** `PENDING`; avoid double-isolating the forensic jumpbox path.

### 5. Verify jumpbox-only reachability

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — SOC analyst with network administrator`
- **command or console action:** From **approved IR jumpbox**, test specifically authorized management port(s) to `10.42.118.31`, e.g., Windows PowerShell `Test-NetConnection 10.42.118.31 -Port <approved-port>`; from **user VLAN**, repeat identical test; from an unauthorized subnet, repeat; inspect ACL/firewall counters for denied general access and ensure host cannot access LIS or external destinations. Record source IP, target port, test method, output, and UTC timestamps. ICMP `ping` is optional and **not sufficient alone** to establish firewall reachability.
- **expected result:** Allowed management connection succeeds from jumpbox only; the same test fails from regular clinical/user subnets; outbound external traffic denied.
- **observed result:** `NOT VERIFIED — no sourced connectivity tests supplied`
- **deviation notes:** `PENDING`; if jumpbox reachability fails, do not claim successful forensic-access containment; escalate and review quarantine policy.

## Containment completion gate

Containment is **not verified** until all of the following are recorded: approved authorization, switch/NAC transaction, firewall policy ID, timestamped post-enforcement network observations, endpoint flag status (or not-applicable reason), positive jumpbox access test, negative user-VLAN access test, and clinical-impact confirmation. Save console exports and connection-test outputs in `/evidence/IR-2026-0414-01/` under `network/`, `endpoint_telemetry/`, or `correlation/`; append SHA-256 entries to the existing `hashes.txt` according to `evidence_store_init.sh`, then check with `sha256sum -c hashes.txt` from the evidence-store root.

## Handoff / rollback trigger

If quarantine interrupts critical clinical services and approved alternatives are unavailable, escalate immediately to James Chen and the laboratory service owner. Roll back **only on explicit authorization**, restoring recorded prior VLAN/ACL values or implementing a documented restricted-care alternative; do not reconnect a compromised workstation without formally accepting and mitigating the exposure. Record every actual change, verification, rollback and clinical impact as a new timestamped timeline entry.

## Timeline entry format — APPEND ONLY WHEN EACH STEP ACTUALLY OCCURS

Copy this structure into `incident_timeline.md` after execution for **each** applicable step. Do **not** copy it now as a completed `ACTION`:

`- <actual-UTC-ISO8601> | ACTION | <named-actor> | <exact command or console action>; expected=<expected>; observed=<observed>; deviation=<none or details> | source=containment_execution.md + <switch/firewall/EDR/test-export> | certainty=<confirmed|high|probable|possible>`

**Timeline integrity:** The existing timeline contains no independently verified Task 4 operations. Do not backdate or invent action entries; append the actual timestamped events as source evidence becomes available. In this task's available records, the accurate status is **planned / pending verification**, not executed.
