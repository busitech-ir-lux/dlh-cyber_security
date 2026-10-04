# Threat Hunting Report — HEALTHBANE Stage 4

## 1. Executive Summary

This hunt investigated whether **HEALTHBANE Stage 4** activity occurred in the MedDefense environment.

The hunt focused on:

- PsExec lateral movement
- LSASS credential access
- WMI activity
- PowerShell Remoting
- service account abuse

The hunt found evidence consistent with **Stage 4 lateral movement**.

The main suspicious pivot host was:

- `WS-RECV-03`

The service account involved was:

- `svc_healthsync`

Systems reached during the activity included:

- `SRV-HEALTH-DB`
- `SRV-INS-DB`
- `SRV-DC-01`

The activity suggests that stolen credentials were used to move from a workstation to important servers.

Before the hunt, ATT&CK detection coverage was about **55%**. After creating new hunt-based detection rules, estimated coverage improved to about **80%**.

---

## 2. Hunt Methodology

This project used a **hypothesis-driven threat hunting** approach.

The process was:

1. Read the HC3 HEALTHBANE advisory.
2. Identify Stage 4 attacker techniques.
3. Compare those techniques with the current ATT&CK coverage.
4. Find techniques that were not covered.
5. Build hunt hypotheses.
6. Search the 14-day SIEM data.
7. Compare activity with Robert Kim's normal admin baseline.
8. Correlate the findings.
9. Create new detection rules.

### Data Sources

Main data sources:

- `siem_export/wazuh_alerts_14d.json`
- `siem_export/wazuh_raw_sysmon_14d.json`
- `baseline/robert_kim_activity.json`

Reference files:

- `reference/admin_schedule.txt`
- `reference/service_accounts.txt`
- `reference/network_topology.txt`

### Baseline

Robert Kim's normal activity was used as the false-positive filter.

Normal admin behavior was:

- source host: `WS-ADMIN-01`
- normal account: `MEDDEFENSE\robert.kim`
- normal working time: `08:00-18:00`
- normal tools: PsExec, WMI, PSRemoting
- service accounts should not be used interactively from workstations

---

## 3. Findings per Hypothesis

### H1 — PsExec Lateral Movement

**Status:** Positive  
**Confidence:** High

PsExec activity was found that did not match Robert Kim's baseline.

Important indicators included:

- activity from a non-admin workstation
- service account use
- off-hours activity
- access to database servers

This behavior was consistent with lateral movement.

---

### H2 — LSASS Credential Access

**Status:** Positive  
**Confidence:** High

Suspicious access to `lsass.exe` was found from a non-system process.

This was important because LSASS memory may contain credentials.

Later activity showed use of `svc_healthsync`, which supports the idea that credentials were obtained and then reused.

---

### H3 — WMI Activity

**Status:** Positive  
**Confidence:** Medium to High

WMI activity was found outside the expected administrator pattern.

The activity was consistent with:

- remote execution
- remote process creation
- reconnaissance

WMI is legitimate in Windows administration, but the source, account, target and timing made the activity suspicious.

---

### H4 — PowerShell Remoting

**Status:** Positive  
**Confidence:** Medium to High

PowerShell Remoting / WinRM activity was found in the attack chain.

The activity was consistent with:

- remote access
- command execution
- file staging

The activity did not fully match Robert Kim's normal administration pattern.

---

### H5 — Service Account Abuse

**Status:** Positive  
**Confidence:** Very High

`svc_healthsync` was used outside its expected service context.

Important indicators included:

- authentication from a workstation
- use from an unauthorized source
- interactive-style use
- correlation with lateral movement activity

This was one of the strongest findings because service accounts should normally operate only from approved systems.

---

## 4. Reconstructed Attack Timeline

The hunt findings were correlated into the following Stage 4 attack chain.

### Credential Access

`WS-RECV-03` showed suspicious LSASS memory access.

This may have allowed the attacker to obtain credentials.

### Service Account Use

The account `svc_healthsync` was later used from a workstation instead of only from its authorized service host.

### Lateral Movement

PsExec activity was observed from the compromised workstation toward server systems.

Example progression:

`WS-RECV-03`  
→ `SRV-HEALTH-DB`  
→ `SRV-INS-DB`

### Reconnaissance

WMI activity was used for remote execution and/or system enumeration.

### Staging

PowerShell Remoting activity was used for remote access and possible file staging.

### Expansion

Activity also reached:

- `SRV-INS-DB`
- `SRV-DC-01`

Overall progression:

```text
WS-RECV-03 compromise
        |
        v
LSASS credential access
        |
        v
svc_healthsync stolen/used
        |
        v
PsExec lateral movement
        |
        v
WMI reconnaissance
        |
        v
PowerShell Remoting / staging
        |
        v
Database and server access
```

The exact dwell time should be calculated from the first and last confirmed malicious timestamps produced by Task 10.

---

## 5. ATT&CK Coverage Update

Before the hunt:

- observed coverage: about **55%**
- several Stage 4 techniques were not covered

Important uncovered techniques included:

- `T1021.002` — SMB / Windows Admin Shares
- `T1047` — WMI
- `T1021.006` — Windows Remote Management
- `T1003.001` — LSASS Memory
- `T1078.002` — Domain Accounts

After the hunt and detection-rule work:

- estimated coverage improved to about **80%**

The hunt showed that the SIEM often had the required data, but detection logic was missing.

---

## 6. Detection Improvements

The hunt produced new Wazuh-style and network-level detection drafts.

### New Detection Rules

**Rule 100100 — PsExec anomalous source**

Detects PsExec activity from unusual hosts or outside Robert Kim's normal admin pattern.

**Rule 100101 — LSASS access**

Detects non-system processes accessing `lsass.exe`.

**Rule 100102 — Service account misuse**

Detects service account authentication from unauthorized hosts or workstations.

**Rule 100103 — WMI child process anomaly**

Detects `wmiprvse.exe` spawning suspicious child processes such as:

- `cmd.exe`
- `powershell.exe`

**Network Rule 9000030 — PsExec SMB activity**

Detects possible PsExec service installation patterns over SMB.

### Detection Posture

Before hunt:

- some attacker activity was visible in logs
- no alert was generated
- several ATT&CK techniques had no behavioral detection

After hunt:

- more Stage 4 behaviors can generate alerts
- baselines can be used as allowlists
- service account misuse can be detected more reliably
- lateral movement coverage improved

---

## 7. Remaining Gaps and Recommendations

About **20%** of the ATT&CK coverage still remains uncovered.

Some activity may also remain unknown because:

- some rules are only drafts
- some data sources may not be complete
- not every Windows system may have the same Sysmon coverage
- some attacker behavior may look similar to legitimate administration

### Immediate Actions

- isolate and investigate `WS-RECV-03`
- preserve logs and forensic evidence
- investigate activity on reached servers
- begin incident response procedures

### Short-Term Actions

- rotate `svc_healthsync` credentials
- review all service account passwords
- review privileged accounts
- review recent authentication activity
- check whether other systems were accessed using the same credentials

### Medium-Term Actions

- deploy Sysmon consistently across important systems
- improve PowerShell logging
- monitor service account source hosts
- use behavioral detection instead of only static IOCs
- regularly review ATT&CK coverage
- repeat this hunt after detection improvements

---

## 8. Lessons Learned

### 55% coverage created a false sense of security

The SIEM did not generate enough alerts, but suspicious activity was still present in the logs.

This shows:

> No alert does not mean no attack.

### Reactive detection was not enough

PsExec, WMI and PowerShell are legitimate tools.

Because attackers used normal Windows administration tools, simple IOC or tool-name detection was not enough.

Context was required:

- source host
- user
- target
- time
- account type

### Baselines were important

Robert Kim's normal activity made it possible to separate legitimate administration from suspicious behavior.

Without the baseline, many hunt results could have been false positives.

### Threat hunting should be repeated

The hunt found activity that existing alerts missed.

The cycle should continue:

```text
hunt -> find -> detect -> hunt again
```

Threat hunting should therefore be a recurring SOC activity, not a one-time task.

---

## Final Assessment

The hunt found multiple correlated indicators consistent with **HEALTHBANE Stage 4 activity in the MedDefense environment**.

The strongest evidence was:

- suspicious LSASS access
- use of `svc_healthsync` outside its authorized context
- PsExec lateral movement
- WMI activity
- PowerShell Remoting
- access to important server systems

**Overall assessment: POSITIVE — HIGH CONFIDENCE**

MedDefense also improved its detection posture by turning the hunt findings into new detection logic, increasing estimated ATT&CK coverage from **55% to approximately 80%**.
