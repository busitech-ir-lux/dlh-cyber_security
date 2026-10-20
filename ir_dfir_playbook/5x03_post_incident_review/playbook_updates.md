# Playbook Updates — IR-2026-0414-01

Each change modifies the *credential exposure* workflow. “Before” text is abbreviated from task context, not a verbatim copy of an existing playbook (the complete original playbook was not supplied).

### Change PB-UPD-001
**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `applies_to.triggers`  
**Gap closed:** GAP-002  
**Finding:** Forensic summary, Azure AD risk-signal suppression open item; Task 1 phase 2.

**Before (task description):**
```yaml
triggers:
  - "Credential compromise alert"
```
**After:**
```yaml
triggers:
  - "Confirmed credential submission to an external domain"
  - "Successful VPN login from a country not seen for this account in 30 days"
  - "Impossible travel: geographically incompatible successful logins within 2 hours"
  - "High-risk Entra sign-in even when the device is marked compliant"
```
**Reason:** Foreign-origin VPN usage must independently trigger investigation rather than rely only on an existing credential alert.

### Change PB-UPD-002
**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response.scope_expansion`  
**Gap closed:** GAP-007, GAP-008  
**Finding:** ART-003-M01 and AD-LOG-01.

**Before (task description):** Containment focused on original compromised host/account.

**After:**
```yaml
scope_expansion:
  trigger: "Suspected lateral movement or Kerberos ticket reuse"
  actions:
    - "Collect source and destination hostnames, account IDs, logon IDs, and logon times"
    - "Find additional hosts touched by the account in VPN, AD, EDR and SIEM logs"
    - "Contain each affected endpoint using the approved clinical continuity process"
    - "Preserve volatile artifacts and tickets before destructive remediation"
    - "Review clinical shares and PDF accesses; notify privacy/security lead"
    - "Reassess containment scope after each newly found host"
```
**Reason:** The observed attack crossed WST-WS-031, WST-WS-017, and LIS-WSIDE-01.

### Change PB-UPD-003
**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response.kerberos_remediation`  
**Gap closed:** GAP-006, GAP-007  
**Finding:** ART-002-M04 and ART-003-M01.

**Before (task description):**
```yaml
actions:
  - "Reset compromised account password"
```
**After:**
```yaml
kerberos_remediation:
  - "Confirm whether evidence indicates stolen tickets, forged tickets, or krbtgt compromise"
  - "Disable or reset affected accounts; revoke sessions; contain affected endpoints"
  - "Investigate delegated/service accounts and ticket lifetime before resetting secrets"
  - "If Golden Ticket forgery or krbtgt compromise is confirmed, coordinate two krbtgt resets with AD owners using Microsoft-supported timing and replication safeguards"
  - "Do not automatically reset krbtgt twice for every ordinary Pass-the-Ticket event"
  - "Review authentication telemetry and validate unauthorized sessions have ended"
```
**Reason:** The task requests a double reset, but **Pass-the-Ticket alone does not establish that `krbtgt` was compromised**. Mandatory unconditional double reset would be operationally risky and technically unjustified. It is included as a conditional mandatory branch for verified forging/compromise.

### Change PB-UPD-004
**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `decision_nodes.phi_exposure`  
**Gap closed:** GAP-008, GAP-009  
**Finding:** AD-LOG-01; forensic summary says 14 PHI PDFs accessed, exfiltration unconfirmed.

**Before (task description):** No clinical/ePHI assessment branch.

**After:**
```yaml
phi_exposure:
  trigger: "Confirmed or suspected access to ePHI systems or records"
  actions:
    - "Notify privacy officer and preserve relevant audit/DLP/egress records"
    - "Identify affected individuals and exactly what information was accessed"
    - "Assess HIPAA breach rule factors: nature/extent of PHI, unauthorized recipient, whether PHI was actually acquired/viewed, and extent of mitigation"
    - "Document a reasonable risk assessment and notification decision with counsel"
    - "Do not claim exfiltration solely from confirmed internal access"
    - "Follow applicable HIPAA and other jurisdictional notification rules and deadlines"
```
**Reason:** Sensitive clinical systems were in the blast radius, so privacy review must be a built-in decision point.
