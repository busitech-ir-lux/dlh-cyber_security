
# MedDefense Severity Matrix

## Purpose

Provide a common severity language for all MedDefense security incidents. Apply it from the first alert through incident closure.

## Severity Matrix

|Level|Patient Safety Impact|Data Exposure|Service Availability|Max Response Time|Decision Authority|
|---|---|---|---|---|---|
|SEV1|high|confirmed_broad|full_outage|15 min|CISO|
|SEV2|moderate|confirmed_limited|partial_outage|30 min|IR Commander|
|SEV3|low|suspected|degraded|60 min|SOC Lead|
|SEV4|none|none|none|240 min|SOC Analyst|

**How to use:** Assign the highest severity indicated by **any** applicable criterion; all columns do not need to match. Response time means the maximum time to acknowledge and begin the incident response, measured from detection or reporting.

## Level Definitions

### SEV1 — Critical

- Ransomware causes an outage of Epic across multiple MedDefense sites, threatening patient care.
- Confirmed large-scale exposure of records from MedDefense's approximately 180,000 active patient records.
- A patient monitoring system goes offline during active care at Main Hospital's ICU.

### SEV2 — High

- Malware disrupts the MedDefense LIS (`LIS-WSIDE-01`), partially interrupting laboratory operations.
- Confirmed limited exposure of patient information through a compromised clinical-access account.
- A clinical network segment at West Campus is isolated, interrupting some outpatient services.

### SEV3 — Medium

- Suspicious logins to an Epic-linked account require investigation, with no confirmed patient-data exposure.
- An isolated clinical workstation (`wst-ws-12.meddefense.local`) experiences degraded performance following a suspicious process alert.
- Nexus Patient Scheduling operates slowly but remains available to staff.

### SEV4 — Low

- A blocked phishing email is reported, with no account compromise or service impact.
- A Wazuh alert on a clinical workstation is confirmed benign after triage.
- An unsuccessful unauthorized login attempt is detected with no evidence of access or disruption.

## Escalation Rule

Reassess severity at every status update and whenever new evidence arrives. **Raise severity immediately** if any patient-safety, data-exposure, or service-availability criterion reaches a higher level; **lower severity only after verified containment and IR Commander approval**, documenting the reason and time.
