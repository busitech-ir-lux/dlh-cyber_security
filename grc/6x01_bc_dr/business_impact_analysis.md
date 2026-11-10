# MedDefense Business Impact Analysis

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Project analyst; individual name not supplied  
**Date:** 2026-11-10  
**CISO approval:** _________________________ **Date:** __________

## Executive Summary

All ten inventory systems support a 230-bed hospital with continuously operating
ED, ICU, laboratory, radiology, and pharmacy services. Network and identity loss
can interrupt several clinical services at once. LIS is Tier 1 because delays in
specimen tracking and critical results can affect urgent treatment. Seven systems
are Tier 1 and three are Tier 2; none of these ten qualify for the lower tiers.
These are proposed business tolerances, not measured recovery capabilities.

## Methodology

Use `meddefense_system_inventory.csv` for functions and owners,
`downtime_impact_notes.md` for the 1-, 4-, and 24-hour clinical thresholds,
`regulatory_reference_map.md` for applicable obligations, and
`dependency_map_seed.md` for sequencing. Compare patient safety first, then
regulatory exposure, revenue, and downstream failure. An early-tier dependency
may outrank a revenue-generating application.

Tier 1 means urgent clinical or foundational restoration, targeted within 45 minutes;
Tier 2 means supporting clinical or communication services within two hours; Tier 3
would mean important support within one working day; Tier 4 would mean deferrable
services within three days. These tier definitions are local planning assumptions.
RTO is measured from interruption to verified usable service, including required
dependencies; it is not an extra budget that starts after each dependency recovers.
MTD is an escalation boundary before unacceptable harm, not a safe waiting period.

No hourly revenue figures or approved tolerance decisions are supplied. Estimates
below are scenario assumptions in USD, each with a ±50% sensitivity range, for
finance review. They represent delayed-service exposure, not proven lost cash,
clinical harm costs, or penalties. Dependency exposures overlap: do not sum them.
For illustration, the 230-bed census at assumed $100 per occupied-bed-hour gives
$23,000/hour of hospital-wide inpatient activity before ED and outpatient activity;
the $50,000 network figure assumes broader hospital interruption. Department
figures are judgment-based shares of exposed activity, not measured billing.

Regulatory references identify applicable safeguards, not automatic reporting
duties or fines for a specified number of outage hours. No Joint Commission
standard identifier is supplied, so no exact accreditation citation is invented.
Clinical leaders and Finance must validate and sign these proposed thresholds.

## System Impact Assessment

### Active Directory

**Owner:** Systems Administrator. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | New logins and service authentication fail; cached sessions are temporary. |
| Patient safety at 4 hours | Clinical applications lose reliable new access and account authorization. |
| Patient safety at 24 hours | Sustained identity loss prevents dependable access to clinical records. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(B),(E); 164.312(a)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $20,000; sensitivity $10,000–$30,000; unvalidated planning assumption. |
| Dependency and failure sequence | Network/DNS/time → AD → clinical logins, email, backup access, security tools. |
| MTD / RTO / RPO | 90 / 15 / 15 minutes, respectively; proposed and subject to owner approval. |

### Epic EHR

**Owner:** Clinical Applications Manager. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Electronic orders, allergy context, medication documentation, and histories are unavailable. |
| Patient safety at 4 hours | Paper orders and medication records accumulate, increasing verification delays. |
| Patient safety at 24 hours | Care coordination and reconciliation become unsafe without emergency operations. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(B),(C),(E); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $30,000; sensitivity $15,000–$45,000; unvalidated planning assumption. |
| Dependency and failure sequence | Network + AD → Epic core → order/result interfaces → lab, pharmacy, imaging. |
| MTD / RTO / RPO | 240 / 25 / 15 minutes, respectively; proposed and subject to owner approval. |

### Laboratory Information System

**Owner:** Laboratory Systems Lead. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | STAT intake and critical results require phone and paper tracking. |
| Patient safety at 4 hours | Specimen-to-patient matching and delayed critical-value follow-up become harder. |
| Patient safety at 24 hours | Accumulated specimen and result backlogs threaten timely treatment decisions. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(B),(C),(E); 164.312(c)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $5,000; sensitivity $2,500–$7,500; unvalidated planning assumption. |
| Dependency and failure sequence | Network + AD + Epic interface + instruments → LIS association → clinical result posting. |
| MTD / RTO / RPO | 120 / 30 / 60 minutes, respectively; proposed and subject to owner approval. |

### PACS/RIS

**Owner:** Radiology Systems Lead. **Priority:** Tier 2.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Urgent imaging may continue locally, but prior images and reports are delayed. |
| Patient safety at 4 hours | Stroke, trauma, and surgery decisions face growing image/report delays. |
| Patient safety at 24 hours | Diagnostic backlog and unavailable studies require sustained emergency arrangements. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(B),(C),(E); 164.312(c)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $8,000; sensitivity $4,000–$12,000; unvalidated planning assumption. |
| Dependency and failure sequence | Network + AD + modalities + Epic orders → metadata/catalog → image distribution. |
| MTD / RTO / RPO | 240 / 120 / 60 minutes, respectively; proposed and subject to owner approval. |

### Pharmacy Dispensing System

**Owner:** Pharmacy IT Lead. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Manual dispensing slows allergy, interaction, and medication checks. |
| Patient safety at 4 hours | Medication reconciliation and cabinet records become increasingly difficult. |
| Patient safety at 24 hours | Prolonged manual medication management raises substantial patient risk. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(B),(C),(E); 164.312(c)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $6,000; sensitivity $3,000–$9,000; unvalidated planning assumption. |
| Dependency and failure sequence | Network + AD + Epic → pharmacy database → cabinets → dispensing/reconciliation. |
| MTD / RTO / RPO | 120 / 45 / 15 minutes, respectively; proposed and subject to owner approval. |

### Medical Device Integration Gateway

**Owner:** Biomedical IT Lead. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Local bedside displays continue, but automatic charting and routed alarms degrade. |
| Patient safety at 4 hours | Repeated manual observation and transcription increase nursing workload. |
| Patient safety at 24 hours | Sustained routing loss risks missed escalation and incomplete observation records. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(B),(C),(E); 164.312(c)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $2,000; sensitivity $1,000–$3,000; unvalidated planning assumption. |
| Dependency and failure sequence | Network + segmentation + gateway → Epic charting and routed alerts; local devices remain independent. |
| MTD / RTO / RPO | 120 / 30 / 60 minutes, respectively; proposed and subject to owner approval. |

### Network Core

**Owner:** Network Engineering Lead. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Several clinical systems, authentication, and communications fail together. |
| Patient safety at 4 hours | Hospital-wide manual coordination strains reduced staffing. |
| Patient safety at 24 hours | Broad service loss requires leadership-led diversion and emergency operations. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(B),(C),(E); 164.312(e)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $50,000; sensitivity $25,000–$75,000; unvalidated planning assumption. |
| Dependency and failure sequence | Power/cooling + spare equipment + offline configuration → routing/DNS reachability → all systems. |
| MTD / RTO / RPO | 60 / 5 / 15 minutes, respectively; proposed and subject to owner approval. |

### Email and Secure Messaging

**Owner:** Collaboration Services Lead. **Priority:** Tier 2.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Electronic handoffs and notifications switch to verified phone contacts. |
| Patient safety at 4 hours | Missed messages and repeated calls delay coordination and external contact. |
| Patient safety at 24 hours | Sustained communication loss impairs care coordination and reporting. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(C),(E); 164.312(e)(1); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $1,000; sensitivity $500–$1,500; unvalidated planning assumption. |
| Dependency and failure sequence | Network egress + identity provider + approved mobile access → message delivery. |
| MTD / RTO / RPO | 480 / 120 / 60 minutes, respectively; proposed and subject to owner approval. |

### Backup and DR Infrastructure

**Owner:** Infrastructure Manager. **Priority:** Tier 1.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Production may remain live, but a second failure cannot be restored reliably. |
| Patient safety at 4 hours | Recovery delays increase as new backup points and catalog access are lost. |
| Patient safety at 24 hours | Lost recovery capability can turn system failure into unrecoverable data loss. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(A),(B),(D),(E); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $3,000; sensitivity $1,500–$4,500; unvalidated planning assumption. |
| Dependency and failure sequence | Offline bootstrap and independent keys → network → AD or break-glass access → catalog/storage → restores. |
| MTD / RTO / RPO | 120 / 20 / 15 minutes, respectively; proposed and subject to owner approval. |

### Security Operations Platform

**Owner:** SOC Manager. **Priority:** Tier 2.

| Impact area | Assessment |
| --- | --- |
| Patient safety at 1 hour | Central threat visibility and response coordination degrade; local controls may continue. |
| Patient safety at 4 hours | Unreviewed alerts and incomplete incident context accumulate during recovery. |
| Patient safety at 24 hours | Extended detection gaps can allow compromise to persist unnoticed. |
| Regulatory impact | 45 CFR 164.308(a)(7)(ii)(B),(C),(E); 164.308(a)(6); 164.312(b); loss of availability or integrity requires contingency measures and documented follow-up. |
| Revenue exposure per hour | Estimated $1,500; sensitivity $750–$2,250; unvalidated planning assumption. |
| Dependency and failure sequence | Network + identity + log sources + EDR management → collectors/index → triage. |
| MTD / RTO / RPO | 480 / 120 / 60 minutes, respectively; proposed and subject to owner approval. |

## Dependency Map

```text
Offline configuration, independent credentials/keys, power/cooling
    -> Network Core (including DNS/time reachability)
        -> Active Directory
            -> Backup and DR catalog/storage access
            -> Epic core -> Epic clinical interfaces
                -> LIS / Pharmacy / PACS ordering and result exchange
            -> Email and Secure Messaging
            -> Security Operations Platform
        -> Medical Device Gateway -> Epic charting / routed alerts
        -> PACS image transport and backup replication
```

Epic and its dependent systems exchange data in both directions. Restore Epic core
and dependent databases in parallel after foundations, then enable interfaces under
clinical control and reconcile queues. Do not wait for every interface to start
before restoring either side. The offline bootstrap and break-glass access path
are proposed changes that remove the backup-platform/identity circular dependency.

## RTO / RPO / MTD Summary Table

All values are minutes from the defined interruption or data-loss boundary.

| System | Priority | RTO | RPO | MTD | Reason for proposed tolerance |
| --- | --- | --- | --- | --- | --- |
| Active Directory | Tier 1 | 15 | 15 | 90 | Authentication must precede clinical restoration. |
| Epic EHR | Tier 1 | 25 | 15 | 240 | Orders and records must be available before dependent interfaces. |
| Laboratory Information System | Tier 1 | 30 | 60 | 120 | Protect STAT processing and critical-result continuity. |
| PACS/RIS | Tier 2 | 120 | 60 | 240 | Prioritize urgent images while restoring wider distribution. |
| Pharmacy Dispensing System | Tier 1 | 45 | 15 | 120 | Limit time under manual medication verification. |
| Medical Device Integration Gateway | Tier 1 | 30 | 60 | 120 | Limit loss of alarm routing and automatic charting. |
| Network Core | Tier 1 | 5 | 15 | 60 | Shared failure path demands redundant failover. |
| Email and Secure Messaging | Tier 2 | 120 | 60 | 480 | Use phone fallback while restoring electronic delivery. |
| Backup and DR Infrastructure | Tier 1 | 20 | 15 | 120 | Restore tooling must be ready before data imports. |
| Security Operations Platform | Tier 2 | 120 | 60 | 480 | Maintain manual monitoring while restoring central visibility. |

## Assumptions and Limitations

The five-minute network and 25-minute Epic targets require failover-ready services,
prepositioned capacity, and parallel responders; current material does not prove
these exist. A nightly LIS dump cannot meet the proposed one-hour RPO. AD's
healthy secondary can support availability, but that is separate from recovering
corrupted/deleted identity data. MTD boundaries assume clinical phone-and-paper
procedures start immediately and remain staffed.

Only the small LIS artifact is tested here; other system values remain unverified.
No transaction rate, patient volume per minute, diversion capacity, restoration
throughput, vendor commitment, or independent clinical acceptance is supplied.
Do not convert downtime minutes to a count of injured patients. If full integrated
restoration cannot meet these targets, leadership must fund the necessary design
or approve revised tolerances with clinical justification and documented residual
risk, while preserving RTO below MTD.
