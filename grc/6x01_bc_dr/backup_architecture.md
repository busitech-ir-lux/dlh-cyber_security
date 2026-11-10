# MedDefense Backup Architecture

**Version:** 1.0 | **Date:** 2026-11-10 | **Status:** Proposed design, not deployed

## Strategy Overview

The [BIA](business_impact_analysis.md) sets seven Tier 1 and three Tier 2 targets.
Protect application-consistent data with independent geographically separated
copies, immutable recent recovery points, separate administrative credentials,
and tested restores. Replication provides availability but can replicate corruption;
retained isolated backups remain necessary. Encrypt every copy, including metadata,
using AES-256 at rest with separately administered KMS/HSM keys and tested escrow
recovery. Transfer over TLS 1.2 or later with certificate validation; do not bypass
invalid certificates to complete a backup.

Destinations below are proposed logical resources, not existing bucket or host
names. Infrastructure must select approved sites/regions with separate power and
administrative failure domains before deployment. An on-site copy and a different
rack in the same building are not geographic separation. CloudVault is named in
`current_backup_schedule.csv`, but this does not prove its agreement, security
clearance, or data access status. The prior project's missing BAA remains a
cross-project issue to verify; do not send ePHI there until approved.

The design keeps 35 days of recent points, 12 monthly full or synthetic-full
recovery points, and 7 annual archive points for each system, unless the approved
records schedule requires longer. An annual archive remains an encrypted exact
recoverable copy with its catalog and key references. These are proposed retention
choices, not a universal HIPAA seven-year medical-record rule; Legal must confirm
retention and holds before expiry. Quarterly exercises must prove archived chain
readability and key recovery, not only recent snapshot success.

## RPO Compliance Verification

A defensible off-site point age includes capture interval plus maximum combined
consistency, transfer, catalog, and validation delay. The bounds below are design
requirements during normal operation, not measured guarantees. Track the last
verified usable off-site point continuously; alert before 80% of the RPO and declare
a breach of objective if its age exceeds RPO. Missed jobs and disconnected sites
invalidate the simple bound and require intervention.

| System | Proposed RPO, min | Current evidence | Proposed point interval, min | Max delivery/verification lag, min | Designed worst age, min | Result if bound is met |
| --- | --- | --- | --- | --- | --- | --- |
| Active Directory | 1 | Snapshots 8h; system state daily: 480/1440 min > 15. | 5 | 5 | 10 | 10 ≤ 1; unverified design. |
| Epic EHR | 1 | Replication 15 min leaves no lag allowance at 15-min RPO. | 5 | 5 | 10 | 10 ≤ 1; unverified design. |
| Laboratory Information System | 1 | Nightly: up to 1440 min > 60. | 30 | 15 | 45 | 45 ≤ 1; unverified design. |
| PACS/RIS | 2 | Snapshots 240 min > 60. | 30 | 15 | 45 | 45 ≤ 2; unverified design. |
| Pharmacy Dispensing System | 1 | Hourly database: 60 min > 15; config daily. | 5 | 5 | 10 | 10 ≤ 1; unverified design. |
| Medical Device Integration Gateway | 1 | Daily config: 1440 min > 60; no geographic copy. | 30 | 15 | 45 | 45 ≤ 1; unverified design. |
| Network Core | 1 | Config 360 min > 15. | 5 | 5 | 10 | 10 ≤ 1; unverified design. |
| Email and Secure Messaging | 2 | Continuous retention is not proven point-in-time recovery; export daily. | 30 | 15 | 45 | 45 ≤ 2; unverified design. |
| Backup and DR Infrastructure | 1 | Catalog 240 min > 15; config daily. | 5 | 5 | 10 | 10 ≤ 1; unverified design. |
| Security Operations Platform | 2 | Index 240 min > 60; config daily. | 30 | 15 | 45 | 45 ≤ 2; unverified design. |

The supplied log review says three RPO conflicts exist but specifies a numerical
one-hour target only for LIS; its other findings include a geographic copy gap
and identity dependency risk. The additional numerical comparisons above use this
BIA's new proposed targets, not supposedly pre-existing approved RPO values.
For a real outage, calculate actual RPO from the newest restored committed
transaction and outage time; backup directory names and row counts cannot prove it.

## Per-System Backup Specifications

Every table inherits the exact encryption and retention rules above. For hashes,
compute SHA-256 after application-consistent capture, retain the authenticated
manifest separately, verify after upload and before restore, then run a restore
and application checks. A hash proves copy consistency relative to the manifest,
not that an attacker did not alter both; restrict and audit manifest modification.

### Active Directory: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Application-aware identity checkpoint every 5 minutes; daily system-state at 01:00; weekly full on Sunday 00:00. Use supported AD-aware recovery technology, not arbitrary VM rollback. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Isolated identity backup NAS in local recovery zone. |
| Secondary destination | Encrypted identity recovery vault in a separate region/site; DC02 in independent failure domain. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Quarterly isolated recovery and monthly DC health/replication checks; verify DNS, SYSVOL and test logon. Never attach a test DC to production. |
| Restoration sequence | Network/DNS/time → keep healthy DC02 serving → recover DC01 nonauthoritatively → validate replication, DNS, SYSVOL and logon. |
| Responsible role | Systems Administrator executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Epic EHR: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Vendor-supported application-consistent replicated checkpoint every 5 minutes; nightly export 23:00; weekly full Sunday 00:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Proposed on-site encrypted clinical export vault; vendor primary replica remains separate. |
| Secondary destination | Vendor warm DR region plus independent encrypted export archive in an approved region. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Monthly vendor restore evidence plus quarterly witnessed clinical failover, orders, medication record and interface checks. |
| Restoration sequence | Network and AD → fail over warmed Epic core → validate access, allergies, medication/order workflows → connect LIS/pharmacy/PACS interfaces. |
| Responsible role | Clinical Applications Manager executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Laboratory Information System: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Production application-consistent full nightly 23:30 plus verified snapshots every 30 minutes; weekly retained full Sunday 23:30. SQLite simulation uses only supplied full SQL. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Dedicated encrypted LIS NAS in recovery zone. |
| Secondary destination | Independent isolated regional object vault; CloudVault only after security and BAA clearance. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Monthly isolated restore with count, integrity, critical records, specimen/result association and queued-interface reconciliation. |
| Restoration sequence | Network/AD and Epic core ready → full plus required changes or selected snapshot → row and critical-record checks → analyzer/interface checks → clinical release. |
| Responsible role | Laboratory Systems Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### PACS/RIS: Tier 2

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Coordinated image and metadata incremental checkpoints every 30 minutes; full baseline first Sunday 00:00 and after material migration; nightly metadata export 23:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Encrypted PACS recovery storage with separate metadata catalog. |
| Secondary destination | Geographically separate image object vault plus matching metadata backup. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Quarterly isolated restore: match image identifiers, metadata, report links and sample image display. |
| Restoration sequence | Network/AD → metadata/catalog → linked image objects and RIS → modality sample and prior-study retrieval → Epic order/report exchange. |
| Responsible role | Radiology Systems Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Pharmacy Dispensing System: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Application-consistent database checkpoint every 5 minutes; full nightly 00:30; cabinet configuration every 5 minutes and after change. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Encrypted pharmacy recovery NAS separate from cabinet controllers. |
| Secondary destination | Separate-region immutable pharmacy vault covering database and cabinet state. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Monthly restore with pharmacist confirmation of orders, cabinet state, controlled-substance records and read-only checks before live release. |
| Restoration sequence | Network/AD/Epic → pharmacy database → cabinet configuration → pharmacist-led inventory/order reconciliation → controlled dispensing validation. |
| Responsible role | Pharmacy IT Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Medical Device Integration Gateway: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Configuration snapshot every 30 minutes and immediately after changes; full supported gateway image nightly 02:30. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Encrypted biomedical recovery share outside the gateway host. |
| Secondary destination | Separate-region vault for configuration, certificates, and supported gateway images. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Quarterly spare-gateway restore; confirm permitted feeds, routed test alarm acknowledgment and charting association. |
| Restoration sequence | Network/VLANs → gateway configuration and keys → local device feeds → approved test alarm route → Epic charting validation. |
| Responsible role | Biomedical IT Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Network Core: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Configuration snapshots every 5 minutes and after each approved change; full device image/version inventory daily 00:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Local encrypted offline bootstrap kit plus configuration management vault. |
| Secondary destination | Encrypted offline regional copy and protected remote configuration repository. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Quarterly spare-device load and segmentation/routing checks; verify reachability without exposing production networks. |
| Restoration sequence | Independent power/cooling confirmed → spare or redundant core → VLAN/routing/DNS/time → segmentation and application reachability checks. |
| Responsible role | Network Engineering Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Email and Secure Messaging: Tier 2

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Provider-consistent mailbox/message recovery checkpoint every 30 minutes under contract; independent export nightly 22:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | On-site encrypted export vault with restricted restore access. |
| Secondary destination | Approved provider region pair plus independent protected regional export vault. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Quarterly mailbox/message restore and delivery acknowledgment across approved devices; verify retention/export recoverability. |
| Restoration sequence | Network egress/identity → provider continuity route → test approved devices → confirm delivery and recover missing messages without duplicate clinical instructions. |
| Responsible role | Collaboration Services Lead executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Backup and DR Infrastructure: Tier 1

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | Catalog and key-reference consistent snapshot every 5 minutes; platform configuration every change and every 5 minutes; full platform image nightly 02:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Isolated backup platform storage plus protected offline bootstrap copy. |
| Secondary destination | Independent regional recovery account with immutable catalog/config copies and separately escrowed keys. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Monthly independent catalog/key recovery plus quarterly timed bootstrap from the off-site copy. |
| Restoration sequence | Offline bootstrap/independent credentials → network → AD or break-glass access → catalog and key access → representative system restore. |
| Responsible role | Infrastructure Manager executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

### Security Operations Platform: Tier 2

| Field | Specification |
| --- | --- |
| Backup type | Full baseline plus application-consistent checkpoints/snapshots or supported incremental chain; see schedule. |
| Schedule | SIEM/EDR management configuration and index checkpoints every 30 minutes; configuration also after changes; full baseline nightly 03:00. |
| Retention | 35 days recent; 12 monthly full/synthetic-full points; 7 annual archive points with catalog and key references, subject to Legal approval. |
| Primary destination | Isolated encrypted security recovery volume. |
| Secondary destination | Independent regional encrypted telemetry and configuration vault. |
| Encryption at rest | AES-256 on source staging, destination, and archive; separate KMS/HSM key administrators and protected escrow with tested retrieval. |
| Encryption in transit | TLS 1.2 or higher with server certificate validation across capture, replication and recovery transfers. |
| Integrity verification | SHA-256 at capture, after delivery, and before restore; Monthly isolated index/config restore and sample event ingestion, search, detection and EDR management check. |
| Restoration sequence | Network and identity → collectors/EDR management → recent indices/configuration → verify event ingestion and triage sample; retain local logs meanwhile. |
| Responsible role | SOC Manager executes; IT Security verifies copy integrity and the business/clinical owner verifies service acceptance. |

## Full Data Center Loss: Restoration Sequence

The clock begins at interruption. The schedule is a proposed parallel recovery
budget, requiring a warm alternate site and staffed responders. It is not evidence
that cold backup imports can complete at these times.

| Window after interruption | Recovery work | Gate before proceeding |
| --- | --- | --- |
| 0–5 min | Network Engineering activates redundant core/alternate network using offline configuration and independent credentials. | Routing, protected DNS/time access, segregation, and recovery-site reachability checked. |
| 5–15 min | Systems Administrator activates healthy identity/DNS services; Infrastructure retrieves catalog and keys in parallel through protected break-glass access. | New authentication and service-account tests pass; no dependency on failed DC01 alone. |
| 15–20 min | Infrastructure completes backup-platform recovery; clinical teams activate warmed application resources in parallel. | Catalog and off-site copy readable; no unverified or quarantined copy selected. |
| 15–25 min | Vendor and Clinical Applications restore/fail over Epic core. | Approved test user verifies core records and order workflow. |
| 20–30 min | LIS team restores its checkpoint, validates records, and reconnects checked interfaces after Epic core; Biomed restores gateway in parallel. | LIS and gateway clinical acceptance by minute 30, not merely database opening. |
| 25–45 min | Pharmacy restores database/cabinets and reconciles with Epic. | Pharmacist approves safe dispensing and inventory state. |
| 20–120 min | PACS restores catalog then images; Collaboration restores messaging; SOC restores central visibility. | Each system owner verifies workflows and reports acceptance. |

Clinical phone-and-paper procedures begin immediately and remain active until
formal release. Reduced SOC monitoring starts with local logs at activation rather
than waiting two hours for central indices. If a dependency misses its gate, report
the downstream RTO risk immediately; do not restart dependent clocks at zero.

## Dependency Restore Constraints

Keep the bootstrap pack, device configurations, recovery keys, account contacts,
and independent recovery credentials accessible without AD or the backup console.
Test those credentials without exposing secrets in documentation. If the pack or
alternate site is unavailable, the five-minute network target is unsupported.

Keep application and database checkpoint consistency groups together. For snapshot
restores, select a complete verified recovery point; for incremental recovery,
restore the baseline and every required increment in order, stopping on a missing
link. Preserve original copies during all tests. Do not revert a domain controller
to an arbitrary VM snapshot; use supported AD recovery or re-promotion.

Test production-sized transfer and startup throughput before accepting the budgets.
Required restore throughput is restorable bytes divided by the usable import
window after bootstrap, validation, and communication. Dataset sizes and bandwidth
are not supplied, so capacity and vendor recovery commitments remain open gates.
Encrypted keys and clean backups must survive a separate-region outage; do not
place key escrow and every backup under the same failed identity authority.
