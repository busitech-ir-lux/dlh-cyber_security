# Recovery concepts: quiz study notes

The source labels the quiz Task 0. These notes support understanding without
attempting to answer unseen platform questions.

## Three different recovery decisions

**Recovery Time Objective (RTO)** is the target time from interruption to an agreed
usable service. **Recovery Point Objective (RPO)** is the maximum acceptable age
of restored data relative to the interruption, measured in time. **Maximum
Tolerable Downtime (MTD)** is the longest disruption the business can tolerate
before unacceptable harm. RTO must be lower than MTD, leaving time for clinical
verification and accumulated work. These distinctions guide the BIA; see
[NIST SP 800-34 Rev. 1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-34r1.pdf).

A LIS target of 30 minutes says how soon the service should work. A one-hour RPO
says how much recent electronic information may need reconstruction. A two-hour
MTD is a planning boundary for escalation, not permission to delay urgent care or
a claim that patients are safe until minute 119.

## Backups must satisfy the arithmetic

A nightly backup can be almost 24 hours old when an outage begins. A one-hour RPO
therefore needs a more frequent usable recovery point. Include the delay for
verification and off-site transfer: a 30-minute interval plus at most 15 minutes
of delivery and validation gives a designed worst-case age of 45 minutes. A failed
job can break that bound, so monitor verified recovery-point age rather than the
schedule alone.

A full backup contains the full selected dataset. An incremental contains changes
since the previous backup and normally requires that full plus every needed
increment. A differential contains changes since the full and normally needs the
full plus the latest differential. Snapshots require application consistency and
an independent copy; replication can copy corruption and does not replace retained
backups.

## Dependency order and verification

Network access and identity must work before dependent clinical applications can
be declared restored. Backup tools also depend on network and credentials, so keep
a protected offline bootstrap pack and independent recovery credentials to avoid
needing the backup platform to restore itself. Restore application data and then
verify interfaces and clinical workflows; a database opening is only one checkpoint.

In this case, `backup_log_review_findings.md` identifies a nightly LIS copy,
infrequent AD snapshots, and a missing geographic device-gateway copy. It says
three RPO conflicts exist, but does not provide three numerical target comparisons.
The architecture must identify exactly which comparisons are measurable rather
than inventing missing targets.

## HIPAA contingency planning

The local `hipaa_164_308_a7_reference.md` covers backup, disaster recovery,
emergency operation, testing and revision, and application/data criticality. A
package connects the BIA to backups, technical runbooks, clinical continuity,
test evidence, and corrective actions. Testing and criticality analysis are
addressable specifications; that requires a documented appropriateness decision,
not an automatic exemption. See [45 CFR 164.308(a)(7)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308).

## What a timed exercise can prove

Start the timer before the first recovery step and keep it running during errors,
corrections, validation, and notification preparation. Preserve exact output and
record deviations before moving on. A missed RTO should lead to specific changes,
not an invented faster result or an unsupported longer target.

The supplied five-row SQLite exercise can test restore commands, checksums, row
counts, and record validation. It does not reproduce hospital data volume,
clinician staffing, network loss, or full application behavior. A subsecond
simulation must never become a subsecond production recovery promise.
