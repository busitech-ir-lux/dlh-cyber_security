### The Encryption Levels

**Goal:** _Compare the six encryption levels defined and recommend the appropriate level for every MedDefense data store._

---

**Context:** "Encrypt the database" sounds simple, but there are at least three ways to do it: encrypt the entire disk the database sits on (full-disk), encrypt the database files (file-level), or encrypt individual fields within the database (record-level). Each has radically different properties: scope of protection, performance impact, key management complexity and what happens when someone with legitimate database access queries the data.

Choosing the wrong level either leaves data exposed or creates operational problems that the clinical staff will not tolerate.

---

**Instructions:** Produce a **comparison table** of the 6 encryption levels from Sec+ 1.4:

|Level|Scope|Performance Impact|Key Management|Use Case|
|---|---|---|---|---|
|Full-disk|Entire physical or virtual disk|?|?|?|
|Partition|One logical partition|?|?|?|
|Volume|Logical volume (may span disks)|?|?|?|
|File|Individual files|?|?|?|
|Database|Entire database or tablespace|?|?|?|
|Record|Individual fields or records|?|?|?|

For each: fill in all columns and explain in one sentence when this level is the best choice.

Then produce a **MedDefense Encryption Level Map**: for each data store at MedDefense, recommend the specific encryption level and justify your choice:

1. Patient records in `PostgreSQL` (`ehr-db-01`)
    
2. Backup data on `NAS-01`
    
3. Financial records in `MySQL` (`billing-srv-01`)
    
4. Medical images on `PACS` (`pacs-srv-01`)
    
5. Email data in O365
    
6. Employee laptops
    
7. BD Alaris pump firmware/configuration

---
# Answer

# 13. The Encryption Levels

## Encryption-Level Comparison

|Level|Scope|Performance Impact|Key Management|Use Case|Best Choice When|
|---|---|---|---|---|---|
|**Full-disk**|Entire physical or virtual disk, including operating system and application files|Low with hardware acceleration|One key per disk or device; normally managed through TPM or central device management|Laptops, workstations and stolen-device protection|Best when the main risk is loss or physical theft of the whole device.|
|**Partition**|One defined partition on a disk|Low|Separate key for each encrypted partition|Separating sensitive data from the operating system or public data|Best when only one section of a disk contains sensitive information.|
|**Volume**|A logical storage volume that may span several disks|Low to medium|One key per logical volume; recovery keys must be protected separately|NAS storage, backup repositories and server data volumes|Best when a complete storage area must be encrypted without encrypting the whole system.|
|**File**|Selected individual files or folders|Medium|Keys must be assigned and controlled for files, folders or users|Documents, exported reports, images and configuration files|Best when only specific files require protection or must remain encrypted when transferred.|
|**Database**|Entire database, tablespace or database files|Low to medium|Usually managed by the database platform or external KMS|EHR, billing and other structured business databases|Best when all data in a database requires transparent protection at rest.|
|**Record**|Individual database fields, columns or records|Medium to high|Complex; different fields or applications may require separate keys|SSNs, card numbers, diagnoses and other highly sensitive values|Best when database administrators or applications should not automatically see every sensitive value.|

## Important Limitation

Disk, partition, volume and database encryption primarily protect **data at rest**. Once the system is running and the storage is unlocked, authorised users and compromised applications may still access the readable data.

Record-level encryption provides stronger separation but requires more application changes and more complex key management.

# MedDefense Encryption-Level Map

|MedDefense data store|Recommended level|Justification|
|---|---|---|
|**Patient records in PostgreSQL — `ehr-db-01`**|**Database-level encryption**|The complete EHR database contains regulated patient information, so transparent database or tablespace encryption protects all PostgreSQL files without requiring clinicians to change their workflow.|
|**Backup data on `NAS-01`**|**Volume-level encryption**|A dedicated encrypted backup volume protects every database dump and backup file across the NAS storage while allowing normal backup operations.|
|**Financial records in MySQL — `billing-srv-01`**|**Record-level encryption**|Highly sensitive fields such as SSNs and insurance identifiers should remain encrypted even when a user or administrator can query the database.|
|**Medical images on PACS — `pacs-srv-01`**|**File-level encryption**|Individual DICOM files may be copied, exported or transferred, so protecting each file allows the image to remain encrypted outside the PACS storage system.|
|**Email data in Microsoft 365**|**Database/service-level encryption**|Microsoft already encrypts mailbox storage centrally, protecting all stored email without requiring users to encrypt each mailbox file manually.|
|**Employee laptops**|**Full-disk encryption**|Full-disk encryption protects operating-system files, cached email, downloaded patient data and credentials if a laptop is lost or stolen.|
|**BD Alaris pump firmware and configuration**|**File-level encryption**|Configuration and update files should remain protected while stored or transferred to the device, especially because constrained medical devices may not support full-disk encryption.|

## Additional MedDefense Considerations

### PostgreSQL EHR

Database encryption should be combined with record-level encryption for exceptionally sensitive fields if database administrators should not see them. Encryption keys should be stored in a separate KMS rather than on `ehr-db-01`.

### NAS Backups

The encrypted volume must remain locked when backups are not running. Its key must not be stored on NAS-01 because compromising the NAS would then expose both the backups and the key.

### MySQL Billing

Record-level encryption is appropriate for full SSNs, payment identifiers and insurance numbers. Less-sensitive operational data can remain protected through database or volume encryption.

### PACS Images

The PACS storage volume should also be encrypted, but file-level protection is important because DICOM files commonly leave the server during authorised transfers.

### Employee Laptops

Full-disk encryption should use centrally managed recovery keys and TPM protection. It does not protect information after the employee has signed in and the disk is unlocked.

### Medical-Device Firmware

Firmware authenticity is more important than secrecy. MedDefense should therefore use **digital signatures** to ensure that only authorised firmware can be installed, in addition to encrypting sensitive configuration files.

# Final Recommendation

MedDefense should use layered encryption rather than one level everywhere:

- **Full-disk:** employee laptops
    
- **Volume:** NAS backup storage
    
- **Database:** PostgreSQL EHR and Microsoft 365 storage
    
- **Record:** sensitive billing fields
    
- **File:** DICOM images and medical-device configurations
    

The selected level should protect the data without creating unnecessary disruption to clinical and business operations.
