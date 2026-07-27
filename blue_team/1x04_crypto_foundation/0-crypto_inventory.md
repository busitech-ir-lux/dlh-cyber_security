# MedDefense Health Systems

## Data Protection Map — Cryptographic Inventory

**Prepared from:** MedDefense Cryptographic Audit Notes, 1x00 observations, and 1x02 vulnerability findings  
**Scope:** Seven data categories across data at rest, in transit, and in use

### Status Criteria

- **Adequate:** Modern cryptography is implemented and enforced.
    
- **Weak:** Cryptography exists, but it is optional, deprecated, mixed with weak algorithms, or otherwise unreliable.
    
- **Absent:** No cryptographic protection is implemented or documented.
    

## Data Protection Matrix

|Data category|At Rest|In Transit|In Use|
|---|---|---|---|
|**Patient medical records**EHR data in PostgreSQL|**Protection:** None**Evidence:** The PostgreSQL 14 data directory on `ehr-db-01` is stored on an unencrypted ext4 filesystem. Patient records can be read directly by anyone with root or physical disk access.**Status:** **Absent**|**Protection:** Optional PostgreSQL TLS**Evidence:** PostgreSQL has `ssl=on`, but `pg_hba.conf` contains both `hostssl` and `hostnossl` rules for `10.10.0.0/16`. Connections may therefore use TLS or plaintext.**Status:** **Weak**|**Protection:** None**Evidence:** Records are decrypted in memory on `ehr-srv-01` while clinicians view them. Nurse station workstations also have no automatic screen locking because the screensaver timeout is set to “Never.”**Status:** **Absent**|
|**Financial and billing data**MySQL on `billing-srv-01`|**Protection:** None**Evidence:** MySQL files are stored on an unencrypted ext4 filesystem. The 1x00 crypto-miner investigation confirmed that database files could be read directly without MySQL credentials.**Status:** **Absent**|**Protection:** None — plaintext MySQL protocol**Evidence:** MySQL listens on `0.0.0.0`, does not enforce SSL, and the billing application connects over the flat network without encryption.**Status:** **Absent**|**Protection:** None documented**Evidence:** The audit identifies no protection for billing information while it is processed or displayed by the billing application. The application must handle names, SSNs, insurance information, and billing records in readable form.**Status:** **Absent**|
|**Medical images**DICOM on PACS|**Protection:** None**Evidence:** `pacs-srv-01` stores DICOM files on unencrypted local disks. Patient identifiers in DICOM headers are readable using a DICOM viewer or text editor.**Status:** **Absent**|**Protection:** None — cleartext DICOM**Evidence:** DICOM traffic over ports 4242 and 11112 does not use DICOM TLS. Images and embedded patient identifiers cross the network in cleartext.**Status:** **Absent**|**Protection:** None documented**Evidence:** Radiology and MRI workstations display decrypted images and patient metadata. The audit identifies no additional cryptographic control while images are being viewed or processed.**Status:** **Absent**|
|**Credentials**Active Directory and application passwords|**Protection:** NTHash using MD4**Evidence:** Active Directory stores NT password hashes for NTLM compatibility. The audit identifies MD4-based NTHash storage as vulnerable to offline password cracking.**Status:** **Weak**|**Protection:** Kerberos AES-256/AES-128, RC4 and DES; LDAP without required signing**Evidence:** 1x02 Finding 018 confirmed that RC4 and DES remain enabled. Finding 007 confirmed that LDAP signing is not required. Strong algorithms exist, but clients may still negotiate obsolete protection.**Status:** **Weak**|**Protection:** None documented**Evidence:** The audit identifies no additional protection for credentials, authentication material, or tickets while they are actively used by domain controllers and applications.**Status:** **Absent**|
|**Backup data**`NAS-01`|**Protection:** None**Evidence:** The Synology NAS stores backups on an unencrypted RAID-5 array. Shared-folder encryption using AES-256-CBC is supported but has not been enabled. Finding 015 also showed that the NAS management interface is exposed across the flat network.**Status:** **Absent**|**Protection:** None documented**Evidence:** The audit identifies no encrypted backup-transfer protocol between the database servers and `NAS-01`. Backup transfers occur within the same flat network environment.**Status:** **Absent**|**Protection:** None documented**Evidence:** Backups and database dumps are readable in plaintext when accessed, restored, or processed. No in-use cryptographic protection is described.**Status:** **Absent**|
|**Email**Microsoft 365|**Protection:** BitLocker and per-mailbox encryption with Microsoft-managed keys**Evidence:** Microsoft encrypts Exchange Online storage using BitLocker at the disk level and per-mailbox encryption.**Status:** **Adequate**|**Protection:** TLS 1.2**Evidence:** Exchange Online connections use Microsoft-enforced TLS 1.2.**Status:** **Adequate**|**Protection:** None at message level**Evidence:** S/MIME and Office Message Encryption are not configured. Sensitive patient information is sometimes displayed and exchanged as readable plaintext by physicians.**Status:** **Absent**|
|**VPN traffic**Site-to-site tunnels|**Protection:** None documented for stored configurations, keys, logs, or packet captures**Evidence:** The audit documents the tunnel algorithms but does not describe how VPN configurations, cryptographic keys, or related logs are protected while stored.**Status:** **Absent**|**Protection:** IPSec with AES-256, SHA-256, IKEv2 and DH Group 14**Evidence:** The Central-to-Westside and Central-to-HQ FortiGate tunnels use AES-256 encryption, SHA-256 integrity, IKEv2, and DH Group 14. The audit considers the configuration adequate.**Status:** **Adequate**|**Protection:** None documented**Evidence:** VPN traffic is decrypted at the tunnel endpoints so that it can be routed and processed. No additional protection for decrypted traffic in memory is documented.**Status:** **Absent**|

# Gap Summary

|Status|Number of cells|Percentage of 21 cells|
|---|--:|--:|
|**Adequate**|**3**|**14.3%**|
|**Weak**|**3**|**14.3%**|
|**Absent**|**15**|**71.4%**|
|**Total**|**21**|**100%**|

## Overall Crypto Coverage

Using only cells with **adequate and enforced cryptographic protection**:

> **Crypto coverage = 3 ÷ 21 × 100 = 14.3%**

Only the following cells currently have adequate protection:

1. Email at rest
    
2. Email in transit
    
3. VPN traffic in transit
    

An additional three cells contain some cryptographic protection, but it is weak or inconsistently enforced. Therefore, the percentage of cells containing **any** cryptographic mechanism, including weak controls, is:

> **Any-control presence = 6 ÷ 21 × 100 = 28.6%**

## Overall Assessment

MedDefense has adequate cryptographic protection in only **14.3%** of the assessed data-state combinations. **Eighteen of the 21 cells, or 85.7%, are either weak or completely unprotected.**

The largest gaps are:

- unencrypted EHR, billing, PACS, and backup storage
    
- plaintext MySQL and DICOM network traffic
    
- optional rather than mandatory PostgreSQL TLS
    
- legacy DES, RC4, and MD4-based credential protection
    
- unsigned or unprotected LDAP communication
    
- no message-level encryption for emails containing patient information
    
- no documented protection for most data while actively being processed
    

No data category is adequately protected across all three states. Microsoft 365 and the site-to-site VPNs provide the strongest current controls, while systems managed directly by MedDefense account for most of the cryptographic gaps.
