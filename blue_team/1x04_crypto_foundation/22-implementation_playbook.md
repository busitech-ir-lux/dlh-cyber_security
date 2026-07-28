### The Implementation Playbook

**Goal:** _Produce a step-by-step operational playbook for the first 5 cryptographic changes to be deployed in production._

---

**Context:** This is the document Sarah Park takes to her IT team on Monday morning. It is not a strategy. It is not a report. It is a playbook: do this, then this, then verify, then proceed. Each action has prerequisites, steps, validation criteria and a rollback plan.

---

**Instructions:** Produce an **Implementation Playbook** for the 5 highest-priority cryptographic changes from your assessment. For each:

```less
Action #[N]: [Descriptive name]
Priority: [From T15 - Immediate / Phase 1 / Phase 2]
System Affected: [Specific hostname]
Prerequisites: [What must be in place before starting]

Steps:
  1. [Specific command or configuration change]
  2. [...]
  3. [...]

Validation:
  - [How to verify the change was applied correctly]
  - [How to verify no service disruption occurred]

Rollback:
  - [How to revert if something goes wrong]
  - [Maximum acceptable downtime before rollback is triggered]

Maintenance Window: [When to perform this - business hours OK or overnight required?]
Communication: [Who needs to be notified before and after]
```


---
# Answer

# 20. MedDefense Cryptographic Implementation Playbook

Replace values inside `< >` with the real database names, usernames, IP addresses, and certificate paths before deployment.

---

## Action #1: Enforce PostgreSQL TLS

**Priority:** Immediate  
**System Affected:** `ehr-db-01`, `ehr-srv-01`

### Prerequisites

- Valid server certificate for `ehr-db-01`
    
- Internal CA certificate installed on `ehr-srv-01`
    
- Backup of PostgreSQL configuration
    
- Confirmed application support for `sslmode=verify-full`
    
- Tested database restore
    

### Steps

1. Back up the configuration:
    

```bash
sudo cp /etc/postgresql/14/main/postgresql.conf \
/etc/postgresql/14/main/postgresql.conf.bak

sudo cp /etc/postgresql/14/main/pg_hba.conf \
/etc/postgresql/14/main/pg_hba.conf.bak
```

2. Install the certificate and private key:
    

```bash
sudo mkdir -p /etc/postgresql/14/main/tls

sudo cp ehr-db-01.crt /etc/postgresql/14/main/tls/
sudo cp ehr-db-01.key /etc/postgresql/14/main/tls/
sudo cp meddefense-ca.crt /etc/postgresql/14/main/tls/

sudo chown -R postgres:postgres /etc/postgresql/14/main/tls
sudo chmod 600 /etc/postgresql/14/main/tls/ehr-db-01.key
```

3. Add to `postgresql.conf`:
    

```ini
ssl = on
ssl_cert_file = '/etc/postgresql/14/main/tls/ehr-db-01.crt'
ssl_key_file = '/etc/postgresql/14/main/tls/ehr-db-01.key'
ssl_ca_file = '/etc/postgresql/14/main/tls/meddefense-ca.crt'
ssl_min_protocol_version = 'TLSv1.2'
```

4. Remove existing `hostnossl` rules and add to the top of `pg_hba.conf`:
    

```text
hostnossl  all             all              10.10.0.0/16       reject
hostssl    <ehr_database>  <ehr_app_user>   <ehr-srv-IP>/32    scram-sha-256
```

PostgreSQL distinguishes `hostssl` from `hostnossl`, and clients can use `verify-full` to verify both the issuing CA and server hostname.

5. Reload PostgreSQL:
    

```bash
sudo systemctl reload postgresql
```

6. Update the EHR application connection string:
    

```text
host=ehr-db-01.meddefense.local
sslmode=verify-full
sslrootcert=/path/to/meddefense-ca.crt
```

### Validation

- Confirm the encrypted connection:
    

```bash
psql "host=ehr-db-01.meddefense.local \
dbname=<ehr_database> \
user=<ehr_app_user> \
sslmode=verify-full \
sslrootcert=/path/to/meddefense-ca.crt" \
-c '\conninfo'
```

- Confirm that plaintext fails:
    

```bash
psql "host=ehr-db-01 \
dbname=<ehr_database> \
user=<ehr_app_user> \
sslmode=disable"
```

- Open, update, and save a test patient record through the EHR.
    
- Confirm that no database connection errors appear in the EHR logs.
    

### Rollback

- Restore both `.bak` configuration files.
    
- Restore the original EHR connection string.
    
- Reload PostgreSQL:
    

```bash
sudo systemctl reload postgresql
```

- **Rollback trigger:** EHR database access remains unavailable for more than **10 minutes**.
    

### Maintenance Window

Overnight maintenance window required.

### Communication

Notify the EHR owner, DBA, clinical operations, help desk, Sarah Park, and James Chen before and after deployment.

---

## Action #2: Enforce MySQL TLS

**Priority:** Immediate  
**System Affected:** `billing-srv-01`, billing application server

### Prerequisites

- Valid server certificate for `billing-srv-01`
    
- Internal CA certificate installed on the billing application server
    
- Backup of MySQL configuration
    
- Confirmed MySQL version and TLS support
    
- Tested billing-database backup
    

### Steps

1. Check current TLS support:
    

```bash
mysql -u root -p -e \
"SHOW VARIABLES WHERE Variable_name IN ('tls_version','require_secure_transport');"
```

2. Back up the configuration:
    

```bash
sudo cp /etc/mysql/mysql.conf.d/mysqld.cnf \
/etc/mysql/mysql.conf.d/mysqld.cnf.bak
```

3. Install the certificates:
    

```bash
sudo mkdir -p /etc/mysql/tls

sudo cp billing-srv-01.crt /etc/mysql/tls/server.crt
sudo cp billing-srv-01.key /etc/mysql/tls/server.key
sudo cp meddefense-ca.crt /etc/mysql/tls/ca.crt

sudo chown -R mysql:mysql /etc/mysql/tls
sudo chmod 600 /etc/mysql/tls/server.key
```

4. Add under `[mysqld]`:
    

```ini
ssl_ca=/etc/mysql/tls/ca.crt
ssl_cert=/etc/mysql/tls/server.crt
ssl_key=/etc/mysql/tls/server.key

require_secure_transport=ON
tls_version=TLSv1.2,TLSv1.3
```

If the installed MySQL version does not support TLS 1.3, temporarily configure TLS 1.2 only and schedule the server upgrade.

5. Require encryption for the billing account:
    

```sql
ALTER USER '<billing_app_user>'@'<billing_app_host>'
REQUIRE SSL;
```

6. Restart MySQL:
    

```bash
sudo systemctl restart mysql
```

MySQL’s `require_secure_transport` setting rejects unencrypted TCP connections.

7. Update the billing application to use:
    

```text
ssl-mode=VERIFY_IDENTITY
ssl-ca=/path/to/meddefense-ca.crt
```

### Validation

- Confirm the encrypted session:
    

```bash
mysql \
--host=billing-srv-01.meddefense.local \
--user=<billing_app_user> \
--password \
--ssl-mode=VERIFY_IDENTITY \
--ssl-ca=/path/to/meddefense-ca.crt \
-e "SHOW STATUS LIKE 'Ssl_cipher';"
```

- Confirm that plaintext fails:
    

```bash
mysql \
--host=billing-srv-01 \
--user=<billing_app_user> \
--password \
--ssl-mode=DISABLED
```

- Process one test invoice.
    
- Confirm that billing application logs contain no database errors.
    

### Rollback

- Restore `mysqld.cnf.bak`.
    
- Remove the account requirement if necessary:
    

```sql
ALTER USER '<billing_app_user>'@'<billing_app_host>'
REQUIRE NONE;
```

- Restart MySQL and restore the original application connection settings.
    
- **Rollback trigger:** Billing remains unavailable for more than **10 minutes**.
    

### Maintenance Window

Overnight maintenance window required.

### Communication

Notify the billing manager, DBA, finance staff, help desk, Sarah Park, and James Chen.

---

## Action #3: Protect DICOM Traffic with TLS

**Priority:** Immediate  
**System Affected:** `pacs-srv-01`, radiology workstations, MRI workstation

### Prerequisites

- Internal CA available
    
- Server and client certificates issued
    
- Approved DICOM TLS gateway VMs
    
- Current DICOM AE titles, ports, and destinations documented
    
- Test image available
    
- Biomedical engineering approval
    

Because the MRI workstation runs Windows XP, it should not terminate modern TLS directly. A supported TLS gateway should protect traffic between the imaging network and PACS.

### Steps

1. Install `stunnel` on the supported PACS-side gateway:
    

```bash
sudo apt install stunnel4
```

2. Configure the PACS-side gateway:
    

```ini
[dicom-tls]
accept = 2762
connect = pacs-srv-01:4242

cert = /etc/stunnel/dicom-server.crt
key = /etc/stunnel/dicom-server.key
CAfile = /etc/stunnel/meddefense-ca.crt

verifyChain = yes
```

3. Configure the imaging-side gateway:
    

```ini
client = yes

[dicom-client]
accept = 0.0.0.0:4242
connect = dicom-gw-pacs.meddefense.local:2762

cert = /etc/stunnel/dicom-client.crt
key = /etc/stunnel/dicom-client.key
CAfile = /etc/stunnel/meddefense-ca.crt

verifyChain = yes
checkHost = dicom-gw-pacs.meddefense.local
```

`stunnel` can add TLS to an existing TCP service, but secure deployment requires certificate-chain and hostname validation.

4. Restart both gateways:
    

```bash
sudo systemctl restart stunnel4
```

5. Change the MRI and radiology DICOM destinations to the local imaging gateway on port `4242`.
    
6. Allow TLS port `2762` only between the two gateways.
    
7. Block direct DICOM ports `4242` and `11112` between the imaging network and `pacs-srv-01`.
    

### Validation

- Test the TLS connection:
    

```bash
openssl s_client \
-connect dicom-gw-pacs.meddefense.local:2762 \
-CAfile meddefense-ca.crt
```

- Run a DICOM C-ECHO test.
    
- Transfer one test image using C-STORE.
    
- Confirm that the image appears correctly in PACS.
    
- Confirm that the patient identifier and image are unchanged.
    
- Confirm that direct cross-network connections to ports `4242` and `11112` fail.
    

### Rollback

- Restore the previous DICOM destination on the affected modality.
    
- Temporarily restore the previous firewall rule.
    
- Record the traffic as a temporary exception until the TLS issue is corrected.
    
- **Rollback trigger:** A modality cannot send clinically required images for more than **20 minutes**.
    

### Maintenance Window

Overnight or low-volume radiology window required.

### Communication

Notify radiology leadership, PACS administration, biomedical engineering, clinical operations, security, and the help desk.

---

## Action #4: Disable Weak Kerberos and Require LDAP Signing

**Priority:** Immediate  
**System Affected:** `ad-dc-01`, `ad-dc-02`, domain-joined systems

### Prerequisites

- System-state backup of both domain controllers
    
- At least 7–14 days of Kerberos and LDAP audit data
    
- Inventory of service accounts and SPNs
    
- RC4-only and unsigned-LDAP clients identified
    
- Pilot OU available
    
- Emergency domain administrator account tested
    

Microsoft recommends identifying RC4 and unsigned-LDAP dependencies before enforcing stronger settings because incompatible services may fail.

### Steps

1. Enable detailed LDAP auditing on both domain controllers:
    

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics ^
/v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
```

2. Review:
    

- Kerberos Event IDs `4768` and `4769`
    
- LDAP Event IDs `2887` and `2889`
    

3. Configure affected service accounts for AES:
    

```powershell
Set-ADUser \
-Identity <service_account> \
-KerberosEncryptionType AES128,AES256
```

4. Reset service-account passwords or migrate suitable accounts to group Managed Service Accounts.
    
5. Create a pilot GPO:
    

```text
Computer Configuration
→ Policies
→ Windows Settings
→ Security Settings
→ Local Policies
→ Security Options
→ Network security: Configure encryption types allowed for Kerberos
```

Enable only:

```text
AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types
```

Microsoft documents selecting AES128 and AES256 while removing RC4 from this policy.

6. Configure LDAP signing:
    

```text
Domain controller: LDAP server signing requirements
= Require signing
```

7. Apply the GPO to the pilot OU and run:
    

```cmd
gpupdate /force
```

8. Restart pilot systems, validate them, and then expand the GPO to all supported systems.
    

### Validation

- Run:
    

```cmd
klist
```

- Confirm Kerberos tickets use AES rather than RC4.
    
- Confirm new Event `4769` records do not show RC4 ticket encryption.
    
- Confirm unsigned LDAP binds fail.
    
- Confirm signed LDAP or LDAPS succeeds.
    
- Confirm Event `2887` reports no remaining unsigned binds.
    
- Test EHR, billing, PACS, VPN, file shares, and administrator login.
    

### Rollback

- Temporarily add RC4 back to the Kerberos GPO if a critical legacy service fails.
    
- Do **not** re-enable DES.
    
- Return LDAP signing to its previous setting only while the affected client is remediated.
    
- Restrict the exception to identified systems and document it.
    
- **Rollback trigger:** A critical authentication-dependent service remains unavailable for more than **15 minutes**.
    

### Maintenance Window

Overnight maintenance window with full IT staffing required.

### Communication

Notify all system owners, clinical operations, help desk, network administrators, Sarah Park, James Chen, and executive management.

---

## Action #5: Encrypt NAS-01 Backup Storage

**Priority:** Immediate  
**System Affected:** `NAS-01`

### Prerequisites

- Confirm the Synology model and DSM version support encrypted volumes
    
- Separate remote KMIP key server available
    
- Sufficient storage for a new encrypted volume
    
- Full backup of NAS configuration
    
- Successful restore test from existing backups
    
- Protected offline location for the recovery key
    

Synology encrypted volumes use LUKS with AES in XTS mode, and the key vault can be hosted on a separate KMIP server.

### Steps

1. Configure the remote KMIP key server on a separate supported system.
    
2. On `NAS-01`, open:
    

```text
Storage Manager
→ Storage
→ Global Settings
→ Encryption Key Vault
```

3. Select the remote KMIP server as the vault location.
    
4. Create a new encrypted volume:
    

```text
Storage Manager
→ Create Volume
→ Encrypt this volume
```

5. Download the recovery key immediately.
    
6. Store the recovery key:
    

- offline
    
- outside `NAS-01`
    
- under dual administrative control
    

7. Create a new backup shared folder on the encrypted volume.
    
8. Copy the current backup repository to the encrypted volume.
    
9. Compare file counts and SHA-256 checksums.
    
10. Pause backup jobs and perform a final incremental copy.
    
11. Change all backup jobs to the encrypted destination.
    
12. Configure offsite replication to copy already encrypted backup data.
    
13. Retain the old plaintext backup volume until two successful backup-and-restore cycles are completed.
    
14. Securely remove the old plaintext backups after approval.
    

### Validation

- Confirm DSM reports the volume as encrypted.
    
- Confirm the key vault is the remote KMIP server.
    
- Confirm the recovery key is stored outside the NAS.
    
- Run one complete backup.
    
- Restore one PostgreSQL backup and one MySQL backup.
    
- Verify restored file hashes.
    
- Confirm offsite replication completes successfully.
    
- Confirm monitoring alerts if the encrypted volume is unavailable.
    

### Rollback

- Pause the new backup jobs.
    
- Change the jobs back to the retained plaintext destination.
    
- Restore access to the previous backup repository.
    
- Do not delete the encrypted volume until the cause is identified.
    
- **Rollback trigger:** Backup or restore services remain unavailable for more than **30 minutes**.
    

### Maintenance Window

Weekend or overnight maintenance window required.

### Communication

Notify the backup administrator, database administrators, system owners, security team, Sarah Park, James Chen, and executive management before and after the migration.
