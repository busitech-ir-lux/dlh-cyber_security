### The Crypto Posture Audit

**Goal:** _Produce a systematic, evidence-based assessment of MedDefense's entire cryptographic posture, connecting every finding to a specific risk and a specific recommendation._

---

**Context:** You started this project with a Data Protection Map (T0) that showed where encryption was absent or weak. Since then, you have learned every primitive, inspected real certificates, built encryption scripts, analyzed TLS configurations and designed key management. Now apply everything you know to a formal audit.

---

**Instructions:** Revisit your Data Protection Map from T0. For every cell that was marked "Weak" or "Absent," produce a **Crypto Finding**:

```less
Finding ID: CRYPTO-[NNN]
Data Category: [From T0 row]
Data State: [At rest / In transit / In use]
Current Protection: [What exists today, or "None"]
Vulnerability Reference: [Finding ID from 1x02 if applicable]
Risk Reference: [RISK-ID from 1x03 if applicable]
Algorithm Assessment: [Is the current algorithm adequate? Reference T6]
Recommended Protection: [Specific algorithm, mode, key length]
Encryption Level: [From T13 recommendation]
Key Management: [From T14 plan]
Implementation Priority: [Immediate / Phase 1 / Phase 2]
```

After all findings, produce:

- **Posture Score:** What percentage of MedDefense's data flows now have a clear remediation path ?
    
- **Top 3 Crypto Risks:** The three findings with the highest combined impact, ranked

---
# Answer

# 15. MedDefense Crypto Posture Audit

## Audit Basis

T0 identified:

- **3 adequate cells**
    
- **3 weak cells**
    
- **15 absent cells**
    

The vulnerability scan confirms unrestricted EHR and billing database exposure, unsigned LDAP, weak Kerberos encryption, and exposed backup management. The earlier assessment also identifies the flat network and backup isolation as critical risks and credential compromise as a high risk.

## Crypto Findings

|Finding|Data Category|Data State|Current Protection|Vulnerability Reference|Risk Reference|Algorithm Assessment|Recommended Protection|Encryption Level|Key Management|Priority|
|---|---|---|---|---|---|---|---|---|---|---|
|**CRYPTO-001**|Patient medical records|At rest|None; PostgreSQL files on unencrypted ext4|Finding 003; M-01|**RISK-001 — EHR data breach**|Absent|AES-256 database or tablespace encryption; use LUKS2 AES-256-XTS where PostgreSQL 14 lacks native TDE|Database level|Database data key wrapped by a master key in an HSM-backed managed KMS|**Phase 1**|
|**CRYPTO-002**|Patient medical records|In transit|PostgreSQL TLS optional; plaintext connections permitted|Finding 003|RISK-001|Weak because encryption is not enforced|Require TLS 1.2/1.3 using AES-256-GCM or AES-128-GCM; remove all `hostnossl` rules|Database connection level|Server certificate and private key managed centrally; rotate certificates automatically|**Immediate**|
|**CRYPTO-003**|Patient medical records|In use|Data readable in server memory and on unlocked nurse screens|No direct 1x02 finding|RISK-001|Absent|AES-256-GCM record-level encryption for especially sensitive fields; automatic screen lock and RBAC|Record level|Applications request field keys from KMS; users never receive keys directly|**Phase 2**|
|**CRYPTO-004**|Financial and billing data|At rest|None; MySQL files readable directly from the filesystem|Findings 001, 002 and 006|Billing-data breach risk; exact ID unavailable|Absent|AES-256-GCM for sensitive fields and tokenization for payment card numbers|Record level|Billing data key stored in HSM-backed KMS; token vault protected separately|**Phase 1**|
|**CRYPTO-005**|Financial and billing data|In transit|Plaintext MySQL protocol over flat network|Finding 006; M-01|Billing-data breach risk; exact ID unavailable|Absent|Require TLS 1.2/1.3 with AES-GCM and certificate validation|Database connection level|MySQL certificates managed centrally and rotated before expiry|**Immediate**|
|**CRYPTO-006**|Financial and billing data|In use|Sensitive fields displayed and processed in plaintext|No direct 1x02 finding|Billing-data breach risk; exact ID unavailable|Absent|Tokenize card numbers; use AES-256-GCM for SSNs and insurance identifiers; mask unnecessary fields|Record level|Detokenization permitted only through the payment service; dual approval for vault administration|**Phase 2**|
|**CRYPTO-007**|Medical images|At rest|DICOM files stored unencrypted|M-01 and M-07|Medical-imaging PHI exposure risk; exact ID unavailable|Absent|AES-256-GCM file encryption or an AES-256-XTS encrypted PACS volume|File level|Per-file data keys wrapped by a central KMS master key|**Phase 1**|
|**CRYPTO-008**|Medical images|In transit|Cleartext DICOM on ports 4242 and 11112|M-01 and M-07|Medical-imaging PHI exposure risk; exact ID unavailable|Absent|Enable DICOM TLS using TLS 1.2/1.3 with AES-GCM|File/network level|PACS and workstation certificates issued by MedDefense’s internal CA|**Immediate**|
|**CRYPTO-009**|Medical images|In use|Images and patient metadata readable on radiology workstations|M-07|Medical-imaging PHI exposure risk; exact ID unavailable|Absent|Keep files encrypted until opened by an authorised viewer; enforce automatic lock and individual authentication|File level|Viewer receives temporary access through KMS-authorised service accounts|**Phase 2**|
|**CRYPTO-010**|Credentials|At rest|Unsalted MD4-based NT hashes; application-password protection undocumented|Finding 018; M-05|Credential-compromise risk; exact ID unavailable|Weak; MD4 is not suitable for modern password storage|Use Argon2id for application passwords; use gMSAs, Windows Hello and MFA for AD accounts|Record level|Password hashes remain in identity systems; KMS stores application peppers where used|**Phase 1**|
|**CRYPTO-011**|Credentials|In transit|Kerberos allows AES, RC4 and DES; LDAP signing not required|Findings 007 and 018|Credential-compromise risk; exact ID unavailable|DES and RC4 are broken or deprecated; unsigned LDAP is inadequate|Permit Kerberos AES-128/AES-256 only; require LDAP signing or LDAPS with TLS 1.2/1.3|Authentication/service level|Kerberos keys managed by AD; reset legacy service accounts and migrate to gMSAs|**Immediate**|
|**CRYPTO-012**|Credentials|In use|Credentials and tickets present in process memory without additional protection|M-05|Credential-compromise risk; exact ID unavailable|Absent|Enable Credential Guard, protected LSASS, short-lived tokens and MFA|Record/credential level|Secrets remain in protected identity services or hardware-backed device stores|**Phase 2**|
|**CRYPTO-013**|Backup data|At rest|None; plaintext backups on unencrypted RAID-5|Finding 015; M-02|Ransomware and backup-loss risk; exact ID unavailable|Absent|LUKS2 volume encryption using AES-256-XTS; optionally encrypt each backup with AES-256-GCM|Volume level|Master key stored in an HSM-backed managed KMS, never on NAS-01; protected recovery copy required|**Immediate**|
|**CRYPTO-014**|Backup data|In transit|No encrypted transfer protocol documented|Finding 015; M-01 and M-02|Ransomware and backup-loss risk; exact ID unavailable|Absent|Use TLS 1.3 with AES-256-GCM for server-to-NAS and NAS-to-cloud replication|Volume/network level|Backup service uses a restricted KMS identity and short-lived credentials|**Phase 1**|
|**CRYPTO-015**|Backup data|In use|Backups readable while mounted, restored or processed|M-02|Ransomware and backup-loss risk; exact ID unavailable|Absent|Unlock only during backup or restore jobs; use isolated restore systems and immutable replicas|Volume level|KMS releases the volume key only to the authorised backup service|**Phase 2**|
|**CRYPTO-016**|Email|In use|Messages containing PHI readable; S/MIME and OME not configured|No DLP finding documented in 1x02; noted in earlier assessment|PHI exfiltration risk; exact ID unavailable|Absent at message level|Use Microsoft Purview Message Encryption or S/MIME; apply DLP to PHI|Message/file level|O365 manages service keys; user certificate keys managed through central certificate lifecycle controls|**Phase 1**|
|**CRYPTO-017**|VPN traffic|At rest|Protection of VPN private keys, PSKs, configurations and logs not documented|Finding 014; M-06|Westside/VPN compromise risk; exact ID unavailable|Unknown and therefore inadequate|Store certificate keys in the FortiGate secure key store; encrypt configuration backups with AES-256-GCM|File level|Restrict keys to network administrators; prefer certificate authentication over shared PSKs|**Phase 1**|
|**CRYPTO-018**|VPN traffic|In use|Traffic is decrypted at VPN endpoints for routing|Finding 014; M-06|Westside/VPN compromise risk; exact ID unavailable|Encryption cannot remain active while packets are processed|Retain IPsec AES-256/SHA-256/IKEv2; segment decrypted traffic and restrict VPN ACLs|Endpoint/network level|Keys remain in FortiGate secure storage; certificates rotated annually or after compromise|**Phase 2**|

## Key-Management Ownership

The governance structure assigns technical remediation to Sarah Park and IT, security accountability to James Chen, business-data decisions to department heads, and executive risk acceptance to the CEO.

- **James Chen:** Accountable for cryptographic remediation and policy.
    
- **Sarah Park:** Responsible for technical implementation.
    
- **Department heads:** Approve access requirements for their data.
    
- **Security analyst:** Monitors key use, expiry, and control effectiveness.
    
- **CEO:** Accepts any residual risk or approved exception.
    

# Posture Score

All 18 weak or absent cells now have:

- a specific protection mechanism
    
- an encryption level
    
- a key-management approach
    
- an implementation priority
    

Therefore:

```text
Remediation-path coverage = 18 ÷ 18 × 100
                          = 100%
```

Across the complete T0 matrix:

```text
3 adequate cells + 18 cells with remediation paths
= 21 of 21 cells addressed
= 100%
```

This is a **planning score**, not an implementation score. MedDefense’s current adequate cryptographic coverage remains:

```text
3 ÷ 21 × 100 = 14.3%
```

# Top 3 Crypto Risks

## 1. CRYPTO-001 — Unencrypted EHR Database

Patient records are readable directly from the disk if `ehr-db-01` is compromised or its storage is removed. This affects MedDefense’s most sensitive data and directly connects to **RISK-001**, which has a previously calculated ALE of **$3,025,000**.

**Required action:** Implement AES-256 database or volume encryption with an HSM-backed managed KMS in Phase 1.

## 2. CRYPTO-013 — Unencrypted Backup Repository

NAS-01 contains readable copies of the EHR, billing database and other critical systems. Because it is accessible from the flat network, ransomware or a NAS compromise could expose or destroy both production recovery data and patient records.

**Required action:** Encrypt the backup volume with LUKS2 AES-256-XTS, keep the key outside NAS-01 and replicate encrypted immutable backups offsite.

## 3. CRYPTO-011 — Weak Kerberos and LDAP Protection

DES and RC4 permit weak Kerberos ticket encryption, while unsigned LDAP supports relay and directory-manipulation attacks. Compromise of Active Directory credentials could give an attacker access to the EHR, billing, PACS, backups and VPN environment.

**Required action:** Disable DES and RC4, enforce Kerberos AES, require LDAP signing or LDAPS and reset legacy service-account credentials.
