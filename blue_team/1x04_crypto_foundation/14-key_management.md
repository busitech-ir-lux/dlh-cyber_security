### Hardware Security and Key Management

**Goal:** _Evaluate TPM, HSM and secure enclave technologies, and design a key management strategy for MedDefense that solves the "where do you keep the keys ?" problem._

---

**Context:** Every encryption scheme has a fatal weakness: the key. If you encrypt 50,000 patient records with AES-256 and store the key in a plaintext configuration file on the same server, you have not actually protected anything. You have added a speed bump.

Sec+ 1.4 identifies three hardware security technologies designed to solve this problem: TPM (Trusted Platform Module), HSM (Hardware Security Module) and secure enclaves. Each operates at a different scale and cost, and MedDefense needs to choose which is appropriate for its budget and risk profile.

---

**Instructions:**

**Part 1 - Technology Comparison**

Research and compare:

|Technology|What It Is|What It Protects|Typical Cost|Typical Deployment|
|---|---|---|---|---|
|TPM|?|?|?|?|
|HSM|?|?|?|?|
|Secure Enclave|?|?|?|?|
|KMS (Software)|?|?|?|?|

**Part 2 - MedDefense Key Management Design**

MedDefense now has encryption on: the patient database (T13 recommendation), the backup storage (T12), the portal TLS (T10) and the VPN tunnels. Each of these has at least one encryption key.

Design a **Key Management Plan** that addresses:

- Where each key is stored (which system/device)
    
- Who has access to each key (which role, from your 1x03 governance structure)
    
- How keys are rotated (frequency and process)
    
- What happens if a key is compromised (revocation and replacement procedure)
    
- What happens if a key is lost (recovery procedure, key escrow if appropriate)
    

**Part 3 - The HSM Decision**

Using the ALE calculations from 1x03, evaluate whether MedDefense should invest in an HSM for database encryption key management. Estimate the cost of an HSM (cloud-based HSM-as-a-Service options are available at approximately $1-2/key/month). Compare this to the risk of key compromise (reference the relevant risk from your Risk Register). Is the investment justified ?


---
# Answer

# 14. Hardware Security and Key Management

## Part 1 — Technology Comparison

|Technology|What It Is|What It Protects|Typical Cost|Typical Deployment|
|---|---|---|---|---|
|**TPM**|A security chip built into a computer or server that provides a hardware root of trust.|Device-bound encryption keys, boot integrity, BitLocker keys and device identity.|Usually included in the device; low additional cost.|Individual laptops, desktops and servers.|
|**HSM**|A tamper-resistant device that generates, stores and uses cryptographic keys without exposing them outside its protected boundary.|High-value database keys, CA keys, TLS private keys and signing keys.|Managed KMS: approximately `$1–2/key/month`; dedicated cloud HSM: about `$1.45/hour` per device.|Central enterprise or cloud key-management infrastructure.|
|**Secure Enclave**|An isolated security processor built into a device’s system-on-chip.|Device keys, biometric data, authentication keys and application secrets.|Included in supported hardware.|Smartphones, tablets and modern laptops.|
|**Software KMS**|Central software or cloud service that creates, stores, rotates and controls access to keys.|Application, database, storage and cloud-service encryption keys.|Open-source software may have no licence cost; cloud services often charge per key and request.|Central data centre or cloud service.|

A TPM is mainly device-specific and supports controls such as BitLocker and Windows Hello. An HSM centrally protects cryptographic keys and performs cryptographic operations inside tamper-resistant hardware. Secure Enclave technology isolates sensitive operations from the main processor, even if the main operating system is compromised.

AWS KMS currently charges `$1` per customer-managed key per month and protects its keys using FIPS 140-3 Level 3 HSMs. A dedicated AWS CloudHSM currently costs approximately `$1.45` per hour per HSM, depending on region.

---

# Part 2 — MedDefense Key Management Plan

## General Ownership

|Responsibility|MedDefense Role|
|---|---|
|**Accountable for key-management policy**|James Chen, Deputy CISO|
|**Technical owner**|Sarah Park, IT Director|
|**Daily key operations**|IT Operations|
|**Monitoring and investigation**|Security Analyst|
|**Business and data approval**|Relevant Department Head|
|**Risk acceptance and funding**|Executive management|

Keys should be centrally inventoried, assigned an owner, given an expiration date and managed under a documented key-management policy.

## Key Plan

|System|Where the Key Is Stored|Access|Rotation|If Compromised|If Lost|
|---|---|---|---|---|---|
|**Patient database**|AES database key encrypted by a master key in an HSM-backed KMS|Database service account can request decryption; Sarah Park administers it; James Chen approves policy|Rotate master key annually; create a new key version and rewrap the database key|Disable the old key, generate a new key, rewrap or re-encrypt data, review access logs and investigate exposure|Recover through KMS redundancy and a protected escrow copy; without the key, the database cannot be decrypted|
|**NAS-01 backups**|Each backup receives a separate data key; the master key remains in the KMS/HSM and never on NAS-01|Backup service account; recovery requires approval from IT Director and Deputy CISO|New data key for every backup; rotate master key annually|Stop replication, disable the key, create a replacement key and re-encrypt affected backups|Recover the master key through controlled escrow; loss of all key copies makes the backups unrecoverable|
|**Portal TLS**|ECDSA P-256 private key in an HSM or protected TLS termination service|Web service may use the key; administrators should not export it|Generate a new key with every certificate renewal|Revoke the certificate, generate a new private key, request a new certificate and investigate possible impersonation|Do not restore a lost TLS private key; generate a new key and reissue the certificate|
|**VPN tunnels**|Certificate private keys in the FortiGate secure key store; migrate away from shared plaintext PSKs|Network administrators; Sarah Park is technical owner|Certificates annually; PSKs every 90 days until certificate authentication is implemented|Disable the old credential, replace it at both endpoints and review VPN activity|Restore approved configuration and issue a new certificate or PSK|
|**Employee devices**|Full-disk encryption keys sealed to each device’s TPM|Device and authorised recovery administrators|Normally changed when the device is rebuilt or compromise is suspected|Rotate recovery credentials and rebuild the affected device|Retrieve the centrally escrowed BitLocker recovery key|

## Rotation Process

1. Create a new key version in the KMS.
    
2. Test the new key with a non-production workload.
    
3. Change applications to use the new key.
    
4. Keep the previous version available only for decrypting existing data.
    
5. Rewrap or re-encrypt existing data where required.
    
6. Disable and later destroy the retired key after recovery testing.
    

Cloud KMS platforms support automatic key-version rotation without requiring applications to change the permanent key identifier. A yearly rotation is a practical MedDefense baseline, with immediate rotation after suspected compromise.

## Key Compromise Procedure

1. Declare a security incident.
    
2. Disable or revoke the affected key.
    
3. Identify every system and dataset protected by it.
    
4. Generate a new key using the KMS or HSM.
    
5. Rewrap or re-encrypt affected data.
    
6. Revoke and replace certificates where applicable.
    
7. Review key-use and administrator logs.
    
8. Determine whether regulated data was exposed.
    
9. Destroy the old key after recovery is complete.
    

## Key Recovery

Encryption keys for databases and backups require protected recovery copies because losing them would permanently destroy access to the data.

Recovery copies should use:

- dual approval
    
- separate administrators
    
- offline or geographically separate protection
    
- regular recovery testing
    
- complete audit logging
    

TLS signing keys should normally not be escrowed. If one is lost, MedDefense should generate a new key pair and obtain a replacement certificate.

---

# Part 3 — HSM Decision

## Cost Comparison

### Managed HSM-Backed KMS

Assume four production master keys:

- patient database
    
- backup system
    
- portal
    
- VPN
    

At the provided estimate of `$1–2 per key per month`:

```text
4 keys × $1 × 12 months = $48 per year

4 keys × $2 × 12 months = $96 per year
```

Additional request and logging costs would normally remain small for this workload.

### Dedicated Cloud HSM

At approximately `$1.45 per hour`:

```text
1 HSM × $1.45 × 8,760 hours = $12,702 per year
```

High availability would normally require at least two devices:

```text
2 HSMs = approximately $25,404 per year
```

Dedicated HSMs provide greater isolation and control, but they also introduce significantly higher cost and administration.

## Comparison with MedDefense Risk

The MedDefense Risk Register calculated:

```text
RISK-001 — EHR data breach
Annual Loss Expectancy: $3,025,000
```

Using the higher managed-key estimate:

```text
$96 ÷ $3,025,000 × 100
= approximately 0.0032%
```

The managed KMS would need to reduce the annual EHR-breach risk by only about **0.0032%** to recover its annual key-storage cost.

For a two-device dedicated HSM service:

```text
$25,404 ÷ $3,025,000 × 100
= approximately 0.84%
```

A dedicated HSM would need to reduce the risk by approximately **0.84%** to equal its annual cost. However, not all EHR breach risk comes from key theft, so the full ALE cannot be attributed to key compromise alone.

## Decision

**MedDefense should invest in an HSM-backed managed KMS for database and backup encryption keys.**

The annual cost of approximately `$48–96` for four managed keys is extremely small compared with the `$3,025,000` EHR breach ALE. It also solves the main design problem: database keys are no longer stored in plaintext on `ehr-db-01` or NAS-01.

A dedicated single-tenant HSM cluster is **not currently necessary** unless MedDefense has a specific compliance requirement, needs exclusive hardware control or begins operating its own certificate authority. A managed KMS using validated HSM protection provides the appropriate balance of security, cost and operational simplicity.
