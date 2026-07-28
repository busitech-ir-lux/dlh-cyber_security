# 6. The Algorithm Landscape

## Status Definitions

* **Current:** Acceptable for modern use with appropriate parameters and implementation.
* **Deprecated:** Should not be selected for new systems; retained only for controlled legacy compatibility.
* **Broken:** Does not provide adequate modern security and should be removed.

# 1. Symmetric Algorithms

| Algorithm             | Type                              |                         Key/Output Size | Primary Use Case                                                               | Status         | Why Deprecated/Broken                                                                                          | MedDefense Usage                                                                                                                                |
| --------------------- | --------------------------------- | --------------------------------------: | ------------------------------------------------------------------------------ | -------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **AES-128**           | Symmetric block cipher            |              128-bit key; 128-bit block | Fast bulk encryption for files, databases, VPNs and TLS                        | **Current**    | —                                                                                                              | Suitable for TLS and constrained medical devices. It provides strong security with less processing than AES-256.                                |
| **AES-192**           | Symmetric block cipher            |              192-bit key; 128-bit block | Bulk encryption requiring an intermediate AES key size                         | **Current**    | —                                                                                                              | No current usage. Little practical reason to select it instead of AES-128 or AES-256.                                                           |
| **AES-256**           | Symmetric block cipher            |              256-bit key; 128-bit block | High-security bulk encryption and data-at-rest protection                      | **Current**    | —                                                                                                              | Currently used in the Central-to-Westside and Central-to-HQ IPSec VPNs. Recommended for EHR, billing, PACS and backup storage.                  |
| **DES**               | Symmetric block cipher            |      56-bit effective key; 64-bit block | Historical data encryption                                                     | **Broken**     | Its 56-bit key can be brute-forced with practical computing resources.                                         | Finding 018 showed that DES remains enabled for Active Directory Kerberos compatibility. It must be disabled.                                   |
| **3DES/TDEA**         | Symmetric block cipher            |   112 or 168 nominal bits; 64-bit block | Legacy replacement for DES                                                     | **Deprecated** | It is slow, uses a small 64-bit block and is vulnerable to birthday-bound attacks on large data volumes.       | No confirmed use, but MedDefense should verify that it is absent from portal, VPN, database and device cipher suites.                           |
| **ChaCha20-Poly1305** | Symmetric stream cipher with AEAD | 256-bit key; 128-bit authentication tag | Authenticated network encryption, especially without AES hardware acceleration | **Current**    | —                                                                                                              | Possible TLS 1.3 alternative for the portal and constrained medical devices. Use only where compliance requirements permit non-FIPS algorithms. |
| **RC4**               | Symmetric stream cipher           |             Variable; commonly 128 bits | Historical stream encryption and legacy Kerberos                               | **Broken**     | Statistical biases allow recovery of information from encrypted traffic; RC4 is prohibited in TLS.             | Finding 018 confirmed that RC4 remains enabled in Active Directory. It exposes service accounts to efficient Kerberoasting attacks.             |
| **Blowfish**          | Symmetric block cipher            |            32–448-bit key; 64-bit block | Historical file and application encryption                                     | **Deprecated** | Its 64-bit block size creates birthday-collision risks when large amounts of data are encrypted under one key. | No documented usage. MedDefense should not introduce it; OpenSSL places Blowfish in its legacy provider.                                        |

AES-128, AES-192 and AES-256 remain standardised in FIPS 197. NIST disallowed 3DES for applying new cryptographic protection after 31 December 2023, while the IETF prohibits RC4 in TLS.

ChaCha20-Poly1305 is a modern authenticated-encryption algorithm defined by the IETF. Blowfish is not fully cryptanalytically broken, but its 64-bit block size enabled practical Sweet32-style attacks and OpenSSL now treats it as a legacy algorithm.

# 2. Asymmetric Algorithms

| Algorithm          | Type                               |                       Key/Output Size | Primary Use Case                                                        | Status      | Why Deprecated/Broken | MedDefense Usage                                                                                                                                          |
| ------------------ | ---------------------------------- | ------------------------------------: | ----------------------------------------------------------------------- | ----------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RSA-2048**       | Asymmetric                         |                     2,048-bit modulus | Digital signatures, certificates and protection of small symmetric keys | **Current** | —                     | Acceptable minimum for portal certificates and digital signatures. It must not encrypt medical files directly.                                            |
| **RSA-4096**       | Asymmetric                         |                     4,096-bit modulus | Higher-security signatures and certificates                             | **Current** | —                     | No current use documented. Suitable where a larger RSA security margin is required, but it increases CPU and certificate size.                            |
| **ECC P-256**      | Asymmetric elliptic curve          |                         256-bit curve | Digital signatures and elliptic-curve key agreement                     | **Current** | —                     | Recommended for portal certificates, ECDHE and constrained devices such as pumps and monitors.                                                            |
| **ECC P-384**      | Asymmetric elliptic curve          |                         384-bit curve | Higher-security signatures and key agreement                            | **Current** | —                     | Suitable for high-assurance or long-lived MedDefense certificates where additional processing is acceptable.                                              |
| **Diffie-Hellman** | Asymmetric key agreement           | Variable; normally 2,048 bits or more | Establishing a shared secret over an untrusted network                  | **Current** | —                     | The VPN uses finite-field DH Group 14, which has a 2,048-bit modulus. It must be authenticated with certificates or a strong pre-shared key.              |
| **ECDHE**          | Asymmetric ephemeral key agreement |               Commonly P-256 or P-384 | Establishing temporary TLS session keys with forward secrecy            | **Current** | —                     | Recommended for the patient portal with TLS 1.2 or TLS 1.3. It should replace static RSA key transport and older finite-field handshakes where supported. |

RSA keys of at least 2,048 bits and approved elliptic curves such as P-256 and P-384 remain acceptable under current NIST guidance. NIST also continues to specify approved finite-field and elliptic-curve Diffie-Hellman schemes.

## Important DH distinction

**Diffie-Hellman and ECDHE are key-agreement algorithms, not data-encryption algorithms.** They generate shared keying material, which is then processed through a KDF and used with a symmetric cipher such as AES-GCM.

ECDHE is normally preferred for modern TLS because it provides strong security with smaller keys and supports forward secrecy.

# 3. Hash Algorithms

| Algorithm   | Type        |                 Key/Output Size | Primary Use Case                                                        | Status         | Why Deprecated/Broken                                                                                                    | MedDefense Usage                                                                                                     |
| ----------- | ----------- | ------------------------------: | ----------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| **MD5**     | Hash        |                  128-bit output | Historical integrity checks and legacy protocol operations              | **Broken**     | Practical collision attacks allow different inputs to produce the same digest. It is also too fast for password storage. | HMAC-MD5 is used internally by the legacy RC4-HMAC Kerberos mechanism. It should disappear when RC4 is disabled.     |
| **SHA-1**   | Hash        |                  160-bit output | Historical signatures, certificates and integrity checks                | **Deprecated** | Practical collision attacks have broken its collision resistance; it is disallowed for new digital-signature generation. | No confirmed usage. MedDefense must check portal certificates, TLS suites and legacy applications for SHA-1.         |
| **SHA-256** | Hash        |                  256-bit output | Integrity checking, digital signatures, HMAC and certificate operations | **Current**    | —                                                                                                                        | Used for VPN integrity and in the laboratory scripts. Recommended as the normal MedDefense integrity hash.           |
| **SHA-512** | Hash        |                  512-bit output | High-strength hashing, HMAC and signature systems                       | **Current**    | —                                                                                                                        | Suitable for integrity and HMAC operations. It may perform efficiently on 64-bit servers.                            |
| **SHA-3**   | Hash family | 224, 256, 384 or 512-bit output | Hashing, integrity, signatures and SHAKE-based applications             | **Current**    | —                                                                                                                        | No current usage. It provides a modern alternative to SHA-2 but is not required merely because SHA-2 remains secure. |

NIST identifies MD5 as broken and has disallowed SHA-1 for new digital signatures. NIST plans to transition away from all remaining applications of SHA-1 by 31 December 2030.

SHA-256 and SHA-512 remain part of the Secure Hash Standard, while SHA-3 is standardised separately in FIPS 202.

# 4. Key-Derivation and Password-Hashing Algorithms

Unlike normal hash functions, password KDFs deliberately consume significant processing time or memory. Their output length is normally configurable.

| Algorithm    | Type                     |                     Key/Output Size | Primary Use Case                                                     | Status      | Why Deprecated/Broken | MedDefense Usage                                                                                                                                            |
| ------------ | ------------------------ | ----------------------------------: | -------------------------------------------------------------------- | ----------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PBKDF2**   | KDF/password hashing     | Variable; commonly 256 bits or more | Deriving keys or password verifiers through repeated HMAC operations | **Current** | —                     | Recommended where MedDefense requires a NIST/FIPS-aligned password or storage KDF. Used in the OpenSSL CBC laboratory commands.                             |
| **bcrypt**   | Password KDF             |       184-bit stored hash plus salt | Adaptive password hashing                                            | **Current** | —                     | Acceptable for existing applications, but not the preferred design for a new system because of its password-length limitation and weaker memory resistance. |
| **Argon2id** | Memory-hard password KDF |         Variable; commonly 256 bits | Modern application password storage                                  | **Current** | —                     | Preferred for new MedDefense application passwords where FIPS approval is not required. Not a replacement for Active Directory’s internal hash format.      |
| **scrypt**   | Memory-hard password KDF |         Variable; commonly 256 bits | Password storage and password-based key derivation                   | **Current** | —                     | Suitable as an alternative where Argon2id is unavailable. No current MedDefense use is documented.                                                          |

PBKDF2 is specified by NIST for password-based key derivation. Argon2 and scrypt are modern memory-hard functions, while bcrypt remains an adaptive password-hashing algorithm with an adjustable cost.

For application password storage:

> **Preferred:** Argon2id
> **FIPS-oriented option:** PBKDF2-HMAC-SHA-256
> **Existing legacy applications:** bcrypt with a properly selected cost
> **Alternative:** scrypt

# MedDefense Crypto Gap Analysis

## Deprecated or Broken Cryptography in Production

| Gap                                  | Current MedDefense State                                                                  | Risk                                                                                                                     | Required Replacement                                                                                                                                                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. DES in Kerberos**               | Finding 018 confirmed that DES encryption types remain enabled on the domain controllers. | DES has only a 56-bit effective key and can be brute-forced.                                                             | Disable DES and permit only supported AES Kerberos encryption types. Test legacy device compatibility first.                                                                                                                       |
| **2. RC4 in Kerberos**               | RC4 remains enabled for legacy compatibility.                                             | Attackers can request RC4 service tickets and perform efficient offline Kerberoasting against service-account passwords. | Migrate accounts and devices to AES Kerberos, reset old service-account passwords and use group Managed Service Accounts where possible.                                                                                           |
| **3. MD5 within RC4-HMAC**           | Kerberos RC4-HMAC depends on HMAC-MD5 internally.                                         | MD5 is a retired cryptographic foundation and remains part of the weak RC4 ticket mechanism.                             | Removing RC4-HMAC and using AES Kerberos encryption types removes this MD5 dependency.                                                                                                                                             |
| **4. MD4-based NT hashes**           | Active Directory stores NT password hashes derived using MD4.                             | The hash is unsalted and extremely fast to test offline; stolen NT hashes can also support pass-the-hash attacks.        | Active Directory cannot simply be changed to Argon2. Replace passwords where possible with Windows Hello for Business, certificate authentication and managed service accounts; deploy MFA and Credential Guard and restrict NTLM. |
| **5. TLS 1.0 on the patient portal** | The portal supports TLS 1.0 alongside TLS 1.2.                                            | TLS 1.0 is formally deprecated and permits outdated cipher and handshake behaviour.                                      | Disable TLS 1.0; enable TLS 1.2 and preferably TLS 1.3 with ECDHE and AES-GCM or ChaCha20-Poly1305.                                                                                                                                |

TLS 1.0 and TLS 1.1 are formally deprecated by the IETF.

## Missing Cryptographic Protection

MedDefense also has major gaps where no algorithm is used at all:

| System or Data              | Current State                                                                        | Recommended Protection                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| **PostgreSQL EHR storage**  | Unencrypted ext4 filesystem                                                          | AES-256-based full-disk, volume or database encryption with keys stored separately from the server                  |
| **PostgreSQL connections**  | TLS is optional because both SSL and non-SSL connections are accepted                | Enforce TLS 1.2 or later and reject all non-TLS database connections                                                |
| **MySQL billing storage**   | Database files are readable directly from disk                                       | AES-256-based storage encryption and separate key management                                                        |
| **MySQL network traffic**   | Plaintext MySQL across the flat network                                              | Enforce authenticated TLS 1.2 or later                                                                              |
| **PACS images at rest**     | DICOM files stored without encryption                                                | AES-256 storage or volume encryption                                                                                |
| **DICOM traffic**           | Images and patient identifiers cross the network in cleartext                        | DICOM TLS using TLS 1.2 or later                                                                                    |
| **NAS backups**             | RAID-5 without encryption                                                            | AES-256 backup encryption with keys held outside NAS-01                                                             |
| **Sensitive email content** | Transport and mailbox storage are encrypted, but messages are readable to recipients | Use Microsoft Purview Message Encryption, S/MIME or another approved message-level control when PHI must be emailed |

# Priority Remediation Order

1. **Disable DES and remove RC4 dependencies from Active Directory.**
2. **Disable TLS 1.0 and harden the patient portal to TLS 1.2/1.3.**
3. **Encrypt EHR, billing, PACS and backup data at rest with AES.**
4. **Encrypt MySQL, PostgreSQL and DICOM traffic.**
5. **Introduce centralised key management and key rotation.**
6. **Use Argon2id or PBKDF2 for application passwords instead of fast hashes.**
7. **Inventory all certificates, cipher suites, hashes and device dependencies before disabling legacy cryptography.**

# Final Assessment

MedDefense already uses strong **AES-256, SHA-256, IKEv2 and Diffie-Hellman** protection in its site-to-site VPNs. However, the environment still contains **DES, RC4, HMAC-MD5, MD4-based NT hashes and TLS 1.0**, while several critical systems have no encryption at all.

The target standard should be:

* **AES-GCM** for bulk authenticated encryption
* **TLS 1.2 or TLS 1.3** for data in transit
* **ECDHE P-256 or P-384** for modern key exchange
* **RSA-2048 or stronger, or approved ECC**, for certificates and signatures
* **SHA-256, SHA-512 or SHA-3** for cryptographic hashing
* **Argon2id or PBKDF2** for application password storage
* **No DES, 3DES, RC4, Blowfish, MD5 or new SHA-1 usage**

