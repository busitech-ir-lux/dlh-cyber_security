### The Cryptographic Attack Surface

**Goal:** _Map the cryptographic attacks to MedDefense's specific weaknesses, showing which attacks are viable today and which controls would neutralize them._

---

**Context:** Downgrade attacks, collision attacks, birthday attacks and more. These are not abstract concepts. Every one of them maps to a real weakness at MedDefense.

---

**Instructions:** For each of the following attack types, produce:

```vbnet
Attack: [Name]
Mechanism: [How it works, 2-3 sentences]
MedDefense Vulnerability: [Which specific system/configuration is susceptible?]
Evidence: [Reference to 1x02 finding or T0/T6 analysis]
Viable Today: [Yes/No, with reasoning]
Mitigation: [What specific control or configuration change neutralizes this attack?]
```

**Attacks to cover:**

1. **TLS Downgrade** (forcing TLS 1.0 on the patient portal)
    
2. **Collision Attack** (exploiting MD5 in Kerberos tickets)
    
3. **Birthday Attack** (theoretical, explain the math and relevance)
    
4. **Kerberoasting** (exploiting RC4/DES in Kerberos for offline cracking)
    
5. **On-path/MITM on unencrypted channels** (DICOM traffic, unencrypted database connections)
    
6. **Key Recovery from Memory** (if an attacker has root on billing-srv-01, can they extract AES keys from RAM ?)


---

# Answer

# The Cryptographic Attack Surface

## 1. TLS Downgrade

**Attack:** TLS Downgrade

**Mechanism:** An attacker interferes with the TLS handshake so that a connection using TLS 1.2 appears to fail. A legacy or misconfigured client may retry using TLS 1.0, allowing the attacker to target weaknesses in the older protocol. Modern clients include downgrade protections, but supporting TLS 1.0 still increases the attack surface.

**MedDefense Vulnerability:** The patient portal supports both TLS 1.0 and TLS 1.2.

**Evidence:** Finding 005; T6 classifies TLS 1.0 as deprecated.

**Viable Today:** **Yes, conditionally.** It is mainly viable against legacy clients or clients with insecure fallback behaviour.

**Mitigation:** Disable TLS 1.0 and permit only TLS 1.2 and TLS 1.3 with ECDHE and AES-GCM or ChaCha20-Poly1305.

---

## 2. Collision Attack

**Attack:** MD5 Collision Attack

**Mechanism:** A collision attack finds two different inputs that produce the same hash value. This can undermine digital signatures or integrity checks when an attacker can prepare both versions of the content, but it does not reveal the original input or recover a password.

**MedDefense Vulnerability:** Kerberos RC4-HMAC uses HMAC-MD5 internally.

**Evidence:** Finding 018; T6 identifies MD5 as broken and RC4-HMAC as deprecated.

**Viable Today:** **No, not directly against Kerberos tickets.** Practical MD5 collisions do not allow an attacker to recover the password-derived Kerberos key or forge arbitrary HMAC-MD5 tickets; Kerberoasting is the practical attack against this configuration. RC4-HMAC’s use of HMAC-MD5 is defined in RFC 4757.

**Mitigation:** Disable RC4 Kerberos encryption, allow AES-128 and AES-256 only, and remove MD5 from all certificate, signature and integrity applications.

---

## 3. Birthday Attack

**Attack:** Birthday Attack

**Mechanism:** A birthday attack searches for any two inputs with the same hash rather than trying to match one specific hash. For an ideal `n`-bit hash, a collision becomes likely after approximately `2^(n/2)` attempts: about `2^64` for MD5 and `2^128` for SHA-256.

**MedDefense Vulnerability:** MD5 remains indirectly present through RC4-HMAC Kerberos, but no current MedDefense digital-signature or integrity system is documented as relying directly on MD5.

**Evidence:** Finding 018; T6 hash-algorithm assessment.

**Viable Today:** **No direct target confirmed.** SHA-256 birthday attacks are computationally impractical, and the documented Kerberos weakness is better attacked through offline password cracking.

**Mitigation:** Use SHA-256, SHA-512 or SHA-3 for integrity and signatures; prohibit MD5 and SHA-1 in new systems.

---

## 4. Kerberoasting

**Attack:** Kerberoasting

**Mechanism:** An authenticated domain user requests a Kerberos service ticket for an account with a Service Principal Name. The ticket is encrypted using material derived from the service account’s password, allowing the attacker to take it offline and test password guesses without causing repeated login failures. Microsoft identifies RC4 Kerberos tickets as particularly suitable for this attack.

**MedDefense Vulnerability:** Active Directory still permits RC4 and DES Kerberos encryption types.

**Evidence:** Finding 018; T0 credentials-in-transit cell; T6 classifies DES as broken and RC4 as broken.

**Viable Today:** **Yes.** A domain user or compromised internal account could request RC4 service tickets and attempt to crack weak service-account passwords offline.

**Mitigation:** Disable DES and RC4, reset service-account passwords to generate AES keys, use group Managed Service Accounts with long random passwords, and monitor Kerberos Event ID 4769 for RC4 tickets.

---

## 5. On-Path/MITM on Unencrypted Channels

**Attack:** On-Path or Man-in-the-Middle Attack

**Mechanism:** An attacker positioned on the network path can capture unencrypted traffic and may alter, inject or replay data. Encryption without certificate or peer validation can also remain vulnerable because the attacker may impersonate one endpoint.

**MedDefense Vulnerability:** DICOM traffic is cleartext, MySQL traffic is plaintext, and PostgreSQL permits non-TLS connections across the flat `10.10.0.0/16` network.

**Evidence:** T0 medical-images-in-transit, billing-in-transit and EHR-in-transit cells.

**Viable Today:** **Yes.** An attacker controlling an internal host, switch path or network segment could read patient images, billing information or database traffic.

**Mitigation:** Enable DICOM TLS 1.2 or TLS 1.3, set MySQL `require_secure_transport=ON`, remove PostgreSQL `hostnossl` rules, require `hostssl`, validate certificates and segment the network. DICOM defines TLS security profiles, while PostgreSQL and MySQL support mandatory encrypted connections.

---

## 6. Key Recovery from Memory

**Attack:** Cryptographic Key Recovery from Memory

**Mechanism:** A root or SYSTEM-level attacker can inspect application memory, debugging interfaces, core dumps or swap data. If an AES key is loaded into a process, the attacker may recover the key; even when the key is hardware-protected, the attacker may capture plaintext while the authorised application processes it. Attackers commonly retrieve credential material from process memory after obtaining administrative access.

**MedDefense Vulnerability:** `billing-srv-01` was previously compromised during the crypto-miner incident and its database currently has no encryption. A future implementation that stores an AES key in a plaintext configuration file or keeps it permanently in memory would remain vulnerable.

**Evidence:** T0 financial-data-at-rest finding; T14 key-management analysis.

**Viable Today:** **No for AES key recovery today**, because the billing database currently uses no AES encryption. However, a root attacker can already read the plaintext database, and memory-key recovery would become viable after a poorly designed encryption deployment.

**Mitigation:** Store master keys in an HSM-backed managed KMS, use envelope encryption and short-lived data keys, restrict root access, disable unnecessary core dumps, encrypt swap and minimise key residence in memory. This reduces key exposure but cannot fully protect data from an attacker controlling the application while it is actively processing plaintext.
