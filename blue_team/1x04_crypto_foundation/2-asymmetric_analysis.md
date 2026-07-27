# 2. The Asymmetric Engine

## Part 1 — RSA Key Generation and Encryption

### 1. Create the patient record

```bash
printf '%s\n' \
'Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation' \
> patient.txt
```

### 2. Generate an RSA-2048 key pair

Generate the private key:

```bash
openssl genrsa -out rsa_private.pem 2048
```

Protect its permissions:

```bash
chmod 600 rsa_private.pem
```

Extract the public key:

```bash
openssl rsa \
  -in rsa_private.pem \
  -pubout \
  -out rsa_public.pem
```

### 3. Encrypt with the public key

Use RSA-OAEP with SHA-256 rather than older PKCS#1 v1.5 encryption:

```bash
openssl pkeyutl \
  -encrypt \
  -pubin \
  -inkey rsa_public.pem \
  -in patient.txt \
  -out patient.rsa.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
```

The public key can encrypt the data, but it cannot decrypt it.

### 4. Decrypt with the private key

```bash
openssl pkeyutl \
  -decrypt \
  -inkey rsa_private.pem \
  -in patient.rsa.enc \
  -out patient.rsa.dec.txt \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
```

### 5. Verify the result

```bash
cmp -s patient.txt patient.rsa.dec.txt \
  && echo "RSA decryption verified"
```

Expected output:

```text
RSA decryption verified
```

OpenSSL’s `pkeyutl` command supports RSA encryption and decryption with OAEP padding.

---

## Attempting to Encrypt the 100 MiB File

Run:

```bash
openssl pkeyutl \
  -encrypt \
  -pubin \
  -inkey rsa_public.pem \
  -in testfile \
  -out testfile.rsa.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256
```

### Observed error

Using OpenSSL 3.5.5, the operation produced:

```text
Public Key operation error
error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex:
data too large for key size
```

The complete error may contain a different memory address or OpenSSL source-file path depending on the installed version.

### Explanation

RSA can encrypt only a message smaller than its modulus after space is reserved for secure padding. With RSA-2048 and OAEP-SHA-256, the maximum input is only **190 bytes**, calculated as `256 − (2 × 32) − 2`, so a 100 MiB file is far too large.

In real systems, RSA encrypts or transports a small randomly generated symmetric key. AES or another symmetric algorithm then encrypts the actual file or network session.

---

# Part 2 — ECC Key Generation

## 1. Generate a P-256 private key

```bash
openssl ecparam \
  -genkey \
  -name prime256v1 \
  -out ecc_private.pem
```

`prime256v1` is OpenSSL’s name for the NIST P-256 curve.

Protect the private key:

```bash
chmod 600 ecc_private.pem
```

## 2. Extract the public key

```bash
openssl ec \
  -in ecc_private.pem \
  -pubout \
  -out ecc_public.pem
```

The `ecparam` command supports named-curve EC parameter and key generation.

## 3. Compare the file sizes

```bash
wc -c rsa_private.pem ecc_private.pem
```

Observed result:

```text
1704 rsa_private.pem
 302 ecc_private.pem
2006 total
```

### Ratio

```text
RSA-to-ECC size ratio = 1704 ÷ 302
                      = 5.64
```

Therefore, the RSA private-key file was approximately:

> **5.64 times larger than the ECC private-key file.**

PEM file sizes can vary slightly between OpenSSL versions because of serialization and formatting differences.

### Explanation

ECC derives its security from the difficulty of the elliptic-curve discrete logarithm problem, allowing much smaller parameters than RSA, which depends on integer factorization. P-256 provides approximately **128 bits of security**, while RSA-2048 provides approximately **112 bits**, meaning the generated P-256 key is both smaller and stronger by NIST’s security-strength comparison.

Smaller ECC keys require less storage, network bandwidth and computation. This is valuable for constrained medical devices such as infusion pumps and patient monitors, although device support, implementation quality and approved cryptographic modules must still be verified.

---

# Part 3 — The Hybrid Model

Asymmetric cryptography is used during the handshake to authenticate systems and establish or protect a small shared secret. Both sides then derive symmetric session keys from that secret. A fast authenticated symmetric cipher, such as AES-GCM or ChaCha20-Poly1305, encrypts the actual application data. This is superior to symmetric encryption alone because it solves the initial key-distribution problem, and it is superior to asymmetric encryption alone because symmetric encryption is faster and can process large amounts of data. The hybrid design therefore combines the key-management benefits of public-key cryptography with the performance of symmetric cryptography.

## MedDefense Patient Portal

When a patient connects to the portal through HTTPS, the **TLS handshake** authenticates the server certificate and establishes shared keying material. In modern TLS, ephemeral Diffie–Hellman—normally ECDHE—performs the key agreement, while the certificate’s RSA or ECC key authenticates the server.

After the handshake, the **TLS record layer** encrypts the patient’s HTTP requests and the portal’s responses using symmetric authenticated encryption, normally AES-GCM or ChaCha20-Poly1305. TLS 1.3 requires AEAD protection and removed legacy RSA key transport and CBC cipher suites.

MedDefense currently supports TLS 1.0 and TLS 1.2 rather than TLS 1.3. With TLS 1.2, the exact key-exchange method depends on the negotiated cipher suite: it could use preferred ECDHE or an older RSA key-transport suite. MedDefense must inspect and restrict the portal’s cipher suites rather than assuming that all TLS 1.2 connections use the same protection.

---

# Part 4 — Key-Length Comparison Table

For this table, **Approved** means suitable for new MedDefense implementations under a NIST-aligned cryptographic standard. Correct modes, padding, nonce handling, certificate validation and key management are still required; an approved algorithm can remain insecure when implemented incorrectly.

|Algorithm|Type|Key lengths|Approximate equivalent security|Status for regulated healthcare data|MedDefense usage|
|---|---|--:|--:|---|---|
|**AES**|Symmetric block cipher|128, 192 or 256 bits|128, 192 or 256 bits|**Approved.** Use an approved mode; prefer authenticated encryption such as GCM for new designs.|AES-256 currently protects site-to-site VPN traffic. Recommended for EHR, billing, PACS and backup encryption.|
|**RSA**|Asymmetric|2048 or 4096 bits|RSA-2048: **112 bits**; RSA-4096: approximately **140 bits**|**Approved with conditions.** RSA-2048 is the current minimum; use OAEP for encryption/key transport and approved signature padding.|Possible portal certificate authentication and key establishment. Must not encrypt medical files directly.|
|**ECC P-256**|Asymmetric elliptic curve|256-bit curve|**128 bits**|**Approved.** Appropriate for signatures and ephemeral key agreement.|Recommended for ECDHE portal key exchange and constrained medical devices.|
|**ECC P-384**|Asymmetric elliptic curve|384-bit curve|**192 bits**|**Approved.** Higher security with more processing cost than P-256.|Suitable for long-lived certificates or systems requiring a higher security margin.|
|**DES**|Symmetric block cipher|56 effective key bits|**56 bits**|**Not approved.** Broken by practical brute force and withdrawn by NIST.|Must not be used. Disable any remaining legacy DES support in Active Directory.|
|**3DES/TDEA**|Symmetric block cipher|168 nominal; approximately 112 effective|**112 bits**, with major block-size and usage limitations|**Not approved for new encryption.** NIST disallowed applying new cryptographic protection with TDEA after 31 December 2023.|No documented MedDefense business requirement. Remove from legacy systems and cipher suites.|
|**ChaCha20-Poly1305**|Symmetric stream cipher plus AEAD authenticator|256-bit encryption key; 128-bit tag|Approximately **256-bit confidentiality** and **128-bit authentication tag**|**Conditionally acceptable.** Modern IETF-standardized AEAD, but not currently a NIST/FIPS-approved algorithm. Do not use where MedDefense requires FIPS-approved cryptography.|Useful in modern TLS, particularly on devices without fast AES hardware. No current usage documented.|
|**RC4**|Symmetric stream cipher|Variable; commonly 128 bits|No meaningful modern security level|**Not approved.** IETF requires TLS clients and servers never to negotiate RC4.|Finding 018 showed RC4 remains enabled for Kerberos compatibility. It should be disabled after dependency testing.|

AES-128, AES-192 and AES-256 are all defined in FIPS 197. NIST maps RSA-2048 to approximately 112-bit security, P-256 to approximately 128-bit security and P-384 to approximately 192-bit security; RSA-4096 lies between the NIST reference points for RSA-3072 and RSA-7680, so its value is an estimate rather than a formal NIST tier.

NIST withdrew DES because it no longer provided adequate protection, and TDEA became disallowed for applying new cryptographic protection from 1 January 2024. ChaCha20-Poly1305 is a modern AEAD construction standardized by the IETF, but current FIPS module documentation classifies it as non-approved. RC4 is prohibited in TLS because its weaknesses prevent it from providing adequate security.

# Final Findings

1. RSA successfully encrypted the small patient record but could not encrypt the 100 MiB file.
    
2. RSA-2048 with OAEP-SHA-256 was limited to approximately 190 bytes of plaintext.
    
3. The RSA private-key file was approximately 5.64 times larger than the P-256 ECC private-key file.
    
4. P-256 provides greater estimated security than RSA-2048 while using a substantially smaller key representation.
    
5. Real-world systems use hybrid encryption: asymmetric cryptography establishes keys, and symmetric cryptography protects bulk data.
    
6. MedDefense should standardize on AES-GCM for bulk encryption and ECDHE using an approved curve for modern TLS key agreement.
    
7. DES, 3DES and RC4 must not be permitted for new MedDefense cryptographic protection.
