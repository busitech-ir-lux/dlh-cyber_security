# 7. The Obfuscation Toolkit

## Part 1 — Technique Comparison

| Technique         | What it does                                                                                               | Can the original data be recovered?                                                                       | Healthcare use case                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Encryption**    | Converts readable data into ciphertext using an algorithm and key.                                         | **Yes.** An authorised user or system with the correct decryption key can recover it.                     | Encrypting EHR databases, backups and DICOM traffic.                                                      |
| **Hashing**       | Converts data into a fixed-length one-way digest.                                                          | **Normally no.** The original value is not decrypted; attackers may only guess inputs and compare hashes. | Verifying file integrity or storing application password verifiers with a password KDF.                   |
| **Tokenization**  | Replaces sensitive data with a non-sensitive token. The real value is stored separately in a secure vault. | **Yes.** Only the authorised tokenization system or vault can recover the real value.                     | Replacing credit card numbers in the billing system with payment tokens.                                  |
| **Data masking**  | Hides part or all of a value while keeping a usable display format.                                        | **Not from the masked display.** Authorised systems may still access the original source data.            | Showing only the last four digits of an SSN to reception staff.                                           |
| **Steganography** | Hides data inside another file or communication so that the hidden data is not obvious.                    | **Yes.** A person with the correct extraction method or key can recover it.                               | Legitimate watermarking of medical images, or malicious hiding of stolen patient data inside DICOM files. |

## Important Difference

* **Encryption hides the meaning of data.**
* **Hashing creates a one-way representation.**
* **Tokenization replaces data with a reference.**
* **Masking limits what a user can see.**
* **Steganography hides the existence of the data.**

---

# Part 2 — MedDefense Tokenization Design

## 1. Data to Tokenize

MedDefense should tokenize the **full payment card number**, also called the Primary Account Number.

Example:

```text
Real card number:
4111 1111 1111 1111

Token:
MDP-8F42-71C9-5A30
```

The token should:

* have no mathematical relationship to the real card number
* be randomly generated
* be unique
* contain no sensitive card information
* be useless outside MedDefense’s approved payment process

For systems that require a card-like format, MedDefense could use a format-preserving token:

```text
Token:
9417 6203 8841 1111
```

The final four digits may remain visible for identification, while the other digits are tokenized.

MedDefense should not store the card security code after payment authorisation.

## 2. Token Vault Location and Protection

The mapping between tokens and real card numbers should be stored in a dedicated **token vault**, separate from `billing-srv-01`.

Recommended design:

```text
Billing application
       |
       | Token only
       v
Tokenization service
       |
       | Restricted connection
       v
Secure token vault
```

The vault should be protected with:

* AES-256 encryption at rest
* TLS 1.2 or TLS 1.3 in transit
* keys stored in a hardware security module or separate key-management system
* strict role-based access control
* multi-factor authentication for administrators
* separate service accounts for tokenization and detokenization
* network segmentation
* complete audit logging
* regular access reviews
* monitoring for unusual detokenization requests

Billing clerks should normally see only the token and the final four card digits. They should not have direct access to the vault.

## 3. If the Token Vault Is Compromised

If attackers obtain only the billing database, the tokens should provide little value because they do not reveal the original card numbers.

If attackers compromise the vault, its encryption keys and its access controls, they may recover the token-to-card mappings. This could expose all stored payment card numbers.

The token vault therefore becomes a high-value system and must receive stronger security than an ordinary application database. MedDefense should be able to disable tokens, rotate keys, investigate detokenization activity and notify the payment provider if compromise occurs.

## 4. Tokenization Compared with Encryption

| Area                         | Tokenization                                                         | Encryption                                              |
| ---------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------- |
| Stored value                 | Replaces the card number with an unrelated token                     | Stores ciphertext created from the card number          |
| Recovery method              | Lookup through the token vault                                       | Decryption with the correct key                         |
| Exposure of billing database | Tokens normally reveal no card data                                  | Encrypted card data remains present and may be attacked |
| Key management               | Required mainly for the vault and its storage                        | Required wherever card data is encrypted or decrypted   |
| Application changes          | Applications must work with tokens                                   | Applications may continue using encrypted fields        |
| Data processing              | Real card number is available only through controlled detokenization | Any authorised application with the key may decrypt it  |
| Main disadvantage            | The vault becomes a critical dependency and attack target            | Key compromise may expose every encrypted card number   |

## Recommendation

Tokenization is better for MedDefense’s billing system because most billing processes do not need the full card number. The application can store and use tokens while the real card data remains in a smaller, strongly protected environment.

Encryption is still required inside the token vault and during communication with the payment processor. Therefore, tokenization does not replace encryption; it reduces the number of systems that handle sensitive payment data.

---

# Part 3 — Data Masking Examples

| Data field       | Full value        | Nurse — Clinical  | Billing clerk       | Reception        |
| ---------------- | ----------------- | ----------------- | ------------------- | ---------------- |
| **SSN**          | `987-65-4321`     | `***-**-4321`     | `***-**-4321`       | `***-**-4321`    |
| **Patient name** | `Maria Gonzalez`  | `Maria Gonzalez`  | `Maria Gonzalez`    | `Maria Gonzalez` |
| **Diagnosis**    | `Type 2 Diabetes` | `Type 2 Diabetes` | `Chronic condition` | `Restricted`     |

## Justification by Role

### SSN

**Nurse — `***-**-4321`:**
A nurse normally does not need the full SSN to provide clinical care, but the last four digits may help confirm identity.

**Billing clerk — `***-**-4321`:**
A billing clerk may need limited identifying information for account verification, but should not routinely see the full SSN.

**Reception — `***-**-4321`:**
Reception staff may use the final four digits to confirm identity but do not need the complete number.

### Patient Name

**Nurse — `Maria Gonzalez`:**
The nurse needs the full name to identify the correct patient and avoid clinical errors.

**Billing clerk — `Maria Gonzalez`:**
The billing clerk needs the full name to connect invoices, insurance information and payments to the correct patient.

**Reception — `Maria Gonzalez`:**
Reception needs the full name for appointments, check-in and patient identification.

### Diagnosis

**Nurse — `Type 2 Diabetes`:**
The nurse needs the complete diagnosis to provide safe treatment and clinical support.

**Billing clerk — `Chronic condition`:**
The billing clerk may need a general category or approved billing code, but usually does not need the full clinical description.

**Reception — `Restricted`:**
Reception staff do not need diagnosis details to schedule or check in the patient.

## Masking Principle

Masking should be based on **need-to-know**, not simply job seniority. A field may be visible to one role and hidden from another depending on the task being performed.

---

# Part 4 — Steganography as a Threat Vector

Steganography is a serious DLP concern because an insider could hide stolen patient data inside legitimate DICOM image files without changing their obvious appearance. The attacker could place information in unused metadata fields, private DICOM tags, image pixels or appended binary data and then transfer the image through an approved radiology workflow. Traditional DLP tools may see an authorised medical image moving between facilities rather than a document containing names, SSNs or medical records. Detection is difficult because DICOM files are large, complex and expected to contain both image data and extensive metadata. MedDefense’s network segmentation, centralised logging and DLP monitoring strategy should baseline normal PACS file sizes, metadata and transfer patterns, then alert on unusual modifications, destinations or volumes.

## Recommended Controls

MedDefense should:

* allow DICOM transfers only between approved systems
* inspect and remove unnecessary private DICOM tags
* validate file structure before import or export
* compare expected and actual file sizes
* monitor unusual PACS transfer volumes
* block transfers to unapproved destinations
* log all image exports
* use behavioural monitoring for insider activity
* perform content-disarm or metadata sanitisation where clinically safe

## Final Summary

Tokenization and masking reduce exposure by limiting where sensitive values appear. Encryption protects readable data using keys, while hashing provides one-way verification. Steganography does not make data cryptographically secure; it merely hides the data and can therefore be used by attackers to bypass normal monitoring. MedDefense should apply each technique only to the problem it was designed to solve.

