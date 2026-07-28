### The Data Classification Matrix

**Goal:** _Apply data protection principles to produce a comprehensive data classification policy for MedDefense that drives every encryption decision._

---

**Context:** Encryption is not binary ("encrypted" or "not encrypted"). It is a spectrum driven by the sensitivity of the data. A hospital cafeteria menu does not need AES-256. A patient's HIV status does. The data classification determines the protection level, and the protection level determines the algorithm, the key management rigor and the access controls.

---

**Instructions:**

**Part 1 - Data Type Inventory**

Classify all MedDefense data into data types: Regulated (HIPAA/PHI), PII, Financial, Intellectual Property, Legal and Operational. Some data may belong to multiple types.

**Part 2 - Classification Levels**

Define 4 classification levels for MedDefense:

- **Public** (example: hospital address, visiting hours)
    
- **Internal** (example: staff directory, meeting schedules)
    
- **Confidential** (example: financial reports, vendor contracts)
    
- **Restricted** (example: patient records, credentials, encryption keys)
    

For each level, define: who can access it, what encryption is required (at rest and in transit), what happens if it is exposed.

**Part 3 - The Classification Decision Tree**

Produce a text-based decision tree that a MedDefense employee could follow to classify a new type of data: "Is it patient data ? → Restricted. Does it contain financial information ? → Confidential. Is it internal operational data ? → Internal."

**Part 4 - Sovereignty and Geolocation**

MedDefense is considering migrating backups to AWS cloud storage (from the 1x03 roadmap). In 2-3 sentences, explain why data sovereignty matters for healthcare. If the AWS region is in a different state or country, what HIPAA implications arise ? Does encryption mitigate the sovereignty concern ?

---
# Answer

# 18. MedDefense Data Classification Matrix

## Part 1 — Data Type Inventory

Some information belongs to more than one data type.

|MedDefense data|Regulated PHI|PII|Financial|Intellectual Property|Legal|Operational|
|---|:-:|:-:|:-:|:-:|:-:|:-:|
|EHR patient records|✓|✓||||✓|
|Diagnoses, medications and clinical notes|✓|✓||||✓|
|Laboratory and test results|✓|✓||||✓|
|DICOM medical images and headers|✓|✓||||✓|
|Patient names, DOBs, addresses and MRNs|✓|✓||||✓|
|Patient SSNs|✓|✓|||||
|Insurance policy and claims data|✓|✓|✓|||✓|
|Billing records and invoices|✓|✓|✓|||✓|
|Payment card information||✓|✓||||
|Employee HR records||✓|✓||✓|✓|
|Payroll information||✓|✓|||✓|
|Usernames and account identifiers||✓||||✓|
|Password hashes and authentication tokens||✓||||✓|
|Encryption keys and private keys||||✓||✓|
|Database and system backups|Depends on contents|Depends on contents|Depends on contents|Depends on contents|Depends on contents|✓|
|Internal email|May contain PHI|May contain PII|May contain financial data|✓|✓|✓|
|Vendor contracts and BAAs||May contain PII|✓||✓|✓|
|Policies, procedures and risk registers||||✓|✓|✓|
|Incident reports and forensic evidence|May contain PHI|✓||✓|✓|✓|
|Audit and security logs|May contain PHI|✓|||✓|✓|
|Application source code and system designs||||✓||✓|
|Device firmware and configurations||||✓||✓|
|Network diagrams and IP addresses||||✓||✓|
|Staff directory and meeting schedules||✓||||✓|
|Public website content and visiting hours||||||✓|

---

## Part 2 — Classification Levels

|Level|Examples|Who Can Access|Encryption at Rest|Encryption in Transit|Exposure Consequence|
|---|---|---|---|---|---|
|**Public**|Hospital address, visiting hours, approved public announcements|Anyone|Not required, but storage integrity should be protected|HTTPS for public websites|Low impact; correct or republish inaccurate information|
|**Internal**|Staff directory, meeting schedules, internal procedures|MedDefense workforce with a business need|Full-disk or service-level encryption where available|TLS 1.2 or TLS 1.3|Internal investigation and corrective action may be required|
|**Confidential**|Financial reports, vendor contracts, payroll and internal security reports|Approved employees, managers and relevant departments|AES-256 at file, database or volume level|TLS 1.2 or TLS 1.3 with authenticated encryption|Investigate, contain access and assess contractual, privacy and financial impact|
|**Restricted**|Patient records, diagnoses, credentials, private keys and payment data|Specifically authorised roles under least privilege and need-to-know|AES-256 with central KMS or HSM-backed key protection|TLS 1.2 or TLS 1.3; message-level encryption where needed|Treat as a security incident; investigate, contain and assess legal or breach-notification duties|

### Public

Public data is approved for unrestricted release. Integrity remains important because altered public information could mislead patients.

### Internal

Internal data is available only to the MedDefense workforce or approved contractors. It should not be published externally without authorisation.

### Confidential

Confidential data could cause financial, contractual, legal or reputational harm if disclosed. Access must be role-based and logged.

### Restricted

Restricted data receives the highest protection. Access must use least privilege, MFA where applicable, detailed logging and centrally managed encryption keys.

---

## Part 3 — Classification Decision Tree

```text
START
  |
  |-- Does the data identify a patient or describe care,
  |   diagnosis, treatment, medication or medical images?
  |       |
  |       |-- YES → RESTRICTED
  |       |
  |       |-- NO
  |
  |-- Does it contain passwords, authentication tokens,
  |   private keys or encryption keys?
  |       |
  |       |-- YES → RESTRICTED
  |       |
  |       |-- NO
  |
  |-- Does it contain full payment card data, SSNs or other
  |   highly sensitive identifiers?
  |       |
  |       |-- YES → RESTRICTED
  |       |
  |       |-- NO
  |
  |-- Does it contain financial reports, payroll, contracts,
  |   legal records or sensitive business information?
  |       |
  |       |-- YES → CONFIDENTIAL
  |       |
  |       |-- NO
  |
  |-- Does it contain source code, security findings,
  |   network diagrams or non-public system configurations?
  |       |
  |       |-- YES → CONFIDENTIAL
  |       |
  |       |-- NO
  |
  |-- Is it intended only for employees or internal operations?
  |       |
  |       |-- YES → INTERNAL
  |       |
  |       |-- NO
  |
  |-- Has an authorised owner approved it for public release?
          |
          |-- YES → PUBLIC
          |
          |-- NO → INTERNAL until reviewed
```

### Classification Rule

When data fits multiple categories, apply the **highest classification level**. For example, a backup containing patient records remains Restricted even if the backup file itself contains no visible patient name.

---

## Part 4 — Sovereignty and Geolocation

Data sovereignty matters because information may become subject to the laws, government-access rules and enforcement conditions of the location where it is stored. HIPAA does not prohibit storing ePHI in another US state or outside the United States, but MedDefense must execute a HIPAA-compliant BAA with AWS, perform a geographic risk assessment and apply appropriate safeguards; HHS specifically notes that overseas storage may create additional security and enforceability risks.

Encryption reduces the confidentiality risk, especially when MedDefense controls the keys, but it does not remove sovereignty concerns or AWS’s business-associate status. Contractual duties, jurisdiction, availability, lawful access and incident-response requirements still apply even when AWS cannot decrypt the data.
