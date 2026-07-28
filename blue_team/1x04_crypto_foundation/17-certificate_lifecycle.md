### Certificate Lifecycle Management

**Goal:** _Design the certificate management program that prevents MedDefense from ever facing another "certificate expires in 18 days" emergency._

---

**Context:** The patient portal certificate is a symptom, not the disease. The disease is that MedDefense has no certificate inventory, no expiration monitoring, no renewal process and no policy on certificate types. This task creates the program.

---

**Instructions:** Produce a **Certificate Lifecycle Management Plan** for MedDefense:

1. **Certificate Inventory:** List every certificate MedDefense should be tracking (patient portal, EHR internal, VPN, email signing, code signing if applicable). For each: the current issuer, expiration date (estimate based on findings) and responsible owner.
    
2. **Auto-Renewal Strategy:** Recommend whether MedDefense should use ACME/Let's Encrypt (automated, free, 90-day certificates) or a commercial CA (manual, paid, 1-year certificates). For the patient portal specifically, justify your choice considering the 800 daily patients and the clinical impact of an expiration.
    
3. **Monitoring and Alerting:** What system should monitor certificate expiration ? At what thresholds should alerts fire (90 days, 60 days, 30 days, 7 days) ? Who receives each alert ?
    
4. **Certificate Policy:** Draft 5 policy rules for MedDefense's certificate usage (example: "All internal services must use certificates signed by the MedDefense internal CA or a trusted public CA. Self-signed certificates are prohibited in production.").

---

# Answer

# 17. Certificate Lifecycle Management Plan

## 1. Certificate Inventory

|Certificate|Current Issuer|Expiration|Responsible Owner|
|---|---|---|---|
|**Patient portal TLS**|Let’s Encrypt|Approximately **15 August 2026**—18 days from 28 July 2026|Sarah Park, IT Director|
|**EHR internal TLS**|None or unknown; internal TLS is not fully implemented|Unknown|EHR System Owner and IT Operations|
|**PostgreSQL database TLS**|Unknown; PostgreSQL TLS exists but is not enforced|Unknown|Database Administrator|
|**VPN peer certificates**|Unknown; the audit does not confirm whether IKEv2 uses certificates or a pre-shared key|Unknown|Network Administrator|
|**Email-signing certificates**|None; S/MIME is not configured|Not applicable|Messaging Administrator|
|**Code-signing certificate**|None documented|Not applicable|Application or Software Owner|
|**Internal CA root and intermediate certificates**|Not currently documented|Unknown|James Chen and Sarah Park|

For each certificate, the inventory must record:

- subject and SAN entries
    
- issuer
    
- serial number
    
- public-key algorithm
    
- issue and expiration dates
    
- system location
    
- responsible owner
    
- renewal method
    
- private-key location
    
- revocation status
    

---

## 2. Auto-Renewal Strategy

### Patient Portal Recommendation

MedDefense should use **Let’s Encrypt with ACME automatic renewal** for the patient portal, provided a DV certificate is acceptable.

Reasons:

- automatic renewal removes dependence on manual calendar tracking
    
- Let’s Encrypt certificates are valid for 90 days
    
- renewal can run automatically approximately 30 days before expiration
    
- the certificate is trusted by standard browsers
    
- an expiration affecting 800 patients per day would create a significant clinical and operational disruption
    

Let’s Encrypt issues standard certificates with 90-day validity and recommends automated renewal. ACME standardises automated domain validation, issuance and renewal.

### Commercial CA

Use a commercial CA only when MedDefense requires:

- Organisation Validation
    
- contractual support
    
- specialised certificate profiles
    
- formal organisational identity in the certificate
    

The description of commercial certificates as “manual, one-year certificates” is outdated. Public TLS certificates issued from **15 March 2026** may have a maximum validity of **200 days**, and commercial CAs should also be integrated with ACME or another automated renewal system.

### Renewal Process

1. ACME checks for renewal daily.
    
2. Renewal begins when approximately 30 days remain.
    
3. The new certificate is installed automatically.
    
4. Apache or Nginx reloads automatically.
    
5. A monitoring system confirms that the new certificate is being served.
    
6. Failure creates an alert and remediation ticket.
    

---

## 3. Monitoring and Alerting

### Monitoring System

MedDefense should use **Wazuh with a scheduled certificate-checking script**.

The system should:

- scan all known TLS endpoints daily
    
- read expiration dates
    
- check hostname and SAN values
    
- verify the certificate chain
    
- detect certificate changes
    
- create alerts and remediation tickets
    

### Alert Thresholds

|Time Remaining|Alert Level|Recipients|Required Action|
|--:|---|---|---|
|**90 days**|Information|Certificate owner and IT Operations|Confirm inventory, ownership and renewal method|
|**60 days**|Warning|Certificate owner and Sarah Park|Confirm that automated renewal is enabled and tested|
|**30 days**|High|Sarah Park, IT Operations and James Chen|Open a priority renewal ticket and investigate failure|
|**7 days**|Critical|Sarah Park, James Chen, on-call IT and executive management|Treat as an urgent service-availability incident|

For certificates with a 90-day lifetime, the 90-day event records successful issuance rather than acting as an expiration warning.

After every renewal, monitoring must confirm:

- correct certificate
    
- correct SAN entries
    
- complete certificate chain
    
- valid expiration date
    
- correct private-key match
    
- successful client connection
    

---

## 4. Certificate Policy

### Rule 1 — Trusted Issuers

All production certificates must be issued by a trusted public CA or the approved MedDefense internal CA. Self-signed certificates are prohibited in production.

### Rule 2 — Certificate Inventory

Every certificate must be recorded in the central inventory with its owner, issuer, expiration date, deployment location and renewal method.

### Rule 3 — Automated Renewal

All certificates must use automated renewal where technically possible. Manual renewal requires a documented exception and assigned backup owner.

### Rule 4 — Approved Cryptography

TLS certificates must use ECDSA P-256 or stronger, or RSA-2048 or stronger, with SHA-256 or a stronger approved signature algorithm.

### Rule 5 — Private-Key Protection

Private keys must be stored in an HSM-backed KMS, secure appliance or restricted operating-system key store. Keys must never be committed to source control, emailed or stored in plaintext configuration files.

## Final Recommendation

The immediate priority is to replace the patient portal certificate before approximately **15 August 2026** and enable ACME renewal. MedDefense should then build the central inventory, assign an owner to every certificate and enable daily expiration monitoring so that no certificate reaches the 30-day threshold without an active renewal ticket.
