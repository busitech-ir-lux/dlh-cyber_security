# 10. The CSR Workshop

## Assumptions

Because MedDefense’s exact legal address was not provided, this lab uses:

```text
Locality: Boston
State: Massachusetts
Country: US
```

These values must be replaced with MedDefense’s real registered location before submitting an OV certificate request.

The CSR created below follows the assignment and uses:

```text
portal.meddefense.local
patient.meddefense.local
```

These names are suitable only for an internal CA. A production patient portal should use registered public DNS names.

---

# Part 1 — Key Generation Decision

## Selected Algorithm: ECC P-256

I selected **ECC P-256** because it provides approximately 128-bit security with a substantially smaller key than RSA-2048 or RSA-4096. It also reduces certificate size and server-side signature processing, although 800 patient connections per day would be a light workload for any of the three options. P-256 is widely supported by modern browsers and devices, while obsolete clients that do not support it should not determine the security level of a healthcare portal. RSA-2048 could be deployed as a secondary compatibility certificate only when MedDefense has a documented legacy requirement.

## Generate the Private Key

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out portal_key.pem
```

Protect its permissions:

```bash
chmod 600 portal_key.pem
```

Inspect the key:

```bash
openssl pkey \
  -in portal_key.pem \
  -text \
  -noout
```

The output should identify:

```text
ASN1 OID: prime256v1
NIST CURVE: P-256
```

The private key must not be emailed, committed to Git or submitted to the CA. Only the CSR is submitted.

---

# Part 2 — CSR Generation

## 1. Create `openssl.cnf`

```ini
[ req ]
prompt = no
default_md = sha256
distinguished_name = subject
req_extensions = extensions

[ subject ]
C = US
ST = Massachusetts
L = Boston
O = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[ extensions ]
subjectAltName = @san
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth

[ san ]
DNS.1 = portal.meddefense.local
DNS.2 = patient.meddefense.local
```

OpenSSL uses the request-extension section to include requested X.509 extensions such as Subject Alternative Names in the CSR.

## Field Decisions

| CSR field               | Value                           | Reason                                             |
| ----------------------- | ------------------------------- | -------------------------------------------------- |
| **Country**             | `US`                            | Assumed MedDefense country for this lab            |
| **State**               | `Massachusetts`                 | Assumed legal state                                |
| **Locality**            | `Boston`                        | Assumed legal city                                 |
| **Organization**        | `MedDefense Health Systems`     | Legal organizational identity                      |
| **Organizational Unit** | `Information Technology`        | Team responsible for the portal                    |
| **Common Name**         | `portal.meddefense.local`       | Required by the assignment                         |
| **SAN 1**               | `portal.meddefense.local`       | Primary portal hostname                            |
| **SAN 2**               | `patient.meddefense.local`      | Alternative patient-facing hostname                |
| **Key Usage**           | `Digital Signature`             | ECDSA signs the TLS handshake                      |
| **Extended Key Usage**  | `TLS Web Server Authentication` | Restricts the certificate to server authentication |

Modern clients validate hostnames against the SAN extension. The CN should still be correct, but it should not be treated as a replacement for SAN entries.

## 2. Generate the CSR

```bash
openssl req \
  -new \
  -key portal_key.pem \
  -out portal.csr \
  -config openssl.cnf
```

Expected output:

```text
No output on success
```

Confirm that the files exist:

```bash
ls -l portal_key.pem portal.csr openssl.cnf
```

## 3. Verify the CSR Signature

```bash
openssl req \
  -verify \
  -noout \
  -in portal.csr
```

Expected output:

```text
Certificate request self-signature verify OK
```

This verifies that the CSR was correctly signed by the private key that corresponds to its embedded public key.

A CSR only **requests** certificate fields and extensions. The CA validates the request and decides which values it will include in the issued certificate.

---

# Part 3 — CSR Inspection

## Inspection Command

```bash
openssl req \
  -text \
  -noout \
  -verify \
  -in portal.csr
```

## Observed Output

The following output was produced with OpenSSL 3.5.5:

```text
Certificate request self-signature verify OK
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject:
            C=US,
            ST=Massachusetts,
            L=Boston,
            O=MedDefense Health Systems,
            OU=Information Technology,
            CN=portal.meddefense.local

        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256

        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    DNS:portal.meddefense.local,
                    DNS:patient.meddefense.local

                X509v3 Key Usage: critical
                    Digital Signature

                X509v3 Extended Key Usage:
                    TLS Web Server Authentication

    Signature Algorithm: ecdsa-with-SHA256
```

The long public-key bytes and signature bytes have been omitted because they are different every time a new key is generated.

## Verification Checklist

| Item                 | Expected value              | Result          |
| -------------------- | --------------------------- | --------------- |
| Country              | `US`                        | Correct         |
| State                | `Massachusetts`             | Correct         |
| Locality             | `Boston`                    | Correct         |
| Organization         | `MedDefense Health Systems` | Correct         |
| Organizational Unit  | `Information Technology`    | Correct         |
| Common Name          | `portal.meddefense.local`   | Correct for lab |
| SAN 1                | `portal.meddefense.local`   | Present         |
| SAN 2                | `patient.meddefense.local`  | Present         |
| Public-key algorithm | EC                          | Correct         |
| Curve                | P-256                       | Correct         |
| CSR signature        | ECDSA with SHA-256          | Correct         |
| Key Usage            | Digital Signature           | Correct         |
| Extended Key Usage   | Server Authentication       | Correct         |

---

# Production Hostname Correction

A public CA must not issue a publicly trusted certificate for:

```text
portal.meddefense.local
patient.meddefense.local
```

Publicly trusted CAs are prohibited from issuing certificates containing internal names because those names cannot be validated as globally unique public DNS names.

For the production patient portal, the CSR should instead use names such as:

```ini
CN = portal.meddefense.com

[ san ]
DNS.1 = portal.meddefense.com
DNS.2 = patient.meddefense.com
```

The exact names must be domains legally controlled by MedDefense.

If MedDefense must retain `.local` for an internal administrative portal, the certificate must be issued by MedDefense’s private enterprise CA and that CA’s root certificate must be distributed to every authorised client. Public patients would not automatically trust that private CA.

---

# Part 4 — Full Certificate Lifecycle

## Step 1 — Generate the Key and CSR

The IT security team generates the P-256 private key on a trusted system or approved key-management platform.

The team then:

1. Protects the key with restrictive permissions.
2. Generates the CSR.
3. Verifies the CSR signature.
4. Checks the Subject and SAN entries.
5. Records the public-key fingerprint.
6. Stores the private key separately from the CSR.

The private key remains inside MedDefense.

---

## Step 2 — Select the Certificate Authority

### Recommended Production Choice

Use a **commercial public CA offering an OV certificate and automated certificate-management support**.

The reasons are:

* MedDefense is a regulated healthcare organization.
* OV verifies MedDefense’s organizational identity in addition to domain control.
* A commercial CA can provide support for emergency issuance and revocation.
* Automated renewal can prevent another certificate-expiration incident.

Possible vendors include established public CAs such as DigiCert, Sectigo or GlobalSign. The final selection should follow MedDefense’s procurement, compliance and incident-response requirements.

### Alternative: Let’s Encrypt

Let’s Encrypt provides publicly trusted DV certificates and supports automated issuance through ACME. It verifies domain control but does not validate MedDefense’s legal organizational identity.

It would be technically suitable when MedDefense accepts DV and changes the hostname to a registered public domain. It cannot issue for `.local`.

---

## Step 3 — Submit the CSR

Submit:

```text
portal.csr
```

Do not submit:

```text
portal_key.pem
```

The CA receives the public key, requested Subject information, SAN entries and requested extensions from the CSR.

For an OV certificate, MedDefense may also need to provide:

* legal organization name
* registered address
* organization registration information
* authorized requester information
* verified telephone or organizational contact details

---

## Step 4 — Complete Validation

The CA validates two main areas.

### Domain Control Validation

The CA verifies that MedDefense controls every requested SAN hostname.

Common methods include:

* creating a specific DNS TXT record
* placing a validation file on the portal web server
* using an automated ACME challenge

For DNS-01 validation, the CA asks MedDefense to publish a temporary TXT record under `_acme-challenge` for the requested domain.

### Organization Validation

For an OV certificate, the CA also confirms that:

* MedDefense Health Systems legally exists
* the address and organization details are accurate
* the requester is authorized to obtain the certificate
* the domain request is connected to the organization

The locality and organization fields should therefore use verified legal information, not assumed lab values.

---

## Step 5 — Certificate Issuance

After validation, the CA issues:

```text
Portal leaf certificate
Intermediate CA certificate or certificates
```

The CA does not return the private key because MedDefense generated and retained it.

Before deployment, verify the certificate:

```bash
openssl x509 \
  -in portal_certificate.pem \
  -noout \
  -subject \
  -issuer \
  -dates \
  -serial \
  -fingerprint \
  -sha256
```

Verify the SAN entries:

```bash
openssl x509 \
  -in portal_certificate.pem \
  -noout \
  -ext subjectAltName
```

Confirm that the certificate’s public key matches the private key:

```bash
openssl pkey \
  -in portal_key.pem \
  -pubout \
  -outform PEM \
  | sha256sum
```

```bash
openssl x509 \
  -in portal_certificate.pem \
  -pubkey \
  -noout \
  | sha256sum
```

The two SHA-256 results must match.

---

## Step 6 — Install the Certificate

Install the following on the portal server or load balancer:

```text
New leaf certificate
Required intermediate chain
New private key
```

The root certificate should normally not be sent by the server because clients already hold trusted roots in their trust stores.

Restrict private-key access:

```bash
chmod 600 portal_key.pem
```

Only the required service account and administrators should have access.

Configure the portal to support:

* TLS 1.2 and TLS 1.3
* ECDHE key exchange
* AES-GCM or another approved AEAD cipher
* the complete intermediate chain
* HSTS after HTTPS operation has been validated

---

## Step 7 — Test Before Production Cutover

Test the new certificate on a staging endpoint or secondary server.

Check the local certificate file:

```bash
openssl x509 \
  -in portal_certificate.pem \
  -noout \
  -checkend 2592000
```

`2592000` represents 30 days.

Test the live server:

```bash
openssl s_client \
  -connect portal.meddefense.com:443 \
  -servername portal.meddefense.com \
  -verify_return_error \
  -showcerts \
  </dev/null
```

Confirm:

```text
Verify return code: 0 (ok)
```

Also verify:

* correct Subject and SAN
* correct expiration date
* complete certificate chain
* trusted issuer
* new public-key fingerprint
* successful desktop browser access
* successful mobile access
* successful portal login
* successful API and application connections
* no certificate warning

---

## Step 8 — Deploy the New Certificate

Deploy the certificate during an approved change window.

The change record should document:

* affected systems
* implementation steps
* certificate serial number
* certificate fingerprint
* backup and rollback procedure
* validation tests
* responsible administrator
* deployment date
* expiration date

Reload or restart the web service only when required.

Example:

```bash
sudo systemctl reload apache2
```

or:

```bash
sudo systemctl reload nginx
```

The exact command depends on the MedDefense web server.

---

## Step 9 — Decommission the Old Certificate

After confirming successful deployment:

1. Remove the old certificate from active server configuration.
2. Remove it from secondary servers and load balancers.
3. Archive only the public certificate and relevant audit evidence.
4. Securely remove the old private key when retention is no longer required.
5. Confirm that no endpoint still presents the old certificate.
6. Revoke the old certificate if its private key was exposed or compromised.

Normal replacement due only to expiration does not always require revocation, but a compromised certificate must be revoked.

---

## Step 10 — Monitor the Next Renewal

As of July 2026, publicly trusted TLS certificates may have a maximum validity period of 200 days under the CA/B Forum Baseline Requirements. Let’s Encrypt currently issues its standard certificates for 90 days and expects automated renewal.

MedDefense should:

* maintain a central certificate inventory
* record the owner and deployment location
* enable automated renewal
* test renewal in staging
* monitor renewal failures
* alert before expiration
* confirm deployment after every renewal
* maintain an emergency revocation procedure

Suggested alerts:

```text
45 days remaining — warning
30 days remaining — renewal confirmation
14 days remaining — urgent escalation
7 days remaining — critical incident
```

Automated renewal should begin well before the certificate expires. Let’s Encrypt recommends using ACME Renewal Information where available and otherwise renewing with approximately one-third of the certificate lifetime remaining.

---

# Part 5 — Simple Automation Script

## `10-generate_csr.sh`

```bash
#!/bin/bash

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out portal_key.pem
chmod 600 portal_key.pem
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
openssl req -text -noout -verify -in portal.csr
```

The script performs:

1. P-256 key generation
2. Private-key permission protection
3. CSR generation
4. CSR inspection and signature verification

## Run It

Place these files in the same directory:

```text
10-generate_csr.sh
openssl.cnf
```

Make the script executable:

```bash
chmod +x 10-generate_csr.sh
```

Run it:

```bash
./10-generate_csr.sh
```

Generated files:

```text
portal_key.pem
portal.csr
```

The private key must be excluded from Git:

```gitignore
portal_key.pem
*.key
```

The CSR is not secret, but the private key is.

