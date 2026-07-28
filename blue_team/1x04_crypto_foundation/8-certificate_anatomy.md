# 8. The Certificate Anatomy

## Part 1 — Inspect Three Real Certificates

### Websites Selected

1. **Let’s Encrypt certificate:** `letsencrypt.org`
2. **Commercial CA certificate:** `github.com`
3. **Broken certificate:** `expired.badssl.com`

---

# OpenSSL Inspection Commands

## 1. Download the leaf certificate

### Let’s Encrypt

```bash
openssl s_client \
  -connect letsencrypt.org:443 \
  -servername letsencrypt.org \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > letsencrypt.pem
```

### GitHub

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > github.pem
```

### Expired BadSSL

```bash
openssl s_client \
  -connect expired.badssl.com:443 \
  -servername expired.badssl.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > expired-badssl.pem
```

The `-servername` option sends the Server Name Indication, or SNI, so the server returns the certificate for the requested website rather than a default certificate.

---

## 2. Display the complete certificate

```bash
openssl x509 -in letsencrypt.pem -noout -text
```

```bash
openssl x509 -in github.pem -noout -text
```

```bash
openssl x509 -in expired-badssl.pem -noout -text
```

A shorter command for the main fields is:

```bash
openssl x509 \
  -in letsencrypt.pem \
  -noout \
  -subject \
  -issuer \
  -dates \
  -serial
```

---

# Certificate 1 — letsencrypt.org

## Basic Fields

| Field                    | Observed value                         |
| ------------------------ | -------------------------------------- |
| **Subject CN**           | `letsencrypt.org`                      |
| **Subject O**            | Not present                            |
| **Subject L**            | Not present                            |
| **Subject ST**           | Not present                            |
| **Subject C**            | Not present                            |
| **Issuer**               | `C=US, O=Let's Encrypt, CN=E7`         |
| **Not Before**           | 7 May 2026, approximately 16:14 UTC    |
| **Not After**            | 5 August 2026, approximately 16:14 UTC |
| **Serial Number**        | `0518AB24C48CAC79C3807E8B312BF4E19C10` |
| **Signature Algorithm**  | `ecdsa-with-SHA384`                    |
| **Public Key Algorithm** | `id-ecPublicKey`                       |
| **Public Key Size**      | 256-bit ECDSA, curve P-256             |

The certificate is a Domain Validation certificate. Its subject does not contain organisation, locality, state or country information because the CA validated control of the domain rather than the legal identity of the organisation.

## Subject Alternative Names

```text
DNS:cp.letsencrypt.org
DNS:cp.root-x1.letsencrypt.org
DNS:cps.letsencrypt.org
DNS:cps.root-x1.letsencrypt.org
DNS:lencr.org
DNS:letsencrypt.com
DNS:letsencrypt.org
DNS:www.lencr.org
DNS:www.letsencrypt.com
DNS:www.letsencrypt.org
```

Modern clients use the SAN extension, rather than relying only on the Common Name, to decide which hostnames the certificate protects.

## Key Usage

```text
Digital Signature
```

Because this is an ECDSA certificate, its public key is used to verify signatures during authentication. It is not used for RSA-style key encipherment.

## Extended Key Usage

```text
TLS Web Server Authentication
```

Let’s Encrypt removed the TLS Client Authentication EKU from its default profile in February 2026 and completed the phase-out in July 2026.

## Authority Information Access

```text
OCSP URL: Not present
CA Issuers URL: http://e7.i.lencr.org/
```

The CA Issuers URI allows a client to download the E7 intermediate certificate. Let’s Encrypt has removed OCSP responder URLs from newly issued certificates and relies on short certificate lifetimes and CRL-based infrastructure.

---

# Certificate 2 — github.com

GitHub’s certificate was issued by **Sectigo**, a commercial certificate authority. It is still a DV certificate; using a commercial CA does not automatically make a certificate OV or EV.

## Basic Fields

| Field                    | Observed value                                                               |
| ------------------------ | ---------------------------------------------------------------------------- |
| **Subject CN**           | `github.com`                                                                 |
| **Subject O**            | Not present                                                                  |
| **Subject L**            | Not present                                                                  |
| **Subject ST**           | Not present                                                                  |
| **Subject C**            | Not present                                                                  |
| **Issuer**               | `C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36` |
| **Not Before**           | 3 July 2026, 00:00 UTC                                                       |
| **Not After**            | 30 September 2026, 23:59:59 UTC                                              |
| **Serial Number**        | `72010E03F4A067FE4E796266430718F6`                                           |
| **Signature Algorithm**  | `ecdsa-with-SHA256`                                                          |
| **Public Key Algorithm** | `id-ecPublicKey`                                                             |
| **Public Key Size**      | 256-bit ECDSA, curve `prime256v1` or P-256                                   |

These values were observed in GitHub’s July 2026 certificate deployment.

## Subject Alternative Names

```text
DNS:github.com
DNS:www.github.com
```

## Key Usage

```text
Digital Signature
```

## Extended Key Usage

```text
TLS Web Server Authentication
```

The certificate is intended to authenticate GitHub’s TLS servers, not to act as a CA or general-purpose client certificate.

## Authority Information Access

```text
OCSP URL:
http://ocsp.sectigo.com

CA Issuers URL:
http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt
```

The OCSP endpoint provides certificate-revocation status. The CA Issuers endpoint provides the Sectigo intermediate certificate needed to build the certificate chain.

---

# Certificate 3 — expired.badssl.com

## Basic Fields

| Field                         | Observed value                                                                                                  |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Subject CN**                | `*.badssl.com`                                                                                                  |
| **Subject O**                 | Not present                                                                                                     |
| **Subject L**                 | Not present                                                                                                     |
| **Subject ST**                | Not present                                                                                                     |
| **Subject C**                 | Not present                                                                                                     |
| **Additional Subject Fields** | `OU=PositiveSSL Wildcard`, `OU=Domain Control Validated`                                                        |
| **Issuer**                    | `C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA` |
| **Not Before**                | 9 April 2015, 00:00 UTC                                                                                         |
| **Not After**                 | 12 April 2015, 23:59:59 UTC                                                                                     |
| **Serial Number**             | `4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09`                                                               |
| **Signature Algorithm**       | `sha256WithRSAEncryption`                                                                                       |
| **Public Key Algorithm**      | `rsaEncryption`                                                                                                 |
| **Public Key Size**           | RSA 2048 bits                                                                                                   |

The certificate has deliberately remained expired so that browsers and TLS clients can test expiration handling.

## Subject Alternative Names

```text
DNS:*.badssl.com
DNS:badssl.com
```

The wildcard matches `expired.badssl.com` because it replaces one hostname label immediately before `badssl.com`.

## Key Usage

```text
Digital Signature
Key Encipherment
```

## Extended Key Usage

```text
TLS Web Server Authentication
TLS Web Client Authentication
```

## Authority Information Access

```text
OCSP URL:
http://ocsp.comodoca.com

CA Issuers URL:
http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt
```

---

# Summary Comparison

| Field                   | letsencrypt.org                | github.com                     | expired.badssl.com            |
| ----------------------- | ------------------------------ | ------------------------------ | ----------------------------- |
| **Certificate type**    | DV                             | DV                             | DV                            |
| **CA**                  | Let’s Encrypt                  | Sectigo                        | COMODO                        |
| **Public key**          | ECDSA P-256                    | ECDSA P-256                    | RSA-2048                      |
| **Signature**           | ECDSA with SHA-384             | ECDSA with SHA-256             | RSA with SHA-256              |
| **Status**              | Valid                          | Valid                          | Expired                       |
| **Server EKU**          | Yes                            | Yes                            | Yes                           |
| **OCSP URL**            | None                           | Sectigo OCSP                   | COMODO OCSP                   |
| **Main security issue** | None identified in certificate | None identified in certificate | Validity period ended in 2015 |

---

# Part 2 — The Broken Certificate

## Verify the BadSSL Certificate

Run:

```bash
openssl s_client \
  -connect expired.badssl.com:443 \
  -servername expired.badssl.com \
  -verify_return_error \
  </dev/null
```

The relevant output is similar to:

```text
verify error:num=10:certificate has expired
Verification error: certificate has expired
Verify return code: 10 (certificate has expired)
```

## What Is Wrong?

The certificate’s `Not After` date was **12 April 2015**, so it is no longer within its permitted validity period. Its hostname is correct, its RSA key is of an acceptable size and its issuer chain was originally publicly trusted, but the certificate is now invalid because the current date is outside the validity window.

## Browser Error

A browser would normally display a full-page warning such as:

```text
Your connection is not private
The certificate has expired
```

Chrome commonly reports:

```text
NET::ERR_CERT_DATE_INVALID
```

Firefox commonly reports:

```text
SEC_ERROR_EXPIRED_CERTIFICATE
```

The browser normally blocks access or requires the user to pass through an advanced warning screen.

## Security Risk

An expired certificate does not automatically reveal the server’s private key or break the encryption algorithm. However, the browser can no longer accept the certificate as current proof of the server’s identity.

Allowing users to bypass certificate warnings creates several risks:

* patients may submit passwords or medical information to an impersonated portal
* users may become trained to ignore genuine man-in-the-middle warnings
* applications and APIs may reject the connection completely
* the expired certificate may indicate failed certificate management
* service availability and patient trust may be affected

Browsers reject expired certificates because a trusted TLS connection cannot be established using an out-of-date identity credential.

## Recommendation to the Patient

A patient should **not proceed** to a healthcare portal displaying this warning.

The patient should:

1. Close the page.
2. Confirm that the URL is correct.
3. Contact MedDefense through a known telephone number or trusted channel.
4. Wait until MedDefense replaces the certificate.

A patient should never enter login credentials, medical information or payment details after bypassing a certificate warning.

---

# Part 3 — Ideal MedDefense Certificate Profile

## Recommended Profile

| Field                             | Recommendation                                                            |
| --------------------------------- | ------------------------------------------------------------------------- |
| **Certificate type**              | Organisation Validation, OV                                               |
| **Issuer**                        | Widely trusted public commercial CA                                       |
| **Primary SAN**                   | `portal.meddefense.com`                                                   |
| **Additional SANs**               | Only genuine production aliases that patients use                         |
| **Public-key algorithm**          | ECDSA using P-256                                                         |
| **Alternative compatibility key** | RSA-2048 or stronger only when legacy compatibility is genuinely required |
| **Signature algorithm**           | ECDSA with SHA-256 or stronger                                            |
| **Extended Key Usage**            | TLS Web Server Authentication                                             |
| **Validity**                      | Approximately 90 days with automated renewal                              |
| **Certificate scope**             | Single-domain or narrowly scoped SAN certificate                          |
| **Wildcard**                      | Not recommended                                                           |
| **Private-key storage**           | HSM, cloud key vault or tightly protected server key store                |

---

## Certificate Type — OV

An **OV certificate** is appropriate because the CA validates both domain control and MedDefense’s legal organisational identity. This gives MedDefense stronger identity governance and places the verified organisation name in the certificate details.

A DV certificate would provide the same TLS encryption strength but would only prove control of the domain. An EV certificate requires more extensive identity validation, but it does not provide stronger encryption than DV or OV and is not necessary for the normal patient-portal use case. The CA/B Forum distinguishes DV, where no entity identity is asserted, from OV, where organisation identity is asserted.

## Certificate Authority

MedDefense should use a public CA that:

* is trusted by major browsers and operating systems
* supports automated issuance and renewal
* offers OV validation
* supports Certificate Transparency
* provides reliable revocation services
* provides technical and incident-response support
* supports API or ACME-based lifecycle management

Examples include Sectigo, DigiCert, GlobalSign or another CA meeting the same requirements. Let’s Encrypt is suitable when DV is sufficient, but it does not issue OV or EV certificates.

## Subject Alternative Names

The certificate should contain:

```text
DNS:portal.meddefense.com
```

Additional entries should be added only when they are genuine patient-facing aliases, for example:

```text
DNS:patient.meddefense.com
```

The certificate should not contain:

* internal server names such as `web-srv-01`
* private IP addresses
* development environments
* unrelated MedDefense services
* unused historical aliases

Every additional SAN increases the certificate’s scope and can expose internal naming information through Certificate Transparency logs.

## Key Algorithm and Size

The preferred key is:

```text
ECDSA P-256
```

P-256 provides approximately 128 bits of security with smaller certificates and faster operations than RSA. It is appropriate for modern browsers using TLS 1.2 and TLS 1.3.

Where older client compatibility is unavoidable, MedDefense may provide a parallel RSA certificate using:

```text
RSA 2048 bits or stronger
```

MedDefense should not weaken the public portal to support obsolete clients such as Windows XP.

## Validity Period

A practical validity period is:

```text
90 days
```

The certificate should renew automatically well before expiration. As of 2026, CA/B Forum requirements limit newly issued publicly trusted TLS certificates to no more than 200 days, with further reductions scheduled in later years.

Recommended renewal process:

```text
Issue certificate: Day 0
First automatic renewal attempt: Day 60
Escalation alert: 21 days remaining
Critical alert: 7 days remaining
```

The current MedDefense certificate expires in 18 days and does not have automatic renewal. This should be treated as an urgent operational risk.

## Wildcard or Single-Domain

MedDefense should use a **single-domain or narrowly scoped SAN certificate**, not a wildcard certificate.

Recommended:

```text
portal.meddefense.com
```

Not recommended:

```text
*.meddefense.com
```

A wildcard private-key compromise could affect many MedDefense services. A dedicated certificate limits the compromise scope, makes ownership clearer and allows the portal certificate to be revoked or replaced without affecting email, VPN, APIs or other web systems.

---

# Required Operational Controls

The certificate alone is not enough. MedDefense should also implement:

* automated renewal and deployment
* certificate-expiration monitoring
* alerts at 45, 30, 14 and 7 days
* TLS 1.2 and TLS 1.3 only
* ECDHE key exchange
* AES-GCM or ChaCha20-Poly1305
* complete intermediate certificate chain
* protected private-key storage
* regular private-key rotation
* Certificate Transparency monitoring
* DNS CAA records limiting authorised CAs
* HSTS after confirming all portal traffic uses HTTPS
* tested certificate revocation and emergency replacement procedures

# Final Assessment

The browser validates more than whether encryption is present. It verifies that the certificate matches the requested hostname, falls within its validity period, chains to a trusted CA, permits server authentication and contains an acceptable public key and signature.

For MedDefense, the recommended solution is an automatically renewed **OV certificate for the exact patient-portal hostname**, using **ECDSA P-256**, a short validity period and a widely trusted public CA. A certificate-expiration warning on a healthcare portal must be treated as a security incident and service-availability failure, not as a warning that patients should bypass.

