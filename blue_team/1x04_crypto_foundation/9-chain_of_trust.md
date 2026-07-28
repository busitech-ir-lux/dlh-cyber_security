# 9. The Chain of Trust

## Part 1 — Capture the Full Certificate Chain

This lab uses `github.com`. The exact certificate chain can change when GitHub renews its certificates or selects a different TLS endpoint.

## 1. Capture the certificates

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts \
  </dev/null \
  > github-chain.txt 2>&1
```

The `-servername` option sends SNI for `github.com`. The `-showcerts` option displays every certificate sent by the server. OpenSSL notes that `s_client` is a diagnostic tool and normally continues after verification errors unless `-verify_return_error` is used.

## 2. Extract each certificate into a separate file

```bash
awk '
/-----BEGIN CERTIFICATE-----/ {
    number++
    file = "cert" number ".pem"
    inside = 1
}
inside {
    print > file
}
/-----END CERTIFICATE-----/ {
    inside = 0
    close(file)
}
' github-chain.txt
```

List the extracted certificates:

```bash
ls -l cert*.pem
```

Count them:

```bash
grep -c "BEGIN CERTIFICATE" github-chain.txt
```

In the July 2026 GitHub chain used for this exercise, the server path contained three certificates:

```text
3
```

GitHub may provide different RSA or ECDSA chains depending on the endpoint and client capabilities. A July 2026 scan showed the ECDSA path through Sectigo’s DV E36 intermediate and Sectigo Public Server Authentication Root E46.

---

## 3. Inspect the Subject and Issuer

```bash
for certificate in cert1.pem cert2.pem cert3.pem
do
    echo "===== $certificate ====="
    openssl x509 \
      -in "$certificate" \
      -noout \
      -subject \
      -issuer
done
```

### Certificate 1 — Leaf certificate

```text
Role: Leaf/server certificate

Subject:
CN=github.com

Issuer:
C=GB, O=Sectigo Limited,
CN=Sectigo Public Server Authentication CA DV E36
```

This certificate identifies the website. It is the certificate presented specifically for `github.com`.

### Certificate 2 — Issuing intermediate CA

```text
Role: Intermediate CA

Subject:
C=GB, O=Sectigo Limited,
CN=Sectigo Public Server Authentication CA DV E36

Issuer:
C=GB, O=Sectigo Limited,
CN=Sectigo Public Server Authentication Root E46
```

Notice that the **issuer of Certificate 1 matches the subject of Certificate 2**.

Sectigo identifies DV E36 as its ECC Domain Validation intermediate and Root E46 as its corresponding ECC public-server root.

### Certificate 3 — Cross-signed Root E46 certificate

```text
Role: Cross-signed CA certificate

Subject:
C=GB, O=Sectigo Limited,
CN=Sectigo Public Server Authentication Root E46

Issuer:
C=GB, ST=Greater Manchester, L=Salford,
O=Comodo CA Limited,
CN=AAA Certificate Services
```

The **issuer of Certificate 2 matches the subject of Certificate 3**.

Although its name contains “Root,” this particular certificate is cross-signed by another CA. In this validation path, it behaves as an intermediate certificate rather than the final trust anchor.

### Final trust anchor — AAA Certificate Services

The final root normally comes from the client’s local trust store rather than from the web server:

```text
Role: Trusted root CA

Subject:
C=GB, ST=Greater Manchester, L=Salford,
O=Comodo CA Limited,
CN=AAA Certificate Services

Issuer:
C=GB, ST=Greater Manchester, L=Salford,
O=Comodo CA Limited,
CN=AAA Certificate Services
```

The matching subject and issuer show that it is self-signed.

## Complete trust path

```text
github.com
    │ signed by
    ▼
Sectigo Public Server Authentication CA DV E36
    │ signed by
    ▼
Sectigo Public Server Authentication Root E46
    │ cross-signed by
    ▼
AAA Certificate Services
    │
    └── Trusted in the local root store
```

Sectigo uses cross-signing so newer Sectigo roots can also chain to older, widely distributed trust anchors.

---

# Part 2 — Manual Chain Verification

## 1. Find the trusted root

On Debian or Ubuntu, the AAA root may be available as:

```bash
ls /etc/ssl/certs/Comodo_AAA_Services_root.pem
```

Create one file containing the untrusted certificates between the leaf and root:

```bash
cat cert2.pem cert3.pem > intermediates.pem
```

## 2. Verify the complete chain

```bash
openssl verify \
  -CAfile /etc/ssl/certs/Comodo_AAA_Services_root.pem \
  -untrusted intermediates.pem \
  cert1.pem
```

Expected output:

```text
cert1.pem: OK
```

This means OpenSSL successfully built the following path:

```text
cert1.pem
→ cert2.pem
→ cert3.pem
→ trusted AAA root
```

The certificates passed signature, issuer, validity and path-validation checks.

---

## 3. Remove the issuing intermediate

Try verification using only Certificate 3:

```bash
openssl verify \
  -CAfile /etc/ssl/certs/Comodo_AAA_Services_root.pem \
  -untrusted cert3.pem \
  cert1.pem
```

Expected failure:

```text
CN = github.com
error 20 at 0 depth lookup: unable to get local issuer certificate
error cert1.pem: verification failed
```

The leaf says it was issued by DV E36, but DV E36 is no longer available. OpenSSL therefore cannot connect the leaf certificate to the trusted root.

## What this demonstrates

A server must send the leaf certificate and all necessary intermediate certificates so the client can construct a path to a trusted root. The root itself normally does not need to be transmitted because it is already installed in the client’s trust store. Missing an intermediate causes verification to fail even when both the leaf and root certificates are otherwise valid.

---

## Simpler verification path

Some systems may trust Sectigo Root E46 directly or receive a shorter chain. In that case, verification may use:

```bash
openssl verify \
  -CAfile /etc/ssl/certs/Sectigo_Public_Server_Authentication_Root_E46.pem \
  -untrusted cert2.pem \
  cert1.pem
```

Expected output:

```text
cert1.pem: OK
```

Different valid paths can exist because of cross-signing.

---

# Part 3 — Revocation Mechanisms

## Certificate Revocation List

A **Certificate Revocation List**, or CRL, is a CA-signed list containing the serial numbers of certificates that have been revoked before their normal expiration dates.

A client uses it as follows:

1. Read the certificate’s CRL Distribution Points extension.
2. Download the CRL from the CA.
3. Verify the CA’s signature on the CRL.
4. Search for the certificate’s serial number.
5. Reject the certificate if its serial number appears in the list.

RFC 5280 defines the Internet X.509 certificate and CRL profile and includes certification-path validation rules.

### Main CRL limitation

CRLs can become large because they may contain many revoked certificate serial numbers. They are also updated periodically rather than continuously, so a newly revoked certificate may not appear until the next CRL is published and downloaded.

```text
CA publishes CRL
        ↓
Client downloads entire list
        ↓
Client searches for certificate serial number
```

---

## Online Certificate Status Protocol

**OCSP** allows a client to ask an OCSP responder about one specific certificate rather than downloading a complete revocation list.

The response is normally one of:

```text
good
revoked
unknown
```

OCSP reduces the amount of data transferred and can provide more current status information than a periodically downloaded CRL. RFC 6960 defines OCSP as a method for determining a certificate’s current status without requiring the client to obtain a complete CRL.

### Basic OCSP process

```text
Browser → CA OCSP responder:
“What is the status of certificate serial 12345?”

CA responder → Browser:
“Good,” “Revoked” or “Unknown”
```

### OCSP limitations

Normal OCSP creates several problems:

* an extra network request may slow the TLS connection
* the CA can learn which websites the user visits
* the responder may be unavailable
* some clients use soft-fail behaviour when the responder cannot be reached

---

## OCSP Stapling

With OCSP stapling, the web server obtains a signed OCSP response from the CA and temporarily caches it. The server then sends, or **staples**, that response to the certificate during the TLS handshake.

```text
Server → CA:
Request OCSP response

CA → Server:
Signed certificate status

Server → Browser:
Certificate + signed OCSP response
```

This provides three main advantages:

* fewer client-to-CA network requests
* faster certificate-status checking
* improved privacy because the browser does not directly tell the CA which site it is visiting

The TLS certificate-status extension permits servers to provide cached certificate-status information during the handshake.

---

# MedDefense Private-Key Compromise Response

Scenario: the patient portal’s private key is accidentally committed to a Git repository.

## Immediate response sequence

### 1. Declare a security incident

MedDefense should activate its incident-response procedure and record:

* when the key was exposed
* which repository contained it
* whether the repository was public or private
* who accessed or cloned it
* which systems use the key
* whether the key appears in commit history, forks, logs or build artifacts

Deleting only the current repository file is insufficient because the key may remain in previous commits and existing clones.

### 2. Isolate the compromised key

Immediately stop using the exposed private key.

Actions include:

```text
Remove it from the portal
Remove it from load balancers
Remove it from reverse proxies
Remove it from deployment pipelines
Remove it from backups and configuration repositories where possible
```

The exposed key must never be reused.

### 3. Generate a new key pair

Generate the replacement private key on a trusted system, preferably inside an HSM, key vault or protected certificate-management platform:

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out portal-new-private.pem
```

Protect it:

```bash
chmod 600 portal-new-private.pem
```

### 4. Generate a new CSR

```bash
openssl req \
  -new \
  -key portal-new-private.pem \
  -out portal-new.csr
```

The CSR should contain the correct patient-portal hostname and authorised SAN entries.

### 5. Request a replacement certificate

Submit the CSR to the approved CA through its portal, API or ACME process. The new certificate must use the new public key; merely reissuing the old certificate with the compromised key does not solve the problem.

### 6. Deploy and test the replacement

Install:

* the new leaf certificate
* the correct intermediate chain
* the new private key

Deploy it to every portal endpoint:

* web servers
* load balancers
* reverse proxies
* disaster-recovery systems
* CDN or web-application firewall services

Verify it:

```bash
openssl s_client \
  -connect portal.meddefense.example:443 \
  -servername portal.meddefense.example \
  -verify_return_error \
  </dev/null
```

Confirm:

```text
Correct hostname
Correct certificate chain
New public-key fingerprint
Valid expiration date
TLS 1.2 or TLS 1.3
No old certificate on another endpoint
```

### 7. Revoke the compromised certificate

Submit a revocation request to the CA and select the reason:

```text
keyCompromise
```

The revocation request should identify the old certificate by serial number or fingerprint. If active exploitation is suspected, revoke it immediately, even if this temporarily interrupts the portal.

### 8. Confirm revocation

Check the CA’s OCSP responder or CRL:

```bash
openssl x509 \
  -in old-portal-cert.pem \
  -noout \
  -serial \
  -ocsp_uri
```

The old certificate should eventually return:

```text
revoked
```

### 9. Remove the key from source control

MedDefense must:

* remove the key from the current repository
* rewrite repository history
* remove exposed CI/CD variables and artifacts
* check forks and mirrors
* rotate repository credentials if necessary
* add private-key patterns to secret scanning
* prevent `.pem`, `.key` and similar sensitive files from being committed

Repository rewriting does not make the leaked key trustworthy again. Revocation and replacement remain mandatory.

### 10. Investigate possible misuse

Review:

* TLS and web-server logs
* Certificate Transparency records
* authentication logs
* DNS changes
* portal traffic anomalies
* source-control access records
* alerts for attempted impersonation

### 11. Document and improve controls

Update:

* certificate inventory
* certificate serial number
* key fingerprint
* issue and expiration dates
* CA details
* deployment locations
* renewal schedule
* incident report

Introduce automated certificate lifecycle management, secret scanning and certificate-expiration monitoring.

---

# Part 4 — Trust Store Exploration

## 1. Common Linux trust-store locations

On Debian and Ubuntu, trusted certificates are normally stored under:

```text
/etc/ssl/certs/
```

The combined CA bundle is:

```text
/etc/ssl/certs/ca-certificates.crt
```

Distribution-provided CA files are usually stored under:

```text
/usr/share/ca-certificates/
```

Locally installed CA certificates are normally placed under:

```text
/usr/local/share/ca-certificates/
```

The `update-ca-certificates` utility populates `/etc/ssl/certs` and generates the combined `ca-certificates.crt` bundle.

---

## 2. Count the trusted CA certificates

```bash
grep -c \
  "BEGIN CERTIFICATE" \
  /etc/ssl/certs/ca-certificates.crt
```

On the Linux environment inspected for this exercise, the result was:

```text
152
```

The number will differ by distribution, package version, administrator configuration and locally installed enterprise CAs.

---

## 3. List trusted certificates

```bash
ls -l /etc/ssl/certs/
```

To inspect the configured CA bundle:

```bash
openssl storeutl \
  -noout \
  -text \
  -certs \
  /etc/ssl/certs/ca-certificates.crt
```

---

## 4. Inspect one trusted root

Selected certificate:

```text
ISRG Root X1
```

File:

```bash
openssl x509 \
  -in /etc/ssl/certs/ISRG_Root_X1.pem \
  -noout \
  -subject \
  -issuer \
  -dates \
  -serial \
  -fingerprint \
  -sha256
```

Observed output:

```text
subject=C=US,
O=Internet Security Research Group,
CN=ISRG Root X1

issuer=C=US,
O=Internet Security Research Group,
CN=ISRG Root X1

notBefore=Jun 4 11:04:38 2015 GMT
notAfter=Jun 4 11:04:38 2035 GMT

serial=8210CFB0D240E3594463E0BB63828B00
```

The matching subject and issuer identify it as a self-signed root.

## Validity period

```text
4 June 2015 to 4 June 2035
```

That is approximately **20 years**.

## Is this surprising?

It may initially appear surprising because public website certificates now have short validity periods. Root certificates, however, are designed to remain stable trust anchors for many years and are distributed through operating systems and browsers, where replacing them is a slow process.

Long validity does not mean a root remains trusted automatically until its certificate expires. Browser and operating-system root programs can remove or distrust a root earlier if the CA fails security, audit or policy requirements.

---

# Final Findings

1. The GitHub leaf certificate was signed by Sectigo DV E36.
2. DV E36 was signed by Sectigo Root E46.
3. A cross-signed Root E46 certificate allowed the path to terminate at the older AAA Certificate Services trust anchor.
4. Removing the issuing intermediate caused OpenSSL verification to fail.
5. CRLs distribute lists of revoked certificate serial numbers but may be large and delayed.
6. OCSP provides status for individual certificates.
7. OCSP stapling allows the server to provide a signed status response during the TLS handshake.
8. A compromised private key must be replaced with a new key pair, and the old certificate must be revoked.
9. The inspected Linux system contained 152 certificates in its CA bundle.
10. Trusted root certificates may have validity periods of 20 years or longer because they are long-lived trust anchors.

