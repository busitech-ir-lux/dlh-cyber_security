## 1. Key generation decision

MedDefense will use **ECC P-256** for the patient portal private key. P-256 provides approximately 128-bit security with a smaller key and lower handshake overhead than RSA-2048 or RSA-4096. The portal handles about 800 patient connections per day, so any of the allowed algorithms could handle the workload, but P-256 is efficient and broadly supported by current browsers and devices. RSA-2048 should be used only as a compatibility alternative if MedDefense identifies a real legacy-client requirement.

Key-generation command:

```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out portal_key.pem
chmod 600 portal_key.pem
```

## 2. Required patient portal certificate identity

The CSR requests these subject fields:

- Country: `US`
    
- State: `Massachusetts`
    
- Locality: `Boston`
    
- Organization: `MedDefense Health Systems`
    
- Organizational Unit: `Information Technology`
    
- Common Name: `portal.meddefense.local`
    
- Subject Alternative Name 1: `portal.meddefense.local`
    
- Subject Alternative Name 2: `patient.meddefense.local`
    
- Key Usage: `Digital Signature`
    
- Extended Key Usage: `TLS Web Server Authentication`
    

The country, state, and locality are lab assumptions and must be replaced with MedDefense's verified legal location before a real OV request. The `.local` names are also internal names; a public CA will not issue a publicly trusted certificate for them. This lab CSR should therefore be issued by MedDefense's internal CA. A public patient portal must instead use registered DNS names such as `portal.meddefense.com` and submit the CSR to a trusted public CA.

CSR-generation command used by `10-generate_csr.sh`:

```
openssl req -new -key portal_key.pem -out portal.csr \
  -subj "/C=US/ST=Massachusetts/L=Boston/O=MedDefense Health Systems/OU=Information Technology/CN=portal.meddefense.local" \
  -addext "subjectAltName=DNS:portal.meddefense.local,DNS:patient.meddefense.local" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```

Inspect and verify the CSR:

```
openssl req -text -noout -verify -in portal.csr
```

The inspection must confirm the full subject, both SAN entries, an EC P-256 public key, Digital Signature key usage, and TLS Web Server Authentication extended key usage.

## 3. Complete certificate lifecycle

**CSR generated (done).** The remaining lifecycle stages are:

1. **Generate and protect the CSR materials:** Create the P-256 private key and CSR on a trusted administrative system. Restrict the private key to authorised administrators and never send it to the CA or commit it to Git.
    
2. **Submission to CA:** Submit this `.local` lab CSR to the MedDefense internal CA. For the real public patient portal, generate a new CSR using registered public DNS names and submit it to an approved commercial CA that supports OV certificates and automated renewal.
    
3. **Validation process:** The internal CA verifies the requester, system ownership, and approved internal hostnames. For a public OV certificate, the commercial CA verifies control of every SAN domain, MedDefense's legal identity, registered address, and the requester's authority.
    
4. **Certificate issuance:** The CA signs the CSR and provides the leaf certificate plus the required intermediate CA certificates. MedDefense verifies the subject, SAN entries, validity dates, issuer, key usage, and public-key fingerprint before installation.
    
5. **Installation on the web server:** Install the new leaf certificate, intermediate chain, and matching private key on every portal web server, reverse proxy, load balancer, and disaster-recovery endpoint. Limit private-key permissions and configure TLS 1.2 or TLS 1.3 with approved cipher suites.
    
6. **Verification that the new certificate is serving correctly:** Test the portal with `openssl s_client`, current desktop browsers, mobile devices, and portal applications. Confirm the correct hostname, complete chain, new serial number and fingerprint, valid dates, and `Verify return code: 0 (ok)`.
    
7. **Decommission of the old certificate:** Remove the old certificate and private key from all active endpoints after the new deployment is confirmed. Revoke the old certificate immediately if its private key was compromised; otherwise archive only the public certificate and required audit evidence.
    
8. **Monitoring for the next renewal:** Record the certificate owner, CA, serial number, deployment locations, issue date, and expiry date in the certificate inventory. Enable automated renewal where possible and alert at 45, 30, 14, and 7 days before expiry. Test the renewal process and confirm that the renewed certificate is actually deployed on every endpoint.
