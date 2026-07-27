# 4. The Key Exchange

## Part 1 — Diffie-Hellman Simulation

The commands below use finite-field Diffie-Hellman with 2048-bit parameters. OpenSSL’s `genpkey` command generates keys from the shared parameter file, while `pkeyutl -derive` performs the key-agreement operation.

### 1. Generate the shared DH parameters

```bash
openssl dhparam -out dhparams.pem 2048
```

Representative output:

```text
Generating DH parameters, 2048 bit long safe prime
.......................+.............................................+
....................................................................+
```

The dots and plus signs show progress. Their exact pattern will be different on every system, and generating a new 2048-bit safe prime may take significant processing time.

Verify the parameters:

```bash
openssl dhparam -in dhparams.pem -check -noout
```

Expected output:

```text
DH parameters appear to be ok
```

---

### 2. Generate Alice’s private key

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out alice_private.pem
```

Expected output:

```text
No output on success
```

Protect the private key:

```bash
chmod 600 alice_private.pem
```

---

### 3. Extract Alice’s public key

```bash
openssl pkey \
  -in alice_private.pem \
  -pubout \
  -out alice_public.pem
```

Expected output:

```text
No output on success
```

Inspect it:

```bash
openssl pkey \
  -pubin \
  -in alice_public.pem \
  -text \
  -noout
```

Representative output:

```text
DH Public-Key: (2048 bit)
public-key:
    00:9e:5d:ae:ad:be:cb:b8:74:7d:28:3a:23:97:af:
    ...
GROUP: ffdhe2048
```

The hexadecimal public-key value will be different in your run.

---

### 4. Generate Bob’s private key

```bash
openssl genpkey \
  -paramfile dhparams.pem \
  -out bob_private.pem
```

Expected output:

```text
No output on success
```

Protect the private key:

```bash
chmod 600 bob_private.pem
```

---

### 5. Extract Bob’s public key

```bash
openssl pkey \
  -in bob_private.pem \
  -pubout \
  -out bob_public.pem
```

Expected output:

```text
No output on success
```

Inspect it:

```bash
openssl pkey \
  -pubin \
  -in bob_public.pem \
  -text \
  -noout
```

Representative output:

```text
DH Public-Key: (2048 bit)
public-key:
    00:e3:b7:41:bc:d9:7f:2e:df:eb:da:e7:23:4e:d9:
    ...
GROUP: ffdhe2048
```

---

### 6. Derive the secret from Alice’s side

Alice combines her private key with Bob’s public key:

```bash
openssl pkeyutl \
  -derive \
  -inkey alice_private.pem \
  -peerkey bob_public.pem \
  -out alice_secret.bin
```

Expected output:

```text
No output on success
```

---

### 7. Derive the secret from Bob’s side

Bob combines his private key with Alice’s public key:

```bash
openssl pkeyutl \
  -derive \
  -inkey bob_private.pem \
  -peerkey alice_public.pem \
  -out bob_secret.bin
```

Expected output:

```text
No output on success
```

---

### 8. Compare the shared secrets

```bash
diff alice_secret.bin bob_secret.bin
```

Expected output:

```text
No output
```

No output means the files are identical.

Confirm the exit code:

```bash
echo $?
```

Expected result:

```text
0
```

An exit code of `0` confirms that Alice and Bob derived the same shared secret.

---

### 9. Confirm the secret sizes

```bash
wc -c alice_secret.bin bob_secret.bin
```

Example output:

```text
256 alice_secret.bin
256 bob_secret.bin
512 total
```

A 2048-bit DH result occupies 256 bytes.

---

### 10. Compare fingerprints

Because the shared secret is binary, calculate a SHA-256 fingerprint instead of displaying it directly:

```bash
sha256sum alice_secret.bin bob_secret.bin
```

Example from a test run:

```text
51be74bd41c153495da0d3d78e5b5fa92a578c4227baee1ff2602920522a07a2  alice_secret.bin
51be74bd41c153495da0d3d78e5b5fa92a578c4227baee1ff2602920522a07a2  bob_secret.bin
```

Your hash will be different because Alice and Bob generate new random private keys during every run. The two hashes within your run must be identical.

### Important security note

The raw output of Diffie-Hellman should normally be passed through a key-derivation function, such as HKDF, before it is used as an AES key. Real protocols derive multiple encryption, authentication and IV values from the shared secret rather than using the raw bytes directly.

---

## Optional Faster Parameter Method

Current OpenSSL documentation recommends using a named safe-prime group where possible instead of generating a completely new prime. This produces standard 2048-bit parameters immediately:

```bash
openssl genpkey \
  -genparam \
  -algorithm DH \
  -pkeyopt group:ffdhe2048 \
  -out dhparams.pem
```

The remaining Alice and Bob commands stay the same.

# Part 2 — Explanation for the CFO

Alice and Bob first agreed on public mathematical parameters that everyone, including Eve, was allowed to see. Alice then created a private number and produced a related public value, while Bob independently did the same. They exchanged only their public values and combined the received value with their own private number. Because of the mathematical structure of Diffie-Hellman, both calculations produced the same shared secret even though neither side transmitted that secret. Eve could see the parameters and both public values, but she would need to solve the computationally infeasible discrete-logarithm problem to recover either private value. Alice and Bob can therefore establish secret keying material across an insecure network without previously sharing an encryption key.

A simplified mathematical representation is:

```text
Public parameters: p and g

Alice:
Private value = a
Public value  = A = gᵃ mod p

Bob:
Private value = b
Public value  = B = gᵇ mod p

Alice calculates:
Bᵃ mod p = gᵃᵇ mod p

Bob calculates:
Aᵇ mod p = gᵃᵇ mod p
```

Both sides reach the same result:

```text
gᵃᵇ mod p
```

# Part 3 — Man-in-the-Middle Attack

Plain Diffie-Hellman protects against passive listening but does not prove who supplied each public key. Eve can replace Alice’s public key with Eve’s key and replace Bob’s public key with another Eve-controlled key, creating one shared secret with Alice and a different shared secret with Bob. Eve can then decrypt, inspect, alter and re-encrypt every message while Alice and Bob incorrectly believe they are communicating directly. If MedDefense’s Central-to-Westside VPN used unauthenticated DH, an attacker controlling the network path could establish separate tunnels with both locations and relay protected traffic between them. Certificates prevent this by binding a verified organizational identity to a public key and allowing the DH exchange to be authenticated with a digital signature; a correctly managed pre-shared key can also authenticate IKE, but DH by itself cannot.

## How Certificate Authentication Changes the Exchange

```text
Unauthenticated DH:

Central  ←──── Eve ────→  Westside
           Secret 1
           Secret 2
```

Central and Westside have no reliable proof that the received DH public values belong to each other.

```text
Authenticated DH:

Central ─── signed DH exchange ───→ Westside
        ←── verified certificate ──
```

The certificate chain identifies the peer, while its private key signs the relevant handshake or key-exchange data. An attacker cannot replace the DH public value with their own without producing a valid signature from the certificate holder’s private key.

## MedDefense Conclusion

The current audit states that the Central-to-Westside tunnel uses:

```text
IPSec
AES-256
SHA-256
IKEv2
DH Group 14
```

These algorithms protect the confidentiality and integrity of VPN traffic, but **DH Group 14 alone does not authenticate the remote site**. MedDefense must verify whether IKEv2 uses properly managed certificate authentication or a strong pre-shared key, confirm peer identities, protect the private keys and validate certificate expiration and revocation. Authenticated Diffie-Hellman provides both secure key agreement and protection against active man-in-the-middle attacks.


