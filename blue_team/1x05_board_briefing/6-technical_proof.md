### The Technical Proof

**Goal:** _Demonstrate hands-on technical mastery by executing a rapid security check using tools from the entire module._

---

**Context:** James Chen needs to know that you can DO what you recommend, not just write about it. Before the Board meeting, he asks you to run a quick technical validation on your own machine to prove proficiency. "Show me you can inspect a cert, verify a hash, check for an exploit and audit a system. Five minutes each."

---

**Instructions:**

Execute the following 4 rapid technical checks and document the commands and output for each:

**Check 1 - Certificate Inspection**

Use OpenSSL to inspect the certificate of any live website. Produce a 5-line summary: Subject, Issuer, Validity, Key Algorithm, SAN entries.

**Check 2 - Hash Verification**

Create a file, hash it with SHA-256, modify the file, hash again. Document both hashes and confirm they differ. In one sentence: why does this matter for verifying the integrity of the FortiGate firmware before installing it ?

**Check 3 - Exploit Research**

Run `searchsploit fortigate` or `searchsploit fortios`. Document the output. Is there a public exploit for CVE-2023-27997 ? What does this tell you about the urgency of patching ?

**Check 4 - System Audit**

Run `sudo lynis audit system --quick` on your machine. Report: the Hardening Index, the top 3 warnings and one suggestion you would apply to MedDefense's billing-srv-01.


---
# Answer

# 6. The Technical Proof

## Check 1 — Certificate Inspection

### Public-site command attempted

```bash
echo | openssl s_client \
  -connect www.google.com:443 \
  -servername www.google.com 2>/dev/null |
openssl x509 -noout -subject -issuer -dates -text
```

### Actual output in this environment

```text
Temporary failure in name resolution
```

The execution environment could not resolve or connect to an external website. To demonstrate the same OpenSSL inspection process, I created and started a live local TLS endpoint on `127.0.0.1:8443`, then inspected its certificate.

### Commands executed

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key \
  -out server.crt \
  -days 30 \
  -config openssl.cnf

openssl s_server \
  -accept 8443 \
  -cert server.crt \
  -key server.key \
  -www &

echo | openssl s_client \
  -connect 127.0.0.1:8443 \
  -servername technical.meddefense.local 2>/dev/null |
openssl x509 -noout -subject -issuer -dates -text
```

### Five-line certificate summary

```text
Subject: C=LU, O=MedDefense Lab, CN=technical.meddefense.local
Issuer: C=LU, O=MedDefense Lab, CN=technical.meddefense.local
Validity: Jul 29 11:09:27 2026 GMT to Aug 28 11:09:27 2026 GMT
Key Algorithm: RSA, 2048-bit public key
SAN entries: DNS:technical.meddefense.local, DNS:localhost, IP:127.0.0.1
```

The identical inspection can be performed against a public site from Kali with:

```bash
echo | openssl s_client \
  -connect example.com:443 \
  -servername example.com 2>/dev/null |
openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

### Interpretation

The local certificate is self-signed because its Subject and Issuer are identical. OpenSSL successfully extracted the identity, issuing authority, validity period, public-key details and Subject Alternative Names.

---

## Check 2 — Hash Verification

### Initial file creation and hash

```bash
printf 'MedDefense FortiGate firmware validation test\n' \
  > firmware_test.txt

sha256sum firmware_test.txt
```

### Initial output

```text
98e4d9fa1d941ac4d10c21edba5a09c3c87cf640cc54060721841f3806600654  firmware_test.txt
```

### File modification and second hash

```bash
printf 'Modified content\n' >> firmware_test.txt

sha256sum firmware_test.txt
```

### Modified output

```text
b19914ef9b902431b42dad5fd0a6e3cd2108ef962bc499de4831652c4262bbd1  firmware_test.txt
```

### Result

```text
Original: 98e4d9fa1d941ac4d10c21edba5a09c3c87cf640cc54060721841f3806600654
Modified: b19914ef9b902431b42dad5fd0a6e3cd2108ef962bc499de4831652c4262bbd1
Match:    No
```

The hashes differ completely even though only one line was added. This demonstrates the avalanche effect of a cryptographic hash.

### Importance for FortiGate firmware

Before installing the FortiGate firmware, MedDefense must compare its SHA-256 hash with Fortinet’s trusted published value; a mismatch would indicate corruption, an incomplete download or possible tampering and the firmware must not be installed.

---

## Check 3 — Exploit Research

### Commands

```bash
searchsploit fortigate
searchsploit fortios
searchsploit --cve 2023-27997
```

### Actual output in this environment

```text
bash: searchsploit: command not found
```

SearchSploit was not installed in this execution environment. SearchSploit normally searches a local copy of the Exploit-DB repository, so its database should be updated before relying on the result.

On a Kali machine, the validation commands are:

```bash
sudo apt update
sudo apt install exploitdb
searchsploit -u
searchsploit fortigate
searchsploit fortios
searchsploit --cve 2023-27997
```

### Exploit availability assessment

**Dedicated Exploit-DB entry:** No dedicated entry for CVE-2023-27997 was identified in the current Exploit-DB search.

**Public exploit or PoC:** **Yes.** Public research and proof-of-concept code exist outside Exploit-DB. Lexfo’s public XORtigate repository includes an `exploit.py` proof of concept demonstrating the remote-code-execution technique. The released PoC is presented for research and is not necessarily a complete one-command weaponised exploit, but it gives attackers detailed technical knowledge for developing reliable exploitation.

### Conclusion

The absence of a dedicated Exploit-DB entry does **not** mean the vulnerability is safe or unexploitable. CVE-2023-27997:

- is remotely accessible through SSL-VPN;
    
- requires no authentication;
    
- has public technical exploitation material;
    
- is listed in CISA’s Known Exploited Vulnerabilities catalogue;
    
- affects MedDefense’s FortiOS 7.0.9 installation.
    

Fortinet provides fixed releases, and CISA identifies the vulnerability as exploited in the wild. Patching—or disabling SSL-VPN until patching is possible—is therefore an emergency action.

---

## Check 4 — System Audit

### Command

```bash
sudo lynis audit system --quick
```

### Current-environment output

```text
bash: lynis: command not found
```

Lynis was not installed in the current execution environment. However, a complete Lynis audit previously executed on your Kali machine was available in the uploaded technical evidence, so the following results are taken from that real audit rather than invented.

### Audit summary

```text
Lynis version:    3.1.6
Operating system: Kali Linux Rolling
Hardening Index:  60/100
Tests performed:  273
Warnings:         2
Suggestions:      58
```

### Top warnings

The scan generated only **two items formally classified as warnings**. A third warning should not be invented.

#### Warning 1 — System reboot required

```text
! Reboot of system is most likely needed [KRNL-5830]
  Solution: reboot
```

**Meaning:** A kernel or important system update has been installed but is not fully active until the machine is restarted.

#### Warning 2 — Insufficient responsive DNS servers

```text
! Couldn't find 2 responsive nameservers [NETW-2705]
```

**Meaning:** Only one working DNS resolver was detected. Loss of that resolver could interrupt name resolution and services that depend on it.

#### Highest-priority suggestion — Host firewall inactive

```text
- Checking host based firewall [NOT ACTIVE]
* Configure a firewall/packet filter to filter incoming and outgoing traffic
  [FIRE-4590]
```

This is a **suggestion**, not the third warning. It is included because it represents one of the most important security weaknesses in the audit.

### Recommendation for `billing-srv-01`

Apply a default-deny host firewall using UFW or `nftables` and permit only required traffic:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permit SSH only from the approved management subnet
sudo ufw allow from <MANAGEMENT-SUBNET> to any port 22 proto tcp

# Permit MySQL only from the authorised application server
sudo ufw allow from <APP-SERVER-IP> to any port 3306 proto tcp

sudo ufw enable
sudo ufw status verbose
```

This directly addresses MedDefense Finding 006 because MySQL on `billing-srv-01` is bound to all interfaces and reachable from the entire flat network. The server also permits password-based SSH and runs Ubuntu 18.04 without activated Extended Security Maintenance.  
The rule set must use the real approved application-server and management addresses and must be tested before activation to avoid interrupting billing operations.

---

# Technical Validation Summary

|Check|Result|
|---|---|
|Certificate inspection|Completed against a live local TLS service; external test blocked by sandbox DNS|
|SHA-256 integrity test|Completed; modification produced a different hash|
|Exploit research|SearchSploit unavailable locally; public PoC confirmed through external research|
|Lynis system audit|Existing real Kali audit reviewed: Hardening Index **60/100**|
|Main billing-server action|Enable a restrictive host firewall and limit MySQL/SSH sources|

These checks demonstrate the ability to inspect certificate fields, validate file integrity, distinguish Exploit-DB results from broader public exploit availability, and convert a system-hardening audit into a system-specific remediation.
