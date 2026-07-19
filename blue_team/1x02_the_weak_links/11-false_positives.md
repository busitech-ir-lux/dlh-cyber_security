# The False Positives

## 1. Finding 020

**Finding ID:** 020

**Reported Vulnerability:**
OpenSSH 8.9p1 affected by CVE-2023-38408.

**Why It Is a False Positive:**
The vulnerability requires SSH-agent forwarding to an attacker-controlled system with specific PKCS#11 conditions. This may not exist on `backup-srv-01`. The software version is affected, but the required exploitation conditions may be absent.

**Validation Method:**
Check whether SSH-agent forwarding is enabled and used:

```bash
grep -i AllowAgentForwarding /etc/ssh/sshd_config
```

Also check running SSH sessions and whether PKCS#11 agent forwarding is used.

**Risk of Acting on This FP:**
The team may perform emergency patching, restart the backup server and interrupt backup operations unnecessarily.

**Risk of Not Validating:**
If agent forwarding is enabled, an attacker could execute code through a forwarded SSH agent.

---

## 2. Finding 030

**Finding ID:** 030

**Reported Vulnerability:**
TLS certificate common-name mismatch on `ehr-srv-01`.

**Why It Is a False Positive:**
The certificate is valid for `ehr.meddefense.local`. The warning appears only because some users access the server by IP address instead of its correct hostname. This is an operational access problem, not a vulnerability in the certificate.

**Validation Method:**
Open the EHR using:

```text
https://ehr.meddefense.local
```

Then verify the certificate name:

```bash
openssl s_client -connect 10.10.2.10:443 -servername ehr.meddefense.local
```

Confirm that the certificate matches the hostname and is trusted.

**Risk of Acting on This FP:**
The team may waste time replacing a valid certificate instead of correcting bookmarks, DNS use or application links.

**Risk of Not Validating:**
If the certificate is actually invalid or untrusted, users may ignore browser warnings and become more vulnerable to man-in-the-middle attacks.

---

## Expected False Positive Rate

The scan report states that OpenVAS normally has a false positive rate of about **5–10%** in this configuration. For 31 findings, this means approximately **2–3 findings** may be false positives. Manual validation is essential because it confirms the affected version, configuration and exploitation conditions before time and money are committed to remediation.

