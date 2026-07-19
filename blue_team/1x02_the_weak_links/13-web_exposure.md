# The Web Exposure

## 1. Patient Portal

**Host:** `web-srv-01` — `10.10.2.50`

**Exposure:** Internet-facing

**Findings:**

- Finding 005 — TLS 1.0 enabled
    
- Finding 012 — Missing HTTP security headers
    
- Finding 013 — TLS certificate expires in 23 days
    
- Finding 021 — HTTP TRACE method enabled
    

**Combined Risk:** High. The portal handles patient data and is exposed to the internet. Weak TLS, missing headers and TRACE increase the chance of traffic interception and browser-based attacks.

**Attack Scenario:** An attacker could target users with a malicious page, use missing headers to support clickjacking or XSS, and abuse weak TLS or TRACE to increase the impact. This matches the external web-entry kill chain from 1x01.

**Priority:** Second. It is internet-facing, but no direct remote-code-execution vulnerability was confirmed.

---

## 2. EHR Application Server

**Host:** `ehr-srv-01` — `10.10.2.10`

**Exposure:** Internal, but accessible across the flat network

**Findings:**

- Finding 017 — Tomcat version and stack-trace disclosure
    
- Finding 030 — TLS certificate name mismatch
    
- Finding 031 — Ghostcat on AJP port 8009
    

**Combined Risk:** Critical. Ghostcat can read application files and may expose database credentials. The flat network allows any compromised internal host to reach the server.

**Attack Scenario:** An attacker first compromises another internal device, uses Finding 017 to identify the Tomcat version, then exploits Finding 031 to read configuration files. Stolen database credentials could then be used against the exposed EHR database in Finding 003.

**Priority:** First. It affects the EHR system, has a public exploit and can expose patient database credentials.

---

## 3. Backup NAS

**Host:** `NAS-01` — `10.10.2.41`

**Exposure:** Internal, but accessible across the flat network

**Findings:**

- Finding 015 — DSM web management interface accessible from the entire internal network
    
- Backup data stored without encryption
    

**Combined Risk:** High. A compromised internal host could reach the NAS management interface and attempt to steal, delete or encrypt backups.

**Attack Scenario:** After gaining access to any internal workstation, a ransomware actor could connect to the DSM interface, attack weak credentials or an unpatched DSM version, and destroy backup data before encrypting production systems.

**Priority:** Third. It is not internet-facing, but it is important for recovery and should be restricted to administrator systems.

---

## Priority Order

1. `ehr-srv-01`
    
2. `web-srv-01`
    
3. `NAS-01`
    

## Value of Investigating Medium Findings

Finding 017 looked like a Medium information-disclosure issue, but it revealed the Tomcat version and led to manual verification of the AJP connector. This exposed Finding 031, a Critical Ghostcat vulnerability. It shows that Medium findings can provide important clues about hidden services, versions and attack paths, so they should not be ignored without investigation.
