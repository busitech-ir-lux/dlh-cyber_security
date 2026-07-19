# Exercise 1: Deconstruction

## Original vulnerability

**Finding:** Finding 001 — CVE-2021-44790  
**Original vector:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Base Score:** 9.8  
**Severity:** Critical

The scan describes an Apache `mod_lua` buffer overflow that can be triggered through a crafted HTTP request and may allow unauthenticated remote code execution.

## Metric-by-metric explanation

|Component|Meaning and selected value|Other possible values|Reason for this vulnerability|
|---|---|---|---|
|**AV:N**|**Attack Vector: Network.** The vulnerability can be exploited remotely through the network.|Adjacent `A`, Local `L`, Physical `P`. More restrictive access normally lowers the score.|The attacker can send a crafted HTTP request to the Apache server without first obtaining local system access.|
|**AC:L**|**Attack Complexity: Low.** No unusual condition outside the attacker’s control is required.|High `H`, which would lower the score because exploitation would depend on special conditions.|The scan states that a crafted request body can trigger the vulnerability. It does not identify a race condition or special environmental requirement.|
|**PR:N**|**Privileges Required: None.** The attacker does not need an account or prior access.|Low `L` or High `H`. Requiring privileges reduces the score.|The vulnerability is described as exploitable without authentication.|
|**UI:N**|**User Interaction: None.** No other user must perform an action.|Required `R`, which lowers the score.|The attacker communicates directly with the web server. No victim needs to open a file or click a link.|
|**S:U**|**Scope: Unchanged.** The vulnerable and affected resources remain under the same security authority.|Changed `C`, where exploitation crosses into a different security authority. Changed scope generally increases the score.|Exploitation compromises resources controlled by the same Apache host and operating system.|
|**C:H**|**Confidentiality: High.** Successful exploitation could expose sensitive system and application information.|Low `L` or None `N`, which would reduce the impact score.|Remote code execution could allow the attacker to read application data, credentials and system files.|
|**I:H**|**Integrity: High.** The attacker could make serious or unrestricted modifications.|Low `L` or None `N`.|Arbitrary code execution could allow modification of files, applications, configurations and billing data.|
|**A:H**|**Availability: High.** Exploitation could seriously interrupt the service or system.|Low `L` or None `N`.|The attacker could crash Apache, stop services, damage files or take the billing server offline.|

FIRST defines Network attacks as remotely reachable, Low complexity as not requiring special conditions, and None for privileges or interaction when the attacker can exploit the system directly. It defines High confidentiality, integrity and availability impacts as serious or complete losses in those areas.

## Changing Attack Vector from Network to Local

### Modified vector

```text
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Calculator result

|Result|Value|
|---|--:|
|**New Base Score**|**8.4**|
|**Severity**|**High**|
|**Original score**|9.8 Critical|
|**Score reduction**|1.4 points|

### Why the score changes

Changing `AV:N` to `AV:L` means the vulnerability can no longer be exploited directly through the network. The attacker must first obtain local read, write or execution capabilities on the system.

This reduces the number of potential attackers and makes the vulnerability less accessible. The confidentiality, integrity and availability impacts remain High, but the **Exploitability Subscore decreases**.

CVSS assigns Network an Attack Vector weight of `0.85` and Local a weight of `0.55`. All other metrics remain unchanged, so the reduced Attack Vector value changes the score from **9.8 Critical** to **8.4 High**.

---

# 1. The CVE Ecosystem

## Selection Method

The task requires three CVEs from the MedDefense vulnerability scan: one Critical finding, one High finding and one Medium finding.

The selected CVEs are:

- **Critical scan finding:** CVE-2021-44790 from Finding 001
    
- **High scan finding:** CVE-2021-34527 from Finding 008
    
- **Medium scan finding:** CVE-2023-38408 from Finding 020
    

The severity assigned by SecurePoint in the MedDefense scan can differ from the NVD CVSS Base Score. SecurePoint considered environmental conditions at MedDefense, while the NVD Base Score represents the vulnerability's general technical severity.

---

# CVE 1: CVE-2021-44790

**Scan Severity:** Critical

**CVE ID:** CVE-2021-44790

**NVD URL:**  
[https://nvd.nist.gov/vuln/detail/CVE-2021-44790](https://nvd.nist.gov/vuln/detail/CVE-2021-44790)

**Description:**  
Apache HTTP Server contains a memory-writing weakness in the multipart request parser used by the `mod_lua` module. A remote attacker can send a specially constructed request body to trigger a buffer overflow. The Apache developers stated that they were not aware of a working exploit at the time of disclosure, but remote code execution may be possible. At MedDefense, the risk is relevant because `billing-srv-01` runs an affected Apache version and the scan confirmed that `mod_lua` is loaded.

**Affected Products:**  
The NVD CPE data identifies Apache HTTP Server 2.4.51 and earlier as affected. Examples include:

1. Apache HTTP Server 2.4.29
    
2. Apache HTTP Server 2.4.50
    
3. Apache HTTP Server 2.4.51
    

The MedDefense billing server runs Apache HTTP Server 2.4.29 and is therefore within the affected version range.

**CVSS v3.1 Vector String:**  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**CVSS Base Score:**  
9.8 — Critical

**CWE:**  
CWE-787 — Out-of-bounds Write

**References:**

1. [https://httpd.apache.org/security/vulnerabilities_24.html](https://httpd.apache.org/security/vulnerabilities_24.html)  
    **Reference Type:** Official Apache vendor security advisory.  
    **Purpose:** Describes affected Apache versions and the corrected release.
    
2. [https://www.debian.org/security/2022/dsa-5035](https://www.debian.org/security/2022/dsa-5035)  
    **Reference Type:** Debian security advisory and patch information.  
    **Purpose:** Identifies affected Debian packages and the security updates provided by Debian.
    
3. [https://packetstormsecurity.com/files/171631/Apache-2.4.x-Buffer-Overflow.html](https://packetstormsecurity.com/files/171631/Apache-2.4.x-Buffer-Overflow.html)  
    **Reference Type:** Public proof of concept.  
    **Purpose:** Demonstrates how a malformed multipart request can trigger the buffer-overflow condition.
    

**Published Date:**  
20 December 2021

**Last Modified:**  
17 June 2026

**MedDefense Relevance:**  
This CVE affects `billing-srv-01`, which runs the MedDefense billing application and stores financial information. The vulnerability can potentially provide initial remote access without authentication. It may also be chained with CVE-2019-0211 to escalate from the Apache service account to root privileges.

---

# CVE 2: CVE-2021-34527

**Scan Severity:** High

**CVE ID:** CVE-2021-34527

**Common Name:** PrintNightmare

**NVD URL:**  
[https://nvd.nist.gov/vuln/detail/CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527)

**Description:**  
The Microsoft Windows Print Spooler improperly performs file operations using elevated privileges. An attacker with a low-privilege account can abuse the Print Spooler to execute arbitrary code with SYSTEM permissions. Successful exploitation can allow the attacker to install programs, modify or delete information and create accounts with full administrative privileges.

**Affected Products:**  
The NVD CPE data lists numerous Microsoft Windows products and versions. Examples include:

1. Microsoft Windows Server 2012 R2
    
2. Microsoft Windows Server 2016 before build 10.0.14393.4470
    
3. Microsoft Windows Server 2019 before build 10.0.17763.2029
    
4. Microsoft Windows 10 Version 1607 before build 10.0.14393.4470
    
5. Microsoft Windows 10 Version 1809 before build 10.0.17763.2029
    

At MedDefense, `print-srv-01` runs Windows Server 2012 R2 and has the Print Spooler service enabled.

**CVSS v3.1 Vector String:**  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

**CVSS Base Score:**  
8.8 — High

**CWE:**  
NVD-CWE-noinfo — Insufficient Information

NVD does not currently provide a specific CWE assignment for this CVE. The NVD page displays `NVD-CWE-noinfo`, meaning that insufficient information is available for a precise NVD CWE mapping.

**References:**

1. [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)  
    **Reference Type:** Official Microsoft vendor advisory.  
    **Purpose:** Provides the vulnerability description, affected Microsoft products, patches and mitigation guidance.
    
2. [https://www.kb.cert.org/vuls/id/383432](https://www.kb.cert.org/vuls/id/383432)  
    **Reference Type:** CERT Coordination Center technical advisory.  
    **Purpose:** Explains the PrintNightmare vulnerability, its impact and available defensive actions.
    
3. [https://packetstormsecurity.com/files/167261/Print-Spooler-Remote-DLL-Injection.html](https://packetstormsecurity.com/files/167261/Print-Spooler-Remote-DLL-Injection.html)  
    **Reference Type:** Public proof of concept and exploit resource.  
    **Purpose:** Demonstrates abuse of the Windows Print Spooler for remote DLL injection.
    

**Published Date:**  
2 July 2021

**Last Modified:**  
16 June 2026

**MedDefense Relevance:**  
This vulnerability affects `print-srv-01`, which uses an end-of-life Windows Server 2012 R2 operating system. The Print Spooler service is running, public exploitation techniques are available and the vulnerability has been used in real attacks. Compromise of this server could provide SYSTEM-level access and support lateral movement through MedDefense's flat internal network.

---

# CVE 3: CVE-2023-38408

**Scan Severity:** Medium

**NVD Severity:** Critical

**CVE ID:** CVE-2023-38408

**NVD URL:**  
[https://nvd.nist.gov/vuln/detail/CVE-2023-38408](https://nvd.nist.gov/vuln/detail/CVE-2023-38408)

**Description:**  
OpenSSH's `ssh-agent` can load shared libraries through its PKCS#11 support when SSH agent forwarding is enabled. If a user forwards their SSH agent to a server controlled by an attacker, the attacker may use specially selected libraries on that remote system to cause code execution on the machine where the agent originally runs. This is not a normal unauthenticated attack against an exposed SSH server because several specific environmental conditions must exist.

**Affected Products:**  
The NVD CPE data includes the following affected products and versions:

1. OpenSSH versions earlier than 9.3
    
2. OpenSSH 9.3
    
3. OpenSSH 9.3p1
    
4. Fedora 37
    
5. Fedora 38
    

OpenSSH 9.3p2 contains the correction. The MedDefense scan detected OpenSSH 8.9p1 on `backup-srv-01`, which is within the affected OpenSSH range.

**CVSS v3.1 Vector String:**  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**CVSS Base Score:**  
9.8 — Critical

**CWE:**  
CWE-428 — Unquoted Search Path or Element

**References:**

1. [https://www.openssh.com/security.html](https://www.openssh.com/security.html)  
    **Reference Type:** Official OpenSSH vendor security advisory.  
    **Purpose:** Lists the OpenSSH vulnerability and affected releases.
    
2. [https://www.openssh.com/txt/release-9.3p2](https://www.openssh.com/txt/release-9.3p2)  
    **Reference Type:** Vendor release notes and remediation information.  
    **Purpose:** Describes the security correction introduced in OpenSSH 9.3p2.
    
3. [https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent](https://blog.qualys.com/vulnerabilities-threat-research/2023/07/19/cve-2023-38408-remote-code-execution-in-opensshs-forwarded-ssh-agent)  
    **Reference Type:** Technical security write-up and proof of concept.  
    **Purpose:** Explains the exploitation conditions and demonstrates how forwarded SSH agents could be attacked.
    
4. [https://github.com/openbsd/src/commit/7bc29a9d5cd697290aa056e94ecee6253d3425f8](https://github.com/openbsd/src/commit/7bc29a9d5cd697290aa056e94ecee6253d3425f8)  
    **Reference Type:** Source-code patch.  
    **Purpose:** Shows the OpenBSD source changes associated with correcting the weakness.
    

**Published Date:**  
19 July 2023

**Last Modified:**  
17 June 2026

**Reason for the Difference Between the Scan and NVD Severity:**  
The NVD score describes the vulnerability's intrinsic technical severity under its CVSS assumptions. It does not determine whether the necessary conditions exist at MedDefense.

SecurePoint rated the MedDefense finding Medium because successful exploitation requires specific conditions, including:

- SSH-agent forwarding must be enabled.
    
- A user must connect to an attacker-controlled SSH server.
    
- PKCS#11 provider loading must be available.
    
- Suitable libraries must exist on the remote system.
    
- The forwarded agent must remain accessible to the attacker.
    

The scan states that these conditions may not exist in the normal operation of `backup-srv-01`. Manual verification is therefore required before treating the finding as an urgent Critical risk.

This CVE is the required **Medium finding from the scan**, although its NVD CVSS Base Score is Critical.

---

# CVE Ecosystem Questions

## 1. What Is the Structure of a CVE ID?

A CVE identifier normally follows this structure:

```text
CVE-YYYY-NNNN
```

It may contain more than four digits in its final section:

```text
CVE-2026-12345
```

The components mean:

- **CVE:** Identifies the record as part of the Common Vulnerabilities and Exposures system.
    
- **YYYY:** The year associated with the CVE identifier, normally the year in which the identifier was assigned or reserved.
    
- **NNNN:** A unique sequence number containing four or more digits.
    

For example:

```text
CVE-2021-44790
```

- `CVE` identifies the CVE system.
    
- `2021` is the year associated with the assignment.
    
- `44790` is the unique sequence number.
    

The number does not indicate:

- the vulnerability's severity
    
- the order in which vulnerabilities were discovered
    
- the number of affected products
    
- whether an exploit exists
    

The year also does not always represent the exact year in which the vulnerability was discovered.

---

## 2. What Is a CNA?

CNA stands for **CVE Numbering Authority**.

A CNA is an organization authorized by the CVE Program to assign CVE IDs and publish CVE Records within an approved area of responsibility.

CNAs may include:

- software vendors
    
- hardware vendors
    
- open-source projects
    
- national or industry CERT organizations
    
- security research organizations
    
- bug-bounty providers
    
- cloud-service providers
    

A CNA performs the following activities:

1. Receives or investigates vulnerability reports.
    
2. Determines whether the reported issue qualifies for a CVE.
    
3. Checks whether another CVE already describes the same vulnerability.
    
4. Reserves and assigns a unique CVE ID.
    
5. Creates and publishes the CVE Record.
    
6. Provides a description and public references.
    
7. Updates the CVE Record when new information becomes available.
    
8. Rejects a CVE when it is invalid, duplicated or incorrectly assigned.
    

For example, Microsoft is a CNA for many vulnerabilities affecting Microsoft products. The Apache Software Foundation can assign CVEs for vulnerabilities affecting Apache projects.

The CNA system distributes vulnerability-management work across many qualified organizations instead of requiring one central organization to process every vulnerability worldwide.

---

## 3. What Lifecycle States Can a CVE Have?

### Reserved

A CVE is Reserved when a CVE ID has been allocated, but the full public record has not yet been published.

This may occur while:

- the vendor investigates the issue
    
- a patch is being developed
    
- disclosure is being coordinated
    
- the CNA prepares the public record
    
- the researcher and vendor agree on a disclosure date
    

A Reserved CVE acts as a placeholder. The identifier exists, but public vulnerability details may not yet be available.

### Published

A CVE is Published when the CNA releases the CVE Record publicly.

A published record normally includes:

- the CVE ID
    
- a vulnerability description
    
- affected product information
    
- one or more public references
    
- the assigning CNA
    
- CWE information where available
    
- CVSS information where available
    

After publication, NVD may enrich the record with:

- CVSS scores and vectors
    
- CPE configurations
    
- CWE mappings
    
- reference classifications
    
- additional analysis
    

A Published record can later be modified as vendors and researchers discover more information.

### Rejected

A CVE is Rejected when the identifier should no longer be used as a valid vulnerability record.

A CVE may be rejected because:

- it duplicates another CVE
    
- it was assigned accidentally
    
- the reported behaviour is not a security vulnerability
    
- the issue was withdrawn
    
- the vulnerability was incorrectly described
    
- the record belongs under another existing CVE
    

Rejected records remain visible in CVE and NVD systems. This prevents the rejected number from being reused and tells security professionals which valid CVE should be used instead.

---

## 4. Example of a Rejected CVE

**Rejected CVE ID:** CVE-2026-61606

**NVD URL:**  
[https://nvd.nist.gov/vuln/detail/CVE-2026-61606](https://nvd.nist.gov/vuln/detail/CVE-2026-61606)

**Status:**  
Rejected

**Reason for Rejection:**  
CVE-2026-61606 was rejected because it was a duplicate of CVE-2026-61457.

The NVD description instructs users not to use CVE-2026-61606 and to reference CVE-2026-61457 instead.

**Published Date:**  
15 July 2026

**Last Modified:**  
15 July 2026

This example shows that rejected CVEs are not deleted. They remain publicly visible to explain why the identifier is invalid and direct users to the correct CVE Record.

---

# Conclusion

The CVE system provides a common global identifier for publicly disclosed vulnerabilities. CNAs assign and maintain CVE Records, while NVD enriches those records with information such as CVSS vectors, affected-product configurations, CWE mappings, references and update history.

The MedDefense examples also demonstrate that the NVD Base Score and the organization's remediation priority are not always identical. CVE-2023-38408 has a Critical NVD score, but SecurePoint rated the finding Medium because the required exploitation conditions may not exist on `backup-srv-01`. A vulnerability analyst must record both values accurately and explain the reason for the difference rather than changing or inventing the NVD data.

---

# Exercise 3: Comparison

## Selection issue

The scan report does not contain an explicitly scored finding between **5.0 and 7.0**. Its stated numerical CVSS scores are primarily 7.5, 7.8, 8.1, 8.8, 9.8 and 10.0.

To complete the exercise correctly, I selected:

1. **Finding 001**, which has a documented 9.8 vector.
    
2. **Finding 017**, a Medium Tomcat information-disclosure finding without a scanner-provided CVSS vector.
    

For Finding 017, I constructed a reasonable Base vector from the report’s description. This is an **analyst-assigned score**, not a score supplied by SecurePoint or NVD.

## Finding A: Apache remote code execution

**Finding:** Finding 001  
**CVE:** CVE-2021-44790

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Score:** 9.8 Critical

## Finding B: Tomcat error-page information disclosure

**Finding:** Finding 017  
**Analyst-constructed vector:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
```

**Calculated score:** 5.3 Medium

The vector assumes:

- the Tomcat error page is network-accessible
    
- no authentication is required to trigger it
    
- no user interaction is required
    
- the disclosed information is limited
    
- the finding does not directly permit modification or service interruption
    

## Side-by-side comparison

|Metric|Finding 001|Finding 017|Effect on score|
|---|---|---|---|
|**Attack Vector**|Network|Network|No difference|
|**Attack Complexity**|Low|Low|No difference|
|**Privileges Required**|None|None|No difference|
|**User Interaction**|None|None|No difference|
|**Scope**|Unchanged|Unchanged|No difference|
|**Confidentiality**|High|Low|Finding 001 can expose much more sensitive information|
|**Integrity**|High|None|Finding 001 can modify files, data and configurations|
|**Availability**|High|None|Finding 001 can disrupt or disable the service|
|**Final score**|**9.8 Critical**|**5.3 Medium**|The difference is produced entirely by the Impact metrics|

## Components explaining the score difference

Both findings are equally accessible according to the selected Exploitability metrics:

```text
AV:N/AC:L/PR:N/UI:N/S:U
```

The difference comes from the three Impact metrics:

```text
Finding 001: C:H/I:H/A:H
Finding 017: C:L/I:N/A:N
```

Finding 001 can cause serious losses to all three security objectives:

- confidentiality
    
- integrity
    
- availability
    

Finding 017 only reveals a limited amount of information and does not directly modify data or interrupt the service.

## Which components have the biggest impact?

For this comparison, **Integrity and Availability have the largest combined effect**, because they change from `None` to `High`. Confidentiality also increases from `Low` to `High`.

Attack Vector, Attack Complexity, Privileges Required, User Interaction and Scope cannot explain the difference because they are identical in both vectors.

This comparison shows that easy remote access does not automatically create a Critical score. A vulnerability also needs sufficient impact. Finding 017 is easy to reach but has limited direct impact, while Finding 001 combines easy exploitation with complete confidentiality, integrity and availability consequences.
