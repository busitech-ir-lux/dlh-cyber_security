# The Misconfiguration Findings

## 1. Finding 003

**Finding ID:** 003
**Host:** `ehr-db-01` — `10.10.2.11`
**Misconfiguration:** PostgreSQL accepts connections from the whole `10.10.0.0/16` network, and no firewall limits access to the EHR database.
**Why No CVE:** The software is working as configured. The problem is the unsafe access rule, not a software bug.
**Severity Assessment:** **Critical** — any compromised internal host could try to access the patient database.
**Cross-Reference 1x00:** Matches the flat-network gap from T5 and the EHR database exposure identified in the asset and network review.
**Comparable CVE Risk:** Comparable to **CVE-2020-1938** because both could expose EHR database credentials or patient information. This misconfiguration may be equally dangerous because it directly exposes the database to the whole internal network.

---

## 2. Finding 006

**Finding ID:** 006
**Host:** `billing-srv-01` — `10.10.2.15`
**Misconfiguration:** MySQL listens on all network interfaces through `bind-address = 0.0.0.0`.
**Why No CVE:** This is an unsafe administrator setting, not a defect in MySQL.
**Severity Assessment:** **High** — a compromised internal device could attack the billing database.
**Cross-Reference 1x00:** Matches the flat-network and weak network-access-control gaps from T5 and T7.
**Comparable CVE Risk:** Comparable to **CVE-2019-0211** because both may lead to serious compromise of the billing server. The database exposure may also reveal financial records without needing privilege escalation.

---

## 3. Finding 007

**Finding ID:** 007
**Host:** `ad-dc-01` — `10.10.2.20`
**Misconfiguration:** LDAP signing is not required, and SMBv1 is enabled.
**Why No CVE:** LDAP signing is a security setting. The domain controller administrator has not enforced the safer configuration.
**Severity Assessment:** **High** — attackers may relay authentication and modify Active Directory objects.
**Cross-Reference 1x00:** Matches the weak identity and access-control gap and the lack of network segmentation identified in T5.
**Comparable CVE Risk:** Comparable to **CVE-2021-34527** because both can help an attacker gain powerful Windows privileges and move through the domain.

---

## 4. Finding 009

**Finding ID:** 009
**Host:** `billing-srv-01` — `10.10.2.15`
**Misconfiguration:** SSH password authentication is enabled, and there is no account lockout policy.
**Why No CVE:** SSH supports secure authentication, but the server was configured to allow weaker password-based access.
**Severity Assessment:** **High** — attackers can perform password guessing or use stolen credentials.
**Cross-Reference 1x00:** Matches the weak authentication and account-control gaps from T5.
**Comparable CVE Risk:** Comparable to **CVE-2023-38408** because both affect SSH access. This misconfiguration may be more practical because password attacks require fewer special conditions.

---

## 5. Finding 015

**Finding ID:** 015
**Host:** `NAS-01` — `10.10.2.41`
**Misconfiguration:** The NAS management interface is available to the entire internal network, and backups are stored without encryption.
**Why No CVE:** The issue comes from broad network access and insecure storage settings, not a software defect.
**Severity Assessment:** **High** — an attacker could delete, encrypt or steal backup data.
**Cross-Reference 1x00:** Matches the backup-protection and access-control gaps from T5 and the exposed service finding from T7.
**Comparable CVE Risk:** Comparable to **CVE-2017-0144** because both could support ransomware. Destroying accessible backups may make recovery impossible even without exploiting a CVE.

---

## 6. Finding 016

**Finding ID:** 016
**Host:** Philips IntelliVue monitors — `10.10.3.10–32`
**Misconfiguration:** Medical-device web and HL7 interfaces are accessible from the entire network without proper authentication.
**Why No CVE:** The problem is the lack of isolation and access restriction around the devices, not a confirmed product bug.
**Severity Assessment:** **High** — compromised internal systems could access patient-monitoring interfaces and data.
**Cross-Reference 1x00:** Matches the medical-device exposure and flat-network gaps identified in T5 and T7.
**Comparable CVE Risk:** Comparable to **CVE-2020-25165** because both affect medical devices and could disrupt clinical operations. The misconfiguration exposes more devices and may also expose patient data.

---

## Why CVE-Only Scanning Gives False Assurance

The statement “Our CVE scan shows nothing critical, so we are secure” is dangerous because many serious weaknesses do not have CVE identifiers. Unsafe database access, default credentials, weak authentication, exposed management interfaces and missing network segmentation can all lead to major breaches. CVE scanners mainly identify known software flaws, but they may ignore configuration, architecture and access-control problems. Security therefore requires reviewing CVEs together with system configuration, asset criticality, exposure and realistic attack paths.

