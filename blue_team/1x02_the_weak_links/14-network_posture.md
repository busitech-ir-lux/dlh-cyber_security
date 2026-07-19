# The Network Posture

## 1. CVE-2021-44790

**CVE:** CVE-2021-44790
**Host:** `billing-srv-01` — `10.10.2.15`
**CVSS Base Score:** 9.8

### Scenario A: Current Flat Network

**Who can reach it:** Any compromised system in `10.10.0.0/16` can reach the Apache service.

**After exploitation:** The attacker could move from the billing server toward the EHR, domain controllers, backup systems and medical devices.

**Effective Risk:** Critical

### Scenario B: Segmented Network

**Who can reach it:** Only approved systems in the billing VLAN.

**After exploitation:** The attacker would mainly be limited to billing systems unless firewall rules allowed further movement.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network turns one compromised billing server into a possible entry point to the whole organization.

---

## 2. CVE-2017-0144

**CVE:** CVE-2017-0144
**Host:** `WS-RAD-01` — `10.10.1.70`
**CVSS Base Score:** 8.1

### Scenario A: Current Flat Network

**Who can reach it:** Systems across the internal `10.10.0.0/16` network can reach the open SMB service.

**After exploitation:** The attacker could control the MRI workstation and then attack other workstations, servers and medical devices.

**Effective Risk:** Critical

### Scenario B: Segmented Network

**Who can reach it:** Only approved radiology and PACS systems in the medical-device VLAN.

**After exploitation:** The attacker would be mostly limited to the radiology segment.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network increases both the number of possible attackers and the number of systems reachable after compromise.

---

## 3. CVE-2020-1938

**CVE:** CVE-2020-1938
**Host:** `ehr-srv-01` — `10.10.2.10`
**CVSS Base Score:** 9.8

### Scenario A: Current Flat Network

**Who can reach it:** Any compromised internal host can reach AJP port 8009.

**After exploitation:** The attacker could read EHR configuration files, steal database credentials and access `ehr-db-01`.

**Effective Risk:** Critical

### Scenario B: Segmented Network

**Who can reach it:** Only trusted application systems in the EHR VLAN.

**After exploitation:** The attacker would be limited to the EHR segment unless firewall rules allowed further access.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network makes an internal-only service reachable from almost any compromised endpoint.

---

## Network Posture Summary

The flat network increases the risk of almost every finding because all internal systems can communicate too freely. It increases both the chance of exploitation and the damage after exploitation. Network segmentation is more impactful than patching one CVE because it limits many attack paths at the same time. Even if one system is compromised, segmentation can stop the attacker from reaching the EHR, Active Directory, backups and medical devices.

