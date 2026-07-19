# The Network Posture

## 1. CVE-2021-44790

**CVE:** CVE-2021-44790  
**Host:** `billing-srv-01` — `10.10.2.15`  
**CVSS Base Score:** 9.8

### Scenario A: Current Flat Network

**Who can reach this vulnerability:** Any compromised system in `10.10.0.0/16` can reach the Apache service.

**What the attacker can reach after exploitation:** The attacker could move from the billing server to the EHR, domain controllers, backup systems and medical devices.

**Effective Risk:** Critical

### Scenario B: Hypothetical Segmented Network

**Who can reach this vulnerability:** Only approved systems in the **same VLAN**.

**What the attacker can reach after exploitation:** Only systems in the **same VLAN**, unless the attacker can pivot through a firewall.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network turns one compromised billing server into a possible entry point to the whole organization.

---

## 2. CVE-2017-0144

**CVE:** CVE-2017-0144  
**Host:** `WS-RAD-01` — `10.10.1.70`  
**CVSS Base Score:** 8.1

### Scenario A: Current Flat Network

**Who can reach this vulnerability:** Systems across `10.10.0.0/16` can reach the open SMB service.

**What the attacker can reach after exploitation:** The attacker could control the MRI workstation and then attack other workstations, servers and medical devices.

**Effective Risk:** Critical

### Scenario B: Hypothetical Segmented Network

**Who can reach this vulnerability:** Only approved radiology and PACS systems in the **same VLAN**.

**What the attacker can reach after exploitation:** Only systems in the **same VLAN**, unless the attacker can pivot through a firewall.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network increases both the number of systems that can attack the workstation and the number of systems reachable after compromise.

---

## 3. CVE-2020-1938

**CVE:** CVE-2020-1938  
**Host:** `ehr-srv-01` — `10.10.2.10`  
**CVSS Base Score:** 9.8

### Scenario A: Current Flat Network

**Who can reach this vulnerability:** Any compromised internal host in `10.10.0.0/16` can reach AJP port 8009.

**What the attacker can reach after exploitation:** The attacker could read EHR configuration files, steal database credentials and access `ehr-db-01`.

**Effective Risk:** Critical

### Scenario B: Hypothetical Segmented Network

**Who can reach this vulnerability:** Only trusted application systems in the **same VLAN**.

**What the attacker can reach after exploitation:** Only systems in the **same VLAN**, unless the attacker can pivot through a firewall.

**Effective Risk:** High

**Risk Amplification Factor:** Very high. The flat network makes an internal-only service reachable from almost any compromised endpoint.

---

## Network Posture Summary

The flat network increases the risk of almost every finding because systems across `10.10.0.0/16` can communicate too freely. In a **segmented network**, a compromised host would normally be limited to the **same VLAN** unless firewall rules allowed further access. Segmentation reduces both exploit reachability and the impact radius of compromise. It is more effective than patching one CVE because it limits many attack paths at the same time.
