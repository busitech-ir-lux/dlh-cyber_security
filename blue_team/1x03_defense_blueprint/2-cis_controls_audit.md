dDefense has no regular scanning, prioritization or patching process.

## CIS Control 8: Audit Log Management

**Score:** Not Implemented  
**Evidence:** MedDefense has no centralized logging or formal process for collecting, storing and reviewing security logs.

## CIS Control 9: Email and Web Browser Protections

**Score:** Partial  
**Evidence:** Phishing was identified as an important attack path, but there is no evidence of DNS filtering or strong email protection.

## CIS Control 10: Malware Defenses

**Score:** Not Implemented  
**Evidence:** A crypto-miner operated for at least two weeks without detection, showing that malware protection was absent or ineffective.

## CIS Control 11: Data Recovery

**Score:** Partial  
**Evidence:** Backups exist, but they are connected to the production network and are not regularly tested.

## CIS Control 12: Network Infrastructure Management

**Score:** Partial  
**Evidence:** MedDefense uses a flat `10.10.0.0/16` network with little segmentation between clinical, administrative and medical systems.

## CIS Control 13: Network Monitoring and Defense

**Score:** Not Implemented  
**Evidence:** MedDefense has no SIEM, intrusion detection, traffic analysis or centralized security alerts.

## CIS Control 14: Security Awareness and Skills Training

**Score:** Not Implemented  
**Evidence:** Project 1x01 identified phishing and human error as major attack paths, but no formal security awareness program exists.

## CIS Control 15: Service Provider Management

**Score:** Partial  
**Evidence:** MedDefense depends on several healthcare and technology suppliers, but their security risks are not formally reviewed and tracked.

## CIS Control 16: Application Software Security

**Score:** Not Implemented  
**Evidence:** No secure software development process or developer security training was identified in the previous assessments.

## CIS Control 17: Incident Response Management

**Score:** Partial  
**Evidence:** MedDefense reacted to previous incidents, but it has no documented and tested incident response plan.

## CIS Control 18: Penetration Testing

**Score:** Not Implemented  
**Evidence:** Project 1x02 performed vulnerability scanning, but MedDefense has no regular internal or external penetration testing program.

# Scorecard Summary

|Score|Number of Controls|
|---|--:|
|Implemented|0|
|Partial|12|
|Not Implemented|6|
|**Total**|**18**|

# Top 5 Priority Controls

### 1. Control 6 — Access Control Management

Implementing MFA and removing shared accounts would reduce credential theft and block important ransomware attack paths.

### 2. Control 7 — Continuous Vulnerability Management

Regular scanning and patching would reduce the number of known weaknesses attackers can exploit.

### 3. Control 11 — Data Recovery

Isolated and tested backups would allow MedDefense to restore patient services after ransomware.

### 4. Control 12 — Network Infrastructure Management

Network segmentation would prevent attackers from moving easily between user devices, servers and medical systems.

### 5. Control 13 — Network Monitoring and Defense

Centralized monitoring and intrusion detection would help MedDefense discover attacks before they cause major damage.

## Overall Assessment

MedDefense does not fully implement any of the 18 CIS Controls. Its first goal should be to complete the **IG1 safeguards**, while beginning selected IG2 controls such as network monitoring and segmentation.
