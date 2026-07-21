# 15. Red Team Your Blueprint

## Part 1 — The Attacker’s Perspective

### Remaining Viable Kill Chain

**Kill Chain #1, phishing-led ransomware, is still partly viable.**

MFA protects VPN and administrator accounts, but it does not stop an employee from opening a malicious attachment or approving a fraudulent login request. EDR and segmentation would limit the attack, but a compromised user could still access permitted file shares and clinical applications. The lack of 24/7 monitoring also means an attack started at night or during a weekend may not be investigated immediately.

### Alternative Attack Path

As a BlackReef affiliate, I would use the following path:

1. Send a targeted phishing message to a billing or clinical employee.
2. Steal the user’s session token or persuade the user to approve an MFA request.
3. Use the valid account to access approved applications and slowly collect patient or financial data.
4. Operate outside normal working hours, when Wazuh alerts may not be reviewed immediately.
5. Encrypt accessible files and demand payment while threatening to publish the stolen data.

This path avoids directly attacking the firewall and uses normal user access to appear less suspicious.

### Remaining Insider Threat

A negligent insider remains dangerous. An employee could send patient information to the wrong recipient, upload it to an unauthorized cloud service or photograph a clinical screen with a personal phone. Segmentation, MFA and EDR do not fully prevent this because the employee already has legitimate access. Security awareness, DLP and regular access reviews are still needed.

## Part 2 — Honest Assessment

### Overall Residual Risk

**Residual Risk: High**

The funded controls greatly reduce ransomware spread, remote compromise and backup destruction. However, MedDefense still handles highly sensitive patient data, has many users and medical devices, and lacks continuous human monitoring. A successful attack would be harder, but the remaining impact could still be severe.

### Biggest Remaining Gap

The largest remaining gap is the lack of **24/7 security monitoring and incident response coverage**. Wazuh can generate alerts, but alerts provide little value if nobody reviews and investigates them quickly.

### Next-Year Priority

The first priority for next year should be an **outsourced managed SOC or equivalent 24/7 monitoring service**. This would provide continuous alert review, faster containment and specialist support without requiring MedDefense to build a full internal SOC. After that, MedDefense should expand DLP, security awareness and dedicated medical-device monitoring.

