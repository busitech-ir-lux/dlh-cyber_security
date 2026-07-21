# 7. Cost-Benefit Analysis

## Control 1 — Network Segmentation

**CIS Control Reference:** Control 12 — Network Infrastructure Management

**Annual Cost: $35,000**

* Licences and network equipment: $5,000
* Implementation labour: $24,000
* Maintenance: $6,000

**Risks Addressed:** EHR breach, VPN lateral movement and medical-device compromise

```text
ALE Reduction = $3,025,000 - $726,000
ALE Reduction = $2,299,000
```

```text
Net Value = $2,299,000 - $35,000
Net Value = $2,264,000
```

**Verdict:** Justified

**Recommendation:** Implement because segmentation greatly reduces an attacker’s ability to reach critical systems.

---

## Control 2 — MFA for VPN and Administrators

**CIS Control Reference:** Control 6 — Access Control Management

**Annual Cost: $12,000**

* Additional licence cost: $0 assumed
* Deployment labour: $8,000
* Training and maintenance: $4,000

For this exercise, the licence cost is assumed to be covered by MedDefense’s existing subscription. MedDefense should confirm its exact Microsoft licence because Microsoft 365 E3 includes Entra ID P1, while Office 365 E3 may require it separately.

**Risk Addressed:** VPN compromise

```text
ALE Reduction = $2,864,400 - $477,400
ALE Reduction = $2,387,000
```

```text
Net Value = $2,387,000 - $12,000
Net Value = $2,375,000
```

**Verdict:** Justified

**Recommendation:** Implement immediately because it provides the highest net financial value.

---

## Control 3 — Wazuh SIEM

**CIS Control Reference:** Controls 8 and 13 — Audit Logs and Network Monitoring

**Annual Cost: $26,000**

* Software licence: $0
* Installation and configuration: $18,000
* Server and storage: $6,000
* Maintenance: $2,000

Wazuh is free and open source, so the main costs are staff time, infrastructure and maintenance.

**Risks Addressed:** EHR breach, VPN compromise and billing ransomware

Assumption: Earlier detection reduces EHR ALE by 10% and billing ransomware ALE by 35%.

```text
EHR reduction = $3,025,000 × 10% = $302,500
Billing reduction = $135,278 × 35% = $47,347

ALE Reduction = $349,847
```

```text
Net Value = $349,847 - $26,000
Net Value = $323,847
```

**Verdict:** Justified

**Recommendation:** Implement because MedDefense currently has no centralized monitoring.

---

## Control 4 — Offsite Immutable Backups

**CIS Control Reference:** Control 11 — Data Recovery

**Annual Cost: $14,000**

* Cloud storage and transfer reserve: $2,000
* Replication setup and automation: $6,000
* Recovery testing and maintenance: $6,000

AWS Glacier storage is usage-based and designed for low-cost archival storage, but recovery requests and labour must also be budgeted.

**Risk Addressed:** Billing ransomware

Assumption: Recoverable offsite backups reduce the exposure factor from 100% to 45%.

```text
ALE After = $473,000 × 45% × 0.286
ALE After = $60,875
```

```text
ALE Reduction = $135,278 - $60,875
ALE Reduction = $74,403
```

```text
Net Value = $74,403 - $14,000
Net Value = $60,403
```

**Verdict:** Justified

**Recommendation:** Implement because isolated backups limit ransomware damage and support recovery.

---

## Control 5 — Endpoint Detection and Response

**CIS Control Reference:** Control 10 — Malware Defences

**Annual Cost: $24,000**

* Licences for approximately 320 systems: $18,000
* Deployment labour: $4,000
* Maintenance: $2,000

**Risks Addressed:** Billing ransomware and post-VPN malware activity

Assumption: EDR reduces billing ransomware ALE by 40% and VPN-related ALE by 7%.

```text
Billing reduction = $135,278 × 40% = $54,111
VPN reduction = $2,864,400 × 7% = $200,508

ALE Reduction = $254,619
```

```text
Net Value = $254,619 - $24,000
Net Value = $230,619
```

**Verdict:** Justified

**Recommendation:** Implement because it can detect and stop malware that passes preventive controls.

---

## Control 6 — Dedicated Westside Firewall

**CIS Control Reference:** Control 12 — Network Infrastructure Management

**Annual Cost: $9,000**

* Annualized hardware cost: $3,000
* Security licences and support: $3,000
* Installation and maintenance: $3,000

**Risk Addressed:** Westside compromise leading to full network access

Assumption: The firewall reduces the Westside attack frequency from 0.03 to 0.01 per year.

```text
ALE Before = $9,548,000 × 0.03 = $286,440
ALE After = $9,548,000 × 0.01 = $95,480

ALE Reduction = $190,960
```

```text
Net Value = $190,960 - $9,000
Net Value = $181,960
```

**Verdict:** Justified

**Recommendation:** Implement because the consumer router creates a weak entry point into the Central network.

---

## Control 7 — Outsourced 24/7 SOC

**CIS Control Reference:** Control 13 — Network Monitoring and Defence

**Annual Cost: $110,000**

* Managed SOC service: $90,000
* Onboarding: $10,000
* Internal oversight: $10,000

**Risks Addressed:** EHR breach, VPN compromise and ransomware

Assumption: After Wazuh is deployed, 24/7 monitoring provides an additional annual ALE reduction of $150,000.

```text
Net Value = $150,000 - $110,000
Net Value = $40,000
```

**Verdict:** Marginal

**Recommendation:** Defer because it consumes almost the entire budget and overlaps with the planned Wazuh deployment.

---

## Control 8 — Full Medical-Device Isolation and Monitoring

**CIS Control Reference:** Controls 12 and 13

**Annual Cost: $60,000**

* Network-access-control licences: $20,000
* Dedicated monitoring sensors: $15,000
* Specialist labour and support: $25,000

**Risk Addressed:** Medical-device compromise

```text
ALE Reduction = $60,000 - $12,000
ALE Reduction = $48,000
```

```text
Net Value = $48,000 - $60,000
Net Value = -$12,000
```

**Verdict:** Not Justified

**Recommendation:** Reject the full solution and use lower-cost VLAN isolation, password changes and Wazuh monitoring instead.

# Cost-Benefit Summary

| Rank | Control                       | Annual Cost | ALE Reduction |  Net Value | Decision  |
| ---: | ----------------------------- | ----------: | ------------: | ---------: | --------- |
|    1 | MFA                           |     $12,000 |    $2,387,000 | $2,375,000 | Implement |
|    2 | Network segmentation          |     $35,000 |    $2,299,000 | $2,264,000 | Implement |
|    3 | Wazuh SIEM                    |     $26,000 |      $349,847 |   $323,847 | Implement |
|    4 | EDR upgrade                   |     $24,000 |      $254,619 |   $230,619 | Implement |
|    5 | Westside firewall             |      $9,000 |      $190,960 |   $181,960 | Implement |
|    6 | Offsite backups               |     $14,000 |       $74,403 |    $60,403 | Implement |
|    7 | Outsourced SOC                |    $110,000 |      $150,000 |    $40,000 | Defer     |
|    8 | Full medical-device isolation |     $60,000 |       $48,000 |   -$12,000 | Reject    |

# Recommended $120,000 Package

| Selected Control     |         Cost |
| -------------------- | -----------: |
| MFA                  |      $12,000 |
| Network segmentation |      $35,000 |
| Wazuh SIEM           |      $26,000 |
| EDR upgrade          |      $24,000 |
| Westside firewall    |       $9,000 |
| Offsite backups      |      $14,000 |
| **Total**            | **$120,000** |

These six controls use the full budget and provide stronger prevention, detection and recovery coverage. The outsourced SOC should be considered in a later budget cycle.

