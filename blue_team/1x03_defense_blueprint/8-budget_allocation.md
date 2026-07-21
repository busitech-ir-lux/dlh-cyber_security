# 8. The Budget Game

## Part 1 — The Selection

### Funded Controls

| Control                         |  Annual Cost | Estimated ALE Reduction |
| ------------------------------- | -----------: | ----------------------: |
| MFA for VPN and administrators  |      $12000 |              $2387000 |
| Network segmentation            |      $35000 |              $2299000 |
| Wazuh SIEM                      |      $26000 |                $349847 |
| Endpoint Detection and Response |      $24000 |                $254619 |
| Westside Clinic firewall        |       $9000 |                $190960 |
| Offsite immutable backups       |      $14000 |                 $74403 |
| **Total**                       | **$120000** |          **$5555829** |

These controls provide prevention, detection and recovery while using the full budget.

### Deferred Control

**Outsourced 24/7 SOC — $110,000**

This control is deferred because it would consume almost the entire budget and overlaps with Wazuh monitoring. It can be reconsidered next year after MedDefense builds its internal monitoring capability.

### Rejected Control

**Full medical-device isolation and dedicated monitoring — $60,000**

This control is rejected because its estimated ALE reduction is only $48,000, creating a negative net value of **-$12,000**. MedDefense should instead use lower-cost VLAN separation, password changes and existing monitoring tools.

### Budget Position

```text
Available budget = $120,000
Total spending   = $120,000
Budget remaining = $0
```

---

## Part 2 — Opportunity Cost

By deferring the **outsourced 24/7 SOC**, MedDefense accepts an estimated **$150,000 in annual risk exposure** that continuous monitoring might otherwise reduce.

This residual risk should be partly managed through Wazuh alerts, documented escalation procedures and on-call staff.

---

## Part 3 — Alternative Allocation

A lower cost alternative is to defer the EDR upgrade while funding the other five selected controls.

| Alternative Control  |        Cost |  ALE Reduction |
| -------------------- | ----------: | -------------: |
| MFA                  |     $12000 |     $2387000 |
| Network segmentation |     $35000 |     $2299000 |
| Wazuh SIEM           |     $26000 |       $349847 |
| Westside firewall    |      $9000 |       $190960 |
| Offsite backups      |     $14000 |        $74403 |
| **Total**            | **$96000** | **$5301210** |

### Compare the Allocations

| Allocation             |     Cost | Estimated ALE Reduction |
| ---------------------- | -------: | ----------------------: |
| Primary recommendation | $120000 |              $5555829 |
| Alternative allocation |  $96000 |              $5301210 |
| Difference             |  $24000 |                $254619 |

The alternative costs **$24,000 less** while retaining about **95%** of the calculated risk reduction. However, the primary plan is preferred because EDR adds an important protection layer against ransomware and malware.

> These reductions overlap because several controls address the same risks. The totals are useful for comparing options but should not be treated as completely independent savings.

