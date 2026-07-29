### The ALE Update

**Goal:** _Recalculate MedDefense's ransomware ALE using the new intelligence from the Crimson Tide advisory, demonstrating that threat intelligence directly changes risk quantification._

---

**Context:** In 1x03 T6, you calculated the ALE for a ransomware attack on MedDefense using sector data from the intelligence dossier. The Crimson Tide advisory provides NEW data: 5 confirmed attacks on similar hospitals in 10 days, 3 in your geographic region. The ARO just changed. The ALE must be recalculated.

This is a powerful demonstration of why risk analysis is continuous, not one-time. New intelligence means new numbers. New numbers mean new priorities. New priorities mean new budget decisions.

---

**Instructions:**

**Part 1 - Original vs Updated ALE**

Present your original ransomware ALE calculation from 1x03 T6. Then recalculate using the Crimson Tide data:

- Original ARO: [Your estimate from 1x03, likely 0.2-0.33]
    
- Updated ARO: [Using the new data: 5 attacks on similar hospitals in 10 days in the current threat landscape. What does this suggest?]
    
- Updated ALE: [New SLE × New ARO]
    

Show all work and explain what changed and why.

**Part 2 - Budget Impact**

Does the updated ALE change any of your cost-benefit conclusions from 1x03 T7 ? Specifically:

- Are any controls that were previously "Not Justified" now justified ?
    
- Does the emergency FortiGate support contract renewal ($2,400) have a positive ROI against the updated ALE ?
    
- Should the Board approve emergency spending beyond the $120,000 budget ?

---
# Answer

# 5. The ALE Update

## Part 1 — Original vs Updated ALE

### Original ransomware ALE from 1x03 T6

The original scenario estimated a ransomware incident affecting `billing-srv-01`.

### Original Single Loss Expectancy

|Loss component|Calculation|Amount|
|---|--:|--:|
|Operational downtime|$16,000 per day × 18 days|$288,000|
|Recovery and investigation|Estimated cost|$85,000|
|Regulatory penalty|Estimated HIPAA-related cost|$100,000|
|**Total SLE**|$288,000 + $85,000 + $100,000|**$473,000**|

The exposure factor was 100%, so:

```text
SLE = Asset Value × Exposure Factor
SLE = $473,000 × 100%
SLE = $473,000
```

### Original Annual Rate of Occurrence

The original estimate assumed one successful ransomware incident approximately every 3.5 years:

```text
ARO = 1 ÷ 3.5
ARO = 0.286
```

### Original Annualised Loss Expectancy

```text
ALE = SLE × ARO
ALE = $473,000 × 0.286
ALE = $135,278 per year
```

## Original result

**Original ransomware ALE: $135,278 per year**

The original intelligence already identified healthcare ransomware as a major threat, with public-facing system exploitation as the most common entry route and an average hospital downtime of 18 days.

---

## Updated ARO using Crimson Tide intelligence

The Crimson Tide advisory reports:

- five successful attacks against similar hospitals in ten days;
    
- three attacks in MedDefense’s geographic region;
    
- an attack profile that directly matches MedDefense;
    
- active exploitation of MedDefense’s vulnerable FortiGate model and version;
    
- the same flat-network, Active Directory and backup weaknesses present at MedDefense.
    

The five incidents cannot be converted directly into a precise per-hospital ARO because the advisory does not state the total number of hospitals exposed to the campaign. For example, annualising five attacks in ten days would produce 182.5 attacks per year across the target population, not 182.5 attacks per individual hospital.

For an organisation-specific risk assessment, a reasonable emergency estimate is:

## **Updated ARO: 1.0**

This means MedDefense should plan on the possibility of **one successful ransomware event within the next year** while:

- the campaign remains active;
    
- FortiOS 7.0.9 remains exposed;
    
- SSL-VPN remains enabled;
    
- the network remains flat;
    
- backups remain accessible from production;
    
- no effective central monitoring is operating.
    

An ARO of 1.0 does not mean an incident is guaranteed. It means the threat is now sufficiently immediate and organisation-specific that treating it as only a once-in-3.5-years event is no longer defensible.

### Updated SLE

To isolate the effect of the new threat intelligence, the original SLE remains:

```text
Updated SLE = $473,000
```

This is conservative. Crimson Tide’s observed ransom demands alone range from $1.2 million to $3.5 million, and the affected hospitals also experienced data theft, large-scale encryption and extended downtime.

### Updated ALE

```text
Updated ALE = SLE × Updated ARO

Updated ALE = $473,000 × 1.0

Updated ALE = $473,000 per year
```

## Comparison

|Measure|Original|Updated|
|---|--:|--:|
|SLE|$473,000|$473,000|
|ARO|0.286|1.0|
|ALE|$135,278|**$473,000**|
|Increase|—|**$337,722**|
|Relative increase|—|**Approximately 250%**|
|Risk multiplier|—|**Approximately 3.5×**|

### What changed?

The SLE did not change in this calculation. The likelihood changed because the new intelligence is:

- current rather than historical;
    
- specific to regional hospitals;
    
- based on confirmed successful attacks;
    
- associated with a vulnerability MedDefense currently has;
    
- associated with an attack chain that matches MedDefense’s known gaps.
    

This demonstrates why ALE must be reviewed continuously. A technically unchanged environment can become much riskier when the external threat landscape changes.

---

# Part 2 — Budget Impact

## Are previously “Not Justified” controls now justified?

### 1. Full medical-device isolation and monitoring

The original analysis estimated:

|Item|Original value|
|---|--:|
|Annual control cost|$60,000|
|Estimated annual loss reduction|$48,000|
|Original net value|**−$12,000**|
|Original decision|**Not Justified**|

If the related annual benefit increases in proportion to the ransomware ARO:

```text
Threat-frequency multiplier = 1.0 ÷ 0.286
Threat-frequency multiplier ≈ 3.50

Updated annual benefit = $48,000 × 3.50
Updated annual benefit ≈ $167,832

Updated net benefit = $167,832 − $60,000
Updated net benefit ≈ $107,832
```

**Updated decision: Justified**

The strongest justification is the **isolation component**. Crimson Tide uses the flat network to move between workstations, servers and medical-device environments. Medical devices may not be directly encrypted, but they can become non-functional when EHR and PACS backends are unavailable.

---

### 2. Outsourced 24/7 managed SOC

The previous CFO scenario estimated:

|Item|Original value|
|---|--:|
|Annual SOC cost|$180,000|
|Original annual loss reduction|$120,000|
|Original net value|**−$60,000**|
|Original decision|**Not Justified using ALE alone**|

Applying the same threat-frequency multiplier:

```text
Updated annual benefit = $120,000 × 3.50
Updated annual benefit ≈ $419,580

Updated net benefit = $419,580 − $180,000
Updated net benefit ≈ $239,580
```

```text
ROI = Net Benefit ÷ Control Cost × 100

ROI = $239,580 ÷ $180,000 × 100
ROI ≈ 133%
```

**Updated decision: Financially justified**

The advisory reports an average attacker dwell time of four to seven days. Continuous monitoring could detect FortiGate anomalies, credential abuse, Rclone, large outbound transfers, backup deletion and unauthorised GPO creation before ransomware deployment.

A full annual SOC contract may still require procurement review, but the updated risk supports immediate managed detection or incident-response coverage.

---

## FortiGate support renewal ROI

### Cost

```text
FortiGate support renewal = $2,400 per year
Updated ransomware ALE = $473,000 per year
```

The support renewal enables MedDefense to obtain the firmware that removes the campaign’s confirmed initial-access vulnerability.

### Break-even analysis

The contract needs to reduce the updated ransomware risk by only:

```text
Break-even reduction = Control Cost ÷ Updated ALE

Break-even reduction = $2,400 ÷ $473,000

Break-even reduction = 0.00507
Break-even reduction ≈ 0.51%
```

Therefore, the contract has a positive return if renewing support and patching reduce ransomware risk by more than approximately **0.51%**.

Even using an extremely conservative 1% reduction:

```text
Expected benefit = $473,000 × 1%
Expected benefit = $4,730

Net benefit = $4,730 − $2,400
Net benefit = $2,330
```

The actual reduction should be considerably higher because CVE-2023-27997 is the campaign’s documented initial-access vector.

## Decision

**Yes, the $2,400 FortiGate support renewal has a strongly positive ROI and should be approved immediately.**

It is also operationally necessary because MedDefense cannot obtain the official firmware without renewing the contract.

---

## Should the Board approve spending beyond the $120,000 budget?

**Yes.**

The $120,000 budget was based on an older threat-frequency estimate. The revised ALE has increased from **$135,278 to $473,000 per year**, while the advisory shows that the threat is already affecting comparable hospitals in the region.

The Board should authorise a separate, controlled emergency allocation for:

1. the $2,400 FortiGate support renewal;
    
2. emergency Fortinet or network-vendor assistance;
    
3. external incident-response or forensic support if compromise indicators are found;
    
4. immutable or isolated backup capacity;
    
5. short-term 24/7 monitoring during the active campaign;
    
6. accelerated segmentation and EDR deployment.
    

This should not be an unlimited emergency budget. Each expenditure should have:

- a defined owner;
    
- a spending cap;
    
- a specific attack phase it reduces;
    
- an implementation deadline;
    
- a measurable expected benefit;
    
- Board reporting and review.
    

## Final conclusion

The updated intelligence increases the ransomware ALE by approximately **3.5 times**, from **$135,278 to $473,000 per year**. Controls previously rejected because their annual cost exceeded their quantified benefit—particularly 24/7 monitoring and comprehensive medical-device isolation—now become financially defensible. The FortiGate support renewal requires only a **0.51% risk reduction** to break even, making it an immediate and obvious approval. The Board should therefore approve emergency spending beyond the original $120,000 budget because that budget was based on risk assumptions that are no longer valid.
