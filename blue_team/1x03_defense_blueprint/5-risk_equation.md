# 5. The Risk Equation

## Scenario 1 — Ransomware on Billing Server

### Asset Value

The full annual transaction value of **$4.2 million** would not necessarily be lost. The main expected costs are:

```text
Downtime = $16,000 × 18 days = $288,000
Recovery costs = $85,000
HIPAA penalty = $100,000

AV = $288,000 + $85,000 + $100,000
AV = $473,000
```

### Exposure Factor

**EF = 100%**

A successful ransomware incident would probably trigger most of these costs.

### Single Loss Expectancy

```text
SLE = AV × EF
SLE = $473,000 × 1.00
SLE = $473,000
```

### Annualized Rate of Occurrence

The expected frequency is once every 3–4 years. Using the midpoint of 3.5 years:

```text
ARO = 1 ÷ 3.5
ARO = 0.286
```

### Annualized Loss Expectancy

```text
ALE = SLE × ARO
ALE = $473,000 × 0.286
ALE = $135,278 per year
```

**Confidence:** Medium
The result would change most if the estimated ransomware frequency or downtime length is incorrect.

---

## Scenario 2 — Patient Data Breach Through EHR

### Asset Value

```text
Record breach cost = 50,000 × $165 = $8,250,000
Notification costs = $25,000
Litigation = $200,000
Lost revenue = $600,000

AV = $8,250,000 + $25,000 + $200,000 + $600,000
AV = $9,075,000
```

### Exposure Factor

**EF = 100%**

This assumes that all 50,000 patient records are exposed and all listed costs occur.

### Single Loss Expectancy

```text
SLE = $9,075,000 × 1.00
SLE = $9,075,000
```

### Annualized Rate of Occurrence

The estimated frequency is once every three years:

```text
ARO = 1 ÷ 3
ARO = 0.333
```

### Annualized Loss Expectancy

```text
ALE = $9,075,000 × 0.333
ALE = $3,025,000 per year
```

**Confidence:** Medium
The largest assumption is that all 50,000 records would be affected. A smaller breach would greatly reduce the ALE.

---

## Scenario 3 — Negligent Insider Data Theft

### Asset Value

The estimated total cost of one negligent insider incident is:

```text
Investigation = $30,000
Containment = $25,000
Remediation = $40,000
Regulatory reporting = $25,000

AV = $30,000 + $25,000 + $40,000 + $25,000
AV = $120,000
```

### Exposure Factor

**EF = 100%**

The $120,000 estimate already represents the expected total cost of one incident.

### Single Loss Expectancy

```text
SLE = $120,000 × 1.00
SLE = $120,000
```

### Annualized Rate of Occurrence

MedDefense expects 2–3 incidents each year. Using the midpoint:

```text
ARO = 2.5
```

### Annualized Loss Expectancy

```text
ALE = $120,000 × 2.5
ALE = $300,000 per year
```

**Confidence:** Medium
The number would change most if MedDefense experiences fewer or more than 2.5 incidents per year.

---

## Scenario 4 — Medical Device Compromise

Two separate risks should be calculated.

### A. Denial-of-Service Event

#### Asset Value

The pumps are not expected to be destroyed. The main costs are operational disruption and investigation:

```text
Operational disruption = $20,000 × 5 days = $100,000
FDA investigation = $150,000

AV = $100,000 + $150,000
AV = $250,000
```

#### Exposure Factor

**EF = 100%**

#### Single Loss Expectancy

```text
SLE = $250,000 × 1.00
SLE = $250,000
```

#### Annualized Rate of Occurrence

Once every ten years:

```text
ARO = 1 ÷ 10
ARO = 0.10
```

#### Annualized Loss Expectancy

```text
ALE = $250,000 × 0.10
ALE = $25,000 per year
```

---

### B. Patient Safety Event

Use the midpoint of the potential liability range:

```text
Liability midpoint = ($500,000 + $5,000,000) ÷ 2
Liability midpoint = $2,750,000

Operational disruption = $100,000
FDA investigation = $150,000

AV = $2,750,000 + $100,000 + $150,000
AV = $3,000,000
```

#### Exposure Factor

**EF = 100%**

#### Single Loss Expectancy

```text
SLE = $3,000,000 × 1.00
SLE = $3,000,000
```

#### Annualized Rate of Occurrence

Once every 50 years:

```text
ARO = 1 ÷ 50
ARO = 0.02
```

#### Annualized Loss Expectancy

```text
ALE = $3,000,000 × 0.02
ALE = $60,000 per year
```

### Combined Medical Device ALE

```text
Combined ALE = $25,000 + $60,000
Combined ALE = $85,000 per year
```

**Confidence:** Low
The patient-safety liability could range from $500,000 to $5 million, so this assumption can greatly change the result.

---

## Scenario 5 — VPN Compromise

### Asset Value

The VPN provides access to both the billing system and the EHR. Therefore, the potential loss is the combined impact of Scenarios 1 and 2:

```text
Billing impact = $473,000
EHR impact = $9,075,000

AV = $473,000 + $9,075,000
AV = $9,548,000
```

### Exposure Factor

**EF = 100%**

This assumes that the attacker successfully reaches the EHR, billing server, Active Directory and backups.

### Single Loss Expectancy

```text
SLE = $9,548,000 × 1.00
SLE = $9,548,000
```

### Annualized Rate of Occurrence

The provided estimated ARO is:

```text
ARO = 0.30
```

### Annualized Loss Expectancy

```text
ALE = $9,548,000 × 0.30
ALE = $2,864,400 per year
```

**Confidence:** Low
The largest assumption is that a VPN compromise would lead to a complete ransomware attack and exposure of all patient records.

# Risk Summary

| Scenario             |         AV |   EF |        SLE |   ARO |        ALE |
| -------------------- | ---------: | ---: | ---------: | ----: | ---------: |
| Billing ransomware   |   $473,000 | 100% |   $473,000 | 0.286 |   $135,278 |
| EHR data breach      | $9,075,000 | 100% | $9,075,000 | 0.333 | $3,025,000 |
| Negligent insider    |   $120,000 | 100% |   $120,000 |   2.5 |   $300,000 |
| Medical-device DoS   |   $250,000 | 100% |   $250,000 |  0.10 |    $25,000 |
| Patient-safety event | $3,000,000 | 100% | $3,000,000 |  0.02 |    $60,000 |
| VPN compromise       | $9,548,000 | 100% | $9,548,000 |  0.30 | $2,864,400 |

These figures are planning estimates, not guaranteed future losses. Their purpose is to compare risks and support security investment decisions.

