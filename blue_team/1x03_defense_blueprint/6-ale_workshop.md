# 6. The ALE Workshop

## Risk 1 — EHR Patient Data Breach

**Source:** Gap M-01 + Findings 003 and 031 + external attacker or malicious insider

**Asset:** EHR system and 50,000 patient records

### Asset Value

```text
Breach response: 50,000 × $165 = $8,250,000
Notification costs:              $25,000
Litigation exposure:            $200,000
Patient trust/revenue loss:     $600,000

AV = $9,075,000
```

**Exposure Factor:** 100%

A full database breach could expose all patient records and trigger all estimated costs.

```text
SLE = AV × EF
SLE = $9,075,000 × 100%
SLE = $9,075,000
```

**ARO:** 0.333, or approximately once every three years

MedDefense has a flat network, exposed database services, unpatched systems and no SIEM.

```text
ALE = $9,075,000 × 0.333
ALE = $3,025,000 per year
```

**Proposed Control:** Segment the EHR network and restrict database access.

**Control Annual Cost:** $35,000

**Estimated ALE After Control:**

```text
New ARO = 0.08
New ALE = $9,075,000 × 0.08
New ALE = $726,000
```

```text
Net Benefit = $3,025,000 - $726,000 - $35,000
Net Benefit = $2,264,000
```

---

## Risk 2 — VPN Compromise and Full Network Access

**Source:** Gap M-05 + Findings 009 and 019 + BlackReef-style RaaS group, Kill Chain #1

**Asset:** Entire MedDefense network

### Asset Value

```text
EHR breach impact:         $9,075,000
Billing ransomware impact:   $473,000

AV = $9,548,000
```

**Exposure Factor:** 100%

The VPN provides access to the flat network, including the EHR, billing server, Active Directory and backups.

```text
SLE = $9,548,000 × 100%
SLE = $9,548,000
```

**ARO:** 0.30, or approximately once every three years

The VPN is the main remote entry point, MFA is missing and the firewall patching schedule is unknown.

```text
ALE = $9,548,000 × 0.30
ALE = $2,864,400 per year
```

**Proposed Control:** Enable VPN MFA, patch the FortiGate and restrict VPN access.

**Control Annual Cost:** $12,000

**Estimated ALE After Control:**

```text
New ARO = 0.05
New ALE = $9,548,000 × 0.05
New ALE = $477,400
```

```text
Net Benefit = $2,864,400 - $477,400 - $12,000
Net Benefit = $2,375,000
```

---

## Risk 3 — Negligent Insider Data Exposure

**Source:** Gap M-07 + Finding 024 + negligent insider threat

**Asset:** Patient data available through clinical workstations and PACS

### Asset Value

```text
Investigation:          $30,000
Containment:            $25,000
Remediation:            $40,000
Regulatory reporting:   $25,000

AV = $120,000
```

**Exposure Factor:** 100%

The value already represents the expected cost of one complete insider incident.

```text
SLE = $120,000 × 100%
SLE = $120,000
```

**ARO:** 2.5 incidents per year

MedDefense has 2,000 employees, shared accounts, no DLP, no USB restrictions and no formal awareness program.

```text
ALE = $120,000 × 2.5
ALE = $300,000 per year
```

**Proposed Control:** Deploy USB restrictions, individual accounts, DLP and security training.

**Control Annual Cost:** $28,000

**Estimated ALE After Control:**

```text
New ARO = 0.8
New ALE = $120,000 × 0.8
New ALE = $96,000
```

```text
Net Benefit = $300,000 - $96,000 - $28,000
Net Benefit = $176,000
```

---

## Risk 4 — Ransomware on Billing Server and Backups

**Source:** Gap M-02 + Findings 001, 002 and 015 + BlackReef-style RaaS group

**Asset:** Billing server, financial records and backups

### Asset Value

```text
Revenue loss: $16,000 × 18 days = $288,000
Recovery and investigation:       $85,000
Regulatory penalty:              $100,000

AV = $473,000
```

**Exposure Factor:** 100%

A serious ransomware attack could stop billing, require system rebuilding and expose regulated information.

```text
SLE = $473,000 × 100%
SLE = $473,000
```

**ARO:** 0.286, or approximately once every 3.5 years

The server is outdated, vulnerable and connected to backups on the production network.

```text
ALE = $473,000 × 0.286
ALE = $135,278 per year
```

**Proposed Control:** Patch the server and create encrypted, immutable and isolated backups.

**Control Annual Cost:** $24,000

**Estimated ALE After Control:**

The controls reduce the incident frequency and limit the loss to approximately 40%.

```text
New SLE = $473,000 × 40%
New SLE = $189,200

New ALE = $189,200 × 0.10
New ALE = $18,920
```

```text
Net Benefit = $135,278 - $18,920 - $24,000
Net Benefit = $92,358
```

---

## Risk 5 — Medical Device Compromise

**Source:** Gap M-03 + Findings 010 and 016 + opportunistic attacker

**Asset:** Seven infusion pumps and connected clinical services

### Asset Value

```text
Patient safety liability:      $2,750,000
FDA investigation:              $150,000
Disruption: $20,000 × 5 days =  $100,000

AV = $3,000,000
```

**Exposure Factor:** 100%

A serious compromise could cause patient harm, investigation costs and clinical disruption.

```text
SLE = $3,000,000 × 100%
SLE = $3,000,000
```

**ARO:** 0.02, or approximately once every 50 years

The event is unlikely, but default credentials and the flat network increase the possibility.

```text
ALE = $3,000,000 × 0.02
ALE = $60,000 per year
```

**Proposed Control:** Isolate medical devices, remove default credentials and restrict network traffic.

**Control Annual Cost:** $18,000

**Estimated ALE After Control:**

```text
New ARO = 0.005
New ALE = $3,000,000 × 0.005
New ALE = $15,000
```

```text
Net Benefit = $60,000 - $15,000 - $18,000
Net Benefit = $27,000
```

# Risk Prioritization by ALE

| Rank | Risk                       | ALE Before | ALE After Control | Control Cost | Net Benefit |
| ---: | -------------------------- | ---------: | ----------------: | -----------: | ----------: |
|    1 | EHR patient data breach    | $3,025,000 |          $726,000 |      $35,000 |  $2,264,000 |
|    2 | VPN compromise             | $2,864,400 |          $477,400 |      $12,000 |  $2,375,000 |
|    3 | Negligent insider exposure |   $300,000 |           $96,000 |      $28,000 |    $176,000 |
|    4 | Billing ransomware         |   $135,278 |           $18,920 |      $24,000 |     $92,358 |
|    5 | Medical device compromise  |    $60,000 |           $15,000 |      $18,000 |     $27,000 |

**Total estimated control cost:**

```text
$35,000 + $12,000 + $28,000 + $24,000 + $18,000
= $117,000
```

The VPN and EHR risks overlap because a VPN compromise may lead to an EHR breach. Their ALE values should therefore not be added together as if they were completely separate losses.

