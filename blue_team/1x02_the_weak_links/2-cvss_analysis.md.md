### The CVSS Deconstruction

**Goal:** _Master the CVSS v3.1 scoring system by deconstructing, constructing and comparing scores using the NIST Calculator._

---

**Context:** A CVSS score without understanding is a number. A CVSS score with understanding is a decision tool. This task turns the former into the latter.

Open the **[NIST CVSS v3.1 Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)** in your browser

You will use it for all three exercises.

---

**Instructions:**

**Exercise 1: Deconstruction**

Take the following CVSS vector string from the scan report (Finding 001, CVE-2021-44790):

```ruby
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

For each component, explain:

- What the abbreviation stands for
    
- What the selected value means
    
- What other values are possible and how they would change the score
    
- Why this specific value was selected for this vulnerability
    

Then answer: If the Attack Vector was changed from Network (N) to Local (L), what would the new score be ? Calculate it on the NIST Calculator and explain why the score changes.

**Exercise 2: Construction**

You discover a vulnerability with these characteristics:

- Exploitable only from the local network (not the internet)
    
- Exploitation is complex and requires specific conditions
    
- The attacker needs low-level privileges
    
- No user interaction is needed
    
- The vulnerability only affects the targeted system (scope unchanged)
    
- Successful exploitation compromises confidentiality completely
    
- No impact on integrity
    
- No impact on availability
    

Build the CVSS vector string manually. Then enter it into the NIST Calculator and verify your score. Document the vector string, the calculated score and the severity rating.

**Exercise 3: Comparison**

Select two findings from the scan report: one with a CVSS score above 9.0 and one with a score between 5.0 and 7.0. Enter both vector strings into the calculator side by side. Identify the **specific components** that explain the score difference. Which components have the biggest impact on the final score ?

---

# Answer

# 2. The CVSS Deconstruction

All scores were checked using the NIST CVSS v3.1 Calculator. CVSS v3.1 uses eight mandatory Base metrics and produces a score from 0.0 to 10.0.

---

# Exercise 1: Deconstruction

## Original vulnerability

**Finding:** Finding 001 — CVE-2021-44790  
**Original vector:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Base Score:** 9.8  
**Severity:** Critical

The scan describes an Apache `mod_lua` buffer overflow that can be triggered through a crafted HTTP request and may allow unauthenticated remote code execution.

## Metric-by-metric explanation

|Component|Meaning and selected value|Other possible values|Reason for this vulnerability|
|---|---|---|---|
|**AV:N**|**Attack Vector: Network.** The vulnerability can be exploited remotely through the network.|Adjacent `A`, Local `L`, Physical `P`. More restrictive access normally lowers the score.|The attacker can send a crafted HTTP request to the Apache server without first obtaining local system access.|
|**AC:L**|**Attack Complexity: Low.** No unusual condition outside the attacker’s control is required.|High `H`, which would lower the score because exploitation would depend on special conditions.|The scan states that a crafted request body can trigger the vulnerability. It does not identify a race condition or special environmental requirement.|
|**PR:N**|**Privileges Required: None.** The attacker does not need an account or prior access.|Low `L` or High `H`. Requiring privileges reduces the score.|The vulnerability is described as exploitable without authentication.|
|**UI:N**|**User Interaction: None.** No other user must perform an action.|Required `R`, which lowers the score.|The attacker communicates directly with the web server. No victim needs to open a file or click a link.|
|**S:U**|**Scope: Unchanged.** The vulnerable and affected resources remain under the same security authority.|Changed `C`, where exploitation crosses into a different security authority. Changed scope generally increases the score.|Exploitation compromises resources controlled by the same Apache host and operating system.|
|**C:H**|**Confidentiality: High.** Successful exploitation could expose sensitive system and application information.|Low `L` or None `N`, which would reduce the impact score.|Remote code execution could allow the attacker to read application data, credentials and system files.|
|**I:H**|**Integrity: High.** The attacker could make serious or unrestricted modifications.|Low `L` or None `N`.|Arbitrary code execution could allow modification of files, applications, configurations and billing data.|
|**A:H**|**Availability: High.** Exploitation could seriously interrupt the service or system.|Low `L` or None `N`.|The attacker could crash Apache, stop services, damage files or take the billing server offline.|

FIRST defines Network attacks as remotely reachable, Low complexity as not requiring special conditions, and None for privileges or interaction when the attacker can exploit the system directly. It defines High confidentiality, integrity and availability impacts as serious or complete losses in those areas.

## Changing Attack Vector from Network to Local

### Modified vector

```text
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Calculator result

|Result|Value|
|---|--:|
|**New Base Score**|**8.4**|
|**Severity**|**High**|
|**Original score**|9.8 Critical|
|**Score reduction**|1.4 points|

### Why the score changes

Changing `AV:N` to `AV:L` means the vulnerability can no longer be exploited directly through the network. The attacker must first obtain local read, write or execution capabilities on the system.

This reduces the number of potential attackers and makes the vulnerability less accessible. The confidentiality, integrity and availability impacts remain High, but the **Exploitability Subscore decreases**.

CVSS assigns Network an Attack Vector weight of `0.85` and Local a weight of `0.55`. All other metrics remain unchanged, so the reduced Attack Vector value changes the score from **9.8 Critical** to **8.4 High**.

---

# Exercise 2: Construction

## Scenario analysis

|Scenario characteristic|CVSS selection|Reason|
|---|---|---|
|Exploitable only from the local network|`AV:A`|The attack is limited to a logically adjacent network, interpreted here as the same local subnet.|
|Complex exploitation requiring specific conditions|`AC:H`|Exploitation depends on conditions outside the attacker’s direct control.|
|Low-level privileges required|`PR:L`|The attacker must already have a normal or limited account.|
|No user interaction|`UI:N`|No separate user must take an action.|
|Only the targeted system is affected|`S:U`|The impact remains within the same security authority.|
|Complete confidentiality compromise|`C:H`|The attacker can access all or highly sensitive protected information.|
|No integrity impact|`I:N`|The attacker cannot modify data or system resources.|
|No availability impact|`A:N`|The attacker cannot interrupt the system or service.|

## Constructed vector

```text
CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
```

## Calculator result

|Result|Value|
|---|--:|
|**CVSS Base Score**|**4.8**|
|**Severity**|**Medium**|

The score remains Medium because the vulnerability has a serious confidentiality impact, but exploitation is restricted by three important factors:

- the attacker must be on an adjacent network
    
- exploitation has High complexity
    
- the attacker already needs Low privileges
    

It also has no integrity or availability impact. CVSS v3.1 classifies scores from 4.0 to 6.9 as Medium.

## Important interpretation note

In CVSS, “local network” does not always automatically mean `AV:A`.

`AV:A` is correct when exploitation is restricted to the same local subnet or another logically adjacent network. If the attack can travel across routed internal networks within the organization, FIRST recommends using `AV:N`, even when the system is not reachable from the public internet.

Under that alternative interpretation, the vector would be:

```text
CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
```

That vector produces a score of **5.3 Medium**.

---

# Exercise 3: Comparison

## Selection issue

The scan report does not contain an explicitly scored finding between **5.0 and 7.0**. Its stated numerical CVSS scores are primarily 7.5, 7.8, 8.1, 8.8, 9.8 and 10.0.

To complete the exercise correctly, I selected:

1. **Finding 001**, which has a documented 9.8 vector.
    
2. **Finding 017**, a Medium Tomcat information-disclosure finding without a scanner-provided CVSS vector.
    

For Finding 017, I constructed a reasonable Base vector from the report’s description. This is an **analyst-assigned score**, not a score supplied by SecurePoint or NVD.

## Finding A: Apache remote code execution

**Finding:** Finding 001  
**CVE:** CVE-2021-44790

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Score:** 9.8 Critical

## Finding B: Tomcat error-page information disclosure

**Finding:** Finding 017  
**Analyst-constructed vector:**

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
```

**Calculated score:** 5.3 Medium

The vector assumes:

- the Tomcat error page is network-accessible
    
- no authentication is required to trigger it
    
- no user interaction is required
    
- the disclosed information is limited
    
- the finding does not directly permit modification or service interruption
    

## Side-by-side comparison

|Metric|Finding 001|Finding 017|Effect on score|
|---|---|---|---|
|**Attack Vector**|Network|Network|No difference|
|**Attack Complexity**|Low|Low|No difference|
|**Privileges Required**|None|None|No difference|
|**User Interaction**|None|None|No difference|
|**Scope**|Unchanged|Unchanged|No difference|
|**Confidentiality**|High|Low|Finding 001 can expose much more sensitive information|
|**Integrity**|High|None|Finding 001 can modify files, data and configurations|
|**Availability**|High|None|Finding 001 can disrupt or disable the service|
|**Final score**|**9.8 Critical**|**5.3 Medium**|The difference is produced entirely by the Impact metrics|

## Components explaining the score difference

Both findings are equally accessible according to the selected Exploitability metrics:

```text
AV:N/AC:L/PR:N/UI:N/S:U
```

The difference comes from the three Impact metrics:

```text
Finding 001: C:H/I:H/A:H
Finding 017: C:L/I:N/A:N
```

Finding 001 can cause serious losses to all three security objectives:

- confidentiality
    
- integrity
    
- availability
    

Finding 017 only reveals a limited amount of information and does not directly modify data or interrupt the service.

## Which components have the biggest impact?

For this comparison, **Integrity and Availability have the largest combined effect**, because they change from `None` to `High`. Confidentiality also increases from `Low` to `High`.

Attack Vector, Attack Complexity, Privileges Required, User Interaction and Scope cannot explain the difference because they are identical in both vectors.

This comparison shows that easy remote access does not automatically create a Critical score. A vulnerability also needs sufficient impact. Finding 017 is easy to reach but has limited direct impact, while Finding 001 combines easy exploitation with complete confidentiality, integrity and availability consequences.