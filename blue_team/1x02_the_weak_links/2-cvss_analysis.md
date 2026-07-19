# The CVSS Deconstruction

## Exercise 1: Deconstruction

**Vector:**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Score: 9.8 — Critical**

| Metric   | Meaning                                                   | Other values                                      | Why selected                                   |
| -------- | --------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------- |
| **AV:N** | Attack Vector: Network. Exploitable remotely.             | Adjacent, Local, Physical. These lower the score. | The attacker sends a request over the network. |
| **AC:L** | Attack Complexity: Low. No special conditions are needed. | High. This lowers the score.                      | A crafted request can trigger the flaw.        |
| **PR:N** | Privileges Required: None.                                | Low or High. These lower the score.               | No login is required.                          |
| **UI:N** | User Interaction: None.                                   | Required. This lowers the score.                  | No user action is needed.                      |
| **S:U**  | Scope: Unchanged. Only the vulnerable system is affected. | Changed. This may increase the score.             | The attack affects the same server.            |
| **C:H**  | Confidentiality impact: High.                             | Low or None. These lower the score.               | The attacker may read sensitive data.          |
| **I:H**  | Integrity impact: High.                                   | Low or None.                                      | The attacker may change files or data.         |
| **A:H**  | Availability impact: High.                                | Low or None.                                      | The attacker may stop or damage the service.   |

### Attack Vector changed to Local

**New vector:**

`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**New score: 8.4 — High**

The score decreases because the attacker must first have local access instead of attacking remotely.

---

## Exercise 2: Construction

**Vector:**

`CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Calculated score: 4.8**

**Severity: Medium**

The score is Medium because the attacker needs local-network access, low privileges and specific conditions. Only confidentiality is affected.

---

## Exercise 3: Comparison

The scan does not contain an explicit CVSS score between 5.0 and 7.0. Therefore, Finding 017 is scored manually from its description.

### Finding 001

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Score: 9.8 — Critical**

### Finding 017

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Score: 5.1 — Medium**

### Main differences

| Metric          | Finding 001 | Finding 017 |
| --------------- | ----------- | ----------- |
| Confidentiality | High        | Low         |
| Integrity       | High        | None        |
| Availability    | High        | None        |

The Impact metrics have the biggest effect. Finding 001 can seriously affect confidentiality, integrity and availability, while Finding 017 only causes limited information disclosure.

