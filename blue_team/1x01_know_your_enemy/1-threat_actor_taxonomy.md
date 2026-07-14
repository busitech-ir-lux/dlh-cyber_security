# Threat Actor Taxonomy

## Report A

**Actor Type:** Nation-state
**Internal/External:** External — the attackers entered through a zero-day VPN vulnerability.
**Resources:** High — they used a zero-day, stolen certificate and long-term infrastructure.
**Sophistication:** High — custom malware, encrypted DNS communication and 14 months of hidden access show advanced capability.
**Primary Motivation:** Espionage — the target was valuable pharmaceutical research and clinical trial data.
**Confidence Level:** High — the target, long dwell time and advanced tools strongly match nation-state behavior.

---

## Report B

**Actor Type:** Organized crime
**Internal/External:** External — access started through a malicious email sent to hospital employees.
**Resources:** Medium — the attackers used commercial malware and known vulnerabilities rather than custom tools.
**Sophistication:** Medium — they combined phishing, data theft, ransomware and double extortion.
**Primary Motivation:** Financial gain — they demanded 40 Bitcoin and threatened to publish patient records.
**Confidence Level:** High — ransomware, a payment demand and data extortion clearly indicate financially motivated criminals.

---

## Report C

**Actor Type:** Hacktivist
**Internal/External:** External — the public website was attacked from outside the hospital.
**Resources:** Low — the group used a known SQL injection weakness and only modified the website.
**Sophistication:** Low to Medium — exploiting SQL injection requires some technical ability, but no advanced tools or lateral movement were used.
**Primary Motivation:** Philosophical or political beliefs — the attackers protested the closure of a free community clinic.
**Confidence Level:** High — the protest message, activist logo and absence of financial demands strongly indicate hacktivism.

---

## Report D

**Actor Type:** Insider threat
**Internal/External:** Internal — the attacker was a former administrator who used knowledge and access gained inside the company.
**Resources:** Low — no expensive tools or external funding were required.
**Sophistication:** Medium — the administrator prepared the attack by creating a hidden VPN account and disabling backups.
**Primary Motivation:** Revenge — the destructive actions occurred immediately after the administrator was terminated.
**Confidence Level:** High — the home IP address, account creation and backup changes directly connect the former employee to the incident.

---

## Report E

**Actor Type:** Unskilled attacker
**Internal/External:** External — automated scanning found an exposed vulnerability in the clinic’s remote management software.
**Resources:** Low — the attackers used a public exploit and publicly available mining software.
**Sophistication:** Low — the campaign was automated and did not include lateral movement, persistence or patient-data theft.
**Primary Motivation:** Financial gain — the attackers used the clinic’s computers to generate cryptocurrency.
**Confidence Level:** High — the same wallet across hundreds of infections shows broad opportunistic activity rather than targeted crime.

---

## Report F

**Actor Type:** Shadow IT
**Internal/External:** Internal as the original cause, followed by an external attacker — an employee introduced an unauthorized device, which was later compromised from the internet.
**Resources:** Low — the employee used a personal Raspberry Pi, and the attacker used default credentials.
**Sophistication:** Low — neither the unauthorized installation nor the compromise required advanced tools.
**Primary Motivation:** Ethical motivation — the employee claimed the device was intended to monitor performance, not cause harm.
**Confidence Level:** High — the unauthorized personal device clearly meets the definition of shadow IT.

The employee was not malicious, but the unsupported device created an entry point that allowed an external attacker to reach a critical medical system.

---

## Report G

**Actor Type:** Organized crime is the provisional classification, but a malicious insider is also possible.
**Internal/External:** Could be either — an external attacker may have stolen the physician’s credentials, or an insider may have used the account to hide their identity.
**Resources:** Medium — the attacker maintained access for six weeks and selected records with potentially valuable insurance information.
**Sophistication:** Medium — the use of valid credentials, off-hours access and selective downloading suggests planned activity.
**Primary Motivation:** Financial gain — patients with high-value insurance plans may have been selected for insurance fraud or identity theft.
**Confidence Level:** Low — the behavior shows credential abuse, but it does not identify who controlled the account.

### Why Report G is ambiguous

An **organized crime group** could have stolen the physician’s password through phishing, malware or credential purchasing. The records may have been collected for insurance fraud.

A **malicious insider** could also have used the physician’s credentials to avoid detection. An employee may know which records have the greatest financial value and how to use the hospital system without triggering alerts.

An **unskilled attacker** is less likely because the records were carefully selected and the activity continued for six weeks.

Evidence that would help distinguish the actors includes:

* MFA and login records
* device fingerprints and browser details
* ownership and location of the source IP address
* phishing emails received by the physician
* malware on the physician’s devices
* access logs from other employee accounts
* evidence that the records were used for insurance fraud
* connections between the IP address and hospital employees

---

## Report H

**Actor Type:** Organized crime
**Internal/External:** External — the API was accessed through a Tor exit node by an unknown person.
**Resources:** Low — the attacker used an existing authentication weakness and basic anonymity services.
**Sophistication:** Medium — they identified the broken authentication endpoint, extracted records and provided valid evidence.
**Primary Motivation:** Blackmail — they demanded payment in exchange for silence about the vulnerability and stolen data.
**Confidence Level:** Medium — the extortion clearly shows criminal intent, but there is not enough evidence to determine whether the attacker belongs to an organized group or is acting alone.

