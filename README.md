# DLH Cyber Security Academy Repository

![Security+ Badge](https://img.shields.io/badge/CompTIA-Security%2B-yellow)
![Academy Badge](https://img.shields.io/badge/Luxembourg-CS_Academy-blue)
![Modules](https://img.shields.io/badge/Modules-11_blue_team-green)

Coursework and lab notes from the DLH Cyber Security Academy, organised into two tracks:
foundational study in `common_core/` and applied defensive operations in `blue_team/`.
Content follows the CompTIA Security+ (SY0-701) domains and references NIST and CIS
security frameworks.

<!-- TODO: rewrite the paragraph above in your own voice. Two sentences is the right
     length — what the repo is, and what it maps to. Delete the Modules badge if you
     don't want a count that needs updating. -->

## Repository Structure

| Directory | Description |
| --- | --- |
| [`blue_team/`](blue_team) | Applied defensive operations — eleven progressive modules from SOC fundamentals to perimeter hardening |
| [`common_core/`](common_core) | Foundational coursework across the five Security+ domains |

---

## `blue_team/`

Eleven modules building SOC analyst skills in sequence. Part 1 establishes the
analytical foundations; Part 2 applies them to hardening real systems.

### Part 1 — Foundations

| Module | Focus |
| --- | --- |
| [`1x00_first_watch/`](blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, initial posture assessment |
| [`1x01_know_your_enemy/`](blue_team/1x01_know_your_enemy) | Threat intelligence, threat actor profiling, MITRE ATT&CK mapping |
| [`1x02_the_weak_links/`](blue_team/1x02_the_weak_links) | Vulnerability management, exploit research, remediation prioritisation |
| [`1x03_defense_blueprint/`](blue_team/1x03_defense_blueprint) | Control frameworks (NIST CSF, CIS Controls), risk quantification, governance |
| [`1x04_crypto_foundation/`](blue_team/1x04_crypto_foundation) | Cryptographic principles, PKI, protocol analysis |
| [`1x05_board_briefing/`](blue_team/1x05_board_briefing) | Executive communication, risk reporting, stakeholder management |

### Part 2 — Applied Hardening

| Module | Focus |
| --- | --- |
| [`2x00_locking_the_gates/`](blue_team/2x00_locking_the_gates) | Firewall rule management, access control lists, network segmentation |
| [`2x01_windows_fortress/`](blue_team/2x01_windows_fortress) | Windows hardening, Group Policy, Active Directory security |
| [`2x02_eyes_on_endpoint/`](blue_team/2x02_eyes_on_endpoint) | Endpoint detection and response, Sysmon, host-based monitoring |
| [`2x03_patch_equation/`](blue_team/2x03_patch_equation) | Patch management lifecycle, deployment strategy, compliance scanning |
| [`2x04_perimeter_defense/`](blue_team/2x04_perimeter_defense) | <!-- TODO: describe --> |

<!-- TODO: the Focus column above is inferred from folder names. Open each module and
     correct anything that misrepresents the actual content — an overstated README is
     worse than a sparse one. 2x04 has no obvious sibling to infer from. -->

<!-- TODO: consider adding an "Exercises" column with a count per module. It signals
     volume of work without prose. Count with:
       for d in blue_team/*/; do echo "$d $(ls -1 "$d" | wc -l)"; done -->

---

## `common_core/`

Foundational coursework. Sub-modules use hex-numbered prefixes indicating sequence
within each topic.

| Sub-module | Contents | Security+ Domain |
| --- | --- | --- |
| [`cybersecurity_basics/`](common_core/cybersecurity_basics) | Introduction to cybersecurity, forensic methodologies, cryptography basics, shell basics, processes and signals | 1.0 |
| [`network_security/`](common_core/network_security) | Passive and active reconnaissance, Nmap host discovery, traffic monitoring and analysis | 2.0, 4.0 |
| [`linux_security/`](common_core/linux_security) | Linux security basics, permissions and SUID/SGID, mandatory access control, network protocols | 3.0, 4.0 |
| [`web_application_security/`](common_core/web_application_security) | OWASP Top 10, Burp Suite fundamentals, content discovery, upload vulnerabilities, WEBSEC | 2.0 |
| [`CVE_CWE_and_NVD/`](common_core/CVE_CWE_and_NVD) | Vulnerability identifier ecosystem — CVE records, CWE weakness taxonomy, NVD scoring | 2.0 |
| [`Understanding_Vulnerabilities_Reading/`](common_core/Understanding_Vulnerabilities_Reading) | Reading track on vulnerability concepts, with accompanying tasks | 2.0 |
| [`scripting_cyber/`](common_core/scripting_cyber) | Python scripting for security automation | 4.0 |
| [`threat-modeling-fundamentals/`](common_core/threat-modeling-fundamentals) | Threat modelling methodologies <!-- TODO: which? STRIDE, PASTA, attack trees? --> | 1.0, 2.0 |
| [`security-policy-analysis/`](common_core/security-policy-analysis) | Policy frameworks, compliance requirements, governance | 5.0 |

<!-- TODO: the Security+ Domain column is a proposed mapping, not a verified one.
     Check it against the SY0-701 objectives PDF before publishing. Domains are:
       1.0 General Security Concepts
       2.0 Threats, Vulnerabilities & Mitigations
       3.0 Security Architecture
       4.0 Security Operations
       5.0 Security Program Management & Oversight
     Drop the column entirely if you'd rather not defend the mapping. -->

<!-- TODO: `0x0B_WEBSEC` — expand this to say what it actually covers. -->

### Module Index

<details>
<summary>Full sub-module listing</summary>

**cybersecurity_basics/**
- `0x00_introduction_cybersecurity/`
- `0x02_forensic_methodologies/`
- `0x03_cryptography_basics/`
- `processes_and_signals/`
- `shell_basics/`

**network_security/**
- `0x01_passive_reconnaissance/`
- `0x02_active_reconnaissance/`
- `0x04_nmap_live_hosts_discovery/`
- `0x05_network_traffic_monitoring_analysis/`

**linux_security/**
- `0x00_linux_security_basics/`
- `0x01_permissions_sguid_sgid/`
- `0x02_mandatory_access_control/`
- `network_protocols/`

**web_application_security/**
- `0x01_owasp_top_10/`
- `0x02_burpsuite_fundamentals/`
- `0x04_content_discovery/`
- `0x05_upload_vulnerabilities/`
- `0x0B_WEBSEC/`

**scripting_cyber/**
- `0x01-python_scripting/`

</details>

---

## Certification Alignment

| Certification / Framework | Coverage | Where |
| --- | --- | --- |
| [CompTIA Security+ (SY0-701)](https://www.comptia.org/certifications/security) | All five domains | `common_core/` + `blue_team/` |
| [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) | Identify, Protect, Detect, Respond, Recover | `blue_team/1x03_defense_blueprint/` |
| [CIS Controls v8](https://www.cisecurity.org/controls) | Prioritised security best practices | `blue_team/1x03_defense_blueprint/` |
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary tactics and techniques | `blue_team/1x01_know_your_enemy/` |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Web application risk categories | `common_core/web_application_security/` |

<!-- TODO: delete any row you can't actually back up with content in the repo. -->

---

## Usage

### Learning Paths

| Path | Start Here | Best For |
| --- | --- | --- |
| Foundation First | [`common_core/cybersecurity_basics/`](common_core/cybersecurity_basics) | New learners, Security+ preparation |
| Applied Defense | [`blue_team/1x00_first_watch/`](blue_team/1x00_first_watch) | SOC analyst skills, hands-on practice |
| Web Security | [`common_core/web_application_security/`](common_core/web_application_security) | AppSec focus, OWASP work |

### Recommended Workflow

1. **New learners** — start with `common_core/cybersecurity_basics/`, then work through
   `linux_security/` and `network_security/` before attempting the blue team track.
2. **Security+ candidates** — cover `common_core/` against the SY0-701 objectives, using
   `blue_team/` modules for applied context on weaker domains.
3. **Blue team track** — follow `blue_team/` modules in numerical order; each builds on
   findings documented in the previous one.

---

## Notes on Structure

Modules are prefixed with hex numbers indicating order (`0x00`, `0x01`, …). Blue team
modules use a two-part scheme: `1xNN` for foundations, `2xNN` for applied hardening.

<!-- TODO: two housekeeping items before you publish.

  1. Naming is inconsistent. Most folders use underscores, but
     `security-policy-analysis/` and `threat-modeling-fundamentals/` use hyphens, and
     `0x01-python_scripting/` mixes both. Renaming them to match makes the repo look
     deliberate. If you rename, update the links in this file.

  2. Numbering has gaps: cybersecurity_basics skips 0x01, network_security and
     web_application_security both skip 0x03, and web jumps from 0x05 to 0x0B. If those
     modules exist but aren't committed, say so. If they were never assigned, a one-line
     note here saves readers wondering what they're missing.
-->

---

## License

<!-- TODO: no LICENSE file was visible in the directory listing. If you add one, link it
     here and GitHub will auto-detect it in the sidebar. CC0-1.0 or MIT are common for
     study repos. If the coursework contains material you don't own — provided exercise
     text, vendor PDFs, academy handouts — check you're allowed to redistribute it
     before choosing a permissive licence. -->
