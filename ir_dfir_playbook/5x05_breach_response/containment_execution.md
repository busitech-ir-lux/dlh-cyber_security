# Containment Execution — IR-2026-0420-01

**Record type:** Append-only execution worksheet. **State:** NOT EXECUTED / pending operator evidence. All timestamps UTC. Do not replace `PENDING` with invented timestamps or claim success without saved results. On each real action, append an immutable completed row and an `ACTION` entry to `incident_timeline.md`.

## Preflight — scope and authority

| UTC | Actor | Action | Expected outcome | Observed outcome | Deviation / evidence |
|---|---|---|---|---|---|
| PENDING | Incident Commander + Clinical Operations | Authorize phased containment; verify clinical fallback/downtime procedures | Approval and patient-care plan recorded | NOT EXECUTED | Approval needed for `FILE-SVR-01` and `SCHED-SVR-01` |
| PENDING | IR analyst / SIEM operator | Verify hosts, domains, account and current sessions in full endpoint/proxy/firewall logs | Confirm indicators and sixth-host scope | NOT EXECUTED | Sample files alone are not confirmation |
| PENDING | Evidence team | Verify WS-101 memory hash and capture remaining volatile evidence, including host connection tables, process trees, RAM, and server logs | Preserve prior-to-change state | NOT EXECUTED | WS-101 capture reported at 19:38Z; no acquisition SHA-256; see Task 1 |

## Step-by-step containment order

| UTC | Actor | Action | Expected outcome | Observed outcome | Deviation / evidence |
|---|---|---|---|---|---|
| PENDING | Network engineer | After a fast pre-block snapshot of egress flow/session logs, add logged **deny** rule for destination IP `45.152.66.114` and validated domain `staging.office365-cdn.net` at DNS/proxy; cover direct-IP traffic and all VLANs | New C2 requests blocked, existing sessions terminated if supported | NOT EXECUTED | Save firewall rule ID, scope, change ticket and logs; no global untested DNS wildcard |
| PENDING | EDR operator + evidence acquirer | Confirm WS-101 memory already captured; capture other volatile state if possible; isolate `CS-WS-101` with EDR | No lateral/Internet communications; forensic host remains powered on | NOT EXECUTED | Save console operation ID and status |
| PENDING | EDR operator + evidence acquirer | Capture volatile state then isolate `CS-WS-104` | Block workstation lateral movement | NOT EXECUTED | Save memory hash and isolation proof |
| PENDING | EDR operator + evidence acquirer | Capture volatile state then isolate `CS-WS-107` | Block workstation lateral movement | NOT EXECUTED | Save memory hash and isolation proof |
| PENDING | EDR operator + evidence acquirer | Capture volatile state then isolate `CS-WS-112` | Block workstation lateral movement | NOT EXECUTED | Save memory hash and isolation proof |
| PENDING | Server owner + Network + Clinical Operations | Collect `FILE-SVR-01` volatile state/access logs; apply host firewall/network ACL restricting **all non-essential** ingress and egress, including attacker IP; allow only clinical endpoints expressly approved by owner | PHI file service preserved where required; attacker paths blocked | NOT EXECUTED | Do not assume no beacon: proxy/Sysmon samples suggest server activity; emergency full isolation if active harm persists |
| PENDING | Server owner + Network + Clinical Operations | **Additional suspected asset:** capture `SCHED-SVR-01` RAM/processes/flows; limit network to approved clinical dependencies; if malicious execution continues, activate downtime workflow and isolate | Maintain scheduling function if safe; stop attacker reachability | NOT EXECUTED | Sixth asset was not in original five-host task; record escalation and extended scope |
| PENDING | Identity administrator | Enumerate identities from **full 72-hour** AD logons, DC events, EDR, file access, service mappings; identify shared/service/privileged accounts | Complete exposed-account list, not only `jdoe` | NOT EXECUTED | Sample shows `MEDDEFENSE\jdoe`; it does not establish all affected accounts |
| PENDING | Identity administrator + application owners | Revoke exposed user sessions, disable/reset compromised interactive and privileged accounts with clean admin access; coordinate dependent service-account rotation and application cutover | Existing stolen credentials/sessions invalidated without uncontrolled clinical outage | NOT EXECUTED | Record identities, token/ticket invalidation, DC replication and retest; password reset alone does not invalidate all NTLM material/sessions |
| PENDING | Network/SIEM analyst | Confirm no successful outbound sessions to C2 in firewall/proxy logs **after** rule time; EDR confirms quarantines, inspect attempted blocked flows and per-host socket status | Demonstrable C2 severance; alerts for any continuing attempts | NOT EXECUTED | Record post-rule start/end times and log search output; historical sample entries cannot prove containment |
| PENDING | Clinical Operations + IR analyst | Test clinical file access, scheduling and other critical dependencies from **clean** stations | Safe continued patient-care operations or controlled downtime | NOT EXECUTED | Record test URLs/outcomes without exposing PHI |

## Suggested verification commands (adapt field names to actual exports)

**List pre-containment C2 host/IP observations in the sample** (context only):

```bash
jq -r 'select(.dst_ip=="45.152.66.114") | [.ts,.host,.src_ip,.dst_ip,.status] | @tsv' proxy_72h.sample.jsonl
```

**Review suspicious process and ransomware staging in sample** (context only):

```bash
jq -r 'select((.image // "" | ascii_downcase | contains("svchost32.exe")) or (.target // "" | ascii_downcase | contains("encryption_staging.ps1"))) | [.ts,.host,(.event_type // ""),(.image // ""),(.target // "")] | @tsv' sysmon_multihost.sample.jsonl
```

**Live verification:** Query central firewall/proxy/SIEM records for times **after the actual block**, all six candidate host IPs, and destination `45.152.66.114` / domain. Successful `ALLOW` or `CONNECT 200` after the change is a failed containment check; blocked attempts alone are expected. Confirm EDR quarantine state and approved clinical traffic separately. The actual API/command depends on the connected firewall and EDR products.

## Closure criteria for this phase

Do not mark containment complete until: approval logged; endpoint/server restrictions verified; exposed identities addressed; C2 sessions absent after enforcement; patient-care checks documented; all actual changes reflected in `incident_timeline.md`. Timestamp or authorization evidence is not provided in the lab samples, so **all above are proposed actions**.
