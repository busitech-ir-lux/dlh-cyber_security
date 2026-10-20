# Improvement Implementation Package: IR-2026-0414-01

## Implementation Table

Deadline values are **days from approval/today**, not fixed dates. All statuses remain pending until deployed and verified.

| ID | Type | Title | Source | Owner Role | Deadline (days) | Success Criterion | Validation Method | Status |
|---|---|---|---|---|---:|---|---|---|
| IMP-001 | detection | Deploy PowerShell-to-MSBuild Sigma rule | GAP-003 | SOC Detection Lead | 7 | Alert fires on both known EID 1 positives | SIEM synthetic replay plus seven-day review | pending |
| IMP-002 | detection | Deploy tuned MSBuild outbound Sigma rule | GAP-004 | SOC Detection Lead | 7 | Both known EID 3 events alert; clean baseline target <0.1% | Sigma conversion, Sysmon replay and representative 30-day FPR check | pending |
| IMP-003 | hardening | Enforce PowerShell CLM via application control | GAP-011 | Endpoint Security Lead | 14 | CLM active for targeted users with clinical apps working | Pilot WDAC/AppLocker policy, LanguageMode test and exception review | pending |
| IMP-004 | hardening | Restrict clinical MSBuild execution | GAP-005 | Windows Platform Lead | 21 | Clinical standard users denied; approved build hosts allowed | AppLocker effective-policy check, test deny/allow, rollback drill | pending |
| IMP-005 | hardening | Enable Credential Guard on supported hosts | GAP-006 | Windows Platform Lead | 30 | Credential Guard active on compatible endpoints | Win32_DeviceGuard query and baseline compliance report | pending |
| IMP-006 | hardening | Enforce risky-geo VPN MFA/block policy | GAP-002 | Identity Security Lead | 14 | New-country risky sign-in blocked or step-up authenticated | Entra report-only then controlled sign-in test; check exclusions | pending |
| IMP-007 | hardening | Restrict PHI report access and outbound egress | GAP-008, GAP-004 | Clinical Systems Lead | 21 | Share restricted, access logged, unwanted public egress blocked | ACL access tests, 4663 read alert and network policy check | pending |
| IMP-008 | playbook | Add foreign VPN and impossible-travel triggers | GAP-002 | IR Lead | 7 | Identity triage starts on suspicious VPN sign-in | Tabletop using prior incident sign-in pattern | pending |
| IMP-009 | playbook | Add lateral movement scope-expansion checklist | GAP-007 | IR Lead | 7 | All three incident hosts identified in tabletop | Scenario-based tabletop and escalation ticket | pending |
| IMP-010 | playbook | Add conditional krbtgt remediation decision | GAP-006 | Active Directory Lead | 14 | Ticket theft vs forging separated; reset only on supported criteria | AD tabletop with simulated Pass-the-Ticket | pending |
| IMP-011 | playbook | Add four-factor ePHI breach assessment | GAP-009 | Privacy Officer | 7 | Privacy decision is formally documented | PHI-access tabletop and completed assessment form | pending |
| IMP-012 | risk | Reassess LOLBin execution risk RSK-2026-031 | Task 7 | Cyber Risk Manager | 14 | Risk score, treatment, and owner approved | GRC register audit | pending |
| IMP-013 | risk | Reassess credential/VPN access risk RSK-2026-032 | Task 7 | Cyber Risk Manager | 14 | Risk score and conditional-access plan approved | GRC register audit | pending |
| IMP-014 | risk | Reassess lateral movement risk RSK-2026-033 | Task 7 | Cyber Risk Manager | 14 | Risk score and monitoring plan approved | GRC register audit | pending |
| IMP-015 | risk | Reassess PHI-exposure risk RSK-2026-034 | Task 7 | Cyber Risk Manager | 14 | Risk score and privacy coordination approved | GRC + privacy review | pending |
| IMP-016 | detection | Run IOC hunting and persistence checks | Task 8 / GAP-010 | Threat Hunting Lead | 7 | Known IOCs/persistence searched across affected systems | SIEM hunt results and reviewed incident findings | pending |
| IMP-017 | corrective | Review DLP and outbound flow for PHI transfer | GAP-009 | Privacy/Network Security Leads | 7 | Transfer status documented as confirmed/not found/inconclusive | DLP and proxy log review with evidence references | pending |

## Deployment Sequence

1. **IMP-017 and IMP-016:** Preserve and review DLP, egress, and threat-hunting evidence before log rotation or endpoint changes.
2. **IMP-001 and IMP-002:** Validate field mappings and baseline process/network detections first so hardening changes do not erase the original signal.
3. **IMP-008 through IMP-011:** Update response procedures immediately; tabletop-test while technical controls are piloted.
4. **IMP-006:** Pilot risk-based VPN controls after confirming logging and break-glass access; eliminate sign-in-risk suppression.
5. **IMP-003 and IMP-004:** Pilot CLM then MSBuild application-control restrictions; preserve approved build workflows and monitor new deny events.
6. **IMP-005 and IMP-007:** Roll out credential isolation and clinical-share/network restrictions after compatibility and access tests.
7. **IMP-012 through IMP-015:** Approve revised risk scoring and verify control owners, deadlines, and acceptance after remediation evidence is reviewed.
8. **IMP-001 / IMP-002 production verification:** Replay safe synthetic events and review the real 30-day queue before marking deployment complete.

**Closure rule:** Each action requires a named assigned person, change record, test evidence, and SOC/risk-owner sign-off; writing a document alone does not close a gap.
