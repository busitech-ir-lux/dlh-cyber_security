# 16. The Risk Appetite Debate

## Part 1 — Risk Appetite Statement

MedDefense has a **low risk appetite** for cybersecurity risks affecting patient safety, patient data, critical clinical services or regulatory compliance. Risks that could cause serious patient harm or prevent recovery of essential systems must always be reduced as far as reasonably possible. MedDefense may accept limited operational or financial risks when the treatment cost is greater than the expected benefit. High or Critical risks may only be accepted temporarily by the CEO with Board approval and documented compensating controls.

## Part 2 — The Three Decisions

### Risk 1

**Risk:** RISK-007 — Medical-device compromise
**Treatment Decision:** Accept the remaining residual risk
**Authority:** The CEO and Board approve it because the risk may affect patient safety and requires executive accountability.
**Justification:** Full medical-device isolation and dedicated monitoring costs $60,000 but provides only $48,000 in estimated ALE reduction, giving a negative net value of **-$12,000**.
**Compensating Measure:** Use lower-cost VLAN isolation, remove default passwords, restrict traffic and monitor devices through Wazuh.
**Review Trigger:** Reassess after a device incident, new critical vulnerability or evidence of unauthorized medical-device traffic.

### Risk 2

**Risk:** RISK-009 — Unsupported Windows XP MRI workstation
**Treatment Decision:** Accept temporarily
**Authority:** The CEO approves the acceptance after consultation with the Deputy CISO, IT Director and Radiology Department Head because replacement affects clinical operations and major capital spending.
**Justification:** Immediate replacement would require ending or changing the $2.1 million scanner lease, while the workstation can be isolated until the lease expires in 18 months.
**Compensating Measure:** Place it in a dedicated VLAN, block internet access, allow only required connections and monitor all traffic.
**Review Trigger:** Reassess if exploitation is detected, the vendor releases an alternative or the lease can be ended early.

### Risk 3

**Risk:** RISK-004 — No continuous 24/7 human monitoring
**Treatment Decision:** Accept temporarily
**Authority:** The CEO and Board approve it because the managed SOC was excluded through the formal budget-allocation process.
**Justification:** The outsourced SOC costs $110,000 per year and would consume almost the entire security budget, while Wazuh provides a lower-cost first step.
**Compensating Measure:** Use Wazuh alerts, an on-call escalation process and daily security-log reviews by the Security Analyst.
**Review Trigger:** Reassess after a missed critical alert, an after-hours incident or approval of the next annual security budget.

## Part 3 — The Debate

### James Chen’s Argument for Mitigation

The Windows XP MRI workstation contains unsupported software and known weaknesses that cannot receive normal security updates. On the flat network, an attacker could use it to enter other clinical systems. Because the scanner supports patient care, compromise could cause operational disruption or patient-safety consequences. James therefore argues that the workstation should be replaced or strongly isolated immediately.

### Robert Kim’s Argument for Acceptance

Replacing the MRI system before the lease expires could create a major financial loss and interrupt an important clinical service. The full scanner investment is much larger than the estimated probability of an attack during the remaining 18 months. Robert argues that MedDefense should temporarily accept the risk while using inexpensive compensating controls. The replacement should be planned for the end of the current lease.

### Verdict

Robert’s position is more practical, but only if strict compensating controls are implemented. Immediate replacement is financially difficult, while leaving the workstation unrestricted is not acceptable. MedDefense should isolate it, block unnecessary access, monitor it closely and document the temporary risk acceptance. The risk must be reviewed regularly and eliminated when the lease expires.

