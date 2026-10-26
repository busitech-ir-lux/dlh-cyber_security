# Participant Guide: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-26  
**Classification:** Internal - Exercise Use Only

## How this exercise works
Respond as you would during a real incident. All inputs and calls are simulated. State decisions, who authorizes them, and when they will be revisited. Nobody may assume the vendor has confirmed facts that have not been delivered. The scenario does not provide a measured SLA or a verified employee rostering data flow.

## James Chen — SOC Lead

**Exercise role:** SOC Lead.  
**Decisions owned:** Declare severity, order preservation, scope indicators, escalate to CISO.  
**Information received directly:** Direct EDR, network telemetry, endpoint inventory and IOC correlations.  
**Success:** Provisional SEV2 within first 5 minutes; preserve logs; share scoping updates.  
**Failure mode:** Assumes only one endpoint matters and never tests signed-update origin.

## Sarah Park — IT Director

**Exercise role:** IT Director.  
**Decisions owned:** Own IT containment choice and coordinate clinical authorization and fallback.  
**Information received directly:** Operational service dependency and downtime reports from IT and clinical staff.  
**Success:** Records decision owner, patient risk, alternative scheduling and review time.  
**Failure mode:** Orders full shutdown without consulting clinical leadership, or delays containment indefinitely.

## Dr. Patricia Morales — CISO / incident executive

**Exercise role:** CISO / incident executive.  
**Decisions owned:** Set command structure, arbitrate risk escalation, present decisions to board.  
**Information received directly:** SOC/IT briefings and executive or board requests.  
**Success:** Can give concise known/unknown status, owner and next decision checkpoint.  
**Failure mode:** Offers unsupported certainty to reassure board rather than identify unresolved risk.

## Helena Reyes — General Counsel

**Exercise role:** General Counsel.  
**Decisions owned:** Assess BAA contractual deadlines, HIPAA exposure and approval of statements.  
**Information received directly:** BAA, Nexus formal correspondence, evidence supplied by privacy and IR.  
**Success:** Separates contractual 24h BA term from HIPAA regulation; documents breach risk assessment.  
**Failure mode:** Equates suspicion with legally confirmed reportable breach, or delegates whole assessment to Nexus.

## Marcus Webb — Communications Director

**Exercise role:** Communications Director.  
**Decisions owned:** Approve consistent external holding response, manage reporters/staff guidance.  
**Information received directly:** Reporter email and approved verified status from CISO/Legal.  
**Success:** Issues accurate approved holding response, avoids unconfirmed denial or breach claim.  
**Failure mode:** Says no PHI was affected before investigation is complete.

## Robert Kim — Infrastructure Lead

**Exercise role:** Infrastructure Lead.  
**Decisions owned:** Inventory agent hosts, preserve images, control integration/credentials and recovery.  
**Information received directly:** Service-principal details, agent inventory, FHIR logs, integration paths.  
**Success:** Identifies all site exposure and requires trusted restoration with monitored verification.  
**Failure mode:** Reinstalls vendor-signed update without proving build/signing path clean.

## Clinical Director representative — Clinical continuity and patient safety owner

**Exercise role:** Clinical continuity and patient safety owner.  
**Decisions owned:** Authorize clinical fallback, triage high-risk appointments and sign off restored schedule integrity.  
**Information received directly:** Clinic calendars, urgent appointment lists and mismatch reports.  
**Success:** Protects eight urgent patients and verifies altered appointments before relying on them.  
**Failure mode:** Protects availability only, allowing inaccurate schedules to harm patients.

## Observer guidance
Observers do not speak, advise or signal participants during play. Record exact words, decisions, timestamps, missing authorizations and evidence against the evaluation criteria; distinguish observations from interpretation. Submit notes privately to the facilitator at debrief.
