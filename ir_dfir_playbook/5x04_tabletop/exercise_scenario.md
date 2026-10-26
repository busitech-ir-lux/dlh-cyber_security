# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 2026-10-26  
**Classification:** Internal - Exercise Use Only  
**Facilitator:** Exercise facilitator (assigned before delivery)  
**Scenario version:** 1.1 (post-simulation revision)

## Organization background
MedDefense operates West Campus, Main, and North Site. Its outpatient appointment and pre-registration processes rely on Nexus for approximately 3,500 patient-facing interactions weekly. As a healthcare covered entity, MedDefense must protect electronic protected health information (ePHI) and assess potential HIPAA breach notifications.

## Vendor background
Nexus Patient Scheduling is a multi-tenant SaaS service provided by Nexus Health Technologies, Inc., used since August 2023. It handles appointments, patient demographics, insurance eligibility, and associated scheduling information; staff rostering access is **not established** in the vendor profile and must be verified, not assumed. Epic exchanges scheduling information with Nexus through HL7 FHIR R4 over HTTPS, with OAuth2 service credentials and an IPsec-protected inbound route. An automatically updated Nexus agent supports the integration; Main's documented host is `SCHED-SVR-01`. Nexus is a HIPAA Business Associate under a BAA effective August 1, 2023, requiring it to notify MedDefense within 24 hours of discovery of a breach. Specific uptime and recovery SLA terms were not supplied and must be requested rather than invented.

## Opening situation — information visible to participants
At the start of the exercise, the SOC reports that 45 minutes ago it detected unusual outbound network traffic involving the Nexus scheduling integration. Endpoint monitoring shows a connection pattern recurring roughly every four hours. The scheduling platform remains operational, but teams cannot yet tell whether this is vendor maintenance, a misconfiguration, or malicious activity. Main's known integration server is `SCHED-SVR-01`; the host names and agent deployments at West Campus and North Site have not yet been verified. The SOC must urgently confirm whether those sites use local agent hosts or share Main's infrastructure.

Patient safety is part of the decision: if appointment records have been modified, patients could arrive at incorrect times or miss needed care. Shutting down the platform may protect integrity but could itself interrupt care.

## Known facts at T+0
- A SOC unusual-outbound-traffic alert was raised 45 minutes before exercise start.
- EDR recorded recurring external connections approximately every four hours.
- `SCHED-SVR-01` at Main is the only host name currently confirmed by the supplied vendor profile; other site hosts are pending validation.
- The platform currently appears available. Attribution, affected records, and confirmed data exposure are unknown.

## Decisions that do not have obvious answers
- Should a business-critical service be isolated before the integrity and exfiltration risk is confirmed, given the immediate disruption to patient scheduling?
- Is a vendor-signed update reassuring, or must its trust be challenged if the software supply chain itself is suspect?
- Does an unconfirmed possibility of ePHI exposure justify immediate public communication, or should MedDefense communicate uncertainty without claiming a breach is proven?

## Exercise limits
All incidents, evidence, people speaking as a vendor, and communications described here are simulated. **Participants are not told the attack origin or full compromise scope in advance.** The facilitator will reveal additional facts through timed injects.
