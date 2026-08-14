# GlobalTech Manufacturing

# Incident Response Policy

## Document Control

|Field|Value|
|---|---|
|Policy ID|POL-IR-001|
|Version|1.0|
|Effective Date|2026-07-01|
|Review Date|2027-07-01|
|Policy Owner|Chief Information Security Officer|
|Approved By|Executive Sponsor|
|Classification|Internal|

## 1. Purpose

This policy establishes a consistent process for detecting, reporting, investigating, containing, eradicating, and recovering from cybersecurity incidents.

Its objectives are to protect employees, personal data, intellectual property, manufacturing operations, and IT, IoT, and operational technology systems while meeting ISO 27001, GDPR, and industry-specific obligations.

## 2. Scope

### 2.1 Applicability

This policy applies to:

- all employees
    
- contractors and consultants
    
- temporary workers
    
- third-party service providers
    
- incident response personnel
    
- all GlobalTech locations and remote workers
    

### 2.2 Systems and Assets Covered

This policy covers:

- corporate IT systems
    
- manufacturing and OT networks
    
- industrial control systems
    
- IoT devices
    
- cloud services
    
- employee endpoints
    
- business applications
    
- personal and confidential information
    
- third-party connections
    

### 2.3 Exclusions

No system, site, or business unit is excluded without an approved exception.

## 3. Policy Statements

### 3.1 Incident Response Lifecycle

GlobalTech will manage incidents through the following stages:

1. Preparation
    
2. Detection and Analysis
    
3. Containment, Eradication, and Recovery
    
4. Post-Incident Review
    

### 3.2 Preparation

GlobalTech must maintain:

- an Incident Response Team
    
- current escalation and contact lists
    
- secure communication channels
    
- system inventories and network diagrams
    
- tested backup and recovery arrangements
    
- forensic and monitoring tools
    
- annual incident-response training
    
- at least one tabletop exercise each year
    

Exercises must periodically include ransomware, personal-data breaches, third-party compromise, and OT or IoT disruption.

## 4. Incident Classification Matrix

Incidents must be classified according to safety impact, operational disruption, data sensitivity, affected systems, geographic scope, regulatory exposure, and recovery complexity.

|Severity|Description|Initial Response Time|Examples|
|---|---|--:|---|
|**Critical**|Immediate or likely major impact on safety, production, regulated data, or multiple sites|15 minutes|Ransomware affecting production, OT safety-system compromise, destructive attack, major personal-data breach|
|**High**|Significant impact on critical systems, sensitive information, or a production location|1 hour|Privileged-account compromise, spreading malware, unauthorized access to confidential databases, local production outage|
|**Medium**|Limited and contained impact with no major business interruption|4 hours|Successful phishing, isolated malware, unauthorized software, limited account compromise|
|**Low**|Minor event or suspicious activity with little immediate impact|1 business day|Blocked scanning, unsuccessful phishing, minor misuse, low-risk monitoring alert|

The Incident Response Manager may increase or reduce severity as the investigation develops.

## 5. Incident Response Team

|Role|Responsibilities|
|---|---|
|**Incident Response Manager**|Activates the response, assigns severity, coordinates teams, approves actions, and briefs management|
|**Security Analysts**|Investigate alerts, analyze threats, collect evidence, and perform technical containment|
|**IT Support**|Isolate, patch, rebuild, restore, and validate IT systems|
|**OT/Engineering Team**|Evaluate safety and production impact and support safe containment and recovery of OT/IoT systems|
|**Legal Counsel**|Assess legal duties, contracts, privilege, regulatory reporting, and law-enforcement involvement|
|**Communications/PR**|Prepare approved employee, customer, partner, and media communications|
|**Executive Sponsor**|Authorize major operational decisions, emergency resources, and business-continuity actions|
|**Data Protection Officer**|Assess personal-data impact and GDPR notification obligations|
|**System Owners**|Confirm business impact and approve restoration of affected services|

## 6. Detection and Reporting

### 6.1 Detection Methods

Incidents may be identified through:

- SIEM, EDR, IDS, and firewall alerts
    
- OT and IoT monitoring
    
- cloud and identity logs
    
- employee reports
    
- threat intelligence
    
- vendor or customer notifications
    
- audit findings
    
- unusual production or equipment behavior
    

### 6.2 Reporting an Incident

All personnel must immediately report suspected incidents through:

- `incident@globaltech.example`
    
- the IT Service Desk
    
- the emergency security hotline for urgent events
    

Employees must not delete files, shut down equipment, contact suspected attackers, or conduct their own investigation unless instructed.

### 6.3 Information to Collect

The initial report should include:

- reporter name and contact details
    
- date and time observed
    
- affected device, system, site, or account
    
- description of the activity
    
- affected users or business process
    
- screenshots, alerts, or error messages
    
- actions already taken
    

### 6.4 Initial Assessment

The first responder must:

1. record the incident
    
2. confirm whether malicious or unauthorized activity may have occurred
    
3. assign an initial severity
    
4. identify affected IT, OT, IoT, data, and locations
    
5. assess safety and production impact
    
6. preserve available evidence
    
7. appoint an incident owner
    
8. notify required stakeholders
    

## 7. Response Procedures

### 7.1 Containment

#### Short-Term Containment

Possible actions include:

- isolating affected endpoints
    
- disabling compromised accounts
    
- blocking malicious traffic
    
- separating affected network segments
    
- restricting third-party access
    
- applying temporary firewall rules
    
- stopping services where approved
    

OT or industrial equipment must not be disconnected without consulting the OT or Engineering Team unless immediate action is necessary to protect human safety.

#### Evidence Preservation

Where practical, responders must preserve:

- system and application logs
    
- volatile memory
    
- disk images
    
- network captures
    
- email records
    
- authentication activity
    
- device and configuration data
    

#### Long-Term Containment

Long-term controls may include:

- temporary replacement systems
    
- additional network segmentation
    
- restricted user access
    
- clean administrative workstations
    
- enhanced monitoring
    
- temporary manual business processes
    

### 7.2 Eradication

The response team must:

- identify the root cause and entry method
    
- remove malware, backdoors, and unauthorized tools
    
- disable attacker-controlled accounts
    
- reset compromised credentials
    
- correct insecure configurations
    
- patch exploited vulnerabilities
    
- inspect related systems
    
- verify that the threat is no longer present
    

### 7.3 Recovery

Recovery must include:

- restoration from trusted backups or clean builds
    
- security and functional testing
    
- OT safety and production validation
    
- system-owner approval
    
- controlled return to service
    
- increased monitoring for at least 72 hours for Critical and High incidents
    
- documentation of any remaining risk
    

## 8. Communication Plan

|Stakeholder|When to Notify|Method|Owner|
|---|---|---|---|
|**Executive Management**|Immediately for Critical incidents; within 2 hours for High incidents|Secure call and written briefing|Incident Response Manager|
|**Legal Counsel**|When legal, contractual, criminal, or regulatory impact is suspected|Secure call or approved collaboration channel|Incident Response Manager|
|**Data Protection Officer**|Immediately when personal data may be affected|Secure notification|Security Team|
|**Regulators**|When required by law or industry regulation|Formal regulatory channel|Legal/DPO|
|**Affected Users**|When required by law or necessary to reduce harm|Approved email, letter, or portal notice|Communications|
|**Customers and Partners**|When services, contracts, or shared data are affected|Approved business communication|Communications|
|**Law Enforcement**|When criminal activity is confirmed and contact is approved|Official liaison|Legal Counsel|
|**Media**|Only after Legal and executive approval|Official statement|Communications/PR|

Only authorized Communications, Legal, or executive personnel may issue public statements.

For applicable GDPR incidents, the Data Protection Officer and Legal Counsel must assess whether notification to the supervisory authority is required within 72 hours of awareness.

## 9. Evidence Handling

### 9.1 Chain of Custody

Each evidence item must record:

- unique evidence number
    
- description and source
    
- collector’s name
    
- collection date and time
    
- collection method
    
- storage location
    
- every transfer or access
    
- final disposition
    

### 9.2 Evidence Preservation

Evidence must:

- be collected using approved methods
    
- be protected from alteration
    
- have a SHA-256 or stronger integrity hash where applicable
    
- be encrypted during storage and transfer
    
- be accessible only to authorized personnel
    
- be retained according to legal and regulatory requirements
    

### 9.3 Documentation

The incident record must contain:

- event timeline
    
- actions and decisions
    
- severity changes
    
- evidence records
    
- notifications
    
- affected systems and data
    
- business and production impact
    
- containment and recovery actions
    

## 10. Post-Incident Activities

### 10.1 Lessons Learned

A lessons-learned meeting must be completed:

- within 10 business days for Critical and High incidents
    
- within 20 business days for Medium incidents
    
- when requested for Low incidents
    

The review must identify:

- root cause
    
- response strengths and failures
    
- control gaps
    
- communication issues
    
- recurrence risk
    
- corrective actions
    
- assigned owners and deadlines
    

### 10.2 Final Report

The final incident report must include:

- executive summary
    
- incident classification
    
- timeline
    
- affected systems, data, and sites
    
- safety and operational impact
    
- root cause and attack method
    
- response actions
    
- evidence summary
    
- notifications made
    
- business impact
    
- lessons learned
    
- corrective actions
    

Corrective actions must remain tracked until formally completed.

## 11. Roles and Responsibilities

|Role|Responsibilities|
|---|---|
|Executive Management|Approve policy and provide response resources|
|Incident Response Manager|Direct incident handling and escalation|
|Security Team|Detect, investigate, contain, and document incidents|
|IT and OT Teams|Support isolation, restoration, and technical validation|
|Legal and DPO|Manage legal, privacy, and regulatory obligations|
|Communications|Control internal and external messaging|
|Managers|Ensure staff report incidents and support investigations|
|All Personnel|Report suspected incidents and preserve evidence|

## 12. Compliance

### 12.1 Monitoring

Compliance will be monitored through:

- response-time metrics
    
- tabletop exercises
    
- incident-record reviews
    
- evidence-handling checks
    
- corrective-action tracking
    
- audit findings
    

### 12.2 Reporting

Quarterly reports must include:

- incidents by severity
    
- average detection, containment, and recovery times
    
- overdue corrective actions
    
- repeated incidents
    
- regulatory notifications
    
- missed response targets
    

### 12.3 Auditing

The incident-response program must be audited and tested at least annually and after every Critical incident.

## 13. Enforcement

### 13.1 Violations

Failure to report an incident, preserve evidence, or follow authorized response instructions may result in:

- retraining
    
- written warning
    
- suspension of access
    
- disciplinary action
    
- termination
    
- legal action where applicable
    

### 13.2 Reporting Violations

Suspected violations must be reported to:

`security@globaltech.example`

## 14. Exceptions

### 14.1 Exception Process

Exceptions require:

1. written request
    
2. business justification
    
3. documented risk assessment
    
4. compensating controls
    
5. system-owner approval
    
6. CISO approval
    

### 14.2 Exception Duration

Exceptions may not exceed 12 months and must be reviewed quarterly.

## 15. Definitions

|Term|Definition|
|---|---|
|Incident|An event that threatens confidentiality, integrity, availability, safety, or operations|
|OT|Technology used to monitor or control industrial processes|
|IoT|Connected devices that collect or exchange data|
|Containment|Actions taken to limit the spread or impact of an incident|
|Eradication|Removal of the threat and its root cause|
|Recovery|Restoration of trusted systems and operations|
|Chain of Custody|Record of evidence collection, access, transfer, and storage|
|Personal-Data Breach|Unauthorized loss, alteration, disclosure, or access involving personal data|

## 16. Related Documents

- Incident Response Plan
    
- Business Continuity Policy
    
- Disaster Recovery Plan
    
- Data Breach Notification Procedure
    
- OT Security Standard
    
- Evidence Handling Procedure
    
- Crisis Communication Plan
    
- NIST SP 800-61
    
- CISA Incident Response Playbooks
    
- SANS Incident Handler’s Handbook
    
- GDPR Article 33
    
- ISO/IEC 27001
    

## 17. Revision History

|Version|Date|Author|Description|
|---|---|---|---|
|1.0|2026-06-23|Information Security Team|Initial release|

## 18. Acknowledgment

By accessing GlobalTech systems, all users acknowledge that they have read, understood, and agree to comply with this policy.

---

# Incident Report Template

## Basic Information

|Field|Details|
|---|---|
|Incident ID||
|Incident Title||
|Date and Time Detected||
|Date and Time Reported||
|Reported By||
|Incident Owner||
|Severity||
|Status||
|Affected Country or Site||

## Incident Summary

- Description:
    
- Detection source:
    
- Affected systems:
    
- Affected users:
    
- Data involved:
    
- OT/IoT impact:
    
- Safety impact:
    
- Production impact:
    
- Regulatory impact:
    

## Timeline

|Date/Time|Event or Action|Owner|
|---|---|---|
||||

## Response Actions

### Containment

- Systems isolated:
    
- Accounts disabled:
    
- Traffic blocked:
    
- Temporary controls:
    

### Eradication

- Root cause:
    
- Threat removed:
    
- Vulnerabilities corrected:
    
- Credentials reset:
    

### Recovery

- Systems restored:
    
- Testing completed:
    
- Approvals received:
    
- Monitoring period:
    

## Evidence Log

|Evidence ID|Description|Collected By|Date/Time|Hash/Storage Location|
|---|---|---|---|---|
||||||

## Notifications

|Stakeholder|Date/Time|Method|Approved By|
|---|---|---|---|
|||||

## Lessons Learned and Actions

|Finding or Action|Owner|Due Date|Status|
|---|---|---|---|
|||||

## Closure

| Field              | Details |
| ------------------ | ------- |
| Closure Date       |         |
| Closed By          |         |
| Final Severity     |         |
| Remaining Risk     |         |
| Executive Approval |         |