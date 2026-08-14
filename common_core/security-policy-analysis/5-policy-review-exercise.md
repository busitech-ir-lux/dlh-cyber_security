# RetailMax Corporation

# Security Policy Program Review and Gap Analysis

## Assessment Information

|Field|Value|
|---|---|
|Assessment Scope|Security policy program|
|Primary Framework|PCI DSS v4.0.1|
|Supporting Frameworks|ISO/IEC 27001:2022, NIST CSF 2.0, SOC 2|
|Assessment Date|2026-06-23|
|Assessor|Security Consultant|
|Classification|Confidential|

# Executive Summary

RetailMax has three active security policies, but all were issued between 2019 and 2021. Three foundational policies—Incident Response, Data Classification, and Access Control—are missing.

The current program is not ready for PCI DSS certification, ISO 27001 certification, or a SOC 2 Type II audit. The main issues are:

- incomplete policy coverage
    
- outdated documents
    
- no evidence of annual review
    
- no formal access-control policy
    
- no incident-response policy
    
- no data-classification or handling policy
    
- no evidence of monitoring, metrics, exceptions, training, or acknowledgment
    

The highest risks are unauthorized access to payment systems, inconsistent protection of cardholder data, and an uncoordinated response to a security incident.

RetailMax should first establish governance and identify the cardholder data environment. It should then create the missing high-risk policies, update existing documents, implement supporting procedures and technical standards, and collect evidence that controls operate consistently.

## Assessment Limitation

Only the policy inventory and publication dates were provided. No policy contents, audit evidence, training records, control configurations, acknowledgments, or monitoring reports were reviewed. Maturity scores therefore represent documented policy capability only.

# Part A: PCI DSS Gap Analysis

|PCI DSS Area|Relevant Policy Need|Current State|Gap|Risk|Recommended Action|
|---|---|---|---|---|---|
|Requirement 1: Network security controls|Network Security and Firewall Standards|No policy identified|Network segmentation, rule ownership, reviews, and change controls are undocumented|High|Create Network Security Policy and configuration standards|
|Requirement 2: Secure configurations|Secure Configuration and Change Management|No policy identified|Default settings, hardening baselines, and configuration ownership are not formally governed|High|Create Secure Configuration Standard and Change Management Policy|
|Requirement 3: Protect stored account data|Data Classification, Retention, Encryption|Data Classification Policy missing|Cardholder data may not be identified, minimized, encrypted, retained, or destroyed consistently|Critical|Create Data Classification and Data Retention Policies|
|Requirement 4: Protect data in transit|Encryption and Data Transmission Standards|No policy identified|Approved transmission methods and encryption requirements are undefined|High|Create Encryption and Secure Data Transfer Standards|
|Requirement 5: Protect against malware|Malware Protection and Endpoint Security|Covered only indirectly by Information Security Policy|No evidence of specific anti-malware responsibilities or monitoring|Medium|Add Endpoint Security Standard and monitoring requirements|
|Requirement 6: Secure systems and software|Secure Development, Patch, Vulnerability, Change Policies|No dedicated policies identified|Software development and vulnerability remediation are not formally controlled|Critical|Create Secure Development, Vulnerability Management, and Patch Management Policies|
|Requirement 7: Restrict access by business need|Access Control Policy|Missing|Least privilege, role-based access, approvals, and access reviews are undefined|Critical|Create Access Control Policy immediately|
|Requirement 8: Identify users and authenticate access|Password and Authentication Policy|Active since 2020|Likely outdated; MFA, account lifecycle, service accounts, and current password guidance may be missing|High|Rewrite policy and issue technical authentication standard|
|Requirement 9: Restrict physical access|Physical Security Policy|No policy identified|Physical access to payment systems, media, and facilities is not governed|High|Create Physical Security and Media Handling Policy|
|Requirement 10: Log and monitor access|Logging and Monitoring Policy|No policy identified|Log ownership, review frequency, retention, and alert escalation are undefined|Critical|Create Logging and Monitoring Policy and operating procedures|
|Requirement 11: Test security regularly|Vulnerability, Penetration Testing, Detection Policies|No policy identified|Scanning, testing, remediation, and evidence requirements are not documented|Critical|Create Vulnerability Management and Security Testing Policies|
|Requirement 12: Support security with organizational policies|Information Security, AUP, IR, Risk, Third-Party, Awareness|Some policies exist; Incident Response missing|Program is incomplete and policies are stale; no documented annual review or governance evidence|Critical|Establish policy governance and complete the policy suite|

## Major Cross-Framework Gaps

|Gap|PCI DSS Impact|ISO 27001 Impact|SOC 2 Impact|
|---|---|---|---|
|Missing Incident Response Policy|Weakens Requirement 12 incident readiness|Weak incident-management controls|Weak detection, response, and communication controls|
|Missing Access Control Policy|Direct gap against Requirements 7 and 8|Weak access-control governance|Weak logical-access controls|
|Missing Data Classification Policy|Weakens Requirements 3 and 4|Weak information classification and handling|Weak confidentiality and privacy controls|
|Outdated policies|Weak governance evidence|Weak document-control and continual improvement|Weak control design and consistency evidence|
|No monitoring metrics|Compliance cannot be demonstrated|ISMS performance is not measured|Type II operating effectiveness cannot be supported|
|No exception process|Uncontrolled non-compliance|Risks may not be formally accepted|Control deviations may not be documented|
|No policy acknowledgment evidence|Weak workforce accountability|Weak awareness and communication evidence|Weak evidence of control operation|

# Part B: Policy Maturity Assessment

## Maturity Scale

|Level|Description|
|--:|---|
|0|Non-existent|
|1|Initial|
|2|Developing|
|3|Defined|
|4|Managed|
|5|Optimized|

## Assessment Results

|Policy|Status|Maturity|Assessment|
|---|---|--:|---|
|Information Security Policy|Active, 2019|**1 – Initial**|A policy exists, but it is old and no evidence of review, communication, monitoring, or improvement was provided|
|Password Policy|Active, 2020|**1 – Initial**|Document exists but may not reflect current MFA, password, privileged-access, and PCI DSS requirements|
|Acceptable Use Policy|Active, 2021|**1 – Initial**|Policy exists, but acknowledgment, monitoring, BYOD, cloud use, and enforcement evidence were not provided|
|Incident Response Policy|Missing|**0 – Non-existent**|No formal direction for preparation, reporting, escalation, evidence handling, or recovery|
|Data Classification Policy|Missing|**0 – Non-existent**|No formal method for identifying and protecting cardholder, confidential, or personal data|
|Access Control Policy|Missing|**0 – Non-existent**|No documented least privilege, access approval, account lifecycle, or periodic review requirements|

### Overall Policy Maturity: **Level 1 – Initial**

RetailMax has started a policy program, but it is incomplete, outdated, and not supported by evidence of consistent operation. It should reach at least **Level 3 – Defined** before certification and then move toward **Level 4 – Managed** through metrics, audits, and control testing.

# Part C: Prioritized Recommendations

|Priority|Recommendation|Justification|Effort|Timeline|
|--:|---|---|:-:|--:|
|1|Define PCI DSS scope and cardholder data flows|All PCI controls depend on accurate identification of the cardholder data environment|High|4–6 weeks|
|2|Establish policy governance and document control|Current policies are stale and lack a controlled lifecycle|Medium|3–4 weeks|
|3|Create Access Control Policy|Directly addresses high-risk PCI requirements for least privilege and authentication|Medium|4 weeks|
|4|Create Data Classification and Handling Policy|Required to identify and protect cardholder, personal, and confidential information|Medium|4 weeks|
|5|Create Incident Response Policy and Plan|Required for coordinated detection, escalation, regulatory notification, and recovery|High|4–6 weeks|
|6|Update Password and Authentication Policy|Must address MFA, account lifecycle, privileged accounts, service accounts, and current standards|Medium|3 weeks|
|7|Create Logging, Monitoring, and Evidence Retention Policy|Needed to detect incidents and demonstrate operating effectiveness|High|5–7 weeks|
|8|Create Vulnerability, Patch, and Security Testing Policies|Supports secure systems, scanning, remediation, and penetration testing|High|6–8 weeks|
|9|Create Secure Development and Change Management Policies|RetailMax must govern software changes and payment application security|High|6–8 weeks|
|10|Update Information Security and Acceptable Use Policies|Align existing policies with current business, cloud, remote-work, and compliance requirements|Medium|4 weeks|
|11|Create Third-Party Risk and Physical Security Policies|Addresses suppliers, service providers, facilities, payment devices, and media|Medium|5–6 weeks|
|12|Implement training, acknowledgment, metrics, and annual review|Certifications require evidence that policies are communicated and operating|Medium|8–12 weeks|

# Part D: 12-Month Implementation Roadmap

## Phase 1 — Governance and Scoping

**Months 1–3**

Objectives:

- appoint a policy owner and steering committee
    
- define PCI DSS scope and cardholder data flows
    
- create a complete policy inventory
    
- approve a standard template and document-control process
    
- identify policy owners, approvers, review dates, and dependencies
    
- perform detailed PCI DSS, ISO 27001, and SOC 2 control mapping
    

Key outputs:

- PCI scope statement
    
- data-flow diagrams
    
- policy governance standard
    
- compliance matrix
    
- approved remediation plan
    

## Phase 2 — Critical Policy Development

**Months 4–6**

Develop and approve:

- Access Control Policy
    
- Data Classification and Handling Policy
    
- Incident Response Policy
    
- revised Password and Authentication Policy
    
- Logging and Monitoring Policy
    
- Data Retention and Secure Disposal Policy
    

Supporting activities:

- define technical standards
    
- create procedures and forms
    
- assign control owners
    
- begin employee communication and acknowledgment
    

## Phase 3 — Technical and Operational Policies

**Months 7–9**

Develop and implement:

- Vulnerability Management Policy
    
- Patch Management Policy
    
- Secure Development Policy
    
- Change Management Policy
    
- Network Security Policy
    
- Encryption Standard
    
- Physical Security Policy
    
- Third-Party Risk Policy
    

Validation activities:

- configuration reviews
    
- access reviews
    
- vulnerability scans
    
- incident-response tabletop exercise
    
- supplier assessments
    

## Phase 4 — Assurance and Audit Readiness

**Months 10–12**

Complete:

- policy training and acknowledgment
    
- internal compliance audit
    
- PCI DSS readiness assessment
    
- ISO 27001 internal audit and management review
    
- SOC 2 control evidence collection
    
- corrective-action tracking
    
- policy performance dashboard
    
- annual policy review schedule
    

Target outcomes:

- all required policies approved and published
    
- evidence retained for each operating control
    
- critical gaps remediated
    
- unresolved exceptions formally accepted
    
- readiness for external certification and audit
    

# Policy Program Metrics

|Metric|12-Month Target|
|---|--:|
|Policies with assigned owners|100%|
|Policies reviewed within schedule|100%|
|Workforce acknowledgment|100%|
|Required training completion|At least 98%|
|Critical policy gaps closed|100%|
|Access reviews completed on time|100%|
|High-risk exceptions past expiry|0|
|Internal audit findings closed by deadline|At least 90%|
|Incident-response exercises completed|At least 1 annually|

# Conclusion

RetailMax’s current policy program is incomplete and operates at an Initial maturity level. The missing Access Control, Data Classification, and Incident Response Policies create immediate certification and business risks.

The recommended roadmap prioritizes PCI DSS scope, governance, critical policies, supporting standards, implementation evidence, and audit readiness. Successful completion should move the organization toward a **Defined maturity level by Month 9** and a **Managed maturity level after monitoring and audit evidence are established**.