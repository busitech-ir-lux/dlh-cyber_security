# Security Policy Analysis

## Sample Policy

> **SECURITY POLICY**
> 
> All employees should use good passwords. Don't share them.  
> IT will handle security stuff.  
> Report problems to someone.
> 
> Updated: Sometime last year

---

# Part A: Missing Components

|Missing Component|Why It Is Important|
|---|---|
|**Policy title specific to the subject**|The title “Security Policy” is too broad. A specific title such as “Password Policy” helps readers understand exactly what the document covers.|
|**Document version**|A version number identifies the current approved policy and prevents employees from following outdated requirements.|
|**Document owner**|The policy must identify the department or person responsible for maintaining it, answering questions, and coordinating updates.|
|**Approval authority**|The document should identify the manager, executive, or governing body that approved it. This gives the policy formal authority.|
|**Approval date**|The approval date shows when management officially accepted the policy.|
|**Effective date**|The effective date tells employees when the requirements become mandatory.|
|**Last review date**|A specific review date shows when the policy was last checked. “Sometime last year” is not measurable or auditable.|
|**Next review date**|The next scheduled review ensures the policy is periodically examined and does not become outdated.|
|**Policy status**|The document should state whether it is a draft, approved, retired, or under review.|
|**Contact information**|Employees need a clear email address, telephone number, or service desk contact for questions and reporting problems.|
|**Purpose statement**|The policy does not explain why password security is necessary or what risks it is intended to reduce.|
|**Scope definition**|The policy does not identify who must follow it or which systems, accounts, applications, and devices it covers.|
|**Applicability statement**|It does not say whether the rules apply to employees, contractors, temporary workers, third parties, administrators, or service accounts.|
|**Specific policy statements**|“Use good passwords” is not measurable. The policy should define password length, prohibited passwords, MFA, password sharing, storage, reset, and reporting requirements.|
|**Password length requirements**|No minimum or supported maximum length is defined, so users and administrators cannot determine compliance.|
|**Requirements for single-factor and MFA accounts**|The policy does not distinguish between accounts protected only by a password and accounts protected by multi-factor authentication.|
|**Compromised-password screening**|The policy does not require systems to reject commonly used, predictable, or previously compromised passwords.|
|**Multi-factor authentication requirements**|It does not identify which accounts must use MFA, such as administrative, remote-access, or sensitive accounts.|
|**Password reuse restrictions**|The policy does not prohibit employees from reusing company passwords on personal or external services.|
|**Password storage requirements**|It does not explain how systems must protect stored passwords, such as through approved salted password-hashing methods.|
|**Password reset and recovery requirements**|There is no secure process for verifying identity and resetting a forgotten or compromised password.|
|**Failed-login protection**|The policy does not require rate limiting, temporary lockout, monitoring, or other protection against repeated password-guessing attempts.|
|**Temporary password requirements**|It does not explain how temporary passwords must be issued, protected, or changed after first use.|
|**Privileged-account requirements**|Administrative accounts generally create greater risk, but the policy does not define stronger controls for them.|
|**Service-account requirements**|Non-human accounts, application credentials, API secrets, and service passwords are not addressed.|
|**Password-manager guidance**|The document does not state whether an approved password manager may or should be used.|
|**Incident-reporting process**|“Report problems to someone” does not identify what must be reported, to whom, by what method, or how quickly.|
|**Roles and responsibilities**|The policy does not clearly assign duties to users, managers, IT administrators, security staff, Human Resources, or system owners.|
|**Separation of responsibilities**|“IT will handle security stuff” wrongly suggests that employees and managers have no security responsibilities.|
|**Compliance-monitoring requirements**|The policy does not explain how compliance will be checked through audits, technical controls, access reviews, or monitoring.|
|**Enforcement section**|There are no defined consequences for failing to follow the policy.|
|**Exception process**|There is no controlled process for requesting a temporary exception when a system cannot meet a requirement.|
|**Definitions**|Terms such as password, passphrase, MFA, privileged account, credential, and compromised password are not defined.|
|**Related documents**|The policy does not reference supporting standards, procedures, frameworks, or other organizational policies.|
|**Review and revision history**|There is no table showing previous versions, dates, authors, or changes.|
|**Training and awareness requirements**|The policy does not require users to receive guidance about secure password creation, phishing, password managers, or reporting compromised credentials.|
|**Records and evidence requirements**|It does not identify what evidence must be retained to demonstrate approval, acknowledgement, exceptions, or compliance.|

---

# Part B: Policy Weaknesses

|Weakness|Problem|Impact|
|---|---|---|
|**“All employees”**|This only mentions employees and excludes contractors, consultants, temporary workers, third parties, and other users who may access organizational systems.|People outside the employee group may believe the policy does not apply to them, creating inconsistent protection.|
|**“should use”**|“Should” normally expresses a recommendation rather than a mandatory requirement.|The organization may be unable to consistently enforce the rule or prove non-compliance.|
|**“good passwords”**|The term is vague and undefined. There is no minimum length, prohibited-password list, MFA requirement, or measurable standard.|Users may create weak or predictable passwords while believing they are compliant.|
|**“Don't share them.”**|The statement is informal and does not explain whether it covers verbal sharing, email, messaging, shared files, browsers, or password managers.|Passwords may still be stored or transmitted through insecure methods.|
|**“Don't share them.”**|It does not explain what users should do when a manager, colleague, service desk worker, or third party asks for a password.|Social engineering and credential theft may be more successful.|
|**“IT will handle security stuff.”**|“Security stuff” is unprofessional, vague, and impossible to measure.|Important security activities may be ignored because nobody knows exactly what IT must perform.|
|**“IT will handle security stuff.”**|It incorrectly places all responsibility on IT and gives no responsibilities to users, managers, Human Resources, security staff, or system owners.|Employees may assume password security and incident reporting are not their responsibility.|
|**“Report problems”**|The policy does not define what counts as a problem, such as phishing, suspected compromise, unexpected MFA prompts, or a lost device.|Users may fail to report serious security events.|
|**“to someone”**|No specific contact, team, reporting channel, or escalation method is provided.|Reports may be delayed, sent to the wrong person, or not investigated.|
|**“Report problems to someone.”**|No reporting deadline is defined.|A compromised account may remain active while an attacker continues accessing systems.|
|**“Updated: Sometime last year”**|The date is vague and cannot be verified. It gives no day, month, year, reviewer, or version.|Auditors and employees cannot confirm whether the policy is current.|
|**No purpose statement**|The policy does not explain the risks it addresses or the security objective it supports.|Employees may not understand why compliance matters.|
|**No scope statement**|The policy does not identify covered accounts, applications, devices, networks, cloud services, or locations.|Important systems may be excluded or handled inconsistently.|
|**No password-storage requirements**|Only user behavior is mentioned; system-side protection is ignored.|Poorly stored passwords could be exposed in a database breach.|
|**No MFA requirement**|Passwords are treated as the only authentication control.|Theft of a password may directly lead to unauthorized access.|
|**No enforcement language**|The policy contains no consequences or corrective actions.|Violations may continue because users do not expect any response.|
|**No exception process**|Legacy systems or special business cases cannot be formally documented and controlled.|Unapproved exceptions may become permanent security gaps.|
|**No measurable review schedule**|The policy does not require annual or event-driven review.|Requirements may remain unchanged after new threats, incidents, systems, or legal obligations emerge.|

---

# Part C: Rewritten Password Policy

# [Organization Name] Password and Authentication Policy

## Document Control

|Field|Information|
|---|---|
|**Document title**|Password and Authentication Policy|
|**Policy ID**|SEC-POL-001|
|**Version**|1.0|
|**Status**|Draft for Management Approval|
|**Policy owner**|Information Security Manager|
|**Document author**|Information Security Department|
|**Approved by**|Pending Management Approval|
|**Approval date**|Pending|
|**Effective date**|Upon approval|
|**Last review date**|22 June 2026|
|**Next review date**|No later than 12 months after approval|
|**Review frequency**|At least annually and after significant changes or incidents|
|**Contact for questions**|security@[organization-domain] or the IT Service Desk|
|**Information classification**|Internal|

---

## 1. Purpose

The purpose of this policy is to establish clear requirements for creating, using, protecting, storing, resetting, and managing passwords and other authentication credentials.

This policy is intended to:

- reduce unauthorized access caused by weak, reused, shared, or compromised passwords;
    
- protect organizational systems, services, and information;
    
- establish consistent authentication requirements;
    
- define user and administrative responsibilities;
    
- support security, legal, regulatory, and contractual obligations; and
    
- ensure that suspected credential compromise is reported and handled promptly.
    

---

## 2. Scope

This policy applies to:

- all employees;
    
- contractors, consultants, interns, temporary personnel, and volunteers;
    
- third parties with access to organizational systems;
    
- system administrators and privileged users;
    
- all organizational user accounts;
    
- administrative and privileged accounts;
    
- remote-access and cloud-service accounts;
    
- applications, databases, operating systems, and network devices;
    
- service, application, and machine accounts;
    
- company-owned devices; and
    
- personally owned devices authorized to access organizational resources.
    

This policy applies regardless of whether access occurs from an office, home, remote location, cloud environment, or third-party location.

Systems that cannot meet a requirement in this policy must use the formal exception process described in Section 10.

---

## 3. Definitions

|Term|Definition|
|---|---|
|**Password**|A secret sequence of characters used to verify a user’s identity.|
|**Passphrase**|A longer password made from several words or a memorable sequence.|
|**Credential**|Information or an authentication method used to prove identity, such as a password, token, certificate, or security key.|
|**Multi-factor authentication (MFA)**|Authentication using two or more different factors, such as something the user knows, has, or is.|
|**Single-factor authentication**|Authentication that depends on only one factor, such as a password alone.|
|**Privileged account**|An account with elevated permissions, such as administrator, root, or security-management access.|
|**Service account**|A non-human account used by an application, system, device, or automated process.|
|**Compromised password**|A password that is known, suspected, or likely to have been exposed to an unauthorized person.|
|**Password manager**|An approved application used to securely generate, store, and retrieve passwords.|
|**Password blocklist**|A list or service used to reject common, predictable, organization-related, or previously compromised passwords.|

---

## 4. Policy Statement

[Organization Name] requires all users and systems to protect authentication credentials using the requirements defined in this policy.

Passwords are confidential security information. They must be unique, protected from unauthorized disclosure, and used only by the person or system to which they are assigned.

Authentication systems must be configured to enforce the applicable requirements wherever technically possible.

---

## 5. Password and Authentication Requirements

### 5.1 Password length

1. Passwords used as the only authentication factor must contain at least **15 characters**.
    
2. Passwords used as part of an approved MFA process must contain at least **8 characters**.
    
3. Systems must support passwords of at least **64 characters** wherever technically possible.
    
4. Users are encouraged to create long, memorable passphrases.
    

Example of a passphrase format:

> `river-glass-window-morning`

The example must not be used as an actual password.

---

### 5.2 Password content

1. Passwords must not contain:
    
    - the user’s username;
        
    - the user’s full name;
        
    - the organization’s name;
        
    - easily guessed personal information;
        
    - common passwords;
        
    - predictable sequences such as `12345678`;
        
    - repeated characters such as `aaaaaaaa`;
        
    - known default passwords; or
        
    - passwords identified as compromised.
        
2. Authentication systems must compare new and changed passwords against an approved password blocklist.
    
3. Systems must allow spaces and common printable characters where technically supported.
    
4. Mandatory complexity rules requiring a fixed mixture of uppercase letters, lowercase letters, numbers, and symbols should not be used unless a specific system, law, contract, or approved risk assessment requires them.
    

---

### 5.3 Password uniqueness and reuse

1. Organizational passwords must be unique to organizational accounts.
    
2. Users must not reuse an organizational password on personal websites, personal email, social media, or unrelated external services.
    
3. A separate password must be used for privileged accounts and normal user accounts.
    
4. Users must not reuse a password that is known or suspected to have been compromised.
    
5. Shared accounts are prohibited unless formally approved for a documented business or technical requirement.
    

---

### 5.4 Password changes

1. Users must change a password immediately when:
    
    - compromise is known or suspected;
        
    - the password has been disclosed to another person;
        
    - the user entered it into a suspected phishing site;
        
    - unusual account activity is detected;
        
    - the Security Team or IT Service Desk instructs the user to change it; or
        
    - a security investigation requires the change.
        
2. Passwords must not be changed on an arbitrary periodic schedule unless:
    
    - required by law or contract;
        
    - required for a specific high-risk system;
        
    - technically required by a legacy system; or
        
    - directed by the Information Security Manager following a risk assessment.
        
3. Default vendor passwords must be changed before a system or device is placed into production.
    

---

### 5.5 Password sharing and disclosure

1. Users must not share passwords with:
    
    - colleagues;
        
    - managers;
        
    - IT personnel;
        
    - family members;
        
    - contractors; or
        
    - third parties.
        
2. IT and security personnel must never ask a user to reveal their password.
    
3. Users must not send passwords through:
    
    - unencrypted email;
        
    - ordinary chat messages;
        
    - text messages;
        
    - support tickets;
        
    - documents;
        
    - spreadsheets; or
        
    - handwritten notes left in visible locations.
        
4. When approved credential sharing is technically necessary, an approved enterprise password manager or secrets-management system must be used.
    
5. Users must report any request to disclose a password to the IT Service Desk or Security Team.
    

---

### 5.6 Multi-factor authentication

MFA is mandatory for:

- privileged and administrative accounts;
    
- remote access;
    
- virtual private network access;
    
- externally accessible email;
    
- cloud administration portals;
    
- systems containing Restricted or highly sensitive information;
    
- financial and payment systems;
    
- Human Resources systems containing sensitive employee information; and
    
- any other system designated by the Information Security Manager.
    

Phishing-resistant MFA, such as approved hardware security keys or passkeys, should be used for high-risk and privileged access where available.

Users must report unexpected MFA prompts immediately and must not approve an authentication request they did not initiate.

---

### 5.7 Password managers

1. Users may use only password managers approved by the Information Security Department.
    
2. Approved password managers should be used to generate and store unique passwords.
    
3. The password manager’s primary password must:
    
    - meet the single-factor minimum length requirement;
        
    - be unique;
        
    - not be used for another account; and
        
    - be protected with MFA where supported.
        
4. Users must not store organizational passwords in unapproved browser storage, personal password managers, plain-text files, notebooks, or spreadsheets.
    

---

### 5.8 Temporary passwords and account activation

1. Temporary passwords must:
    
    - be generated securely;
        
    - be unique to the user;
        
    - be delivered through an approved secure channel;
        
    - expire after a defined period or after first use; and
        
    - require replacement during the first successful sign-in.
        
2. Temporary passwords must not be sent together with the username through the same insecure communication channel.
    
3. Unused temporary credentials must expire within **24 hours**, unless a documented operational requirement justifies a different period.
    

---

### 5.9 Password reset and account recovery

1. Password resets must use an approved identity-verification process.
    
2. Security questions based on publicly available or easily guessed information must not be used as the only recovery method.
    
3. Support personnel must not reveal an existing password.
    
4. A reset process must issue a temporary credential or secure reset link rather than disclose the old password.
    
5. Reset links and temporary credentials must:
    
    - expire after a limited period;
        
    - be single use;
        
    - be protected against unauthorized access; and
        
    - be invalidated after successful use.
        
6. Users must be notified when their password, MFA method, or recovery information is changed.
    

---

### 5.10 Failed authentication and automated attacks

Authentication systems must:

- use rate limiting, progressive delays, temporary lockout, or equivalent controls;
    
- log repeated failed authentication attempts;
    
- alert security personnel when suspicious activity exceeds defined thresholds;
    
- protect against automated password guessing and credential-stuffing attacks; and
    
- avoid permanently locking legitimate users out without a recovery process.
    

Thresholds must be defined by the system owner and Information Security Department according to system risk.

---

### 5.11 Password storage and transmission

1. Systems must not store passwords in plain text.
    
2. Passwords must be stored using an approved salted password-hashing method designed for password protection.
    
3. Reversible encryption must not be used for user passwords unless there is an approved and documented technical requirement.
    
4. Passwords and authentication credentials must be protected during transmission using approved encrypted protocols.
    
5. Applications must not:
    
    - write passwords to logs;
        
    - display passwords on screen in clear text;
        
    - include passwords in URLs; or
        
    - expose passwords through error messages.
        
6. Password reset tokens and authentication secrets must be protected as sensitive information.
    

---

### 5.12 Privileged accounts

1. Privileged accounts must be separate from normal user accounts.
    
2. Privileged accounts must use MFA.
    
3. Privileged passwords must be unique and must not be reused for normal accounts.
    
4. Privileged access must be logged and monitored.
    
5. Privileged credentials must be stored in an approved privileged-access or password-management system where available.
    
6. Administrative access must be granted only to authorized users based on business need and least privilege.
    
7. Privileged-account access must be reviewed at least quarterly.
    

---

### 5.13 Service and application accounts

1. Service accounts must have a documented owner and business purpose.
    
2. Service-account credentials must not be embedded in:
    
    - source code;
        
    - scripts;
        
    - public repositories;
        
    - configuration files accessible to unauthorized users; or
        
    - documentation.
        
3. Service-account secrets must be stored in an approved secrets-management system.
    
4. Service accounts must receive only the permissions required for their function.
    
5. Interactive login must be disabled unless specifically required.
    
6. Credentials must be changed or rotated:
    
    - after suspected compromise;
        
    - when an administrator with access leaves or changes role;
        
    - according to the approved system risk assessment; or
        
    - when required by the secrets-management platform.
        
7. Service accounts must be reviewed at least quarterly.
    

---

### 5.14 Suspected compromise and reporting

Users must immediately report:

- a lost, stolen, or disclosed password;
    
- suspected phishing;
    
- an unexpected MFA request;
    
- unauthorized account activity;
    
- a password entered on a suspicious website;
    
- a lost authentication device;
    
- accidental credential disclosure; or
    
- any request from another person to reveal a password.
    

Reports must be made to:

- **Security Team:** security@[organization-domain]
    
- **IT Service Desk:** [service-desk telephone/email]
    
- **Emergency contact:** [24-hour security contact, if applicable]
    

Users must not delay reporting while attempting to investigate the incident themselves.

The IT or Security Team must disable, reset, monitor, or otherwise protect the affected account according to the Incident Response Policy.

---

## 6. Roles and Responsibilities

### 6.1 All users

All users must:

- follow this policy;
    
- create and maintain secure passwords;
    
- protect passwords from disclosure;
    
- use MFA where required;
    
- use only approved password managers;
    
- report suspected compromise immediately;
    
- complete required security-awareness training; and
    
- cooperate with security investigations.
    

### 6.2 Managers

Managers must:

- ensure team members understand this policy;
    
- approve access only when there is a valid business need;
    
- notify Human Resources and IT when a user changes role or leaves;
    
- support corrective actions for violations; and
    
- review access assigned to their staff when requested.
    

### 6.3 Information Technology Department

IT must:

- configure systems to enforce applicable password requirements;
    
- implement secure authentication, reset, storage, and transmission controls;
    
- remove or change default passwords;
    
- maintain supported authentication systems;
    
- promptly disable accounts when authorized;
    
- assist users through approved recovery procedures;
    
- preserve authentication logs; and
    
- not request or record user passwords.
    

### 6.4 Information Security Department

The Information Security Department must:

- own and maintain this policy;
    
- define approved authentication technologies;
    
- maintain or approve password blocklists;
    
- review high-risk authentication configurations;
    
- monitor compliance;
    
- investigate suspected credential compromise;
    
- review exception requests;
    
- provide awareness and guidance; and
    
- report significant non-compliance to management.
    

### 6.5 System and application owners

System owners must:

- classify the risk and sensitivity of their systems;
    
- implement this policy in systems they manage;
    
- document technical limitations;
    
- review privileged and service accounts;
    
- ensure authentication controls are tested; and
    
- request formal exceptions where compliance is not technically possible.
    

### 6.6 Human Resources

Human Resources must:

- support policy acknowledgement;
    
- notify IT promptly about employment changes and terminations;
    
- coordinate disciplinary action when necessary; and
    
- ensure enforcement follows employment agreements and applicable law.
    

### 6.7 Third parties

Third parties must:

- comply with this policy or equivalent contractual requirements;
    
- protect credentials issued by the organization;
    
- report suspected compromise immediately; and
    
- return or securely remove organizational credentials when access ends.
    

---

## 7. Compliance and Monitoring

Compliance may be verified through:

- automated system-configuration checks;
    
- access reviews;
    
- authentication-log monitoring;
    
- audits;
    
- security assessments;
    
- penetration testing;
    
- incident investigations;
    
- password-blocklist checks;
    
- reviews of privileged and service accounts; and
    
- confirmation of MFA deployment.
    

The organization must not collect or inspect users’ clear-text passwords during compliance testing.

Policy effectiveness should be measured using indicators such as:

- percentage of covered systems enforcing required password lengths;
    
- percentage of privileged accounts protected with MFA;
    
- number of accounts using default credentials;
    
- number of credential-related incidents;
    
- time taken to disable compromised accounts;
    
- percentage of privileged accounts reviewed each quarter;
    
- number and age of approved exceptions; and
    
- completion rate for authentication-security training.
    

---

## 8. Enforcement

Violations of this policy may result in:

- required security training;
    
- password reset;
    
- temporary suspension of access;
    
- removal of privileged access;
    
- corrective or disciplinary action;
    
- termination of employment or contract; and
    
- legal action where appropriate.
    

Enforcement must be consistent with:

- applicable laws;
    
- employment agreements;
    
- contractual obligations;
    
- Human Resources procedures; and
    
- the seriousness and frequency of the violation.
    

The organization may immediately restrict or suspend an account when necessary to protect systems, information, users, or business operations.

---

## 9. Policy Exceptions

A user or system owner who cannot comply with a requirement must submit a written exception request before operating outside the policy.

The request must include:

- the specific requirement;
    
- the business or technical reason;
    
- affected systems and users;
    
- information classification;
    
- risk assessment;
    
- proposed compensating controls;
    
- requested duration;
    
- responsible owner; and
    
- remediation plan.
    

Exceptions must be approved by:

- the system or business owner;
    
- the Information Security Manager; and
    
- an authorized risk owner when significant risk remains.
    

Every exception must:

- be documented;
    
- have an expiration date;
    
- be reviewed before renewal;
    
- be monitored for compliance with compensating controls; and
    
- be closed when the limitation no longer exists.
    

An exception must not be treated as permanent authorization to ignore the policy.

---

## 10. Training and Awareness

All users must receive password and authentication awareness training:

- during onboarding;
    
- at least annually;
    
- after significant policy changes; and
    
- after relevant security incidents when additional training is necessary.
    

Training should address:

- creating long passphrases;
    
- password reuse;
    
- password managers;
    
- MFA fatigue attacks;
    
- phishing;
    
- password sharing;
    
- suspicious reset requests; and
    
- incident reporting.
    

---

## 11. Related Documents and References

This policy should be read together with:

- Acceptable Use Policy;
    
- Access Control Policy;
    
- Incident Response Policy;
    
- Information Security Policy;
    
- Remote Access Policy;
    
- User Account Management Procedure;
    
- Privileged Access Standard;
    
- Security Incident Reporting Procedure;
    
- NIST SP 800-12, _An Introduction to Information Security_;
    
- NIST SP 800-63B, _Digital Identity Guidelines: Authentication and Authenticator Management_; and
    
- applicable SANS security-policy templates and standards.
    

---

## 12. Review and Maintenance

This policy must be reviewed:

- at least annually;
    
- after a significant authentication-related incident;
    
- after a major change to identity or access-management systems;
    
- when relevant legal, regulatory, or contractual requirements change;
    
- when audits identify material weaknesses; or
    
- when new authentication threats require updated controls.
    

The Information Security Manager is responsible for coordinating the review and submitting revisions for approval.

---

## 13. Contact Information

Questions, clarification requests, and suspected violations should be directed to:

**Information Security Department**  
Email: security@[organization-domain]  
Telephone: [security contact number]

**IT Service Desk**  
Email: [service-desk email] 
Telephone: [service-desk number]

---

## 14. Approval

|Role|Name|Signature|Date|
|---|---|---|---|
|Information Security Manager|Pending|Pending|Pending|
|Chief Information Officer|Pending|Pending|Pending|
|Authorized Executive|Pending|Pending|Pending|

---

## 15. Revision History

|Version|Date|Author/Owner|Description|
|---|---|---|---|
|0.1|22 June 2026|Information Security Department|Initial draft|
|1.0|Pending approval|Information Security Manager|First approved release|