# SecureBank Financial Services

# Password and Authentication Policy

## Document Control

| Field          | Value                              |
| -------------- | ---------------------------------- |
| Policy ID      | POL-SEC-002                        |
| Version        | 1.0                                |
| Effective Date | 2026-06-23                         |
| Review Date    | 2027-06-23                         |
| Policy Owner   | Chief Information Security Officer |
| Approved By    | Executive Management Committee     |
| Classification | Internal                           |

## 1. Purpose

This policy establishes password and authentication requirements to protect SecureBank systems, customer information, financial records, and payment-card data.

## 2. Scope

### 2.1 Applicability

This policy applies to:

- all employees
    
- contractors and consultants
    
- third-party users
    
- administrators and developers
    
- service and application accounts
    

### 2.2 Systems/Assets Covered

- core banking system
    
- customer portal
    
- employee workstations
    
- administrative systems
    
- development environment
    
- cardholder data environment
    
- cloud and remote-access systems
    

### 2.3 Exclusions

No system is excluded without an approved policy exception.

## 3. Policy Statements

### 3.1 Password Requirements

Users must:

- use at least **15 characters** for password-only authentication
    
- use at least **12 characters** where passwords are combined with MFA
    
- use unique passwords for each account
    
- avoid company names, usernames, personal information, common phrases, and predictable patterns
    
- not reuse any of the previous four passwords
    
- not share passwords or store them in unapproved locations
    

Systems must:

- support passwords of at least 64 characters
    
- allow passphrases and spaces
    
- reject common, breached, default, and compromised passwords
    
- not silently shorten passwords
    
- not require arbitrary character-composition rules unless a system or regulatory requirement makes them necessary
    

### 3.2 Password Management

Passwords must be changed immediately when compromise is known or suspected.

Routine password expiration is not required where MFA and risk-based monitoring are implemented. Systems using password-only authentication within PCI DSS scope must either:

- require a password change at least every 90 days, or
    
- use approved dynamic risk-based access controls
    

Temporary passwords must:

- be unique
    
- expire within 24 hours
    
- be changed at first login
    
- be delivered through an approved secure channel
    

Password resets must verify the user’s identity and notify the user after completion.

### 3.3 Lockout and Session Controls

Accounts must be locked after no more than **10 failed login attempts**.

Lockout must remain in effect for at least **30 minutes** or until identity is verified.

Sessions connected to the cardholder data environment must require reauthentication after no more than **15 minutes** of inactivity.

### 3.4 Multi-Factor Authentication

MFA is required for:

- all access to the cardholder data environment
    
- administrative and privileged accounts
    
- core banking systems
    
- remote and VPN access
    
- cloud administration
    
- access to sensitive financial or customer data
    

Approved methods include:

- FIDO2 security keys
    
- platform passkeys
    
- smart cards or certificates
    
- approved authenticator applications
    
- number-matching push authentication
    

SMS and voice MFA may be used only through an approved exception.

### 3.5 Password Storage

Passwords must:

- never be stored in plain text
    
- never be stored using reversible encryption
    
- be protected with approved salted password-hashing algorithms
    
- be encrypted during transmission
    
- never appear in logs, URLs, source code, scripts, or tickets
    

Approved enterprise password managers must be used for storing business passwords.

### 3.6 Privileged Accounts

Privileged users must:

- use separate standard and administrative accounts
    
- use phishing-resistant MFA
    
- access privileged credentials through the approved Privileged Access Management system
    
- not share administrative accounts
    
- use time-limited privileged access where supported
    

Privileged credentials must be reviewed quarterly and rotated after suspected compromise or personnel changes.

### 3.7 Service and Application Accounts

Service accounts must:

- have a documented owner and purpose
    
- use vault-managed credentials
    
- follow least privilege
    
- prohibit interactive login unless approved
    
- avoid credentials embedded in source code
    
- have credentials rotated according to risk and system capability
    

## 4. Roles and Responsibilities

|Role|Responsibilities|
|---|---|
|Executive Management|Approve policy and provide resources|
|Information Security|Define controls, monitor compliance, review exceptions|
|IT Operations|Configure authentication, resets, lockouts, and MFA|
|System Owners|Implement requirements and review account access|
|Managers|Ensure staff compliance and report access changes|
|Users|Protect credentials, use MFA, and report compromise|
|Internal Audit|Assess compliance with PCI DSS, SOX, FFIEC, and this policy|

## 5. Compliance

### 5.1 Monitoring

Compliance will be monitored through:

- configuration reviews
    
- MFA coverage reports
    
- privileged-account reviews
    
- authentication-log monitoring
    
- password-control testing
    

### 5.2 Reporting

Suspected password compromise must be reported immediately to:

`security@securebank.example`

### 5.3 Auditing

Authentication controls must be audited at least annually and during PCI DSS, SOX, and regulatory assessments.

## 6. Enforcement

### 6.1 Violations

Violations may result in:

- mandatory password reset
    
- access suspension
    
- retraining
    
- disciplinary action
    
- termination
    
- legal action where applicable
    

### 6.2 Reporting Violations

Report suspected violations to the Information Security Team or IT Service Desk.

## 7. Exceptions

### 7.1 Exception Process

Exceptions require:

1. written business justification
    
2. documented risk assessment
    
3. compensating controls
    
4. approval from the CISO and system owner
    
5. documented expiration date
    

### 7.2 Exception Duration

Exceptions may not exceed 12 months and must be reviewed quarterly.

## 8. Definitions

|Term|Definition|
|---|---|
|MFA|Authentication using two or more independent factors|
|Privileged Account|Account with elevated administrative permissions|
|PAM|System used to control and monitor privileged access|
|Passphrase|Long password formed from multiple words|
|CDE|Cardholder Data Environment|

## 9. Related Documents

- Access Control Policy
    
- Privileged Access Standard
    
- Incident Response Policy
    
- PCI DSS v4.0.1 Requirement 8
    
- NIST SP 800-63B
    
- OWASP Authentication Cheat Sheet
    
- OWASP Password Storage Cheat Sheet
    
- CISA MFA Guidance
    
- FFIEC Authentication Guidance
    

## 10. Revision History

|Version|Date|Author|Description|
|---|---|---|---|
|1.0|2026-06-23|Information Security Team|Initial release|

## 11. Acknowledgment

By accessing SecureBank systems, users acknowledge that they have read, understood, and agree to comply with this policy.

---

# Password Technical Standard

## 1. Password Configuration

|Control|Standard|
|---|---|
|Password-only minimum|15 characters|
|Password with MFA minimum|12 characters|
|Supported maximum|At least 64 characters|
|Password history|Previous 4 prohibited|
|Compromised-password check|Required|
|Default passwords|Changed before production|
|Failed attempts|Maximum 10|
|Lockout|Minimum 30 minutes|
|CDE inactivity timeout|Maximum 15 minutes|

## 2. Password Storage

Approved order of preference:

1. Argon2id
    
2. scrypt
    
3. PBKDF2-HMAC-SHA-256 where required for approved compliance or platform compatibility
    
4. bcrypt only for approved legacy systems
    

Each password must use a unique cryptographic salt.

Hashing parameters must be reviewed annually and adjusted based on current security guidance and system performance.

## 3. MFA Standard

Preferred methods:

1. FIDO2 security key or passkey
    
2. smart card or certificate
    
3. approved authenticator application
    
4. number-matching push notification
    

SMS, email, and voice codes are not approved for privileged or core banking access.

## 4. Password Managers and PAM

- Users must use the approved enterprise password manager.
    
- Privileged passwords must be stored in the PAM platform.
    
- Shared privileged credentials must be checked out, logged, time-limited, and rotated after use where supported.
    
- Browser-based or personal password storage is prohibited for business credentials.
    

## 5. Review

This standard must be reviewed annually and after major incidents, regulatory changes, or authentication-platform changes.