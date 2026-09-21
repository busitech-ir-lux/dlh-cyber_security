Structured IOC Table

IOC Type

IOC Value

Source Email

Context

Confidence

Recommended Action

Domain

meddefense-portal[.]com

E2

MedDefense IT impersonation domain used for staff portal re-verification

HIGH

BLOCK

IP

91[.]234[.]99[.]107

E2

External sending IP for meddefense-portal.com

HIGH

ALERT

URL

hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

E2

Credential-verification link clicked by Diane Marsh

HIGH

BLOCK

Email address

noreply@meddefense-portal[.]com

E2

Sender address used in MedDefense IT impersonation

HIGH

BLOCK

Tool

PHPMailer 6.6.0

E2

Mailer used to generate the message

LOW

CONTEXT ONLY

Domain

outlook-protection[.]com

E3

Lookalike domain used to impersonate Microsoft Account Protection

HIGH

BLOCK

IP

51[.]38[.]42[.]17

E3

External sending IP for outlook-protection.com

MEDIUM

ALERT

URL

hxxps://outlook-protection[.]com/verify

E3

Account-verification link in Microsoft-themed phishing lure

HIGH

BLOCK

Email address

security@outlook-protection[.]com

E3

Sender address used in Microsoft impersonation

HIGH

BLOCK

Tool

PHPMailer 6.6.0

E3

Mailer used to generate the message

LOW

CONTEXT ONLY

Domain

medequip-supplies[.]net

E5

Medical-supply invoice and payment lure targeting Accounts Payable

HIGH

BLOCK

IP

185[.]176[.]43[.]22

E5

External sending IP for medequip-supplies.net

HIGH

ALERT

URL

hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

E5

Payment URL linked to the invoice lure

HIGH

BLOCK

URL

hxxps://medequip-supplies[.]net/portal/login

E5

Login portal included in the suspicious invoice email

HIGH

BLOCK

Email address

invoices@medequip-supplies[.]net

E5

Sender address used in the invoice lure

HIGH

BLOCK

File hash

2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f

E5

SHA-256 value embedded in the PDF attachment data shown in the raw email evidence

MEDIUM

ALERT

Attachment artifact

INV-2026-04891.pdf

E5

PDF attachment matching the invoice pretext

MEDIUM

ALERT

Tool

PHPMailer 6.6.0

E5

Mailer used to generate the message

LOW

CONTEXT ONLY

Domain

meddefense-benefits[.]org

E7

MedDefense HR/benefits impersonation domain

HIGH

BLOCK

IP

164[.]90[.]218[.]73

E7

External sending IP for meddefense-benefits.org

HIGH

ALERT

URL

hxxps://meddefense-benefits[.]org/enroll

E7

Open-enrollment link in benefits phishing lure

HIGH

BLOCK

Email address

hr-notifications@meddefense-benefits[.]org

E7

Sender address used in MedDefense HR impersonation

HIGH

BLOCK

Tool

PHPMailer 6.6.0

E7

Mailer used to generate the message

LOW

CONTEXT ONLY

Infrastructure note

Lookalike domains using terms such as portal, benefits, supplies, or login

E8

HC3-reported pattern for the active healthcare-sector phishing campaign

MEDIUM

MONITOR

Infrastructure note

Newly registered domains with registration age under 30 days

E8

HC3-reported campaign pattern; registration age is not confirmed for the MedDefense domains in this evidence batch

MEDIUM

MONITOR

Tool

PHPMailer-based sending infrastructure

E8

HC3-reported campaign pattern that matches E2, E5, and E7

LOW

CONTEXT ONLY

Infrastructure note

Budget VPS hosting

E8

HC3-reported infrastructure pattern

LOW

CONTEXT ONLY

Infrastructure note

24–48 hour deadlines / account lockout / open-enrollment pressure

E8

HC3-reported urgency pattern

LOW

CONTEXT ONLY

Infrastructure note

Role-specific targeting of clinical, billing, and HR recipients

E8

HC3-reported targeting pattern that closely matches the MedDefense evidence

MEDIUM

MONITOR

IOC Categorization by Attack Phase

Delivery

These indicators relate to how the phishing messages were sent to MedDefense.

noreply@meddefense-portal[.]com

security@outlook-protection[.]com

invoices@medequip-supplies[.]net

hr-notifications@meddefense-benefits[.]org

91[.]234[.]99[.]107

51[.]38[.]42[.]17

185[.]176[.]43[.]22

164[.]90[.]218[.]73

PHPMailer 6.6.0

The sender addresses and sending IPs are useful for searching mail logs or alerting on related messages. PHPMailer is not strong enough to block by itself because it is legitimate software and may be used by many unrelated senders.

Credential Harvesting

These indicators directly point to pages that ask the user to verify, log in, or enroll.

hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

hxxps://outlook-protection[.]com/verify

hxxps://medequip-supplies[.]net/portal/login

hxxps://meddefense-benefits[.]org/enroll

These are high-confidence campaign indicators because they are directly embedded in phishing messages and support the phishing pretexts.

Attachment or Lure Artifact

INV-2026-04891.pdf

SHA-256: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f

hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

The PDF filename and invoice number are useful for searching related mail or file artifacts. The hash is more specific than the filename and is therefore a better alerting indicator. The evidence batch does not prove that the PDF itself executed malicious code.

Infrastructure

meddefense-portal[.]com

outlook-protection[.]com

medequip-supplies[.]net

meddefense-benefits[.]org

91[.]234[.]99[.]107

51[.]38[.]42[.]17

185[.]176[.]43[.]22

164[.]90[.]218[.]73

The domains are stronger campaign indicators than general hosting characteristics because they are directly tied to the observed phishing messages.

Context-Only Indicators

The following should support correlation, not be used alone for blocking:

PHPMailer 6.6.0

PHPMailer-based infrastructure

Budget VPS hosting

Newly registered domains

Domain names containing words such as portal, benefits, supplies, or login

Urgency-based messages with 24–48 hour deadlines

Account-lockout threats

Open-enrollment pressure

Role-specific targeting of clinical, finance, billing, or HR-related users

These characteristics appear in the HC3 alert and match the MedDefense phishing set, but each one can also occur in legitimate activity.

IOC Quality Assessment

High-Confidence IOCs

The strongest IOCs are the domains and URLs directly observed in the phishing messages:

meddefense-portal[.]com

outlook-protection[.]com

medequip-supplies[.]net

meddefense-benefits[.]org

Their phishing URLs listed above

Sender addresses using those same phishing domains

These are suitable for blocking in the MedDefense environment because the investigation directly connects them to phishing activity.

Indicators Best Used for Alerting or Monitoring

The sending IPs are useful for detection and correlation:

91[.]234[.]99[.]107

51[.]38[.]42[.]17

185[.]176[.]43[.]22

164[.]90[.]218[.]73

They should generally be used for alerting or investigation rather than treated as permanent standalone block indicators because IP infrastructure can change or be reused.

The E5 PDF SHA-256 is specific and useful for alerting. Its confidence is marked MEDIUM because the evidence batch contains the hash value and suspicious attachment context, but it does not independently prove malicious file execution or behavior.

Indicators That Should Not Be Used Alone

The following have high false-positive potential if used by themselves:

PHPMailer 6.6.0

PHPMailer-based sending infrastructure

Budget VPS hosting

A recently registered domain

A domain containing portal, benefits, supplies, or login

High-priority email headers

Urgency language

Role-specific business lures

For example, PHPMailer is a legitimate email library. Blocking all PHPMailer-generated messages would affect unrelated legitimate senders.

Similarly, a newly registered domain or a domain containing the word portal is not automatically malicious. These are useful when combined with stronger evidence such as a known phishing URL, failed authentication, impersonation, or campaign correlation.

HC3-Ready IOC Summary

Domains

meddefense-portal[.]com

outlook-protection[.]com

medequip-supplies[.]net

meddefense-benefits[.]org

Sending IPs

91[.]234[.]99[.]107 — E2

51[.]38[.]42[.]17 — E3

185[.]176[.]43[.]22 — E5

164[.]90[.]218[.]73 — E7

Sender Addresses

noreply@meddefense-portal[.]com

security@outlook-protection[.]com

invoices@medequip-supplies[.]net

hr-notifications@meddefense-benefits[.]org

URLs

hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

hxxps://outlook-protection[.]com/verify

hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

hxxps://medequip-supplies[.]net/portal/login

hxxps://meddefense-benefits[.]org/enroll

Attachment Indicator

Filename: INV-2026-04891.pdf

SHA-256: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f

Campaign Context

Observed MedDefense activity matches several patterns described in the HC3 alert:

Healthcare-sector targeting

Lookalike domains

PHPMailer-based sending

Role-specific lures

Urgency and deadline pressure

Portal, benefits, supplies, and login themes

These similarities support campaign correlation, but they do not identify or prove a specific threat actor.
