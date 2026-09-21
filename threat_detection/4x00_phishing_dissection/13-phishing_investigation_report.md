Executive Summary

MedDefense Health Systems received eight emails during a roughly 57-hour period, including legitimate messages, spam, and multiple targeted phishing attempts. The strongest campaign cluster consists of Emails 2, 5, and 7, which share PHPMailer-based delivery, similar Message-ID patterns, high-priority headers, failed or weak authentication, and role-specific lures. Email 3 is also phishing, but it differs because SPF, DKIM, and DMARC pass for its own lookalike domain rather than for Microsoft. Diane Marsh clicked the Email 2 credential-verification link, but the available evidence does not show whether credentials were entered or later abused. Immediate priorities are containment of the identified phishing infrastructure, protection of Diane’s account, and monitoring for similar role-targeted messages.

Investigation Timeline

Collection Window

Evidence batch collection window: 2026-04-14 07:22 CDT to 2026-04-16 15:22 CDT

Approximate duration: 57 hours

Evidence collected by Mike Torres on 2026-04-17 09:15 CDT

Scope: Eight raw SMTP emails with full headers preserved

Investigation basis: Email evidence only; no live Wazuh, Sysmon, Suricata, SIEM, or endpoint telemetry was available

Relevant Email Events

Time

Event

Apr 14, 07:22 CDT

E1 newsletter delivered

Apr 14, 14:47 CDT

E2 MedDefense portal-verification phishing email delivered to Diane Marsh

Apr 14, 15:02:33 CDT

Diane Marsh reported as having clicked the E2 link from WS-NURSE-04

Apr 15, 09:13 CDT

E3 Microsoft-themed account-warning phishing email delivered

Apr 15, 10:00 CDT

E4 legitimate internal MedDefense password-change reminder delivered

Apr 16, 08:47 CDT

E8 HC3 healthcare-sector phishing alert delivered

Apr 16, 11:28 CDT

E5 medical-supply invoice phishing email delivered

Apr 16, 13:04 CDT

E6 pharmaceutical spam delivered

Apr 16, 15:22 CDT

E7 MedDefense benefits phishing email delivered

Email-by-Email Analysis

Email

Final Classification

Confidence

Key Evidence

E1

LEGITIMATE-WITH-ISSUE

HIGH

SPF, DKIM, and DMARC pass; sender and infrastructure are consistent; MailChimp and unsubscribe headers indicate legitimate bulk mail.

E2

PHISHING-TARGETED

HIGH

MedDefense IT impersonation; meddefense-portal.com; SPF fail; DKIM none; DMARC fail; PHPMailer; 24-hour access threat; confirmed user click.

E3

PHISHING-TARGETED

HIGH

Claims Microsoft Account Protection but authenticates only outlook-protection.com; PHPMailer; urgent account-compromise and lockout lure.

E4

LEGITIMATE

HIGH

Internal meddefense.com sender; internal IP 10.10.1.15; SPF, DKIM, and DMARC pass; Microsoft Exchange; content matches internal guidance.

E5

PHISHING-TARGETED

HIGH

Accounts Payable invoice lure; SPF softfail; DKIM none; DMARC fail; PHPMailer; payment/login URLs; PDF attachment; financial pressure.

E6

SPAM

HIGH

Pharmaceutical bulk advertisement; SPF softfail; DKIM none; DMARC fail with quarantine action; spam score 9.8; bulk mailer; raw-IP URL.

E7

PHISHING-TARGETED

HIGH

MedDefense HR/benefits impersonation; SPF fail; DKIM none; DMARC fail; PHPMailer; next-day enrollment deadline and coverage-loss pressure.

E8

LEGITIMATE

HIGH

HC3@hhs.gov; SPF, DKIM, and DMARC pass for hhs.gov; HHS mail infrastructure; healthcare phishing alert aligns with observed campaign patterns.

E1 — Newsletter

E1 is best classified as LEGITIMATE-WITH-ISSUE, not phishing. The sender domain, Return-Path, authentication results, and sending infrastructure are consistent, and the message includes normal bulk-mail fields such as List-Unsubscribe, List-Unsubscribe-Post, and Precedence: bulk. It may be unwanted by the user, but the evidence does not support a malicious classification.

E2 — Portal Verification

E2 is targeted phishing against Diane Marsh. It claims to be from MedDefense IT Security while using meddefense-portal.com, an external domain rather than the known internal meddefense.com domain. SPF and DMARC fail, DKIM is absent, the message was generated with PHPMailer, and the user is pressured to verify access within 24 hours.

E3 — Microsoft Account Warning

E3 is targeted phishing even though SPF, DKIM, and DMARC pass. Those controls authenticate outlook-protection.com, not Microsoft. The visible brand claims Microsoft Account Protection, but outlook-protection.com is not the same as microsoft.com or outlook.com.

E4 — Internal IT Message

E4 is legitimate. It was sent through internal MedDefense infrastructure from 10.10.1.15, uses meddefense.com, passes SPF, DKIM, and DMARC, and identifies Microsoft Exchange Server 2019 as the mailer.

E5 — Invoice Lure

E5 is targeted phishing aimed at Accounts Payable. It contains a realistic invoice number, a payment amount of USD 24,716.38, a payment deadline, a PDF attachment, and both payment and login URLs. Authentication is weak or failed: SPF softfail, no DKIM, and DMARC fail.

E6 — Pharmaceutical Spam

E6 is spam rather than part of the targeted campaign. It advertises discounted pharmaceuticals, uses a bulk mailer, has a spam score of 9.8, and links directly to an IP address. DMARC fails with a quarantine action.

E7 — Benefits Lure

E7 is targeted phishing using a MedDefense HR/benefits pretext. It tells Linda Patterson that benefits enrollment closes the next day and threatens loss of coverage. The message uses meddefense-benefits.org, fails SPF and DMARC, has no DKIM signature, and was generated with PHPMailer.

E8 — HC3 Alert

E8 is legitimate healthcare-sector threat intelligence from HC3/HHS. SPF, DKIM, and DMARC pass for hhs.gov, and the message describes an active healthcare phishing pattern involving lookalike domains, PHPMailer infrastructure, role-specific lures, and urgency.

Campaign Analysis

Why E2, E5, and E7 Are Likely Connected

E2, E5, and E7 show multiple independent similarities:

All use PHPMailer 6.6.0.

All use X-Priority: 1 (Highest).

All use a PHP-<identifier>@domain Message-ID pattern.

All use external domains tied to believable MedDefense or healthcare business functions.

All use role-relevant lures rather than generic phishing content.

All rely on urgency, deadlines, or negative consequences.

All have failed or weak SPF results.

All have no DKIM signature.

All fail DMARC.

All were delivered within roughly two days.

The lures are adapted to different business processes:

E2: clinical/staff portal access

E5: Accounts Payable and medical-supply invoicing

E7: employee benefits/open enrollment

This combination of technical repetition and role-specific social engineering supports a coordinated campaign assessment.

How E8 Supports the Campaign Hypothesis

The HC3 alert in E8 describes a healthcare-sector phishing campaign with several patterns that directly match the MedDefense evidence:

Lookalike domains using terms such as portal, benefits, supplies, and login

PHPMailer-based sending infrastructure

Urgency-based social engineering

24–48 hour deadlines and account-lockout or enrollment pressure

Role-specific targeting of clinical, billing, and HR-related recipients

Credential harvesting as the primary objective

The MedDefense evidence independently shows several of these same characteristics.

The HC3 alert also mentions newly registered domains, but the evidence batch itself does not contain registration-age data for the MedDefense phishing domains, so that specific point cannot be confirmed from the supplied evidence alone.

How E3 Should Be Interpreted

E3 is phishing, but it should not be treated as identical to E2, E5, and E7.

Its main difference is that SPF, DKIM, and DMARC all pass. However, the authenticated domain is outlook-protection.com, while the message claims to be Microsoft Account Protection. Passing email authentication therefore confirms control of the lookalike domain, not Microsoft legitimacy.

E3 uses the same PHPMailer version and a similar PHP-... Message-ID pattern as the main phishing cluster, so it is relevant for correlation. However, the available evidence is not strong enough to prove that E3 was operated by the same actor as E2, E5, and E7.

Click Incident Assessment

Confirmed Facts

User: Diane Marsh

Email: dmarsh@meddefense.com

Workstation: WS-NURSE-04

Workstation IP: 10.10.2.15

Phishing email: E2

Domain: meddefense-portal.com

URL: hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

E2 sending IP: 91[.]234[.]99[.]107

Click timestamp: 2026-04-14 15:02:33 CDT

What Can Be Concluded

The click is confirmed. E2 is a targeted credential-verification lure, so the click represents meaningful exposure to a phishing portal.

What Cannot Be Concluded

The evidence batch does not show:

Whether the page loaded successfully

Whether Diane entered credentials

Whether she approved an MFA prompt

Whether a file was downloaded

Whether an attacker logged in afterward

Whether account settings were changed

Whether any process or file activity occurred on the workstation

Therefore the correct status is:

Click confirmed; compromise not yet determined.

Safe Next Actions

Interview Diane and determine exactly what she entered or approved.

Reset her password if credential exposure cannot be ruled out.

Revoke active sessions and authentication tokens.

Verify registered MFA methods.

Review for suspicious login activity if identity logs become available.

Check for unexpected inbox rules, forwarding rules, password changes, or group changes.

Review browser history, downloads, process execution, PowerShell/cmd activity, and file creation if endpoint logs become available.

Continue monitoring for other users who received or clicked related phishing links.

IOC Summary

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

E5 Attachment Indicators

Filename: INV-2026-04891.pdf

SHA-256: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f

Context Indicators

The following are useful for correlation but should not be blocked by themselves:

PHPMailer 6.6.0

PHP-... Message-ID pattern

X-Priority: 1 (Highest)

Recently registered domains

Budget VPS hosting

Domains using words such as portal, benefits, supplies, or login

Urgency-based and role-specific business lures

Detection and Control Gaps

What Existing Controls Did Not Prevent

The evidence shows that at least E2 reached Diane Marsh and was clicked. E5 and E7 were also reported by users, which indicates that these suspicious messages reached user-visible mailboxes.

Important gaps include:

Failed or weak authentication alone did not prevent delivery of E2, E5, and E7.

Lookalike MedDefense-themed domains were not stopped before reaching users.

Role-specific phishing content was convincing enough to require user reporting and, in E2, caused a confirmed click.

A correctly authenticated lookalike domain such as E3 can bypass simple logic that treats SPF/DKIM/DMARC pass as proof of legitimacy.

Repeated PHPMailer and Message-ID patterns were visible across several suspicious emails but were not sufficient by themselves to prevent delivery.

Improvements

Alert on external domains that imitate internal MedDefense names or functions.

Correlate SPF/DMARC failures with external URLs and MedDefense impersonation.

Detect brand mismatch where the display name claims Microsoft but the sender domain is unrelated to microsoft.com or outlook.com.

Search for repeated PHPMailer 6.6.0 plus PHP-... Message-ID patterns across multiple inbound messages.

Detect role-specific campaigns where different departments receive different lures from related infrastructure.

Alert when suspicious inbound email is followed by visits to matching external domains.

Maintain blocks for confirmed campaign domains and URLs.

Use sending IPs primarily for alerting and correlation because IP ownership can change.

Detection Ideas

A separate Task 12 artifact was not available in the supplied material, so the detection ideas below are derived directly from the observed evidence and should be aligned with the Task 12 output if that artifact is available elsewhere.

Lookalike MedDefense Domain Detection

Alert when inbound email uses an external sender domain containing meddefense but not the legitimate meddefense.com domain.

Failed Authentication + External Link

Alert when SPF or DMARC fails and the message contains an external verification, login, payment, or enrollment link.

PHPMailer Campaign Correlation

Group messages using PHPMailer 6.6.0 and the PHP-... Message-ID pattern, then compare sender domains, target departments, and URLs.

Brand/Domain Mismatch

Alert when the display identity claims Microsoft but the sender domain is not an approved Microsoft domain.

Role-Specific Phishing Correlation

Correlate similar urgent lures sent to clinical, finance, billing, and HR-related recipients within a short time period.

Post-Click Correlation

If endpoint or proxy data becomes available, correlate a phishing email with subsequent browser access to the same domain, file creation, unusual process execution, or suspicious outbound connections.

Recommendations

Immediate — Next 24 Hours

Block the confirmed phishing domains and URLs:

meddefense-portal[.]com

outlook-protection[.]com

medequip-supplies[.]net

meddefense-benefits[.]org

Search mailboxes for additional messages using the same sender addresses, domains, URLs, PHPMailer headers, or PHP-... Message-ID pattern.

Contact Diane Marsh and determine whether credentials or MFA information were entered.

Reset Diane’s password if credential exposure cannot be ruled out.

Revoke Diane’s active sessions and verify MFA methods.

Check for suspicious mailbox rules, forwarding rules, or account changes if account logs are available.

Preserve E2, E3, E5, E7, and their IOCs as investigation evidence.

Share the high-confidence IOC set with HC3.

Short-Term — Next 7 Days

Review recent inbound mail for MedDefense lookalike domains.

Search for other employees who received or interacted with the campaign.

Add detections for external domains containing MedDefense branding.

Add correlation logic for failed authentication plus login/verification/payment URLs.

Add detection for Microsoft-branded messages where the sender domain is not an approved Microsoft domain.

Review mail-gateway handling of SPF and DMARC failures.

Brief clinical, billing, Accounts Payable, and HR-related staff on the campaign themes.

Monitor Diane’s account for unusual login attempts or account changes.

Medium-Term — Next 30 Days

Improve lookalike-domain and brand-impersonation detection.

Build campaign correlation using mailer type, Message-ID format, sender domain, URL, target role, and timing.

Review whether DMARC enforcement and mail-gateway policy should be strengthened for failed authentication.

Establish a repeatable workflow for passive URL review, attachment hashing, IOC extraction, and campaign reporting.

Integrate confirmed campaign IOCs into detection and alerting rules.

Create detection logic that links suspicious inbound email with later browser, identity, endpoint, or network activity when those data sources are available.

Review lessons learned from Diane’s click and update phishing awareness material using the exact portal, invoice, account-warning, and benefits themes observed in this campaign.

Final Assessment

The investigation identifies four phishing emails: E2, E3, E5, and E7. E2, E5, and E7 show the strongest evidence of a coordinated MedDefense-focused campaign because they share delivery tooling, header patterns, authentication weaknesses, timing, and role-specific business lures, while E8 independently describes a matching healthcare-sector campaign pattern.

E3 is also phishing, but its correctly configured authentication demonstrates an important limitation: SPF, DKIM, and DMARC can validate a malicious lookalike domain without validating the brand being impersonated.

Diane Marsh’s click on E2 creates a credible risk of credential exposure, but the evidence batch alone does not prove account compromise. The case should therefore remain open for identity and endpoint follow-up while the confirmed campaign indicators are blocked, monitored, and shared.
