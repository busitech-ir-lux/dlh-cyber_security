Campaign Thread Analysis

Shared Indicators

E2, E5, and E7 use different pretexts, but they share several notable characteristics:

All three were generated with PHPMailer 6.6.0.

All three use X-Priority: 1 (Highest).

All three use a Message-ID in the same pattern:

E2: <PHP-5D7E2F4A@meddefense-portal.com>

E5: <PHP-7C2D4E1A@medequip-supplies.net>

E7: <PHP-2E4A7B1C@meddefense-benefits.org>

All three use external domains designed around believable business functions:

meddefense-portal.com

medequip-supplies.net

meddefense-benefits.org

E2 and E7 directly imitate MedDefense internal functions.

E5 imitates a medical-supply vendor and targets a business payment process.

All three rely on urgency or pressure:

E2: portal access must be verified within 24 hours.

E5: payment is due within 7 days, with threatened late fees and delivery suspension.

E7: benefits enrollment closes the next day.

All three use role-relevant business processes instead of a generic mass-phishing story.

Authentication is weak or failed across the three:

E2: SPF fail, DKIM none, DMARC fail.

E5: SPF softfail, DKIM none, DMARC fail.

E7: SPF fail, DKIM none, DMARC fail.

These repeated technical and social-engineering patterns support correlation between the emails.

Targeting Map

Email

Recipient / Role Context

Lure

Targeting Pattern

E2

Diane Marsh / clinical staff context

Staff portal re-verification

Uses internal-access language, EHR gateway, scheduling, and shift-swap systems

E5

Angela Rivera / Accounts Payable

Medical-supply invoice

Uses invoice number, amount due, payment deadline, and supplier-payment workflow

E7

Linda Patterson / employee benefits lure

Open enrollment / HR benefits

Uses coverage-loss pressure and benefits re-enrollment language

E2 is tailored to a clinical employee, E5 is tailored to Accounts Payable, and E7 is built around an HR/benefits process.

The evidence batch identifies Linda Patterson as being in Billing, so E7 should not be described as proven HR staff targeting. It is better described as an employee-targeted benefits lure using an HR-style pretext.

Timing Map

Email

Date / Time

Observation

E2

April 14, 2026 — 14:47:51 CDT

Portal-verification lure delivered to Diane Marsh

E5

April 16, 2026 — 11:28:37 CDT

Invoice lure delivered to Angela Rivera

E7

April 16, 2026 — 15:22:05 CDT

Benefits-enrollment lure delivered to Linda Patterson

The three messages were delivered within roughly two days of each other.

The evidence does not show an April 15 delivery for E5 or E7. E5 and E7 were both delivered on April 16.

Comparison With HC3 Alert

Email 8 contains an HC3 alert describing an active healthcare-sector phishing campaign.

The HC3 alert reports the following patterns:

Lookalike domains using terms such as portal, benefits, supplies, or login.

PHPMailer-based sending infrastructure.

Urgency-based social engineering.

24–48 hour deadlines, account-lockout threats, and open-enrollment cutoffs.

Role-specific targeting of clinical staff, billing staff, and HR recipients.

Credential harvesting as the primary observed objective.

The MedDefense evidence shows several direct similarities:

HC3 Pattern

MedDefense Evidence

Portal-themed lookalike domain

E2 uses meddefense-portal.com

Supplies-themed domain

E5 uses medequip-supplies.net

Benefits-themed lookalike domain

E7 uses meddefense-benefits.org

PHPMailer infrastructure

E2, E5, and E7 all use PHPMailer 6.6.0

Urgency / pressure

All three use deadlines or consequences

Clinical targeting

E2 targets Diane with portal/EHR-related language

Billing / finance targeting

E5 targets Accounts Payable

HR / benefits theme

E7 uses an open-enrollment benefits lure

Credential-harvesting style

E2 and E7 direct users to verification/enrollment portals; E5 also includes a login portal

One HC3 pattern cannot be confirmed from the raw email evidence alone: the alert says the campaign uses newly registered domains, but the evidence batch does not contain domain-registration dates for E2, E5, or E7.

Attribution Assessment

The evidence supports the conclusion that E2, E5, and E7 are likely related at the campaign level.

Supporting points include:

Same sending software: PHPMailer 6.6.0.

Same PHP-... Message-ID style.

Same highest-priority header.

Similar authentication weaknesses.

Similar use of realistic business-process lures.

Delivery within a short time window.

Role-specific targeting.

Strong overlap with the HC3 healthcare-sector campaign description.

However, the evidence does not prove:

The real-world identity of the attacker.

A named threat actor or criminal group.

That the same server or IP address sent all three messages.

That one person directly operated every domain.

That the domains share confirmed ownership or registration details.

That the same backend credential-harvesting infrastructure was used.

The sending IPs are different:

E2: 91.234.99.107

E5: 185.176.43.22

E7: 164.90.218.73

This means the strongest connection is the repeated tooling, message structure, targeting strategy, timing, and match to the HC3 alert rather than direct reuse of one sending IP.

Conclusion

The evidence supports treating E2, E5, and E7 as part of a single coordinated phishing campaign targeting MedDefense Health Systems.

The conclusion is based on multiple independent similarities: PHPMailer usage, shared Message-ID style, priority headers, targeted business-process lures, close timing, authentication failures, and strong alignment with the HC3 healthcare-sector phishing patterns described in E8.

The evidence is strong enough for campaign-level correlation, but not for attribution to a specific attacker or named threat actor.
