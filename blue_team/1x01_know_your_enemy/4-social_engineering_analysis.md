# The Human Vector — MedDefense Analysis

## Scenario 1

**Vector Type:** Phishing
The email uses Fortinet brand impersonation, but the main delivery method is email phishing.

**Target:** Sarah Park, IT Director — she manages the FortiGate and may react quickly to a critical security warning.

**Psychological Lever:** Urgency and fear

**Red Flags:**

* The sender domain is `fortinet-support.net`, not an official Fortinet domain.
* The message threatens service termination within 24 hours.
* It asks her to download a patch through an email link instead of the official support portal.

**Technical Control:**
Use secure email filtering with domain-reputation checks and URL scanning.

**Administrative Control:**
Require all firmware updates to be verified and downloaded through the approved vendor portal.

---

## Scenario 2

**Vector Type:** Business Email Compromise (BEC)

**Target:** Robert Kim, CFO — he has authority to approve payments and regularly receives confidential financial requests.

**Psychological Lever:** Authority and urgency

**Red Flags:**

* The CEO’s email address contains a small spelling difference.
* The request demands an immediate transfer of $85,000.
* The sender says not to speak to anyone and requests email-only communication.

**Technical Control:**
Configure email authentication controls such as DMARC, DKIM and SPF, with external-sender warnings.

**Administrative Control:**
Require verbal confirmation and dual approval for all unusual or high-value transfers.

---

## Scenario 3

**Vector Type:** Vishing
The attacker also uses pretexting and impersonation, but the main vector is a phone call.

**Target:** Nurse — clinical staff are busy, helpful and may trust someone claiming to be from IT.

**Psychological Lever:** Authority and helpfulness

**Red Flags:**

* IT asks for the nurse’s password.
* The caller creates urgency by mentioning an emergency audit.
* The nurse did not request support and cannot confirm the caller’s identity.

**Technical Control:**
Use MFA so a stolen password alone cannot provide access.

**Administrative Control:**
Establish a policy stating that IT staff must never request passwords by phone, email or message.

---

## Scenario 4

**Vector Type:** Smishing

**Target:** All MedDefense employees — many staff use parking facilities and may respond quickly to avoid towing.

**Psychological Lever:** Urgency and fear

**Red Flags:**

* The message creates a next-day deadline.
* It threatens towing to force quick action.
* The link requests Active Directory credentials through an SMS message.

**Technical Control:**
Use mobile threat protection or DNS filtering to block known malicious links.

**Administrative Control:**
Require employees to renew parking permits only through the official HR portal or approved application.

---

## Scenario 5

**Vector Type:** Watering Hole Attack

**Target:** MedDefense physicians — they regularly visit the trusted association website for CME credits.

**Psychological Lever:** Familiarity

**Red Flags:**

* Unexpected redirects occur while browsing the association website.
* The browser displays security or certificate warnings.
* A page unexpectedly requests a download, update or browser permission.

**Technical Control:**
Keep browsers patched and use endpoint protection capable of blocking exploit attempts.

**Administrative Control:**
Create a procedure for reporting suspicious behavior on trusted third-party websites.

---

## Scenario 6

**Vector Type:** Typosquatting
The fake website also uses brand impersonation, but the misspelled domain is the main technique.

**Target:** Patients and employees searching for the portal — users may trust the first search result and fail to inspect the domain.

**Psychological Lever:** Familiarity

**Red Flags:**

* The domain uses `meddefence` instead of `meddefense`.
* The portal is reached through a paid advertisement rather than a saved link.
* The site may show small differences in the certificate, URL or login process.

**Technical Control:**
Register common misspellings of MedDefense domains and monitor for similar fraudulent domains.

**Administrative Control:**
Tell patients and staff to access the portal only through the official MedDefense website or a saved bookmark.

---

## Scenario 7

**Vector Type:** Impersonation

**Target:** Staff members entering the restricted IT corridor — employees may assume that someone wearing scrubs belongs in the hospital.

**Psychological Lever:** Familiarity and helpfulness

**Red Flags:**

* The person does not use their own badge.
* Their visitor badge is expired and partially hidden.
* They ask to follow another employee through a badge-controlled door.

**Technical Control:**
Use anti-passback access controls or security doors that allow only one authenticated person to enter.

**Administrative Control:**
Require employees to challenge or report anyone entering a restricted area without using a valid badge.

