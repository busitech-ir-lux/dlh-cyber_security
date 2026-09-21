Email

Initial Class

Final Class

Confidence

Key Evidence

Recommended Action

E1

SPAM

LEGITIMATE-WITH-ISSUE

HIGH

SPF, DKIM and DMARC pass; sender domain and infrastructure are consistent; MailChimp bulk-mail headers and unsubscribe fields are present. The message appears to be a legitimate newsletter, although it is still bulk email.

No security containment required. Treat as newsletter/bulk mail and allow the user to unsubscribe if unwanted.

E2

PHISHING-TARGETED

PHISHING-TARGETED

HIGH

Claims to be MedDefense IT Security but uses meddefense-portal.com; SPF fail; no DKIM; DMARC fail; PHPMailer; urgent portal-verification lure; Diane clicked the link.

Reset Diane’s password if exposure cannot be ruled out, revoke sessions, verify MFA, review account activity, and block the phishing domain.

E3

PHISHING-TARGETED

PHISHING-TARGETED

HIGH

SPF, DKIM and DMARC pass only for outlook-protection.com; the message impersonates Microsoft Account Protection; outlook-protection.com is not microsoft.com or outlook.com; PHPMailer and urgent account-lockout lure.

Block the lookalike domain, search for other recipients, and monitor for related credential-harvesting activity.

E4

LEGITIMATE

LEGITIMATE

HIGH

Internal sender meddefense.com; internal IP 10.10.1.15; SPF, DKIM and DMARC pass; Microsoft Exchange 2019; content matches internal password-change guidance.

No action required beyond normal mail retention.

E5

PHISHING-TARGETED

PHISHING-TARGETED

HIGH

Accounts Payable invoice lure; SPF softfail; no DKIM; DMARC fail; PHPMailer; payment and login URLs; suspicious PDF attachment; financial pressure and role-specific targeting.

Block the domain, preserve the attachment and URLs as evidence, check for other recipients, and warn Accounts Payable.

E6

SPAM

SPAM

HIGH

Bulk pharmaceutical advertisement; SPF softfail; no DKIM; DMARC fail with action=quarantine; spam score 9.8; XPedia Bulk Mailer 4.2; raw IP link.

Keep quarantined or block as spam. No phishing escalation is required unless related activity appears.

E7

PHISHING-TARGETED

PHISHING-TARGETED

HIGH

Claims to be MedDefense HR Benefits but uses meddefense-benefits.org; SPF fail; no DKIM; DMARC fail; PHPMailer; urgent open-enrollment lure targeted to Linda Patterson.

Block the domain, search for other recipients, warn HR/users, and monitor for credential-harvesting attempts.

E8

LEGITIMATE

LEGITIMATE

HIGH

Sender is HC3@hhs.gov; SPF, DKIM and DMARC pass for hhs.gov; HHS mail infrastructure; HC3 advisory content is consistent with the suspicious-message patterns found in the batch.

Retain as threat-intelligence evidence and use the advisory to support the investigation.

Classification Changes

E1 — SPAM → LEGITIMATE-WITH-ISSUE

Initial triage treated E1 as spam-like because it is a bulk newsletter.

Deeper analysis shows:

SPF passes for healthcare-education-weekly.com.

DKIM passes for the same domain.

DMARC passes.

The sender, Return-Path, DKIM domain and sending infrastructure are consistent.

The message contains normal bulk-mail indicators such as List-Unsubscribe, List-Unsubscribe-Post, Precedence: bulk, and MailChimp Mailer v12.4.

The deeper evidence does not support phishing. It is better classified as a legitimate bulk newsletter, although a recipient may still consider it unwanted.

E3 — Authentication Pass Does Not Change the Phishing Verdict

E3 is an important case because SPF, DKIM and DMARC all pass.

However:

They authenticate outlook-protection.com.

The visible identity claims “Microsoft Account Protection.”

outlook-protection.com is not the same as microsoft.com or outlook.com.

The message uses an account-compromise warning and 48-hour lockout threat to push the user toward a verification page.

The authentication results prove that the sender controls or is authorized to use outlook-protection.com; they do not prove Microsoft legitimacy.

Triage Accuracy Assessment

Using the evidence-batch triage notes as the initial baseline:

E1 was initially treated as spam-like but is better classified as LEGITIMATE-WITH-ISSUE.

E2 was correctly identified as phishing.

E3 was correctly treated as suspicious/phishing.

E4 was correctly identified as legitimate internal mail.

E5 was correctly identified as phishing.

E6 was correctly identified as spam.

E7 was correctly identified as phishing.

E8 was correctly identified as legitimate HC3 mail.

Correct initial classifications: 7 of 8

Triage accuracy: 87.5%

The only classification change is E1. The initial triage correctly separated the main phishing set from the legitimate internal/HC3 messages and obvious spam, while deeper analysis refined the newsletter classification.

Final Summary

E1: LEGITIMATE-WITH-ISSUE

E2: PHISHING-TARGETED

E3: PHISHING-TARGETED

E4: LEGITIMATE

E5: PHISHING-TARGETED

E6: SPAM

E7: PHISHING-TARGETED

E8: LEGITIMATE

The strongest malicious cluster is E2, E3, E5 and E7. They share PHPMailer-based sending patterns and targeted social-engineering themes, while E2, E5 and E7 also show weak or failed email authentication. E3 demonstrates that correct SPF, DKIM and DMARC configuration does not make a lookalike-domain message legitimate.
