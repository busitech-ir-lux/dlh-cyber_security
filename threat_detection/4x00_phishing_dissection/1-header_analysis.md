1. Header Analysis

This analysis uses only the provided MedDefense email evidence batch. No live Wazuh, Sysmon, Suricata, or endpoint telemetry is used.

Email 2 — meddefense-portal.com

Header Evidence

From: "MedDefense IT Security" <noreply@meddefense-portal.com>

Return-Path: <noreply@meddefense-portal.com>

Sending IP: 91.234.99.107

X-Mailer: PHPMailer 6.6.0

Message-ID: <PHP-5D7E2F4A@meddefense-portal.com>

Message-ID format: PHP-<8-character identifier>@meddefense-portal.com

Received Chain Summary

The message was generated locally on mail.meddefense-portal.com through PHPMailer 6.6.0.

mail.meddefense-portal.com at external IP 91.234.99.107 sent the message to mx01.meddefense.com.

mx01.meddefense.com passed the message to inbound-relay.meddefense.com for delivery to Diane Marsh.

Claimed Sender vs. Infrastructure

The display name claims to be MedDefense IT Security, but the message came from the external domain meddefense-portal.com and external IP 91.234.99.107, not the internal MedDefense mail infrastructure shown elsewhere in the evidence batch.

Anomalies

[HIGH] SPF failed: 91.234.99.107 was not authorized for meddefense-portal.com.

[HIGH] DKIM is missing.

[HIGH] DMARC failed.

[HIGH] The display name claims MedDefense IT Security, but the sender uses an external domain rather than the internal meddefense.com domain.

[MEDIUM] The message was generated with PHPMailer 6.6.0 rather than the Microsoft Exchange software seen in the known internal MedDefense email.

[MEDIUM] The Message-ID uses the repeated PHP-... style found in the suspicious messages.

[MEDIUM] The headers set X-Priority: 1, X-MSMail-Priority: High, and Importance: High, supporting the urgent tone.

Conclusion

E2 has strong header evidence of impersonation. The sender claims to represent MedDefense IT, but the message came through external infrastructure and failed SPF and DMARC with no DKIM signature. The PHPMailer-generated header pattern adds further suspicion.

Email 3 — outlook-protection.com

Header Evidence

From: "Microsoft Account Protection" <security@outlook-protection.com>

Return-Path: <security@outlook-protection.com>

Sending IP: 51.38.42.17

X-Mailer: PHPMailer 6.6.0

Message-ID: <PHP-9F2D7E1B@outlook-protection.com>

Message-ID format: PHP-<8-character identifier>@outlook-protection.com

Received Chain Summary

The message was generated from wp-admin.outlook-protection.com through PHPMailer 6.6.0.

mail.outlook-protection.com at external IP 51.38.42.17 sent the message to mx01.meddefense.com over TLS.

mx01.meddefense.com passed the message to inbound-relay.meddefense.com for delivery to Rafael Mendez.

Claimed Sender vs. Infrastructure

The display name claims Microsoft Account Protection, but the sender address, DKIM domain, and sending infrastructure all belong to outlook-protection.com. The headers therefore prove authentication for outlook-protection.com; they do not prove that the message actually came from Microsoft.

Anomalies

[HIGH] The claimed brand is Microsoft, while all authenticated sender infrastructure is outlook-protection.com.

[HIGH] SPF, DKIM, and DMARC all pass only for outlook-protection.com. Successful authentication does not resolve the mismatch between the claimed Microsoft identity and the actual domain.

[MEDIUM] The message was generated with PHPMailer 6.6.0.

[MEDIUM] The Message-ID follows the same PHP-... format found in the other suspicious messages.

[MEDIUM] X-Priority: 1 (Highest) supports the urgent account-warning presentation.

Conclusion

E3 shows why successful authentication does not automatically make an email trustworthy. It authenticates as outlook-protection.com, but its visible identity claims Microsoft Account Protection. The PHPMailer and PHP-... header pattern also matches the suspicious-message pattern in this batch.

Email 5 — medequip-supplies.net

Header Evidence

From: "MedEquip Supplies Billing" <invoices@medequip-supplies.net>

Return-Path: <invoices@medequip-supplies.net>

Sending IP: 185.176.43.22

X-Mailer: PHPMailer 6.6.0

Message-ID: <PHP-7C2D4E1A@medequip-supplies.net>

Message-ID format: PHP-<8-character identifier>@medequip-supplies.net

Received Chain Summary

The message was generated from billing-svc.medequip-supplies.net through PHPMailer 6.6.0.

mail.medequip-supplies.net at external IP 185.176.43.22 sent the message to mx01.meddefense.com.

mx01.meddefense.com passed the message to inbound-relay.meddefense.com for delivery to Angela Rivera.

Claimed Sender vs. Infrastructure

The visible From address, Return-Path, Message-ID domain, and sending hostname all use medequip-supplies.net, so there is no direct domain mismatch inside the headers themselves.

However, the authentication results are weak or failing. The evidence batch does not provide a known-good MedEquip email for comparison, so the headers alone cannot prove that this domain belongs to a legitimate supplier.

Anomalies

[HIGH] SPF returned softfail for sending IP 185.176.43.22.

[HIGH] DKIM is missing.

[HIGH] DMARC failed.

[MEDIUM] The message was generated with PHPMailer 6.6.0.

[MEDIUM] The Message-ID follows the same PHP-... pattern as E2, E3, and E7.

[MEDIUM] X-Priority: 1 (Highest) reinforces the pressure used in the invoice message.

Conclusion

E5 is suspicious based on weak/failed authentication and the same PHPMailer/PHP-... header pattern seen in the other suspicious emails. Unlike E2 and E7, the headers do not show a direct mismatch between the visible sender domain and the sending domain, so the header evidence should not be used to claim a proven brand/domain mismatch by itself.

Email 7 — meddefense-benefits.org

Header Evidence

From: "MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>

Return-Path: <hr-notifications@meddefense-benefits.org>

Sending IP: 164.90.218.73

X-Mailer: PHPMailer 6.6.0

Message-ID: <PHP-2E4A7B1C@meddefense-benefits.org>

Message-ID format: PHP-<8-character identifier>@meddefense-benefits.org

Received Chain Summary

The message was generated from wp-portal.meddefense-benefits.org through PHPMailer 6.6.0.

mail.meddefense-benefits.org at external IP 164.90.218.73 sent the message to mx01.meddefense.com.

mx01.meddefense.com passed the message to inbound-relay.meddefense.com for delivery to Linda Patterson.

Claimed Sender vs. Infrastructure

The display name claims MedDefense HR Benefits, but the message comes from the external domain meddefense-benefits.org and external IP 164.90.218.73, not the internal meddefense.com infrastructure shown in the evidence batch.

Anomalies

[HIGH] SPF failed: 164.90.218.73 was not authorized for meddefense-benefits.org.

[HIGH] DKIM is missing.

[HIGH] DMARC failed.

[HIGH] The message claims to be MedDefense HR but uses an external meddefense-benefits.org domain rather than the internal MedDefense domain.

[MEDIUM] The email was generated with PHPMailer 6.6.0.

[MEDIUM] The Message-ID follows the same PHP-... pattern as E2, E3, and E5.

[MEDIUM] X-Priority: 1 (Highest) supports the urgent enrollment deadline.

Conclusion

E7 has strong header evidence of MedDefense impersonation. It uses external infrastructure, fails SPF and DMARC, has no DKIM signature, and follows the same PHPMailer/PHP-... pattern found across the suspicious email set.

Cross-Email Header Pattern

E2, E3, E5, and E7 share several notable header characteristics:

All four were generated with PHPMailer 6.6.0.

All four use a Message-ID beginning with PHP- followed by an 8-character identifier.

All four use external sending infrastructure.

E2, E5, and E7 have failed or weak SPF results, no DKIM signature, and failed DMARC.

E3 is different because SPF, DKIM, and DMARC pass, but they authenticate outlook-protection.com, while the visible identity claims Microsoft.

All four use X-Priority: 1 (Highest).

These repeated header patterns support treating the four messages as related or at least worthy of correlation during the wider phishing investigation. Header analysis alone does not prove that they were operated by the same attacker, but it provides strong common routing and mailer indicators for the next investigation steps.
