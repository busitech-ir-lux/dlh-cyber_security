Indicator 1

Source email: E2

Original value: https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1

Defanged value: hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

Domain or IP: meddefense-portal.com

Indicator type: URL / domain

Evidence from email:

The message claims to be from “MedDefense IT Security.”

The URL uses meddefense-portal.com, not the internal meddefense.com domain shown elsewhere in the evidence batch.

The message threatens loss of staff portal, scheduling, EHR gateway, and shift-swap access within 24 hours.

The sending IP is 91.234.99.107.

SPF failed, DKIM is absent, and DMARC failed.

The message was generated with PHPMailer 6.6.0.

Safe investigation method:

whois meddefense-portal.com

dig meddefense-portal.com

nslookup meddefense-portal.com

Search existing VirusTotal reputation records for the domain or URL without requesting a new scan.

Search existing urlscan.io results for the domain without submitting the URL.

Search existing URLhaus records for the domain or URL.

Finding: The URL is tied to a MedDefense impersonation and account-verification lure. The domain differs from MedDefense’s internal domain and is supported by failed authentication and suspicious sending infrastructure.

Risk rating: HIGH

Indicator 2

Source email: E3

Original value: https://outlook-protection.com/verify

Defanged value: hxxps://outlook-protection[.]com/verify

Domain or IP: outlook-protection.com

Indicator type: URL / domain

Evidence from email:

The visible sender claims to be “Microsoft Account Protection.”

outlook-protection.com is not the same as microsoft.com or outlook.com.

The lure claims an unusual sign-in and threatens account lockout within 48 hours.

The sending IP is 51.38.42.17.

SPF, DKIM, and DMARC all pass, but only for outlook-protection.com.

The message was generated with PHPMailer 6.6.0.

Safe investigation method:

whois outlook-protection.com

dig outlook-protection.com

nslookup outlook-protection.com

Search existing VirusTotal records without requesting a fresh scan.

Search existing urlscan.io results only; do not submit the suspicious URL.

Search existing URLhaus records for the domain or URL.

Finding: The domain authenticates successfully as itself, but the message impersonates Microsoft. Authentication of outlook-protection.com does not make the Microsoft claim legitimate.

Risk rating: HIGH

Indicator 3

Source email: E5

Original value: https://medequip-supplies.net/invoices/pay?id=INV-2026-04891

Defanged value: hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

Domain or IP: medequip-supplies.net

Indicator type: URL / domain

Evidence from email:

The message targets Accounts Payable with invoice INV-2026-04891.

It requests payment of USD 24,716.38.

It threatens suspension of future deliveries and a 2% late fee.

The sending IP is 185.176.43.22.

SPF returned softfail, DKIM is absent, and DMARC failed.

The same invoice identifier appears in the URL and attachment filename.

Safe investigation method:

whois medequip-supplies.net

dig medequip-supplies.net

nslookup medequip-supplies.net

Search existing VirusTotal reputation records without requesting a live scan.

Search existing urlscan.io results only; do not submit the URL.

Search existing URLhaus records.

Finding: The URL is part of a targeted invoice/payment lure and is supported by weak or failed authentication results.

Risk rating: HIGH

Indicator 4

Source email: E5

Original value: https://medequip-supplies.net/portal/login

Defanged value: hxxps://medequip-supplies[.]net/portal/login

Domain or IP: medequip-supplies.net

Indicator type: URL / login portal

Evidence from email:

The message tells the recipient to use this login portal if the attached invoice cannot be viewed.

It appears in the same invoice lure as the payment URL.

The email targets Accounts Payable.

SPF is softfail, DKIM is absent, and DMARC failed.

Safe investigation method:

Use the same passive WHOIS and DNS checks as for the domain above.

Search existing VirusTotal, urlscan.io, and URLhaus records only.

Do not open or submit the login URL.

Finding: A login portal inside a suspicious invoice email may be intended to collect credentials. The evidence file does not prove the page behavior, so the conclusion remains limited to the suspicious context.

Risk rating: HIGH

Indicator 5

Source email: E5

Original value: INV-2026-04891.pdf

Defanged value: Not applicable

Domain or IP: Not applicable

Indicator type: PDF attachment

Evidence from email:

The attachment is presented as invoice INV-2026-04891.pdf.

The message targets Accounts Payable.

The email requests payment of USD 24,716.38.

The attachment is base64-encoded as application/pdf.

The email also contains payment and login URLs using medequip-supplies.net.

The sender has SPF softfail, no DKIM signature, and DMARC fail.

Safe investigation method:

Do not open the PDF on the workstation.

Extract the attachment only as a file artifact if required.

Calculate a SHA-256 hash without executing or opening the file.

Search the hash in existing VirusTotal records.

Record visible PDF metadata and embedded indicators from the raw email evidence.

Finding: The attachment name and invoice context match the financial lure. The raw evidence alone does not prove that the PDF itself is malicious.

Risk rating: MEDIUM

Indicator 6

Source email: E7

Original value: https://meddefense-benefits.org/enroll

Defanged value: hxxps://meddefense-benefits[.]org/enroll

Domain or IP: meddefense-benefits.org

Indicator type: URL / domain

Evidence from email:

The message claims to be from “MedDefense HR Benefits.”

It threatens loss of current benefits coverage if Linda does not act before the deadline.

The domain is meddefense-benefits.org, not the internal meddefense.com domain.

The sending IP is 164.90.218.73.

SPF failed, DKIM is absent, and DMARC failed.

The message was generated with PHPMailer 6.6.0.

Safe investigation method:

whois meddefense-benefits.org

dig meddefense-benefits.org

nslookup meddefense-benefits.org

Search existing VirusTotal reputation records only.

Search existing urlscan.io results only; do not submit the URL.

Search existing URLhaus records.

Finding: The URL is part of a MedDefense HR-benefits impersonation lure using external infrastructure and failed authentication.

Risk rating: HIGH

Indicator 7

Source email: E6

Original value: http://203.0.113.228/shop?ref=pwhite

Defanged value: hxxp://203[.]0[.]113[.]228/shop?ref=pwhite

Domain or IP: 203.0.113.228

Indicator type: IP-based URL / IP address

Evidence from email:

The URL uses a raw IP address instead of a domain.

The same IP 203.0.113.228 appears as the external sending IP in the Received: header.

SPF returned softfail.

DKIM is absent.

DMARC failed with action=quarantine.

The message has X-Spam-Score: 9.8 and X-Spam-Status: Yes.

The email was sent with XPedia Bulk Mailer 4.2.

Safe investigation method:

whois 203.0.113.228

dig -x 203.0.113.228

nslookup 203.0.113.228

Search existing VirusTotal, URLhaus, or urlscan.io records for the IP without requesting a new scan.

Do not browse to or request the IP-based URL.

Finding: The IP is reused as both the sending infrastructure and the HTTP destination in E6, creating a direct infrastructure relationship within the evidence batch.

Risk rating: HIGH

Cross-Indicator Findings

meddefense-portal.com, outlook-protection.com, medequip-supplies.net, and meddefense-benefits.org all appear in messages generated with PHPMailer 6.6.0.

E2, E5, and E7 have weak or failed SPF results, no DKIM signature, and failed DMARC.

E3 passes authentication, but only for outlook-protection.com, not Microsoft.

E2 and E7 use MedDefense-themed external domains that imitate internal functions.

E5 combines an invoice attachment, payment URL, and login URL in one financial lure.

E6 reuses 203.0.113.228 as both the external sending IP and the URL host.

All conclusions above can be reached from the email evidence and passive lookup methods without contacting suspicious web content.

No live lookup or active URL interaction is required or claimed in this file.
