4. URL and Attachment Autopsy

This analysis uses only the provided raw email evidence. No suspicious URL or attachment was opened directly, and no live DNS, SIEM, Wazuh, Sysmon, or Suricata data is required for the conclusions below.

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

E2 was generated with PHPMailer 6.6.0.

The sending IP is 91.234.99.107.

SPF failed, DKIM is absent, and DMARC failed.

Safe investigation method:

whois meddefense-portal.com

dig meddefense-portal.com

nslookup meddefense-portal.com

curl -I https://meddefense-portal.com only from an approved isolated investigation environment

Search the URL/domain in VirusTotal.

Submit or search the URL in urlscan.io using an approved safe-analysis workflow.

Finding: The URL is directly tied to a MedDefense impersonation and credential-verification lure. The domain differs from MedDefense’s internal domain and is supported by failed authentication and suspicious sending infrastructure.

Risk rating: HIGH

Indicator 2

Source email: E3

Original value: https://outlook-protection.com/verify

Defanged value: hxxps://outlook-protection[.]com/verify

Domain or IP: outlook-protection.com

Indicator type: URL / domain

Evidence from email:

The visible sender claims to be “Microsoft Account Protection.”

The domain is outlook-protection.com, which is not the same as microsoft.com or outlook.com.

The lure claims an unusual sign-in from Lagos, Nigeria and threatens account lockout within 48 hours.

The email was generated with PHPMailer 6.6.0.

The sending IP is 51.38.42.17.

SPF, DKIM, and DMARC all pass, but only for outlook-protection.com.

Safe investigation method:

whois outlook-protection.com

dig outlook-protection.com

nslookup outlook-protection.com

curl -I https://outlook-protection.com only from an approved isolated investigation environment

Search the domain and URL in VirusTotal.

Search or submit the URL in urlscan.io using a safe-analysis workflow.

Finding: The URL belongs to a domain that successfully authenticates itself but impersonates Microsoft through branding and naming. Passing SPF, DKIM, and DMARC does not make this URL legitimate.

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

The email was generated with PHPMailer 6.6.0.

The sending IP is 185.176.43.22.

SPF returned softfail, DKIM is absent, and DMARC failed.

The same invoice identifier is used in the URL and attachment filename.

Safe investigation method:

whois medequip-supplies.net

dig medequip-supplies.net

nslookup medequip-supplies.net

curl -I https://medequip-supplies.net only from an approved isolated investigation environment

Search the URL/domain in VirusTotal.

Search or submit the URL in urlscan.io using a safe-analysis workflow.

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

The sender targets Accounts Payable and uses a supplier-payment workflow.

The email has SPF softfail, no DKIM signature, and DMARC fail.

Safe investigation method:

whois medequip-supplies.net

dig medequip-supplies.net

nslookup medequip-supplies.net

Search the full URL in VirusTotal.

Search or submit the URL in urlscan.io.

Use curl -I only from an approved isolated environment if header inspection is required.

Finding: A login portal inside a suspicious invoice email can be used to collect credentials. The evidence file does not prove what the page does, so the conclusion should remain limited to the suspicious context and authentication failures.

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

The email body requests payment of USD 24,716.38.

The attachment is delivered as base64-encoded application/pdf.

The email also contains payment and login URLs using medequip-supplies.net.

The sender has SPF softfail, no DKIM signature, and DMARC fail.

Safe investigation method:

Do not open the PDF on the analyst workstation.

Extract the attachment in an isolated analysis environment if required.

Calculate a cryptographic hash such as SHA-256 without executing the file.

Search the resulting hash in VirusTotal.

Submit the file to an approved sandbox such as Hybrid Analysis if permitted.

Finding: The attachment name and invoice context are consistent with the financial lure. The raw email evidence alone does not prove that the PDF is malicious, so it should be treated as suspicious pending safe file analysis.

Risk rating: MEDIUM

Indicator 6

Source email: E7

Original value: https://meddefense-benefits.org/enroll

Defanged value: hxxps://meddefense-benefits[.]org/enroll

Domain or IP: meddefense-benefits.org

Indicator type: URL / domain

Evidence from email:

The message claims to be from “MedDefense HR Benefits.”

It tells Linda Patterson that open enrollment closes the next day.

It threatens loss of current coverage and placement into a basic plan.

The sender uses meddefense-benefits.org, not the internal meddefense.com domain.

The sending IP is 164.90.218.73.

The email was generated with PHPMailer 6.6.0.

SPF failed, DKIM is absent, and DMARC failed.

Safe investigation method:

whois meddefense-benefits.org

dig meddefense-benefits.org

nslookup meddefense-benefits.org

curl -I https://meddefense-benefits.org only from an approved isolated investigation environment

Search the URL/domain in VirusTotal.

Search or submit the URL in urlscan.io.

Finding: The URL is part of an HR-benefits impersonation lure using a MedDefense-themed external domain and failed authentication.

Risk rating: HIGH

Indicator 7

Source email: E6

Original value: http://203.0.113.228/shop?ref=pwhite

Defanged value: hxxp://203[.]0[.]113[.]228/shop?ref=pwhite

Domain or IP: 203.0.113.228

Indicator type: IP-based URL / IP address

Evidence from email:

E6 links directly to an IP address rather than a normal domain name.

The same IP 203.0.113.228 appears as the external sending IP in the Received: header.

SPF returned softfail.

DKIM is absent.

DMARC failed with action=quarantine.

The message has an X-Spam-Score of 9.8 and is marked X-Spam-Status: Yes.

The email is a bulk pharmaceutical advertisement and uses XPedia Bulk Mailer 4.2.

Safe investigation method:

whois 203.0.113.228

dig -x 203.0.113.228

nslookup 203.0.113.228

Search the IP and full URL in VirusTotal.

Search the URL/IP in urlscan.io or URLhaus.

Avoid directly browsing to the IP-based URL.

Finding: The IP is reused as both the sending infrastructure and the HTTP destination in E6. Within the evidence batch, this creates a direct infrastructure relationship between message delivery and the advertised URL.

Risk rating: HIGH

Cross-Indicator Findings

The suspicious email evidence shows several useful relationships:

meddefense-portal.com, outlook-protection.com, medequip-supplies.net, and meddefense-benefits.org all appear in emails generated with PHPMailer 6.6.0.

E2, E5, and E7 have weak or failed SPF results, no DKIM signature, and failed DMARC.

E3 is different because authentication passes, but it only authenticates outlook-protection.com, not Microsoft.

E2 and E7 use MedDefense-themed external domains that imitate internal organizational functions.

E5 combines an invoice attachment, payment URL, and login URL in the same financial pretext.

E6 reuses 203.0.113.228 as both the external sending IP and the host in the HTTP link.

The evidence supports safe IOC extraction and correlation without directly opening any suspicious URL or attachment.

No live lookup result is claimed in this file. Commands and external services are documented only as safe investigation methods that could be used from an approved analysis environment.
