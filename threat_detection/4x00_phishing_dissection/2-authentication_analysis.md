
## Email 1 — healthcare-education-weekly.com

- SPF: `pass` — the sending IP `198.51.100.42` is authorized to send for `healthcare-education-weekly.com`.
    
- DKIM: `pass` — the message contains a valid DKIM signature for `healthcare-education-weekly.com`.
    
- DMARC: `pass`, `action=none` — the authentication result aligns with the visible `From:` domain, and no enforcement action was applied.
    
- Authentication verdict: Authentication supports the apparent legitimacy of the sender because SPF, DKIM, and DMARC all pass for the same domain shown in the message.
    
- Investigation meaning: The headers show consistent authentication and no obvious sender-domain conflict.
    

### Final verdict

Authentication supports E1 as a normally authenticated message.

---

## Email 2 — meddefense-portal.com

- SPF: `fail` — the sending IP `91.234.99.107` is not authorized to send for `meddefense-portal.com`.
    
- DKIM: `none` — the message is not DKIM-signed, so there is no cryptographic domain signature to validate.
    
- DMARC: `fail`, `action=none` — DMARC fails for the visible `From:` domain, but the header shows that no automatic rejection or quarantine action was applied.
    
- Authentication verdict: Authentication contradicts the apparent legitimacy of the email. The message claims to represent MedDefense IT Security, but its own sending domain fails SPF and DMARC and has no DKIM signature.
    
- Investigation meaning: The authentication failures add strong support to the existing suspicion around this MedDefense-themed message.
    

### Final verdict

E2 has failed email authentication and should be treated as suspicious.

---

## Email 3 — outlook-protection.com

- SPF: `pass` — the sending IP `51.38.42.17` is authorized to send for `outlook-protection.com`.
    
- DKIM: `pass` — the DKIM signature validates for `outlook-protection.com`.
    
- DMARC: `pass`, `action=none` — the authenticated domain aligns with the visible `From:` domain `outlook-protection.com`.
    
- Authentication verdict: The authentication results are internally valid for `outlook-protection.com`, but they do not prove that the email is from Microsoft.
    
- Investigation meaning: The visible identity says **Microsoft Account Protection**, but `outlook-protection.com` is not the same as `microsoft.com` or `outlook.com`. SPF, DKIM, and DMARC only prove that the sender is authorized to use `outlook-protection.com`. A sender can control a lookalike domain and configure its authentication correctly.
    

### Final verdict

E3 passes SPF, DKIM, and DMARC, but the authentication only validates the lookalike domain `outlook-protection.com`. It does not establish Microsoft legitimacy.

---

## Email 4 — meddefense.com

- SPF: `pass` — the sending IP `10.10.1.15` is identified as an internal MedDefense sender and is authorized for `meddefense.com`.
    
- DKIM: `pass` — the message has a valid DKIM signature for `meddefense.com`.
    
- DMARC: `pass`, `action=none` — authentication aligns with the visible `From:` domain and no enforcement action was needed.
    
- Authentication verdict: Authentication supports the apparent legitimacy of the message. The sender domain, internal sending IP, DKIM domain, and visible `From:` domain are consistent.
    
- Investigation meaning: The authentication results match the internal MedDefense infrastructure shown in the evidence.
    

### Final verdict

Authentication strongly supports E4 as a legitimate internal MedDefense message.

---

## Email 5 — medequip-supplies.net

- SPF: `softfail` — the sending IP `185.176.43.22` is not clearly authorized for `medequip-supplies.net`, but the result is weaker than a full SPF fail.
    
- DKIM: `none` — the message has no DKIM signature.
    
- DMARC: `fail`, `action=none` — DMARC fails for the visible `From:` domain, and no automatic action was applied.
    
- Authentication verdict: Authentication does not support the apparent legitimacy of the invoice message. SPF is weak, DKIM is absent, and DMARC fails.
    
- Investigation meaning: The header results add suspicion, but authentication alone does not prove who actually controls the domain.
    

### Final verdict

E5 has weak and failed authentication results and should remain suspicious.

---

## Email 6 — canadian-pharma-discount.org

- SPF: `softfail` — the sending system is not clearly authorized for `canadian-pharma-discount.org`.
    
- DKIM: `none` — no DKIM signature is present.
    
- DMARC: `fail`, `action=quarantine` — DMARC fails and the header shows a quarantine action.
    
- Authentication verdict: Authentication contradicts the apparent legitimacy of the message. There is no DKIM validation, SPF is weak, and DMARC fails.
    
- Investigation meaning: The authentication results are consistent with the message being untrusted or unauthorized bulk mail.
    

### Final verdict

E6 fails meaningful authentication checks and the DMARC result indicates quarantine.

---

## Email 7 — meddefense-benefits.org

- SPF: `fail` — the sending IP `164.90.218.73` is not authorized for `meddefense-benefits.org`.
    
- DKIM: `none` — the message is not DKIM-signed.
    
- DMARC: `fail`, `action=none` — DMARC fails for the visible `From:` domain, but no automatic enforcement action was taken.
    
- Authentication verdict: Authentication contradicts the apparent legitimacy of the email. It claims to be MedDefense HR Benefits, but the sending domain fails SPF and DMARC and has no DKIM signature.
    
- Investigation meaning: The failed authentication results strengthen the suspicion that the MedDefense-themed sender identity is not trustworthy.
    

### Final verdict

E7 has failed authentication and should be treated as suspicious.

---

## Email 8 — hhs.gov

- SPF: `pass` — the sending IP `134.174.47.82` is authorized to send for `hhs.gov`.
    
- DKIM: `pass` — the message has a valid DKIM signature for `hhs.gov`.
    
- DMARC: `pass`, `action=none` — authentication aligns with the visible `From:` domain and no enforcement action was needed.
    
- Authentication verdict: Authentication supports the apparent legitimacy of the HC3 message because SPF, DKIM, DMARC, the visible sender domain, and the sending infrastructure are consistent.
    
- Investigation meaning: The authentication results support the message being genuinely sent from the `hhs.gov` domain.
    

### Final verdict

Authentication strongly supports E8 as a legitimate HC3/HHS message.

---

## Overall Authentication Summary

- E1, E4, and E8 have consistent SPF, DKIM, and DMARC passes that support their apparent legitimacy.
    
- E2 and E7 fail SPF and DMARC and have no DKIM signature.
    
- E5 has SPF `softfail`, no DKIM, and DMARC `fail`.
    
- E6 has SPF `softfail`, no DKIM, and DMARC `fail` with `action=quarantine`.
    
- E3 passes SPF, DKIM, and DMARC, but only for `outlook-protection.com`. That domain is not the same as `microsoft.com` or `outlook.com`, so the passing results authenticate the lookalike domain rather than Microsoft.
    

Email authentication is therefore useful evidence, but the batch demonstrates that a full pass does not automatically mean a message is legitimate.
