# 13. The Quick Wins

## Quick Win #1: Enable MFA for VPN and Administrator Accounts

**Risk Addressed:** RISK-002 — VPN compromise

**Action:**

1. Identify all VPN and administrator accounts.
2. Enable MFA using the existing Microsoft licences.
3. Remove unused remote-access accounts.
4. Test access with IT and Security staff.
5. Inform users before enforcement.

**Owner:** IT Director, supported by the Security Analyst

**Timeline:** 3–5 days

**Cost:** $0 because existing licences and staff are used.

**Risk Reduction:** Disrupts Kill Chain #1 by making stolen passwords less useful for VPN and administrative access.

**Verification:** Confirm that every VPN and administrator login requires MFA and test that password-only access fails.

---

## Quick Win #2: Remove Shared, Dormant and Default Accounts

**Risk Addressed:** RISK-006, RISK-007 and RISK-010

**Action:**

1. List shared and inactive accounts.
2. Disable accounts that are no longer required.
3. Replace shared PACS access with individual accounts.
4. Change default passwords on infusion pumps and other medical devices.
5. Document any account that cannot yet be removed.

**Owner:** IT Director and relevant Department Heads

**Timeline:** 5–10 days

**Cost:** $0 using existing account-management systems.

**Risk Reduction:** Disrupts insider and medical-device attack paths by improving accountability and removing easy credentials.

**Verification:** Review the account list and confirm that no active medical device uses a default password.

---

## Quick Win #3: Emergency Patching and Exposure Reduction

**Risk Addressed:** RISK-003 and RISK-009

**Action:**

1. Patch the FortiGate, billing server and other critical supported systems.
2. Disable unnecessary services and ports.
3. Restrict PostgreSQL, SSH and RDP access using existing firewall rules.
4. Isolate unsupported systems where immediate replacement is impossible.
5. Record systems that still require remediation.

**Owner:** IT Director and Security Analyst

**Timeline:** 7–14 days

**Cost:** $0 because vendor patches and existing firewall functions are used.

**Risk Reduction:** Disrupts the initial-access stage of the ransomware and vulnerability-exploitation kill chains.

**Verification:** Rescan affected systems and confirm that the vulnerable versions and exposed ports are no longer detected.

---

## Quick Win #4: Test Backups and Create a Temporary Offline Copy

**Risk Addressed:** RISK-003 — Billing ransomware and backup loss

**Action:**

1. Select critical EHR and billing data.
2. Perform a test restoration from the current backups.
3. Confirm that restored files are complete and usable.
4. Create an additional encrypted copy using existing storage.
5. Disconnect the temporary copy from the production network after completion.

**Owner:** IT Director and backup administrator

**Timeline:** 3–7 days

**Cost:** $0 or minimal because existing storage and backup tools are used.

**Risk Reduction:** Limits the effect of the ransomware kill chain by preserving a recovery copy that malware cannot immediately reach.

**Verification:** Complete a documented restoration test and confirm that the offline copy is disconnected and encrypted.

---

## Quick Win #5: Launch Security Reporting and Awareness Briefing

**Risk Addressed:** RISK-004 and RISK-006

**Action:**

1. Create a dedicated email address for reporting suspicious activity.
2. Publish a one-page reporting guide.
3. Deliver a short briefing on phishing, MFA requests, USB devices and data handling.
4. Tell employees not to investigate incidents themselves.
5. Track reports and response times.

**Owner:** Security Analyst, supported by Department Heads

**Timeline:** 5–10 days

**Cost:** $0 using existing email, meeting and training platforms.

**Risk Reduction:** Disrupts phishing and negligent-insider attack paths by helping employees recognize and report suspicious activity earlier.

**Verification:** Confirm that all departments received the briefing and test the process with a simulated suspicious-email report.

## Why Quick Wins Matter

Quick wins provide more than immediate technical protection. They show the Board and employees that the security program is active, practical and capable of producing results. They also clarify responsibilities, improve cooperation between Security and IT, and create early measurements that can support future funding. Successful early actions build trust before larger projects such as segmentation, SIEM and EDR deployment begin.

