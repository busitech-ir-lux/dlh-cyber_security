
| Email | From                                           | Subject                                                                          | SPF      | DKIM | DMARC | Class      | Priority  | Evidence                                                                         |
| ----- | ---------------------------------------------- | -------------------------------------------------------------------------------- | -------- | ---- | ----- | ---------- | --------- | -------------------------------------------------------------------------------- |
| E1    | newsletter[@]healthcare-education-weekly[.]com | Your April newsletter: Medication reconciliation best practices                  | PASS     | PASS | PASS  | SPAM       | P4-LOW    | No urgency indicator<br>Return address same as sender<br>Unsubscribe notice      |
| E2    | noreply[@]meddefense-portal[.]com              | ACTION REQUIRED: Portal re-verification needed within 24 hours                   | FAIL     | NONE | FAIL  | SUSPICIOUS | P1-URGENT | Urgency action required for tricking user(common indicator of phishing attempts) |
| E3    | security[@]outlook-protection[.]com            | Unusual sign-in activity detected on your Microsoft 365 account                  | PASS     | PASS | PASS  | SUSPICIOUS | P1-URGENT | Look-alike domain                                                                |
| E4    | it-announcements[@]meddefense[.]com            | Reminder: Quarterly password change window opens April 20                        | PASS     | PASS | PASS  | LEGITIMATE | P4-LOW    | Same Domain                                                                      |
| E5    | invoices[@]medequip-supplies[.]net             | Invoice INV-2026-04891 â€” Payment required within 7 days                        | SIFTFAIL | NONE | FAIL  | SUSPICIOUS | P2-HIGH   | Includes links                                                                   |
| E6    | deals[@]canadian-pharma-discount[.]org         | 90% OFF Viagra, Cialis, Xanax â€” No prescription needed!!!                      | SIFTFAIL | NONE | FAIL  | SUSPICIOUS | P1-URGENT | Includes links different form sender domain.<br>Deceptive offers                 |
| E7    | hr-notifications[@]meddefense-benefits[.]org   | Open Enrollment closes TOMORROW â€” action required                              | FAIL     | NONE | FAIL  | SUSPICIOUS | P2-HIGH   | Look-alike domain<br>Urgency wording                                             |
| E8    | HC3[@]hhs[.]gov                                | [HC3 ALERT â€” TLP:CLEAR] Active phishing campaign targeting regional healthcare | PASS     | PASS | PASS  | LEGITIMATE | P4-LOW    | Government bulk mail<br>Nothing suspicious inside mail body                      |

## Triage Summary 

- SPAM: 1
- SUSPICIOUS: 5
- LEGITIMATE: 2
- Highest priority: 4
