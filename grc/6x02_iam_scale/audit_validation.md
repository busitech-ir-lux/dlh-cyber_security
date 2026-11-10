# Audit Validation Record

Validation date: 2026-11-10. These checks ran locally against the submitted files; no production environment was contacted.

## Executed Checks

- Ran `python3 6x02_iam_scale/tasks/audit_iam.py` from the workspace root. It processed 20 accounts and wrote `iam_findings.json` beside the script, confirming that defaults do not depend on `/opt` or the shell's working directory.
- Confirmed 22 findings with six Critical, nine High, three Medium and four Low, affecting 10 distinct accounts. Recounted severity directly from the findings array.
- Confirmed every finding's source_row maps to the same username in the copied CSV, using header-as-row-1 numbering.
- Verified the copied inventory is byte-for-byte identical to the local source.
- Tested user dormancy boundaries: 90 days does not flag, 91 does. Tested privileged service boundaries: 365 days does not flag, 366 does.
- Confirmed disabled users do not trigger enabled-user MFA checks; service N/A MFA is not treated as a missing user enrollment.
- Confirmed Server Admin service exposure is Medium, repeated phishing failures with missing user MFA are Medium, lifecycle matching is case-insensitive, and disabled groups are flagged.
- Confirmed a lookalike group name does not match exact Domain Admins membership.
- Parsed all three corrected policy JSON files and the annotated SAML XML. Verified local Markdown links resolve.

## Interpretation and Limits

The boundary/control assertions passed. These checks validate the local audit logic and file consistency, not live directory correctness or clinical dependencies. JSON parsing confirms syntax rather than IAM authorization semantics. No AWS Access Analyzer, policy simulator, Keycloak signature-validation test or live Vault revocation was executed. The Vault outcomes described in the response belong to the supplied transcripts.

`markdownlint` is not installed, so no markdownlint pass is claimed. The learning file contains twelve original questions with answer explanations; they have not been validated by CompTIA. Rendered page count depends on the Markdown renderer and print settings, so the executive brief's one-page target still requires layout confirmation at submission.
