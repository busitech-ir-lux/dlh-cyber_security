# Identity at Scale: Task Responses

All submissions are in this folder. Source materials remain unchanged under `../opt/meddefense/materials` relative to this folder, or `./opt/meddefense/materials` from the module root. No dependency on the operating system's `/opt/meddefense/materials` is introduced.

| Task | Deliverable |
| --- | --- |
| 0 | [Quiz notes](00_quiz_notes.md) |
| Learning objectives | [Explanations and twelve original practice questions](LEARNING_OBJECTIVES.md) |
| 1 | [SAML reference](keycloak_saml_config.md), [annotated XML](saml_assertion_d_walsh_annotated.xml) |
| 2 | [Policies](iam_policies/), [analysis](iam_policy_analysis.md) |
| 3 | [Vault evidence analysis](vault_pam_lab.md) |
| 4 | [Script](audit_iam.py), [inventory](accounts.csv), [findings](iam_findings.json) |
| 5 | [IAM report](iam_audit_report.md) |
| 6 | [Cloud assessment](cloud_security_assessment.md) |
| 7 | [CISO brief](iam_program_brief.md) |

## Reproduce the Audit

From `6x02_iam_scale`, run:

```bash
python3 tasks/audit_iam.py
```

Defaults resolve beside the script, so the command also works from another working directory. Explicit inputs are supported:

```bash
python3 tasks/audit_iam.py --input ./opt/meddefense/materials/iam_audit/accounts.csv --output /tmp/iam_findings_review.json
```

The script ran successfully on 20 supplied accounts, producing 22 findings across 10 accounts: six Critical, nine High, three Medium and four Low. Retained CSV/JSON/report form one evidence snapshot; timestamps reflect execution, while supplied day counts remain snapshot values. `audit_validation.md` records verification.

## Evidence Boundaries

No cloud, directory, Keycloak, Vault or database changes were performed. SAML/Vault artifacts are supplied evidence; policy corrections are authored proposals requiring deployment testing. Reviews and approvals remain pending. The CIS map supplies control areas without numbered benchmark controls, so no numbered compliance claim is invented. The HIPAA provision mislabeled in the task is corrected with HHS attribution in the report. The supplied SAML signature is simulated, not a verified production signature. MFA enrollment is not proof of enforcement.

Source artifact names are preserved. Supplemental AWS/HHS references clarify technical policy behavior and legal terminology; MedDefense facts come from local materials.
