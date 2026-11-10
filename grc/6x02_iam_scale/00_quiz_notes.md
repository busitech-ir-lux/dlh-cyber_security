# Task 0: Know What You Are Auditing

The supplied task contains a kickoff scenario but no actual quiz questions. These notes explain the scenario without inventing a quiz answer key.

An access review asks who holds access, what that access permits and why it remains justified. A valid account name or a past project does not justify indefinite administrative authority. The svc_epic_int example combines 1,156 days of dormancy with Domain Admin membership and no current function, matching the standing-credential risk in the supplied incident path.

Use the explicit severity model for actual findings rather than interpreting the kickoff's broad wording as a rule that every excess permission is Critical. Service Domain Admins are Critical; service Server Admins are Medium. Likewise, MFA enrollment, enabled state, recent activity and business justification answer different questions and must be checked separately.

[Learning objectives and twelve practice questions](LEARNING_OBJECTIVES.md) develop federation, least privilege, dynamic credentials and evidence-based reporting in more detail.

Sources: [task briefing](../tasks.md), [severity model](../opt/meddefense/materials/iam_audit/severity_model.md), [incident identity path](../opt/meddefense/materials/iam_audit/incident_identity_path.md).
