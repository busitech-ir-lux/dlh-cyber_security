# MedDefense Vault PAM Lab

## Lab Evidence Summary

Analysis uses the supplied transcripts, not commands executed against a live Vault or database. The database engine is mounted at `database/` and configures `meddefense-lis` with the MySQL plugin. Credentials printed in source transcripts are lab examples and are not reproduced as usable secrets here. Production configuration must supply secure management credentials and explicit creation/revocation statements; the abbreviated transcript is not a complete deployment recipe.

## Dynamic Credential Demonstration

| Role | Issued username | Lease ID | Issued TTL | Maximum TTL |
| --- | --- | --- | --- | --- |
| lis-readonly | v-lis-readonly-H7s9k2 | database/creds/lis-readonly/3s9fXJd7aMedDefense001 | 1 hour | 4 hours |
| lis-readwrite | v-lis-readwrite-Q2p8 | database/creds/lis-readwrite/9kLmVaultRw002 | 15 minutes | 1 hour |

The read-only MySQL test shows SELECT on `lis_production`.*. The read-write name and issuance are evidenced, but its actual grants are not shown; do not infer verified write permissions from its name alone.

## Lease and TTL Evidence

Both issued leases are renewable. A credential's issued TTL differs from its maximum permitted renewable lifetime. The lease-list command shows the read-only lease suffix. Vault tracks expiry and revocation, reducing the period a stolen credential can be reused, but renewal and backend revocation behavior must work correctly. Short lifetime does not undo data already read or changed.

## Revocation Evidence

`vault lease revoke database/creds/lis-readwrite/9kLmVaultRw002` queues revocation. The subsequent connection fails with MySQL error 1045, and the database user query shows only the read-only user remains. Together those observations support actual removal of this issued read-write user in the supplied exercise; the queue acknowledgment alone would not prove completion. The transcript does not test termination of an already established database session or automatic expiration.

## Static vs Dynamic Credential Comparison

| Aspect | Static account | Dynamic database credential |
| --- | --- | --- |
| Lifetime | Persists until disabled/changed | Issued TTL, with bounded permitted renewal |
| Rotation | Owner must change stored password and consumers | New credentials issued; leases expire or are revoked |
| Stolen-credential impact | Reusable while valid, potentially with domain-wide authority | Limited by actual database grants and remaining validity |
| Audit trail | Shared persistent identity obscures individual requests | Distinct issuance/lease supports correlation if audit logging is configured |
| Off-boarding | Disable identity and update consumers/secrets | Revoke relevant leases and upstream application/Vault identity access |

## Migration Recommendation

Prioritize `svc_epic_int`: 1,156 days dormant, Domain Admins and no known current function. Confirm dependencies, contain and remove excess access; retirement is preferable to migrating an unnecessary account. Next replace `svc_helpdesk` vendor-granted Domain Admin access with scoped ticket-routing rights and review `svc_backup` backup privileges. Audit severity for all three is Critical even though the migration-candidate file ranks backup High for migration priority.

`svc_monitoring` should use scoped read-only collection rather than Server Admins. Review `svc_av_mgmt` against its endpoint-management need rather than blindly removing required rights. Database dynamic credentials apply only where the workload supports that backend; they do not automatically replace Windows domain permissions. Vault itself needs protected administration, workload authentication, audit logging and availability planning.

Sources: [PAM materials](../opt/meddefense/materials/pam/): `vault_database_secrets_transcript.md`, `vault_lease_revoke_transcript.md`, `svc_epic_int_static_account_risk.md`, `pam_migration_candidates.csv`.
