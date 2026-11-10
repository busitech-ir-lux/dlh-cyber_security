# MedDefense IAM Policy Analysis

## Policy 1: MedDefenseSIEMLogReader Violations

Original `s3:*` on all resources permits reading, changing or deleting unrelated data. The correction splits bucket-level `s3:ListBucket` from object-level `s3:GetObject`, confined to `meddefense-siemlog-prod`. Original `logs:*` and `cloudwatch:*` unnecessarily permit administration and unrelated monitoring operations. The correction retains only stream creation and event writing for `/aws/lambda/siem-log-reader`. Assumption: the log group already exists in us-east-1/account 123456789012; confirm the real region before deployment. No broad log-group creation permission is added.

## Policy 2: MedDefenseEHRBackupRole Violations

Original `s3:*` and `kms:*` on all resources expose unrelated buckets and encryption-key administration. The correction confines bucket listing/location and object backup/restore operations to `meddefense-ehr-backup-prod`. It assumes upload, restore and multipart upload are needed; it grants no object deletion, bucket-policy changes or key administration. Confirm application calls before deployment and remove unused restore permissions for a write-only job.

KMS permits only `GenerateDataKey` for encrypted writes and `Decrypt` for restore/multipart processing, on the exact supplied key ARN. The key policy must also authorize the role. This policy does not itself require all uploads to use that key; enforce encryption through bucket configuration and approved bucket-policy controls. AWS documents these data-key requirements in its [SSE-KMS guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html).

## Policy 3: MedDefenseBreakGlassAdmin Violations

The original allows unrestricted administration without MFA or a source restriction. The correction permits emergency admin only with MFA and a source in `198.51.100.0/24`. Separate explicit denies reject missing/false MFA and missing/outside IP, so another attached Allow cannot bypass these conditions. Combining both failures in a single deny would incorrectly require both to fail before blocking.

`BoolIfExists` covers requests lacking the MFA key. This design targets AWS credentials with that MFA context; federated sessions may not supply it and can be denied despite upstream MFA. Validate the trust/session design before use. AWS explains [global context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html). The required address block is a documentation range, not evidence of a real MedDefense office network.

## Least Privilege Summary

| Policy | Preserved capability | Removed exposure |
| --- | --- | --- |
| SIEM reader | Read one log bucket; write one function's log streams | S3 modification and broad monitoring administration |
| EHR backup | Backup/restore in one bucket with one KMS key | Cross-bucket access, deletion and KMS administration |
| Break-glass | Conditional emergency administration | Administration without required MFA/network conditions |

## Residual Risk and Operational Notes

These JSON files are authored corrections, not attached policies or verified remediation. Existing grants, role trust policies, resource policies, permission boundaries and organization controls still affect access. Break-glass remains powerful inside its allowed conditions and needs approval, time-limited sessions, monitoring and tested recovery access. Do not deploy a network/MFA restriction without testing safe emergency access.

Before deployment, validate policy syntax with IAM Access Analyzer, test allowed and denied requests with approved test identities, confirm application function and retain rollback evidence. No AWS account connection or live test is claimed. Sources: the three `original_*_policy.json` artifacts in [cloud_iam](../opt/meddefense/materials/cloud_iam/) and Task 2 requirements.
