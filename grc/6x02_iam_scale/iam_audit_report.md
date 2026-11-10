# MedDefense IAM Audit Report

**Classification:** Confidential  
**Audit date:** 2026-11-10 (execution timestamp in JSON)  
**Prepared by:** Student audit response  
**Review requested:** James Chen, SOC Lead; review not yet performed  
**Approved by:** _________________________ Date: _________

## Executive Summary

The supplied 20-account inventory produces 22 check findings affecting 10 distinct accounts: six Critical, nine High, three Medium and four Low. Findings are control failures, not separate affected people; one account can trigger several checks. All remain Open because no directory remediation has been performed.

The most urgent risks include three Domain Admin service accounts. `svc_epic_int` has no identified current function and has not authenticated in 1,156 days; IAM-015 and IAM-016 document its privilege and dormancy. `svc_helpdesk` and `svc_backup` retain the same broad domain authority despite narrower stated business functions. Containment must include dependency checks so removing obsolete privileges does not interrupt patient services.

The supplied incident path connects credential extraction with service-account Domain Admin access and lateral movement. These findings recreate that opportunity; they do not prove each named account was used in the incident. The audit replaces an uncertain privilege list with reproducible checks, row-level evidence and assigned remediation priorities. Written corrections still need implementation and verification.

## Audit Scope and Methodology

The audit reads the supplied CSV snapshot using Python standard-library code. Header is row 1; source_row in JSON identifies the physical CSV record for this single-line dataset. Day counts are supplied snapshot values, not recalculated November activity. Twenty accounts are supplied, despite narrative references to 200. No live AD query, cloud remediation, MFA challenge or HR status verification was performed.

Six named functions implement Task 4. Privilege checks recognize exact Domain Admins/Server Admins group tokens. User dormancy is >90 days; privileged service dormancy is >365. Disabled privileged users are included in dormancy because the check has no enabled-state restriction, but their blocked sign-in is acknowledged as a mitigating factor. General no-MFA checks intentionally overlap the privileged MFA check, so duplicate risk categories do not inflate the number of affected accounts.

Severity follows `severity_model.md`: Domain Admin service exposure is Critical; dormant privileged users and missing privileged MFA are High; retained disabled groups, Server Admin services and repeated-failure users without MFA are Medium; general missing user MFA is Low. Proposed lifecycle interpretation: enabled departed/transferred Domain Admins are Critical, enabled lifecycle review otherwise High. The >365-day dormant privileged service is Critical here because its actual membership is Domain Admins. Keyword matches require manual confirmation; they are not automatic proof of HR status or misuse.

## Findings Summary Table

| Finding ID | Account | Category | Severity | Status |
| --- | --- | --- | --- | --- |
| IAM-001 | admin.legacy | check_dormant_privileged | High | Open |
| IAM-002 | admin.legacy | check_mfa_coverage | High | Open |
| IAM-003 | admin.legacy | check_departed_or_transferred | High | Open |
| IAM-004 | admin.legacy | check_no_mfa_high_risk | Low | Open |
| IAM-005 | t.morrison | check_dormant_privileged | High | Open |
| IAM-006 | t.morrison | check_mfa_coverage | High | Open |
| IAM-007 | t.morrison | check_departed_or_transferred | Critical | Open |
| IAM-008 | t.morrison | check_no_mfa_high_risk | Low | Open |
| IAM-009 | k.nguyen | check_no_mfa_high_risk | Medium | Open |
| IAM-010 | l.okafor | check_departed_or_transferred | High | Open |
| IAM-011 | l.okafor | check_no_mfa_high_risk | Low | Open |
| IAM-012 | b.carter | check_dormant_privileged | High | Open |
| IAM-013 | b.carter | check_disabled_with_groups | Medium | Open |
| IAM-014 | svc_backup | check_service_account_overpriv | Critical | Open |
| IAM-015 | svc_epic_int | check_service_account_overpriv | Critical | Open |
| IAM-016 | svc_epic_int | check_dormant_privileged | Critical | Open |
| IAM-017 | svc_helpdesk | check_service_account_overpriv | Critical | Open |
| IAM-018 | svc_monitoring | check_service_account_overpriv | Medium | Open |
| IAM-019 | j.yamamoto | check_dormant_privileged | High | Open |
| IAM-020 | j.yamamoto | check_mfa_coverage | High | Open |
| IAM-021 | j.yamamoto | check_departed_or_transferred | Critical | Open |
| IAM-022 | j.yamamoto | check_no_mfa_high_risk | Low | Open |

## Detailed Findings

### IAM-007: Lifecycle review: contract ended

**Account:** `t.morrison`  
**Severity:** Critical  
**Check:** `check_departed_or_transferred`  
**Evidence:** accounts.csv row 8; `username=t.morrison; display_name=Tom Morrison; department=IT Contractors; account_type=user; enabled=TRUE; last_login_days_ago=248; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Contract ended 2025-09-01`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Verify HR/project status; disable departed accounts, remove prior-role permissions on transfer, and retire completed migration access; record approval and service checks.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-014: Service account with Domain Admin membership

**Account:** `svc_backup`  
**Severity:** Critical  
**Check:** `check_service_account_overpriv`  
**Evidence:** accounts.csv row 13; `username=svc_backup; display_name=Backup Service Account; department=IT; account_type=service; enabled=TRUE; last_login_days_ago=1; mfa_enrolled=N/A; privileged_groups=Domain Admins; description=Nightly backup automation; DA granted per legacy config`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Remove svc_backup from Domain Admins after dependency validation; replace with documented task-scoped permissions and test its function.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-015: Service account with Domain Admin membership

**Account:** `svc_epic_int`  
**Severity:** Critical  
**Check:** `check_service_account_overpriv`  
**Evidence:** accounts.csv row 14; `username=svc_epic_int; display_name=Epic Integration Service; department=Clinical Systems; account_type=service; enabled=TRUE; last_login_days_ago=1156; mfa_enrolled=N/A; privileged_groups=Domain Admins; description=Post-EHR-migration service account; no current function identified`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Remove svc_epic_int from Domain Admins after dependency validation; replace with documented task-scoped permissions and test its function.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-016: Dormant privileged service account

**Account:** `svc_epic_int`  
**Severity:** Critical  
**Check:** `check_dormant_privileged`  
**Evidence:** accounts.csv row 14; `username=svc_epic_int; display_name=Epic Integration Service; department=Clinical Systems; account_type=service; enabled=TRUE; last_login_days_ago=1156; mfa_enrolled=N/A; privileged_groups=Domain Admins; description=Post-EHR-migration service account; no current function identified`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Contain unused account after dependency check; remove privileged membership and investigate historical use.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-017: Service account with Domain Admin membership

**Account:** `svc_helpdesk`  
**Severity:** Critical  
**Check:** `check_service_account_overpriv`  
**Evidence:** accounts.csv row 15; `username=svc_helpdesk; display_name=Helpdesk Automation; department=IT; account_type=service; enabled=TRUE; last_login_days_ago=0; mfa_enrolled=N/A; privileged_groups=Domain Admins; description=Ticket routing automation; DA granted by vendor during install; review later`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Remove svc_helpdesk from Domain Admins after dependency validation; replace with documented task-scoped permissions and test its function.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-021: Lifecycle review: transferred from

**Account:** `j.yamamoto`  
**Severity:** Critical  
**Check:** `check_departed_or_transferred`  
**Evidence:** accounts.csv row 18; `username=j.yamamoto; display_name=Jun Yamamoto; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=312; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Transferred from IT to Finance 2024-02; elevated rights not removed`  
**Severity justification:** Broad domain authority can reproduce the credential-theft-to-domain-control path, threatening clinical availability and access to patient information.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Verify HR/project status; disable departed accounts, remove prior-role permissions on transfer, and retire completed migration access; record approval and service checks.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** Immediate containment; verified correction within 7 days after authorization.

### IAM-001: Dormant privileged user

**Account:** `admin.legacy`  
**Severity:** High  
**Check:** `check_dormant_privileged`  
**Evidence:** accounts.csv row 7; `username=admin.legacy; display_name=Legacy Admin Account; department=IT; account_type=user; enabled=TRUE; last_login_days_ago=187; mfa_enrolled=FALSE; privileged_groups=Domain Admins; description=Created for EHR migration 2021; migration complete`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Confirm owner and business need; disable unused access and remove obsolete privileged memberships.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-002: Enabled privileged user without MFA

**Account:** `admin.legacy`  
**Severity:** High  
**Check:** `check_mfa_coverage`  
**Evidence:** accounts.csv row 7; `username=admin.legacy; display_name=Legacy Admin Account; department=IT; account_type=user; enabled=TRUE; last_login_days_ago=187; mfa_enrolled=FALSE; privileged_groups=Domain Admins; description=Created for EHR migration 2021; migration complete`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Suspend unnecessary privileged access; require verified MFA enrollment before approved privileged use.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-003: Lifecycle review: migration complete

**Account:** `admin.legacy`  
**Severity:** High  
**Check:** `check_departed_or_transferred`  
**Evidence:** accounts.csv row 7; `username=admin.legacy; display_name=Legacy Admin Account; department=IT; account_type=user; enabled=TRUE; last_login_days_ago=187; mfa_enrolled=FALSE; privileged_groups=Domain Admins; description=Created for EHR migration 2021; migration complete`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Verify HR/project status; disable departed accounts, remove prior-role permissions on transfer, and retire completed migration access; record approval and service checks.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-005: Dormant privileged user

**Account:** `t.morrison`  
**Severity:** High  
**Check:** `check_dormant_privileged`  
**Evidence:** accounts.csv row 8; `username=t.morrison; display_name=Tom Morrison; department=IT Contractors; account_type=user; enabled=TRUE; last_login_days_ago=248; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Contract ended 2025-09-01`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Confirm owner and business need; disable unused access and remove obsolete privileged memberships.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-006: Enabled privileged user without MFA

**Account:** `t.morrison`  
**Severity:** High  
**Check:** `check_mfa_coverage`  
**Evidence:** accounts.csv row 8; `username=t.morrison; display_name=Tom Morrison; department=IT Contractors; account_type=user; enabled=TRUE; last_login_days_ago=248; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Contract ended 2025-09-01`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Suspend unnecessary privileged access; require verified MFA enrollment before approved privileged use.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-010: Lifecycle review: left organization

**Account:** `l.okafor`  
**Severity:** High  
**Check:** `check_departed_or_transferred`  
**Evidence:** accounts.csv row 11; `username=l.okafor; display_name=Lena Okafor; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=142; mfa_enrolled=FALSE; privileged_groups=Finance Users; description=Left organization per HR 2025-11-28`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Verify HR/project status; disable departed accounts, remove prior-role permissions on transfer, and retire completed migration access; record approval and service checks.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-012: Dormant privileged user

**Account:** `b.carter`  
**Severity:** High  
**Check:** `check_dormant_privileged`  
**Evidence:** accounts.csv row 12; `username=b.carter; display_name=Brian Carter; department=IT; account_type=user; enabled=FALSE; last_login_days_ago=224; mfa_enrolled=TRUE; privileged_groups=Server Admins;Helpdesk; description=Account disabled; group memberships not removed at offboarding`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited. This account is disabled, so current sign-in is blocked; retained rights matter on reactivation and for lifecycle assurance.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Confirm owner and business need; disable unused access and remove obsolete privileged memberships.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-019: Dormant privileged user

**Account:** `j.yamamoto`  
**Severity:** High  
**Check:** `check_dormant_privileged`  
**Evidence:** accounts.csv row 18; `username=j.yamamoto; display_name=Jun Yamamoto; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=312; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Transferred from IT to Finance 2024-02; elevated rights not removed`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Confirm owner and business need; disable unused access and remove obsolete privileged memberships.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-020: Enabled privileged user without MFA

**Account:** `j.yamamoto`  
**Severity:** High  
**Check:** `check_mfa_coverage`  
**Evidence:** accounts.csv row 18; `username=j.yamamoto; display_name=Jun Yamamoto; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=312; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Transferred from IT to Finance 2024-02; elevated rights not removed`  
**Severity justification:** The account state creates a strong path to unauthorized access or privileged persistence; clinical system disruption or patient-data exposure may follow if exploited.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Suspend unnecessary privileged access; require verified MFA enrollment before approved privileged use.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 7 days after authorization.

### IAM-009: Enabled user without MFA and repeated security failures

**Account:** `k.nguyen`  
**Severity:** Medium  
**Check:** `check_no_mfa_high_risk`  
**Evidence:** accounts.csv row 10; `username=k.nguyen; display_name=Kevin Nguyen; department=Radiology; account_type=user; enabled=TRUE; last_login_days_ago=1; mfa_enrolled=FALSE; privileged_groups=Epic Users;PACS Users; description=Three phishing simulation failures in 90 days`  
**Severity justification:** Excess or residual access, or weak verification, creates preventable exposure. This is not evidence of current compromise.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-013: Disabled account retains group memberships

**Account:** `b.carter`  
**Severity:** Medium  
**Check:** `check_disabled_with_groups`  
**Evidence:** accounts.csv row 12; `username=b.carter; display_name=Brian Carter; department=IT; account_type=user; enabled=FALSE; last_login_days_ago=224; mfa_enrolled=TRUE; privileged_groups=Server Admins;Helpdesk; description=Account disabled; group memberships not removed at offboarding`  
**Severity justification:** Excess or residual access, or weak verification, creates preventable exposure. This is not evidence of current compromise. This account is disabled, so current sign-in is blocked; retained rights matter on reactivation and for lifecycle assurance.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Remove obsolete memberships from b.carter; verify no privileged access returns on reactivation.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-018: Service account with Server Admin membership

**Account:** `svc_monitoring`  
**Severity:** Medium  
**Check:** `check_service_account_overpriv`  
**Evidence:** accounts.csv row 16; `username=svc_monitoring; display_name=Monitoring Agent; department=IT; account_type=service; enabled=TRUE; last_login_days_ago=0; mfa_enrolled=N/A; privileged_groups=Server Admins; description=Prometheus metrics collection`  
**Severity justification:** Excess or residual access, or weak verification, creates preventable exposure. This is not evidence of current compromise.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Replace svc_monitoring Server Admins access with documented scoped permissions; verify service operation.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-004: Enabled user without MFA

**Account:** `admin.legacy`  
**Severity:** Low  
**Check:** `check_no_mfa_high_risk`  
**Evidence:** accounts.csv row 7; `username=admin.legacy; display_name=Legacy Admin Account; department=IT; account_type=user; enabled=TRUE; last_login_days_ago=187; mfa_enrolled=FALSE; privileged_groups=Domain Admins; description=Created for EHR migration 2021; migration complete`  
**Severity justification:** Missing MFA weakens account protection; actual reach depends on application authorization and other controls.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-008: Enabled user without MFA

**Account:** `t.morrison`  
**Severity:** Low  
**Check:** `check_no_mfa_high_risk`  
**Evidence:** accounts.csv row 8; `username=t.morrison; display_name=Tom Morrison; department=IT Contractors; account_type=user; enabled=TRUE; last_login_days_ago=248; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Contract ended 2025-09-01`  
**Severity justification:** Missing MFA weakens account protection; actual reach depends on application authorization and other controls.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-011: Enabled user without MFA

**Account:** `l.okafor`  
**Severity:** Low  
**Check:** `check_no_mfa_high_risk`  
**Evidence:** accounts.csv row 11; `username=l.okafor; display_name=Lena Okafor; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=142; mfa_enrolled=FALSE; privileged_groups=Finance Users; description=Left organization per HR 2025-11-28`  
**Severity justification:** Missing MFA weakens account protection; actual reach depends on application authorization and other controls.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

### IAM-022: Enabled user without MFA

**Account:** `j.yamamoto`  
**Severity:** Low  
**Check:** `check_no_mfa_high_risk`  
**Evidence:** accounts.csv row 18; `username=j.yamamoto; display_name=Jun Yamamoto; department=Finance; account_type=user; enabled=TRUE; last_login_days_ago=312; mfa_enrolled=FALSE; privileged_groups=Domain Admins;Server Admins; description=Transferred from IT to Finance 2024-02; elevated rights not removed`  
**Severity justification:** Missing MFA weakens account protection; actual reach depends on application authorization and other controls.  
**Risk:** Unauthorized identity use can expose patient-related systems or disrupt care; this snapshot does not establish a breach.  
**Remediation:**

1. Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.
2. IAM owner records approval and updated membership/enrollment/status evidence; test the documented business function and rerun the relevant check.

**Owner:** IAM administrator with business owner; HR validates lifecycle changes.  
**Target completion:** 30 days after authorization.

## MFA Coverage Analysis

There are 14 privileged accounts under the Domain/Server Admin definition: 10 users and 4 services. All privileged users: 7 enrolled, 3 not enrolled. Enabled privileged users: 6/9 enrolled (66.7%), with 3 missing enrollment. Disabled b.carter is reported separately rather than silently counted as an active sign-in risk. Service values are N/A and are not converted to missing user MFA. Enrollment itself does not prove enforcement.

Task wording associates unique user ID with HIPAA 164.312(d). The correct unique-identification provision is **164.312(a)(2)(i)**; 164.312(d) concerns person/entity authentication. Unique identification and MFA are different controls, and an enrollment percentage cannot establish legal compliance. See [HHS unique-user-ID guidance](https://www.hhs.gov/hipaa/for-professionals/faq/does-the-security-rule-permit-a-covered-entity-to-assign-the-same-log-on-id-to-multiple-employees/index.html) and [HHS audit protocol](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html).

## Service Account Risk Summary

| Account | Source CSV row | Current privilege/function | Recommendation |
| --- | --- | --- | --- |
| svc_backup | 13 | Domain Admins; nightly backup | Replace broad authority with tested backup-specific rights |
| svc_epic_int | 14 | Domain Admins; no current function | Contain, remove privilege and retire if dependencies confirm unused |
| svc_helpdesk | 15 | Domain Admins; ticket routing | Remove Domain Admins; validate minimum ticket-routing rights, including Helpdesk membership only if sufficient and approved |
| svc_monitoring | 16 | Server Admins; metrics collection | Scope read-only collection and test monitoring |

svc_av_mgmt (row 17) uses Workstation Admins and has an EDR management function; it is outside the required Domain/Server service-overprivilege check, not certified safe.

## Remediation Roadmap

| Priority | Action | Owner role | Target after approval | Success criterion |
| --- | --- | --- | --- | --- |
| 1 | Contain Critical standing rights and confirm lifecycle status | IAM, service owners, HR | Immediate; correction ≤7 days | Obsolete rights removed; clinical functions verified |
| 2 | Resolve privileged dormancy/MFA and departed-user access | IAM and HR | 7 days | Approved active roster; enforced verification; removal evidence |
| 3 | Clean retained groups and monitoring rights; assist high-risk user MFA | IAM/service owners | 30 days | Scoped permissions, enrollment and operational tests |
| 4 | Establish recurring access and lifecycle review | IT Director, HR | 30 days | Named owners, review calendar and exceptions register |

## Appendix: Audit Script

[audit_iam.py](audit_iam.py) generated [iam_findings.json](iam_findings.json) from [accounts.csv](accounts.csv). Input is an exact copy of `../opt/meddefense/materials/iam_audit/accounts.csv`. Source [severity model](../opt/meddefense/materials/iam_audit/severity_model.md) and [incident identity path](../opt/meddefense/materials/iam_audit/incident_identity_path.md) govern interpretation. Finding IDs follow inventory order and check order; changing either can change IDs, so retain the submitted snapshot with its report.
