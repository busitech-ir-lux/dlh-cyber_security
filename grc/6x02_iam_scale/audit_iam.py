#!/usr/bin/env python3
"""Audit the supplied snapshot; day counts are inventory values, not live queries."""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def groups(a):
    return set(filter(None, (s.strip() for s in a['privileged_groups'].split(';'))))


def privileged(a):
    return bool(groups(a) & {'Domain Admins', 'Server Admins'})


def issue(severity, title, remediation, category=None):
    return {'severity': severity, 'title': title, 'remediation': remediation,
            **({'category': category} if category else {})}


def check_dormant_privileged(account, dormancy_threshold_days=90):
    a = account
    if privileged(a):
        if a['account_type'] == 'user' and int(a['last_login_days_ago']) > dormancy_threshold_days:
            return issue('High', 'Dormant privileged user', 'Confirm owner and business need; disable unused access and remove obsolete privileged memberships.')
        if a['account_type'] == 'service' and int(a['last_login_days_ago']) > 365:
            return issue('Critical', 'Dormant privileged service account', 'Contain unused account after dependency check; remove privileged membership and investigate historical use.', 'dormant_service_privileged')


def check_mfa_coverage(a):
    if a['account_type'] == 'user' and a['enabled'] == 'TRUE' and privileged(a) and a['mfa_enrolled'] == 'FALSE':
        return issue('High', 'Enabled privileged user without MFA', 'Suspend unnecessary privileged access; require verified MFA enrollment before approved privileged use.')


def check_service_account_overpriv(a):
    if a['account_type'] == 'service':
        if 'Domain Admins' in groups(a):
            return issue('Critical', 'Service account with Domain Admin membership', f"Remove {a['username']} from Domain Admins after dependency validation; replace with documented task-scoped permissions and test its function.")
        if 'Server Admins' in groups(a):
            return issue('Medium', 'Service account with Server Admin membership', f"Replace {a['username']} Server Admins access with documented scoped permissions; verify service operation.")


def check_departed_or_transferred(a):
    matches = [k for k in ('contract ended', 'left organization', 'transferred from', 'migration complete') if k in a['description'].lower()]
    if matches:
        severity = 'Critical' if 'Domain Admins' in groups(a) and any(k in matches for k in ('contract ended', 'transferred from')) else 'High' if a['enabled'] == 'TRUE' else 'Medium'
        return {**issue(severity, 'Lifecycle review: ' + ', '.join(matches), 'Verify HR/project status; disable departed accounts, remove prior-role permissions on transfer, and retire completed migration access; record approval and service checks.'), 'matched_keywords': matches}


def check_disabled_with_groups(a):
    if a['enabled'] == 'FALSE' and groups(a):
        return issue('Medium', 'Disabled account retains group memberships', f"Remove obsolete memberships from {a['username']}; verify no privileged access returns on reactivation.")


def check_no_mfa_high_risk(a):
    if a['enabled'] == 'TRUE' and a['account_type'] == 'user' and a['mfa_enrolled'] == 'FALSE':
        repeated = 'phishing simulation failures' in a['description'].lower() or 'repeated security failures' in a['description'].lower()
        return issue('Medium' if repeated else 'Low', 'Enabled user without MFA' + (' and repeated security failures' if repeated else ''), 'Enroll user in MFA through verified process; provide private support and review access need; do not use simulation history for discipline.')


CHECKS = (check_service_account_overpriv, check_dormant_privileged, check_mfa_coverage,
          check_departed_or_transferred, check_disabled_with_groups, check_no_mfa_high_risk)


def audit(path):
    with path.open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        required = {'username', 'display_name', 'department', 'account_type', 'enabled', 'last_login_days_ago', 'mfa_enrolled', 'privileged_groups', 'description'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Inventory missing required columns')
        accounts = list(reader)
    findings = []
    seen = set()
    for row, a in enumerate(accounts, 2):
        if not a['username'] or a['username'] in seen:
            raise ValueError(f'Empty or duplicate username at CSV row {row}')
        seen.add(a['username'])
        if a['enabled'] not in ('TRUE', 'FALSE') or a['account_type'] not in ('user', 'service') or a['mfa_enrolled'] not in ('TRUE', 'FALSE', 'N/A') or int(a['last_login_days_ago']) < 0:
            raise ValueError(f'Invalid field value at CSV row {row}')
        for check in CHECKS:
            result = check(a)
            if result:
                findings.append({'finding_id': f'IAM-{len(findings)+1:03}', 'account': a['username'], 'check': check.__name__, **result,
                                 'source_row': row, 'evidence': '; '.join(f'{k}={v}' for k, v in a.items())})
    counts = Counter(f['severity'] for f in findings)
    return {'audit_metadata': {'script_version': '1.0', 'accounts_processed': len(accounts), 'audit_timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'source': str(path), 'row_convention': 'header is row 1', 'findings_count': {s: counts[s] for s in ('Critical', 'High', 'Medium', 'Low')}}, 'findings': findings}


def main():
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=base / 'accounts.csv')
    parser.add_argument('--output', type=Path, default=base / 'iam_findings.json')
    args = parser.parse_args()
    try:
        result = audit(args.input)
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'Audit failed: {exc}\n')
    print(f"Accounts processed : {result['audit_metadata']['accounts_processed']}")
    for severity, count in result['audit_metadata']['findings_count'].items():
        print(f'{severity} findings : {count}')
        for finding in result['findings']:
            if finding['severity'] == severity:
                print(f"  [{finding['finding_id']}] {finding['account']}: {finding['title']}")


if __name__ == '__main__':
    main()
