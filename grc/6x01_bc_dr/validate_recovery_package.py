#!/usr/bin/env python3
"""Validate BIA-to-backup consistency and the current recovery evidence, read-only."""
from pathlib import Path
import hashlib
import json
import math
import re
import sqlite3
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def tables(text):
    lines = text.splitlines()
    found = []
    i = 0
    while i + 1 < len(lines):
        if lines[i].startswith('|') and re.fullmatch(r'[| :\-]+', lines[i + 1]):
            header = [x.strip() for x in lines[i].split('|')[1:-1]]
            rows = []
            i += 2
            while i < len(lines) and lines[i].startswith('|'):
                values = [x.strip() for x in lines[i].split('|')[1:-1]]
                assert len(values) == len(header), 'Malformed table row'
                rows.append(dict(zip(header, values)))
                i += 1
            found.append((header, rows))
        else:
            i += 1
    return found


def check_architecture(bia, architecture):
    objectives = next(rows for header, rows in tables(bia) if {'System', 'Priority', 'RTO', 'RPO', 'MTD'}.issubset(header))
    proposed = next(rows for header, rows in tables(architecture) if {'System', 'Proposed RPO, min', 'Proposed point interval, min'}.issubset(header))
    errors = []
    by_name = {row['System']: row for row in objectives}
    if len(objectives) != 10 or {row['System'] for row in proposed} != set(by_name):
        errors.append('Coverage must include exactly the ten BIA systems')
    for row in proposed:
        name = row['System']
        expected_rpo = int(by_name[name]['RPO'])
        declared_rpo = int(row['Proposed RPO, min'])
        interval = int(row['Proposed point interval, min'])
        lag = int(row['Max delivery/verification lag, min'])
        age = int(row['Designed worst age, min'])
        if declared_rpo != expected_rpo:
            errors.append(name + ': architecture RPO differs from BIA RPO')
        if interval + lag != age or age > declared_rpo or interval > declared_rpo:
            errors.append(name + ': schedule cannot satisfy its stated RPO')
        if int(by_name[name]['RTO']) >= int(by_name[name]['MTD']):
            errors.append(name + ': RTO is not below MTD')
        section = re.search(r'^### ' + re.escape(name) + r': Tier [12]\n(.*?)(?=^### |^## |\Z)', architecture, re.M | re.S)
        if not section:
            errors.append(name + ': backup specification missing')
            continue
        schedule = next(rows[0:] for header, rows in tables(section[1]) if header == ['Field', 'Specification'])
        fields = {item['Field']: item['Specification'] for item in schedule}
        cadences = [int(value) for value in re.findall(r'every (\d+) minutes', fields['Schedule'])]
        if not cadences or min(cadences) != interval:
            errors.append(name + ': specified point cadence disagrees with verification table')
    return errors


def main():
    checks = []
    def require(condition, message):
        if not condition:
            raise AssertionError(message)
        checks.append('PASS: ' + message)
    bia = (ROOT / 'business_impact_analysis.md').read_text()
    architecture = (ROOT / 'backup_architecture.md').read_text()
    errors = check_architecture(bia, architecture)
    require(not errors, 'All ten backup schedules match BIA RPOs, lag arithmetic, and per-system cadences: ' + '; '.join(errors))
    historical = (ROOT / 'evidence/initial_run/backup_architecture.original.md.txt').read_text()
    require(len(check_architecture(bia, historical)) >= 10, 'Regression check rejects the original priority-tier/RPO column error')
    ev = ROOT / 'evidence/retest'
    journal = [json.loads(line) for line in (ev / 'journal.jsonl').read_text().splitlines()]
    require([r['step'] for r in journal if r['event'] == 'step_start'] == list(range(1, 11)), 'All ten steps have contemporaneous start events')
    require([r['step'] for r in journal if r['event'] == 'step_end' and r['status'] == 'PASS'] == list(range(1, 11)), 'All ten steps have recorded completion')
    exits = {r['key']: r['exit_code'] for r in journal if r['event'] == 'command_end'}
    require(exits['2check'] == 1 and exits['4check'] == 2 and all(code == 0 for key, code in exits.items() if key not in ['2check', '4check']), 'Actual diagnostic failures and successful corrections retained')
    record = (ROOT / 'recovery_test_record.md').read_text()
    log = (ROOT / 'recovery_test_log.txt').read_text()
    summary = (ev / 'timer_summary.txt').read_text()
    require(log in record and summary in record, 'Record contains unchanged full timer log and summary')
    require(len(re.findall(r'^\[STEP \d{2}\].*\| PASS$', log, re.M)) == 10, 'Full step log contains ten completed steps')
    state = ROOT / 'tmp/rtest_state'
    elapsed = int((state / 'last').read_text()) - int((state / 'first').read_text())
    metrics = json.loads((ev / 'metrics.json').read_text())
    require(elapsed == metrics['elapsed_ns'] and elapsed > 0, 'Timer total agrees with persisted epoch state')
    require(f'{elapsed / 1e9:.9f} seconds' in record and f'{math.ceil(elapsed / 1e9) % 60:02d}s' in summary, 'Actual and displayed times agree with raw state')
    require(('RTO (30 minutes): PASS' in summary) == (elapsed <= 1800 * 10**9), 'RTO verdict agrees with actual duration')
    for condition in ['path', 'config', 'manifest']:
        times = {r['event']: r['epoch_ns'] for r in journal if r.get('condition') == condition}
        duration = (times['resolved'] - times['discovered']) / 60e9
        require(duration >= 0 and f'{duration:.6f} minutes' in record, condition + ': numeric handling time agrees with contemporaneous journal')
    require((ev / '6.stdout.txt').read_text() == '5\n', 'Exact row-count stdout is five')
    expected = 'MRN-10043|BMP|K+: 6.1 mEq/L|1\nMRN-10045|TROPONIN|0.08 ng/mL|1\n'
    require((ev / 'critical_records.txt').read_text() == expected and expected in record, 'Both required critical records match exactly')
    database = ROOT / 'tmp/meddefense-dr-test/recovery/lis_recovered.db'
    connection = sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True)
    try:
        require(connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'Recovered database passes SQLite integrity check')
        require(connection.execute('SELECT COUNT(*) FROM patient_orders').fetchone()[0] == 5, 'Submitted recovered database has five rows')
    finally:
        connection.close()
    manifest = ev / 'backup_manifest.local.sha256'
    result = subprocess.run(['sha256sum', '-c', str(manifest)], cwd=ROOT, capture_output=True, text=True)
    require(result.returncode == 0, 'Repeat checksum manifest verifies the copied archive')
    for file in [ROOT / 'recovery_runbooks.md', ROOT / 'gap_analysis.md']:
        for code in re.findall(r'```bash\n(.*?)\n```', file.read_text(), re.S):
            result = subprocess.run(['bash', '-n'], input=code, capture_output=True, text=True)
            require(result.returncode == 0, 'Published Bash block syntax: ' + file.name)
    with tempfile.TemporaryDirectory(prefix='bc_timer_check_') as directory:
        timer = str(ROOT / 'recovery_timer.sh')
        def call(*args):
            return subprocess.run([timer, *args], cwd=directory, capture_output=True, text=True)
        require(call('check', 'START').returncode == 0 and call('check', 'FAIL').returncode == 0, 'Timer accepts and logs a failed completed step')
        result = call('SUMMARY')
        require('Overall timer result: FAIL' in result.stdout, 'A fast failed step does not produce an overall PASS')
        require(call('SUMMARY').stdout == result.stdout, 'Repeated timer summary preserves its result')
    for f in list(ROOT.glob('*.md')) + [ROOT.parent / 'LEARNING_OBJECTIVES.md']:
        for dest in re.findall(r'\]\(([^)]+)\)', f.read_text()):
            if '://' not in dest:
                require((f.parent / dest.split('#')[0]).exists(), 'Local link resolves: ' + f.name + ' -> ' + dest)
    print('\n'.join(checks))
    print('Markdownlint and the external task checker were not run; the SSH lab requirement remains unverified.')


if __name__ == '__main__':
    main()
