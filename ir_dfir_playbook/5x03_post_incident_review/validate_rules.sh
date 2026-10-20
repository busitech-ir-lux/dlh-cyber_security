#!/bin/bash
# Validate the two provided Sigma rule patterns against both provided samples.
# Usage: ./validate_rules.sh [directory containing files]
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${1:-$BASE_DIR}"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || {
  echo "PyYAML required: python3 -m pip install pyyaml" >&2
  exit 1
}

for rule in sigma_powershell_msbuild_lolbin.yml sigma_msbuild_network_connection.yml; do
  python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$BASE_DIR/$rule"
  for log in incident_sysmon.jsonl clean_sysmon.jsonl; do
    python3 "$BASE_DIR/match_sigma_samples.py" "$BASE_DIR/$rule" "$LOG_DIR/$log"
  done
done
