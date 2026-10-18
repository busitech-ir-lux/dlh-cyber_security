#!/bin/bash
# Verify forensic evidence before starting an analysis session.
# Put this script next to the three evidence files, or set EVIDENCE_DIR.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-$SCRIPT_DIR}"
HASH_FILE="$SCRIPT_DIR/hashes.txt"
LOG_FILE="$SCRIPT_DIR/verification_log.txt"
ACTOR="${ACTOR:-$(whoami)}"

ids=("ART-001" "ART-002" "ART-003")
files=("wst-ws-031.dd" "wst-ws-031.mem" "wst-ws-017.mem")

# Record every attempted check in UTC.
log_event() {
    local timestamp
    timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    printf '%s | %s | %s | %s | expected=%s | computed=%s\n' \
        "$timestamp" "$ACTOR" "$1" "$2" "$3" "$4" >> "$LOG_FILE"
}

# Calculate a single file's SHA-256 without changing its contents.
file_hash() {
    sha256sum -- "$1" | awk '{print $1}'
}

# First run: hash everything successfully before creating a baseline file.
if [ ! -e "$HASH_FILE" ]; then
    hashes=()
    for i in "${!files[@]}"; do
        path="$EVIDENCE_DIR/${files[$i]}"
        if [ ! -f "$path" ] || [ ! -r "$path" ]; then
            echo "[FAIL] ${ids[$i]} ${files[$i]} missing or unreadable: $path"
            log_event "${ids[$i]}" "FAIL" "NOT_SET" "UNAVAILABLE"
            exit 1
        fi
        hash="$(file_hash "$path")" || {
            echo "[FAIL] ${ids[$i]} ${files[$i]} hashing failed"
            log_event "${ids[$i]}" "FAIL" "NOT_SET" "HASH_ERROR"
            exit 1
        }
        hashes+=("$hash")
    done

    # Exclusive creation avoids silently replacing an existing baseline.
    ( set -C; : > "$HASH_FILE" ) 2>/dev/null || {
        echo "[FAIL] Could not create hashes.txt (already exists or permission denied)."
        exit 1
    }
    for i in "${!files[@]}"; do
        printf '%s  %s\n' "${hashes[$i]}" "${files[$i]}" >> "$HASH_FILE"
        echo "[BASELINE_SET] ${ids[$i]} ${files[$i]} sha256=${hashes[$i]}"
        log_event "${ids[$i]}" "BASELINE_SET" "NOT_TAKEN_AT_ACQUISITION" "${hashes[$i]}"
    done
    chmod a-w "$HASH_FILE" 2>/dev/null || true
    echo "Baseline written to hashes.txt. Run again to verify."
    exit 0
fi

# Later runs: each artifact must match its saved baseline.
failed=0
for i in "${!files[@]}"; do
    name="${files[$i]}"
    path="$EVIDENCE_DIR/$name"
    expected="$(awk -v name="$name" '$2 == name { print $1 }' "$HASH_FILE" 2>/dev/null)"

    if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        expected="INVALID_OR_MISSING"
    fi
    if [ -f "$path" ] && [ -r "$path" ]; then
        computed="$(file_hash "$path")" || computed="HASH_ERROR"
    else
        computed="UNAVAILABLE"
    fi

    if [ "$expected" != "INVALID_OR_MISSING" ] && [ "$expected" = "$computed" ]; then
        result="PASS"
    else
        result="FAIL"
        failed=1
    fi

    echo "[$result] ${ids[$i]} $name expected=$expected computed=$computed"
    log_event "${ids[$i]}" "$result" "$expected" "$computed"
    if [ "$result" = "FAIL" ]; then
        echo "DEVIATION: ${ids[$i]} $name failed verification; do not begin analysis." | tee -a "$LOG_FILE"
    fi
done

if [ "$failed" -eq 0 ]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
fi

echo "VERIFICATION FAILED - DO NOT START ANALYSIS"
exit 1
