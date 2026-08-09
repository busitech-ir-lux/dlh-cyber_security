#!/bin/bash
#
# name: 15-handoff_validation.sh
# Handoff Validation - the quality gate before the builder -> analyst handoff.
#
# purpose: Validates telemetry_handoff/ against seven gates:
#   1. File existence      2. JSON validity       3. Required fields
#   4. Minimum counts      5. Timestamp validity  6. Cross-platform alignment
#   7. Ground truth completeness (every action has a detection matrix entry)
#
# Emits PASS/FAIL per check, a final verdict, and handoff_validation.json.
# Requires jq.
# author: Mahdi Hamidi

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
command -v jq >/dev/null 2>&1 || { echo "[!] jq is required." >&2; exit 1; }

# ------------------------------ Inputs (literal paths) -----------------------
DIR="telemetry_handoff"
WIN="telemetry_handoff/windows_events.json"
LIN="telemetry_handoff/linux_events.json"
GT="telemetry_handoff/attack_ground_truth.json"
WIN_DM="windows_detection_matrix.json"
LIN_DM="linux_detection_matrix.json"
OUT="handoff_validation.json"

EMPTY="$(mktemp)"; : > "$EMPTY"
trap 'rm -f "$EMPTY"' EXIT
pf() { [ -f "$1" ] && printf '%s' "$1" || printf '%s' "$EMPTY"; }

# ------------------------------ Result tracking ------------------------------
TOTAL=0; PASSED=0
RESULTS=()

add_result() { # category, status(PASS/FAIL), message
    RESULTS+=("$(jq -n --arg c "$1" --arg s "$2" --arg m "$3" \
        '{category:$c, status:$s, message:$m}')")
    TOTAL=$((TOTAL+1)); [ "$2" = "PASS" ] && PASSED=$((PASSED+1))
    echo "[$2] $3"
}

human_size() {
    local b; b=$(stat -c%s "$1" 2>/dev/null || echo 0)
    awk -v b="$b" 'BEGIN{
        if (b>=1048576) printf "%.1f MB", b/1048576;
        else if (b>=1024) printf "%d KB", b/1024;
        else printf "%d B", b;
    }'
}

commafy() { echo "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'; }

json_count() { # file -> number of top-level objects
    if [ -f "$1" ]; then
        jq 'if type=="array" then length else ((.events // .actions // []) | length) end' "$1" 2>/dev/null || echo 0
    else echo 0; fi
}

echo "[*] Validating telemetry_handoff/ ..."

# ============================== 1. File existence ============================
echo "=== File Existence ==="
for pair in "$WIN|windows_events.json" "$LIN|linux_events.json" "$GT|attack_ground_truth.json"; do
    path="${pair%%|*}"; name="${pair##*|}"
    if [ -f "$path" ]; then
        add_result "file_existence" "PASS" "$name exists ($(human_size "$path"))"
    else
        add_result "file_existence" "FAIL" "$name is missing"
    fi
done

# ============================== 2. JSON validity =============================
echo "=== JSON Validity ==="
for pair in "$WIN|windows_events.json" "$LIN|linux_events.json" "$GT|attack_ground_truth.json"; do
    path="${pair%%|*}"; name="${pair##*|}"
    if [ -f "$path" ] && jq empty "$path" >/dev/null 2>&1; then
        add_result "json_validity" "PASS" "$name: valid JSON, $(json_count "$path") objects"
    else
        add_result "json_validity" "FAIL" "$name: invalid or unparseable JSON"
    fi
done

# ============================== 3. Required fields ===========================
echo "=== Required Fields ==="
reqmiss=$(jq -n --slurpfile w "$(pf "$WIN")" --slurpfile l "$(pf "$LIN")" '
    def arr($x): ($x[0] | if type=="array" then . elif type=="object" then (.events // []) else [] end);
    (arr($w) + arr($l)) as $ev
    | [ $ev[] | select(
          (((.timestamp? // "")     | tostring) != "") and
          (((.hostname? // "")      | tostring) != "") and
          (((.source_type? // "")   | tostring) != "") and
          (((.event_category? // "")| tostring) != "") | not
      ) ] | length' 2>/dev/null || echo -1)
if [ "$reqmiss" = "0" ]; then
    add_result "required_fields" "PASS" "All events have timestamp, hostname, source_type, event_category"
else
    add_result "required_fields" "FAIL" "$reqmiss event(s) missing required fields"
fi

# ============================== 4. Minimum counts ============================
echo "=== Minimum Event Counts ==="
WC=$(json_count "$WIN"); LC=$(json_count "$LIN"); GC=$(json_count "$GT")
WC=${WC:-0}; LC=${LC:-0}; GC=${GC:-0}

if [ "$WC" -ge 1000 ]; then
    add_result "min_counts" "PASS" "Windows: $(commafy "$WC") >= 1,000"
else
    add_result "min_counts" "FAIL" "Windows: $(commafy "$WC") < 1,000"
fi
if [ "$LC" -ge 500 ]; then
    add_result "min_counts" "PASS" "Linux: $(commafy "$LC") >= 500"
else
    add_result "min_counts" "FAIL" "Linux: $(commafy "$LC") < 500"
fi
if [ "$GC" -ge 10 ]; then
    add_result "min_counts" "PASS" "Ground truth: $GC >= 10"
else
    add_result "min_counts" "FAIL" "Ground truth: $GC < 10"
fi

# ============================== 5. Timestamp consistency =====================
echo "=== Timestamp Consistency ==="
NOW=$(date -u +%s)
tsinfo=$(jq -n --slurpfile w "$(pf "$WIN")" --slurpfile l "$(pf "$LIN")" --argjson now "$NOW" '
    def arr($x): ($x[0] | if type=="array" then . elif type=="object" then (.events // []) else [] end);
    def isoRE: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$";
    def norm: sub("[+]00:00$";"Z") | sub("[.][0-9]+";"");
    def ep: (norm | try fromdateiso8601 catch null);
    arr($w) as $wv | arr($l) as $lv
    | ([ $wv[].timestamp // "" | tostring ]) as $wts
    | ([ $lv[].timestamp // "" | tostring ]) as $lts
    | ($wts + $lts) as $all
    | ([ $all[] | ep | select(. != null) ]) as $alle
    | ([ $wts[] | ep | select(. != null) ]) as $we
    | ([ $lts[] | ep | select(. != null) ]) as $le
    | {
        total:   ($all | length),
        invalid: ([ $all[] | select((test(isoRE)) | not) ] | length),
        future:  ([ $alle[] | select(. > $now) ] | length),
        min:  ($alle | min), max:  ($alle | max),
        wmin: ($we | min),   wmax: ($we | max),
        lmin: ($le | min),   lmax: ($le | max)
    }' 2>/dev/null || echo '{}')

invalid=$(jq -r '.invalid // -1' <<<"$tsinfo")
future=$(jq -r '.future // -1' <<<"$tsinfo")
minE=$(jq -r '.min // empty' <<<"$tsinfo")
maxE=$(jq -r '.max // empty' <<<"$tsinfo")
wmin=$(jq -r '.wmin // empty' <<<"$tsinfo"); wmax=$(jq -r '.wmax // empty' <<<"$tsinfo")
lmin=$(jq -r '.lmin // empty' <<<"$tsinfo"); lmax=$(jq -r '.lmax // empty' <<<"$tsinfo")

if [ "$invalid" = "0" ]; then
    add_result "timestamps" "PASS" "All timestamps valid ISO 8601"
else
    add_result "timestamps" "FAIL" "$invalid timestamp(s) not valid ISO 8601"
fi
if [ "$future" = "0" ]; then
    add_result "timestamps" "PASS" "No future timestamps"
else
    add_result "timestamps" "FAIL" "$future future timestamp(s) detected"
fi
# Informational range line (not a counted gate)
if [ -n "$minE" ] && [ -n "$maxE" ]; then
    rmin=$(date -u -d "@$minE" +%Y-%m-%dT%H:%M:%SZ)
    rmax=$(date -u -d "@$maxE" +%Y-%m-%dT%H:%M:%SZ)
    echo "[PASS] Range: $rmin to $rmax"
else
    rmin=""; rmax=""
    echo "[INFO] Range: unavailable"
fi

# ============================== 6. Cross-platform alignment ==================
echo "=== Cross-Platform Alignment ==="
read -r ov_ok ov_hours < <(awk -v a="$wmin" -v b="$wmax" -v c="$lmin" -v d="$lmax" 'BEGIN{
    if (a=="" || b=="" || c=="" || d==""){ print "0 0"; exit }
    lo=(a>c?a:c); hi=(b<d?b:d); ov=hi-lo;
    if (ov>0) printf "1 %.1f", ov/3600; else print "0 0";
}')
if [ "$ov_ok" = "1" ]; then
    add_result "alignment" "PASS" "Windows and Linux time ranges overlap (${ov_hours} hours shared)"
else
    add_result "alignment" "FAIL" "Windows and Linux time ranges do not overlap"
fi

# ============================== 7. Ground truth completeness =================
echo "=== Ground Truth Completeness ==="
gtc=$(jq -n --slurpfile gt "$(pf "$GT")" --slurpfile wdm "$(pf "$WIN_DM")" --slurpfile ldm "$(pf "$LIN_DM")" '
    (($gt[0].actions) // []) as $A
    | ([ (($wdm[0].matrix) // [])[] | {p:"windows", n:.action_number} ]
      + [ (($ldm[0].matrix) // [])[] | {p:"linux",   n:.action_number} ]) as $M
    | { matched: ([ $A[] | . as $a
                    | select( any($M[]; .p == ($a.platform // "windows") and .n == $a.action_number) )
                  ] | length),
        total: ($A | length) }' 2>/dev/null || echo '{"matched":0,"total":0}')
matched=$(jq -r '.matched' <<<"$gtc"); gtotal=$(jq -r '.total' <<<"$gtc")
if [ "$gtotal" -gt 0 ] && [ "$matched" = "$gtotal" ]; then
    add_result "ground_truth" "PASS" "$matched/$gtotal actions have detection matrix entries"
else
    add_result "ground_truth" "FAIL" "$matched/$gtotal actions have detection matrix entries"
fi

# ============================== Verdict ======================================
if [ "$PASSED" -eq "$TOTAL" ]; then verdict="PASS"; else verdict="FAIL"; fi
echo "VERDICT: $verdict ($PASSED/$TOTAL checks)"
if [ "$verdict" = "PASS" ]; then
    echo "Handoff package is ready for Module 3."
else
    echo "Handoff package is NOT ready. Resolve the FAIL item(s) above."
fi

# ============================== Save report ==================================
results_json=$(printf '%s\n' "${RESULTS[@]}" | jq -s '.')
jq -n \
    --arg verdict "$verdict" \
    --argjson passed "$PASSED" \
    --argjson total "$TOTAL" \
    --arg range_min "${rmin:-}" \
    --arg range_max "${rmax:-}" \
    --arg overlap_hours "${ov_hours:-0}" \
    --argjson results "$results_json" \
    '{
        generated_at: (now | todateiso8601),
        verdict: $verdict,
        checks_passed: $passed,
        checks_total: $total,
        timestamp_range: { min: $range_min, max: $range_max },
        cross_platform_overlap_hours: ($overlap_hours | tonumber),
        results: $results
    }' > "$OUT"

echo "Report saved to: $OUT"
