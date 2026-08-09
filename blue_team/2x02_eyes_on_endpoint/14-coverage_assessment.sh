#!/bin/bash
#
# name: 14-coverage_assessment.sh
# Cross-Platform Coverage Assessment (Block 3 metadata)
#
# purpose: Folds the handoff package, detection matrices, quality reports and Sysmon
# coverage matrix into a single metadata file that travels with the telemetry
# so the SOC can immediately see what is detectable, partial, or blind.
#
# Uses jq for all JSON processing. Missing inputs degrade gracefully.
# author: Mahdi Hamidi

set -e
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

command -v jq >/dev/null 2>&1 || { echo "[!] jq is required." >&2; exit 1; }

# ------------------------------ Inputs ---------------------------------------
HANDOFF="telemetry_handoff"
WIN_EV="telemetry_handoff/windows_events.json"
LIN_EV="telemetry_handoff/linux_events.json"
GT="telemetry_handoff/attack_ground_truth.json"
WIN_DM="windows_detection_matrix.json"
LIN_DM="linux_detection_matrix.json"
WIN_Q="windows_telemetry_quality.json"
LIN_Q="linux_telemetry_quality.json"
SYS="sysmon_coverage_matrix.json"
OUT="telemetry_coverage_assessment.json"

EMPTY="$(mktemp)"; : > "$EMPTY"
trap 'rm -f "$EMPTY"' EXIT
pf() { [ -f "$1" ] && printf '%s' "$1" || printf '%s' "$EMPTY"; }

echo "[*] Loading telemetry handoff package..."

# ------------------------------ Event counts ---------------------------------
count_arr() {
    if [ -f "$1" ]; then
        jq 'if type=="array" then length else ((.events // []) | length) end' "$1" 2>/dev/null || echo 0
    else echo 0; fi
}
by_field() {
    if [ -f "$1" ]; then
        jq --arg f "$2" '[ (if type=="array" then .[] else (.events // [])[] end) | .[$f] // "unknown" ]
                         | group_by(.) | map({(.[0]): length}) | add // {}' "$1" 2>/dev/null || echo '{}'
    else echo '{}'; fi
}

win_events=$(count_arr "$WIN_EV")
lin_events=$(count_arr "$LIN_EV")
win_by_src=$(by_field "$WIN_EV" source_type)
lin_by_src=$(by_field "$LIN_EV" source_type)
win_by_cat=$(by_field "$WIN_EV" event_category)
lin_by_cat=$(by_field "$LIN_EV" event_category)

# ------------------------------ Ground truth ---------------------------------
if [ -f "$GT" ]; then
    gt_actions=$(jq '(.total_actions // ((.actions // []) | length) // 0)' "$GT" 2>/dev/null || echo 0)
else gt_actions=0; fi

# ------------------------------ Detection matrices ---------------------------
# Detection matrix summary: simulated actions, captured, missed, multi-source.
dm_val() { # file, filter, default
    if [ -f "$1" ]; then jq "($2) // $3" "$1" 2>/dev/null || echo "$3"; else echo "$3"; fi
}
win_tot=$(dm_val "$WIN_DM" '.total_actions // (.matrix | length)' 0)
win_cap=$(dm_val "$WIN_DM" '.captured' 0)
win_multi=$(dm_val "$WIN_DM" '.multi_source' 0)
lin_tot=$(dm_val "$LIN_DM" '.total_actions // (.matrix | length)' 0)
lin_cap=$(dm_val "$LIN_DM" '.captured' 0)
lin_multi=$(dm_val "$LIN_DM" '.multi_source' 0)

total=$(( win_tot + lin_tot ))
captured=$(( win_cap + lin_cap ))
missed=$(( total - captured ))
multi=$(( win_multi + lin_multi ))

# ------------------------------ ATT&CK evaluation ----------------------------
# Join each matrix action to the combined ground truth by (platform, action_number)
# to recover its MITRE technique, then bucket by best detail level.
attack=$(jq -n \
    --slurpfile gt  "$(pf "$GT")" \
    --slurpfile wdm "$(pf "$WIN_DM")" \
    --slurpfile ldm "$(pf "$LIN_DM")" '
    (($gt[0].actions) // []) as $actions
    | (($wdm[0].matrix) // []) as $wm
    | (($ldm[0].matrix) // []) as $lm
    | ([ $wm[] | . + {platform:"windows"} ] + [ $lm[] | . + {platform:"linux"} ]) as $rows
    | [ $rows[] | . as $r
        | (first($actions[]
                 | select(.platform==$r.platform and .action_number==$r.action_number)
                 | .mitre_id) // $r.mitre_id // "unknown") as $mid
        | {
            technique: $mid,
            platform:  $r.platform,
            action:    ($r.action // $r.description // ("action " + ($r.action_number|tostring))),
            captured:  ($r.captured // ([ $r.sources[]? | select(.status=="CAPTURED") ] | length > 0)),
            full:      ([ $r.sources[]? | select(.detail=="Full") ] | length > 0),
            sources:   [ $r.sources[]? | select(.status=="CAPTURED") | .source ]
          }
      ] as $eval
    | {
        covered: [ $eval[] | select(.captured and .full) ],
        partial: [ $eval[] | select(.captured and (.full | not)) ],
        blind:   [ $eval[] | select(.captured | not) ]
      }
')

covered_cnt=$(jq '.covered | length' <<<"$attack")
partial_cnt=$(jq '.partial | length' <<<"$attack")
blind_cnt=$(jq '.blind | length' <<<"$attack")

# ------------------------------ Recommendations ------------------------------
RECMAP='{
  "T1071":"Enable Sysmon Event ID 3 network-connection logging with destination fields",
  "T1071.001":"Enable Sysmon Event ID 3 plus proxy/DNS logging",
  "T1059.001":"Enable PowerShell Script Block Logging (4104) and module logging",
  "T1059.004":"Add auditd -a always,exit -F arch=b64 -S connect -k network_connect",
  "T1027":"Enable PowerShell Script Block Logging to decode obfuscated commands",
  "T1547.001":"Add Sysmon Event ID 11 file-create rules for Startup folder paths",
  "T1053.005":"Enable Security 4698 scheduled-task auditing",
  "T1053.003":"Add auditd watch -w /etc/cron.d/ -p wa -k cron_persist",
  "T1548.003":"Add auditd watch -w /etc/sudoers.d/ -p wa -k sudoers",
  "T1003.008":"Add auditd watch -w /etc/shadow -p r -k identity",
  "T1136.001":"Enable account-creation auditing (Security 4720 / auditd identity)",
  "T1098":"Enable Security 4732 group-membership-change auditing"
}'

gaps=$(jq -n --argjson a "$attack" --argjson rec "$RECMAP" '
    [ $a.blind[]   | {severity:"blind", description:.action, impacted_platform:.platform, impacted_technique:.technique,
                      reason:"No telemetry source captured this action within the detection window.",
                      recommended_instrumentation_improvement:($rec[.technique] // "Add or enable a telemetry source for this technique.")} ]
  + [ $a.partial[] | {severity:"partial", description:.action, impacted_platform:.platform, impacted_technique:.technique,
                      reason:"Action captured but with incomplete field-level detail.",
                      recommended_instrumentation_improvement:($rec[.technique] // "Increase field capture / logging verbosity for this source.")} ]
')

# ------------------------------ Quality scores -------------------------------
q_score() {
    if [ -f "$1" ]; then
        jq -r '(.score // .overall_score // .quality_score // .overall.score // .summary.score // .overall_quality // empty)' "$1" 2>/dev/null | head -n1
    fi
}
win_q=$(q_score "$WIN_Q")
lin_q=$(q_score "$LIN_Q")

is_num() { case "$1" in ''|*[!0-9.]*) return 1;; *) return 0;; esac; }
num_or_null() { is_num "$1" && printf '%s' "$1" || printf 'null'; }

# ------------------------------ Confidence rating ----------------------------
rate=$(awk -v c="$captured" -v t="$total" 'BEGIN{ if(t==0)print 0; else printf "%.1f", c*100/t }')
have_q=0
if is_num "$win_q" && is_num "$lin_q"; then have_q=1; fi
avg=$(awk -v a="${win_q:-0}" -v b="${lin_q:-0}" 'BEGIN{ printf "%.2f", (a+b)/2 }')
confidence=$(awk -v r="$rate" -v q="$avg" -v hq="$have_q" 'BEGIN{
    if (hq==1) {
        if (r>=95 && q>=90) print "high";
        else if (r>=80 && q>=80) print "acceptable";
        else print "low";
    } else {
        if (r>=95) print "high";
        else if (r>=80) print "acceptable";
        else print "low";
    }
}')

# ------------------------------ Assemble report ------------------------------
jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson win_events "$win_events" \
    --argjson lin_events "$lin_events" \
    --argjson win_by_src "$win_by_src" \
    --argjson lin_by_src "$lin_by_src" \
    --argjson win_by_cat "$win_by_cat" \
    --argjson lin_by_cat "$lin_by_cat" \
    --argjson total "$total" \
    --argjson captured "$captured" \
    --argjson missed "$missed" \
    --argjson multi "$multi" \
    --argjson attack "$attack" \
    --argjson gaps "$gaps" \
    --argjson win_score "$(num_or_null "$win_q")" \
    --argjson lin_score "$(num_or_null "$lin_q")" \
    --arg confidence "$confidence" \
    '{
        generated_at: $generated_at,
        dataset: {
            total_events: ($win_events + $lin_events),
            by_platform: { windows: $win_events, linux: $lin_events },
            by_source_type: { windows: $win_by_src, linux: $lin_by_src },
            by_event_category: { windows: $win_by_cat, linux: $lin_by_cat }
        },
        detection_matrix_summary: {
            total_simulated_actions: $total,
            captured_actions: $captured,
            missed_actions: $missed,
            multi_source_detections: $multi
        },
        attack_coverage: {
            covered: {
                count: ($attack.covered | length),
                techniques: ($attack.covered | map(.technique) | unique),
                source_responsible: ($attack.covered | map({technique, platform, sources}))
            },
            partial: {
                count: ($attack.partial | length),
                techniques: ($attack.partial | map(.technique) | unique),
                source_responsible: ($attack.partial | map({technique, platform, sources}))
            },
            blind: {
                count: ($attack.blind | length),
                techniques: ($attack.blind | map(.technique) | unique)
            }
        },
        known_gaps: $gaps,
        quality_summary: {
            windows_score: $win_score,
            linux_score: $lin_score,
            handoff_confidence: $confidence
        }
    }' > "$OUT"

# ------------------------------ Console summary ------------------------------
echo "Windows events: $win_events"
echo "Linux events: $lin_events"
echo "Ground truth actions: $gt_actions"
echo "Detection matrix: $captured/$total captured"
echo "ATT&CK covered: $covered_cnt"
echo "ATT&CK partial: $partial_cnt"
echo "ATT&CK blind: $blind_cnt"
echo "Windows quality: ${win_q:-N/A}"
echo "Linux quality: ${lin_q:-N/A}"
echo "Confidence: $confidence"
echo "Report saved to: $OUT"
