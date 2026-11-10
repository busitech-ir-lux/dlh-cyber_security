#!/bin/bash
set -euo pipefail
state=./tmp/rtest_state
log=./recovery_test_log.txt
mkdir -p "$state"
exec 9>"$state/lock"
flock -x 9
if [[ $# == 1 && $1 == SUMMARY ]]; then
    mode=SUMMARY
    name=SUMMARY
elif [[ $# == 2 ]]; then
    name=$1
    mode=$2
else
    echo 'Usage: recovery_timer.sh "step name" START|PASS|FAIL; recovery_timer.sh SUMMARY' >&2
    exit 2
fi
[[ $name != *$'\n'* && $name != *$'\t'* && -n $name ]] || exit 2
now=$(date +%s%N)
clock=$(date '+%H:%M:%S')
case "$mode" in
START)
    [[ ! -f $state/active ]] || { echo 'A step is already active.' >&2; exit 2; }
    [[ ! -f $state/summary ]] || { echo 'Run finished; archive this run before starting another.' >&2; exit 2; }
    if [[ ! -f $state/first ]]; then
        [[ ! -e $log ]] || { echo 'Existing log without state; use a new run directory.' >&2; exit 2; }
        printf '%s\n' "$now" > "$state/first"
        printf '0\n' > "$state/count"
        printf '0\n' > "$state/failures"
    fi
    count=$(<"$state/count")
    printf '%s\n' "$((count + 1))" > "$state/count"
    printf '%s\n%s\n%s\n' "$name" "$now" "$clock" > "$state/active"
    ;;
PASS|FAIL)
    [[ -f $state/active ]] || { echo 'No active step.' >&2; exit 2; }
    mapfile -t active < "$state/active"
    [[ ${active[0]} == "$name" ]] || { echo 'Step name does not match.' >&2; exit 2; }
    elapsed=$(((now - active[1]) / 1000000000))
    ((elapsed >= 0)) || { echo 'Clock moved backwards; timing invalid.' >&2; exit 1; }
    count=$(<"$state/count")
    printf '[STEP %02d] %-32s | Start: %s | End: %s | Duration: %dm %02ds | %s\n' \
      "$count" "$name" "${active[2]}" "$clock" "$((elapsed/60))" "$((elapsed%60))" "$mode" | tee -a "$log"
    if [[ $mode == FAIL ]]; then
        failures=$(<"$state/failures")
        printf '%s\n' "$((failures + 1))" > "$state/failures"
    fi
    printf '%s\n' "$now" > "$state/last"
    rm -- "$state/active"
    ;;
SUMMARY)
    [[ -f $state/first && -f $state/last && ! -f $state/active ]] || {
        echo 'Run missing completed steps or has an active step.' >&2; exit 2;
    }
    if [[ ! -f $state/summary ]]; then
        first=$(<"$state/first")
        last=$(<"$state/last")
        ns=$((last-first))
        ((ns >= 0)) || exit 1
        # Round upwards so a fractional second beyond the RTO cannot pass.
        seconds=$(((ns+999999999)/1000000000))
        rto=PASS
        overall=PASS
        ((ns <= 1800000000000)) || rto=FAIL
        failures=$(<"$state/failures")
        [[ $rto == PASS && $failures == 0 ]] || overall=FAIL
        {
            printf 'Total elapsed: %dm %02ds (%s ns; rounded up to seconds)\n' "$((seconds/60))" "$((seconds%60))" "$ns"
            printf 'RTO (30 minutes): %s\nCompleted step failures: %s\nOverall timer result: %s\n' "$rto" "$failures" "$overall"
        } > "$state/summary"
    fi
    cat "$state/summary"
    ;;
*) echo 'Unknown status.' >&2; exit 2 ;;
esac
