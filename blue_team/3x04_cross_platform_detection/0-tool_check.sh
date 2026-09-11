#!/bin/bash

# 3x04 - Check required tools, directories, evidence, and Wazuh exports

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

FAIL=0


# ------------------------------------------------------------
# Helper for failed checks
# ------------------------------------------------------------

fail() {
    printf '%-14s: failed (%s)\n' "$1" "$2"
    FAIL=1
}


# ------------------------------------------------------------
# 1. Check required CLI tools
# ------------------------------------------------------------

check_tool() {
    tool="$1"
    version=""

    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool" "not found on PATH"
        return
    fi

    case "$tool" in
        jq)
            version=$(jq --version 2>/dev/null | sed 's/^jq-//')
            ;;

        yq)
            version=$(yq --version 2>/dev/null |
                grep -oE 'v?[0-9]+(\.[0-9]+)+' |
                tail -1 |
                sed 's/^v//')
            ;;

        python3)
            version=$(python3 --version 2>&1 | awk '{print $2}')
            ;;

        sigma)
            version=$(sigma version 2>&1 |
                grep -oE '[0-9]+(\.[0-9]+)+' |
                head -1)
            ;;

        xmllint)
            version=$(xmllint --version 2>&1 |
                grep -oE 'version [0-9]+' |
                head -1 |
                awk '{print $2}')
            ;;

        curl)
            version=$(curl --version 2>/dev/null |
                head -1 |
                awk '{print $2}')
            ;;
    esac

    if [ -z "$version" ]; then
        fail "$tool" "could not read version"
    else
        printf '%-14s: %s\n' "$tool" "$version"
    fi
}


for tool in jq yq python3 sigma xmllint curl
do
    check_tool "$tool"
done


# ------------------------------------------------------------
# 2. Check required upstream directories
# ------------------------------------------------------------

check_dir() {
    name="$1"
    path="$2"

    if [ ! -d "$path" ]; then
        fail "$name" "directory not found: $path"
    fi
}

check_dir "HANDOFF_DIR" "$HANDOFF_DIR"
check_dir "BASELINE_PKG" "$BASELINE_PKG"
check_dir "CATALOG_DIR" "$CATALOG_DIR"
check_dir "TRIAGE_PKG" "$TRIAGE_PKG"
check_dir "ASSETS_DIR" "$ASSETS_DIR"


# ------------------------------------------------------------
# 3. Check enriched_events.json
# ------------------------------------------------------------

ENRICHED="$HANDOFF_DIR/data/enriched_events.json"

if [ -s "$ENRICHED" ]; then
    printf '%-14s: ok (enriched_events.json present)\n' "handoff"
else
    fail "handoff" "enriched_events.json missing or empty"
fi


# ------------------------------------------------------------
# 4. Check Sigma rule catalog
# ------------------------------------------------------------

SIGMA_DIR="$CATALOG_DIR/rules/sigma"

if [ -d "$SIGMA_DIR" ]; then

    SIGMA_COUNT=$(find "$SIGMA_DIR" \
        -maxdepth 1 \
        -type f \
        \( -name '*.yml' -o -name '*.yaml' \) |
        wc -l)

    printf '%-14s: ok (%s sigma rules)\n' \
        "catalog" "$SIGMA_COUNT"

else
    fail "catalog" "rules/sigma directory missing"
fi


# ------------------------------------------------------------
# 5. Check Wazuh exports
# ------------------------------------------------------------

WAZUH_OK=1

# Required metadata files
for file in field_mapping.json index_metadata.json
do
    if [ ! -s "$WAZUH_EXPORTS/$file" ]; then
        fail "wazuh_exports" "$file missing or empty"
        WAZUH_OK=0
    fi
done


# Count scenario search result files
SEARCH_COUNT=0

if [ -d "$WAZUH_EXPORTS" ]; then
    SEARCH_COUNT=$(find "$WAZUH_EXPORTS" \
        -maxdepth 1 \
        -type f \
        -name '*_search_results.json' |
        wc -l)
fi

if [ "$SEARCH_COUNT" -ne 4 ]; then
    fail "wazuh_exports" \
        "expected 4 search_results files, found $SEARCH_COUNT"
    WAZUH_OK=0
fi


# Expected output also requires four dashboard traces
TRACE_COUNT=0

if [ -d "$WAZUH_EXPORTS" ]; then
    TRACE_COUNT=$(find "$WAZUH_EXPORTS" \
        -maxdepth 1 \
        -type f \
        -name '*dashboard*trace*.json' |
        wc -l)
fi

if [ "$TRACE_COUNT" -ne 4 ]; then
    fail "wazuh_exports" \
        "expected 4 dashboard trace files, found $TRACE_COUNT"
    WAZUH_OK=0
fi


if [ "$WAZUH_OK" -eq 1 ]; then
    printf '%-14s: ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)\n' \
        "wazuh_exports"
fi


# ------------------------------------------------------------
# 6. Check anchor scenario
# ------------------------------------------------------------

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"

if [ ! -s "$ANCHOR_FILE" ]; then

    fail "anchor" "anchor_event.json missing or empty"

elif [ ! -s "$ENRICHED" ]; then

    fail "anchor" "enriched_events.json unavailable"

else

    # Read anchor values
    TARGET_HOST=$(jq -r \
        '.target_host // empty' \
        "$ANCHOR_FILE" 2>/dev/null)

    START_TIME=$(jq -r \
        '.time_window.start //
         .time_window.from //
         .time_window[0] //
         empty' \
        "$ANCHOR_FILE" 2>/dev/null)

    END_TIME=$(jq -r \
        '.time_window.end //
         .time_window.to //
         .time_window[1] //
         empty' \
        "$ANCHOR_FILE" 2>/dev/null)


    if [ -z "$TARGET_HOST" ] ||
       [ -z "$START_TIME" ] ||
       [ -z "$END_TIME" ]; then

        fail "anchor" "could not read target_host/time_window"

    else

        # Works with either a JSON array or newline-separated JSON objects.
        # Look for the target host inside the required time window.
        MATCH=$(jq -r \
            --arg host "$TARGET_HOST" \
            --arg start "$START_TIME" \
            --arg end "$END_TIME" '

            if type == "array" then .[] else . end

            |

            (
                .target_host? //
                .hostname? //
                .host_name? //
                .computer_name? //
                .agent.name? //
                .host.name? //
                (if (.host? | type) == "string"
                 then .host
                 else empty
                 end) //
                ""
            ) as $event_host

            |

            (
                .["@timestamp"]? //
                .timestamp? //
                .event_time? //
                (if (.time? | type) == "string"
                 then .time
                 else empty
                 end) //
                ""
            ) as $event_time

            |

            select(
                $event_host == $host and
                $event_time >= $start and
                $event_time <= $end
            )

            | "match"

        ' "$ENRICHED" 2>/dev/null |
        head -1)


        if [ "$MATCH" = "match" ]; then

            printf '%-14s: ok (%s matched in enriched_events.json)\n' \
                "anchor" "$TARGET_HOST"

        else

            fail "anchor" \
                "$TARGET_HOST not found inside anchor time window"

        fi
    fi
fi


# ------------------------------------------------------------
# 7. Final result
# ------------------------------------------------------------

if [ "$FAIL" -ne 0 ]; then
    printf '%-14s: failed\n' "all checks"
    exit 1
fi

printf '%-14s: passed\n' "all checks"
exit 0
