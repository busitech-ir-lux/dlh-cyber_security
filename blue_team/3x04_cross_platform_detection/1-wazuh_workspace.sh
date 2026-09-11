#!/bin/bash

# Task 1 - Prepare the Wazuh evidence workspace

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

INDEX_META="$WAZUH_EXPORTS/index_metadata.json"
FIELD_MAP="$WAZUH_EXPORTS/field_mapping.json"
CREDENTIALS="$ASSETS_DIR/dashboard_credentials.json"
QUERY_RESULTS="$ASSETS_DIR/query_results"

WORKSPACE="workspace"
OUTPUT="$WORKSPACE/workspace_init.json"

FAIL=0


# ------------------------------------------------------------
# 1. Check main required files
# ------------------------------------------------------------

for file in "$INDEX_META" "$FIELD_MAP" "$CREDENTIALS"
do
    if [ ! -s "$file" ]; then
        echo "ERROR: missing or empty file: $file" >&2
        FAIL=1
    fi
done

if [ ! -d "$QUERY_RESULTS" ]; then
    echo "ERROR: missing directory: $QUERY_RESULTS" >&2
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi


# ------------------------------------------------------------
# 2. Read index metadata
# ------------------------------------------------------------

INDEX_NAME=$(jq -r '
    .index_name //
    .index //
    .name //
    empty
' "$INDEX_META")

TOTAL_DOCUMENTS=$(jq -r '
    .total_documents //
    .document_count //
    .documents //
    .total //
    empty
' "$INDEX_META")

EARLIEST=$(jq -r '
    .time_range.earliest //
    .earliest //
    .min_timestamp //
    empty
' "$INDEX_META")

LATEST=$(jq -r '
    .time_range.latest //
    .latest //
    .max_timestamp //
    empty
' "$INDEX_META")

if [ -z "$INDEX_NAME" ] ||
   [ -z "$TOTAL_DOCUMENTS" ] ||
   [ -z "$EARLIEST" ] ||
   [ -z "$LATEST" ]; then
    echo "ERROR: could not read required values from index_metadata.json" >&2
    exit 1
fi


# ------------------------------------------------------------
# 3. Read dashboard username
# ------------------------------------------------------------

USERNAME=$(jq -r '
    .username //
    .user //
    empty
' "$CREDENTIALS")

if [ -z "$USERNAME" ]; then
    echo "ERROR: username not found in dashboard_credentials.json" >&2
    exit 1
fi


# ------------------------------------------------------------
# 4. Verify Wazuh export files
# ------------------------------------------------------------

EXPORT_OK=1
VERIFIED=0

# Metadata files
for file in field_mapping.json index_metadata.json
do
    if [ -s "$WAZUH_EXPORTS/$file" ]; then
        VERIFIED=$((VERIFIED + 1))
    else
        echo "ERROR: missing $WAZUH_EXPORTS/$file" >&2
        EXPORT_OK=0
    fi
done


# Four search-result files
SEARCH_COUNT=$(find "$WAZUH_EXPORTS" \
    -maxdepth 1 \
    -type f \
    -name '*_search_results.json' |
    wc -l)

if [ "$SEARCH_COUNT" -eq 4 ]; then
    VERIFIED=$((VERIFIED + SEARCH_COUNT))
else
    echo "ERROR: expected 4 search result files, found $SEARCH_COUNT" >&2
    EXPORT_OK=0
fi


# Four dashboard-trace files
TRACE_COUNT=$(find "$WAZUH_EXPORTS" \
    -maxdepth 1 \
    -type f \
    -name '*dashboard*trace*.json' |
    wc -l)

if [ "$TRACE_COUNT" -eq 4 ]; then
    VERIFIED=$((VERIFIED + TRACE_COUNT))
else
    echo "ERROR: expected 4 dashboard trace files, found $TRACE_COUNT" >&2
    EXPORT_OK=0
fi


# Query-result files
QUERY_COUNT=$(find "$QUERY_RESULTS" \
    -maxdepth 1 \
    -type f \
    -name '*.json' |
    wc -l)

if [ "$QUERY_COUNT" -gt 0 ]; then
    VERIFIED=$((VERIFIED + QUERY_COUNT))
else
    echo "ERROR: no JSON files found in $QUERY_RESULTS" >&2
    EXPORT_OK=0
fi


if [ "$EXPORT_OK" -ne 1 ]; then
    exit 1
fi


# ------------------------------------------------------------
# 5. Load and print field mappings
# ------------------------------------------------------------

MAPPING_COUNT=$(jq '
    (.mappings // .field_mappings // .)
    | length
' "$FIELD_MAP")


# ------------------------------------------------------------
# 6. Print workspace information
# ------------------------------------------------------------

printf '%-14s: wazuh_export (no live dashboard required)\n' "mode"
printf '%-14s: %s\n' "index" "$INDEX_NAME"
printf '%-14s: %s\n' "documents" "$(printf "%'d" "$TOTAL_DOCUMENTS")"
printf '%-14s: %s to %s\n' "time range" "$EARLIEST" "$LATEST"
printf '%-14s: %s (from dashboard_credentials.json)\n' \
    "credentials" "$USERNAME"

printf '%-14s: loaded (%s mappings)\n' \
    "field mapping" "$MAPPING_COUNT"


# Print first 10 mappings as two columns
jq -r '
    (.mappings // .field_mappings // .)
    | to_entries[:10][]
    | "\(.key)\t\(.value)"
' "$FIELD_MAP" |
while IFS=$'\t' read -r NORMALIZED WAZUH
do
    printf '  %-12s -> %s\n' "$NORMALIZED" "$WAZUH"
done


printf '%-14s: all present (%s files verified)\n' \
    "export files" "$VERIFIED"


# ------------------------------------------------------------
# 7. Write workspace/workspace_init.json
# ------------------------------------------------------------

mkdir -p "$WORKSPACE"

INITIALIZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg mode "wazuh_export" \
    --arg index "$INDEX_NAME" \
    --argjson documents "$TOTAL_DOCUMENTS" \
    --arg earliest "$EARLIEST" \
    --arg latest "$LATEST" \
    --arg initialized "$INITIALIZED_AT" \
    '{
        mode: $mode,
        source_index: $index,
        total_documents: $documents,
        time_range: {
            earliest: $earliest,
            latest: $latest
        },
        export_files_verified: true,
        field_mapping_loaded: true,
        initialized_at: $initialized
    }' > "$OUTPUT"

echo "workspace_init.json written"

exit 0
