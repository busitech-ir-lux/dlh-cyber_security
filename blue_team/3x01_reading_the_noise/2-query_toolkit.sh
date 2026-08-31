#!/bin/bash

set -euo pipefail

# ============================================================
# 2-query_toolkit.sh
#
# Reusable CLI query toolkit for enriched MedDefense events.
#
# Input:
#   $HANDOFF_DIR/data/enriched_events.json
#
# The dataset is NDJSON:
#   one JSON event per line.
# ============================================================


# ============================================================
# CONFIGURATION
#
# Use HANDOFF_DIR if it is already set.
# Otherwise use the required project default.
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"


# ============================================================
# HELP
# ============================================================

show_help()
{
    cat <<'EOF'
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message
EOF
}


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi


# A verb is required.
if [ $# -lt 1 ]; then
    show_help
    exit 1
fi


VERB="$1"
shift


# Help does not need the dataset to exist.
if [ "$VERB" = "help" ]; then
    show_help
    exit 0
fi


# Make sure the handoff dataset exists.
if [ ! -f "$DATA_FILE" ]; then
    echo "Error: dataset not found: $DATA_FILE" >&2
    exit 1
fi


# ============================================================
# DEFAULT OPTIONS
#
# Empty filter values mean:
#   do not filter on this field.
# ============================================================

SOURCE=""
HOST=""
FROM=""
TO=""
CATEGORY=""

FIELD=""
LIMIT=""
BUCKET=""


# ============================================================
# READ COMMAND-LINE OPTIONS
#
# Filters can be supplied in any order and combination.
#
# Examples:
#
#   --source windows_json
#   --host ehr-srv-01
#   --category authentication
#
# They can also be combined.
# ============================================================

while [ $# -gt 0 ]; do

    case "$1" in

        --source)
            if [ $# -lt 2 ]; then
                echo "Error: --source needs a value." >&2
                exit 1
            fi

            SOURCE="$2"
            shift 2
            ;;


        --host)
            if [ $# -lt 2 ]; then
                echo "Error: --host needs a value." >&2
                exit 1
            fi

            HOST="$2"
            shift 2
            ;;


        --from)
            if [ $# -lt 2 ]; then
                echo "Error: --from needs a value." >&2
                exit 1
            fi

            FROM="$2"
            shift 2
            ;;


        --to)
            if [ $# -lt 2 ]; then
                echo "Error: --to needs a value." >&2
                exit 1
            fi

            TO="$2"
            shift 2
            ;;


        --category)
            if [ $# -lt 2 ]; then
                echo "Error: --category needs a value." >&2
                exit 1
            fi

            CATEGORY="$2"
            shift 2
            ;;


        --field)
            if [ $# -lt 2 ]; then
                echo "Error: --field needs a value." >&2
                exit 1
            fi

            FIELD="$2"
            shift 2
            ;;


        --limit)
            if [ $# -lt 2 ]; then
                echo "Error: --limit needs a value." >&2
                exit 1
            fi

            LIMIT="$2"
            shift 2
            ;;


        --bucket)
            if [ $# -lt 2 ]; then
                echo "Error: --bucket needs a value." >&2
                exit 1
            fi

            BUCKET="$2"
            shift 2
            ;;


        *)
            echo "Error: unknown option: $1" >&2
            exit 1
            ;;

    esac

done


# ============================================================
# REUSABLE EVENT FILTER
#
# This is the important reusable part of the toolkit.
#
# Every verb uses the same filtering logic.
#
# The project schema defines:
#
#   source     -> source_type
#   host       -> hostname
#   category   -> event_category
#   time       -> timestamp
#
# Empty variables disable that particular filter.
# ============================================================

FILTER_JQ='
    select(
        ($source == "" or .source_type == $source)
        and
        ($host == "" or .hostname == $host)
        and
        ($from == "" or .timestamp >= $from)
        and
        ($to == "" or .timestamp <= $to)
        and
        ($category == "" or .event_category == $category)
    )
'


# ============================================================
# RUN THE COMMON FILTER
#
# jq -c keeps every matching JSON object on one line,
# producing NDJSON output.
# ============================================================

run_filter()
{
    jq -c \
        --arg source "$SOURCE" \
        --arg host "$HOST" \
        --arg from "$FROM" \
        --arg to "$TO" \
        --arg category "$CATEGORY" \
        "$FILTER_JQ" \
        "$DATA_FILE"
}


# ============================================================
# COMMAND DISPATCH
# ============================================================

case "$VERB" in


    # --------------------------------------------------------
    # FILTER
    #
    # Print complete matching JSON records.
    # --------------------------------------------------------

    filter)

        run_filter

        ;;


    # --------------------------------------------------------
    # COUNT
    #
    # Count records after applying any filters.
    # --------------------------------------------------------

    count)

        run_filter |
            wc -l |
            tr -d ' '

        ;;


    # --------------------------------------------------------
    # TOP
    #
    # Example:
    #
    #   top --field user --limit 10
    #
    # Output:
    #
    #   alice    24
    #   bob      18
    #
    # Nested fields such as event_data.Image also work.
    # --------------------------------------------------------

    top)

        if [ -z "$FIELD" ]; then
            echo "Error: top requires --field <name>." >&2
            exit 1
        fi


        if [ -z "$LIMIT" ]; then
            echo "Error: top requires --limit <n>." >&2
            exit 1
        fi


        # Limit must be a positive integer.
        if ! [[ "$LIMIT" =~ ^[1-9][0-9]*$ ]]; then
            echo "Error: --limit must be a positive integer." >&2
            exit 1
        fi


        run_filter |

            jq -r --arg field "$FIELD" '
                getpath($field | split("."))
                | select(. != null)
                | tostring
            ' |

            sort |

            uniq -c |

            sort -nr |

            awk -v limit="$LIMIT" '
                NR <= limit {
                    count=$1

                    $1=""

                    sub(/^ /, "")

                    print $0 "\t" count
                }
            '

        ;;


    # --------------------------------------------------------
    # DISTINCT
    #
    # Print each different value once.
    #
    # Example:
    #
    #   distinct --field hostname
    # --------------------------------------------------------

    distinct)

        if [ -z "$FIELD" ]; then
            echo "Error: distinct requires --field <name>." >&2
            exit 1
        fi


        run_filter |

            jq -r --arg field "$FIELD" '
                getpath($field | split("."))
                | select(. != null)
                | tostring
            ' |

            sort -u

        ;;


    # --------------------------------------------------------
    # WINDOW
    #
    # Bucket timestamp values by hour or day.
    #
    # Examples:
    #
    #   window --field timestamp --bucket hour
    #   window --field timestamp --bucket day
    # --------------------------------------------------------

    window)

        if [ -z "$FIELD" ]; then
            echo "Error: window requires --field <name>." >&2
            exit 1
        fi


        if [ "$BUCKET" != "hour" ] &&
           [ "$BUCKET" != "day" ]; then

            echo "Error: window requires --bucket <hour|day>." >&2
            exit 1

        fi


        run_filter |

            jq -r \
                --arg field "$FIELD" \
                --arg bucket "$BUCKET" '
                
                getpath($field | split("."))

                | select(
                    type == "string"
                    and length >= 10
                )

                | if $bucket == "hour"
                  then
                      .[0:13] + ":00:00Z"
                  else
                      .[0:10]
                  end
            ' |

            sort |

            uniq -c |

            awk '
                {
                    count=$1

                    $1=""

                    sub(/^ /, "")

                    print $0 "\t" count
                }
            '

        ;;


    # --------------------------------------------------------
    # UNKNOWN VERB
    # --------------------------------------------------------

    *)

        echo "Error: unknown verb: $VERB" >&2
        show_help >&2
        exit 1

        ;;

esac
