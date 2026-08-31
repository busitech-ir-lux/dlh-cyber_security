#!/bin/bash

set -euo pipefail

# ============================================================
# TASK 3 - EVENT TYPE TAXONOMY
#
# Creates:
#   event_taxonomy.json
#   labeled_events.json
#
# labeled_events.json is NDJSON:
# one JSON event per line.
# ============================================================


# ============================================================
# PATHS
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

TAXONOMY_FILE="event_taxonomy.json"
LABELED_FILE="labeled_events.json"


# ============================================================
# BASIC CHECKS
# ============================================================

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required." >&2
    exit 1
fi

if [ ! -f "$DATA_FILE" ]; then
    echo "Error: enriched dataset not found: $DATA_FILE" >&2
    exit 1
fi

# Make sure the input contains valid JSON.
if ! jq -e . "$DATA_FILE" >/dev/null 2>&1; then
    echo "Error: enriched dataset contains invalid JSON." >&2
    exit 1
fi


# ============================================================
# TEMPORARY FILES
#
# We build the outputs in temporary files first.
# The real output files are replaced only after success.
# ============================================================

TMP_BASE=$(mktemp)
TMP_TAXONOMY=$(mktemp)
TMP_LABELED=$(mktemp)


cleanup()
{
    rm -f "$TMP_BASE" "$TMP_TAXONOMY" "$TMP_LABELED"
}

trap cleanup EXIT


# ============================================================
# CREATE TAXONOMY
#
# Every rule has:
#
#   source_type
#   match
#   label
#
# Simple values mean exact matching.
#
# A value such as:
#
#   {"regex": "..."}
#
# means match the field using a regular expression.
#
# Nested event_data fields use dot notation:
#
#   event_data.ParentImage
#
# More specific rules are placed before general rules because
# the first matching rule wins.
# ============================================================

cat > "$TMP_BASE" <<'JSON'
{
  "version": "1.0",
  "rules": [

    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4740
      },
      "label": "account_lockout"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_category": "authentication",
        "raw_message": {
          "regex": "(?i)account.*locked|pam_faillock"
        }
      },
      "label": "account_lockout"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4625
      },
      "label": "login_failure"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_category": "authentication",
        "action": "failed"
      },
      "label": "login_failure"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4634
      },
      "label": "logout"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_category": "authentication",
        "raw_message": {
          "regex": "(?i)session closed|logged out|logout"
        }
      },
      "label": "logout"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4624
      },
      "label": "login_success"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_category": "authentication",
        "action": "success"
      },
      "label": "login_success"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4672
      },
      "label": "privilege_escalation"
    },
    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4732
      },
      "label": "privilege_escalation"
    },
    {
      "source_type": "linux_text",
      "match": {
        "process_name": "sudo"
      },
      "label": "privilege_escalation"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 1,
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
        "event_data.ParentImage": {
          "regex": ".+"
        }
      },
      "label": "child_process_spawn"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4689
      },
      "label": "process_stop"
    },
    {
      "source_type": "windows_json",
      "match": {
        "event_id": 5,
        "source_channel": "Microsoft-Windows-Sysmon/Operational"
      },
      "label": "process_stop"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4688
      },
      "label": "process_start"
    },
    {
      "source_type": "windows_json",
      "match": {
        "event_id": 1,
        "source_channel": "Microsoft-Windows-Sysmon/Operational"
      },
      "label": "process_start"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_category": "process"
      },
      "label": "process_start"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4670
      },
      "label": "file_permission_change"
    },
    {
      "source_type": "linux_text",
      "match": {
        "raw_message": {
          "regex": "(?i)\\b(chmod|chown|fchmod|fchown)\\b"
        }
      },
      "label": "file_permission_change"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4663,
        "event_data.ObjectName": {
          "regex": "(?i)^(C:\\\\Windows\\\\System32\\\\config\\\\|C:\\\\Users\\\\[^\\\\]+\\\\NTUSER\\.DAT)"
        },
        "event_data.AccessList": {
          "regex": "(?i)ReadData|ReadAttributes|READ"
        }
      },
      "label": "file_read_sensitive"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_data.name": {
          "regex": "^/(etc/(passwd|shadow|group|sudoers)|etc/ssh/|root/\\.ssh/|home/[^/]+/\\.ssh/)"
        },
        "event_data.perm": {
          "regex": "r"
        }
      },
      "label": "file_read_sensitive"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 4663,
        "event_data.ObjectName": {
          "regex": "(?i)^(C:\\\\Windows\\\\System32\\\\config\\\\|C:\\\\Users\\\\[^\\\\]+\\\\NTUSER\\.DAT)"
        },
        "event_data.AccessList": {
          "regex": "(?i)WriteData|AppendData|WRITE"
        }
      },
      "label": "file_write_sensitive"
    },
    {
      "source_type": "windows_json",
      "match": {
        "event_id": 11,
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
        "event_data.TargetFilename": {
          "regex": "(?i)^(C:\\\\Windows\\\\System32\\\\config\\\\|C:\\\\Users\\\\[^\\\\]+\\\\NTUSER\\.DAT)"
        }
      },
      "label": "file_write_sensitive"
    },
    {
      "source_type": "linux_text",
      "match": {
        "event_data.name": {
          "regex": "^/(etc/(passwd|shadow|group|sudoers)|etc/ssh/|root/\\.ssh/|home/[^/]+/\\.ssh/)"
        },
        "event_data.perm": {
          "regex": "w|a"
        }
      },
      "label": "file_write_sensitive"
    },


    {
      "source_type": "firewall",
      "match": {
        "action": "BLOCK"
      },
      "label": "network_blocked"
    },
    {
      "source_type": "suricata",
      "match": {
        "action": {
          "regex": "(?i)block|blocked|drop|reject"
        }
      },
      "label": "network_blocked"
    },


    {
      "source_type": "suricata",
      "match": {
        "event_category": "network_alert"
      },
      "label": "network_alert"
    },


    {
      "source_type": "windows_json",
      "match": {
        "event_id": 3,
        "source_channel": "Microsoft-Windows-Sysmon/Operational"
      },
      "label": "network_connection_outbound"
    },
    {
      "source_type": "firewall",
      "match": {
        "event_data.direction": {
          "regex": "(?i)^out(bound)?$"
        }
      },
      "label": "network_connection_outbound"
    },


    {
      "source_type": "firewall",
      "match": {
        "event_data.direction": {
          "regex": "(?i)^in(bound)?$"
        }
      },
      "label": "network_connection_inbound"
    }

  ]
}
JSON


# ============================================================
# ADD RULES GROUPED BY CANONICAL LABEL
#
# The "rules" array keeps rule priority.
#
# The "labels" object makes the taxonomy easy for later scripts
# and humans to inspect:
#
#   labels.login_success
#   labels.process_start
#   labels.network_alert
#   ...
# ============================================================

jq '
    .labels = (
        reduce .rules[] as $rule
        (
            {};
            .[$rule.label] =
                ((.[$rule.label] // []) + [$rule])
        )
    )
' "$TMP_BASE" > "$TMP_TAXONOMY"


# ============================================================
# APPLY TAXONOMY
#
# field_value:
#   Reads both normal fields such as event_id and nested fields
#   such as event_data.ParentImage.
#
# criterion_matches:
#   Supports exact equality and regex matching.
#
# rule_matches:
#   All fields in a rule must match.
#
# The first matching rule becomes canonical_label.
# If no rule matches, the record becomes "unlabeled".
# ============================================================

jq -c \
    --slurpfile taxonomy "$TMP_TAXONOMY" '

    def field_value($event; $field):
        try (
            $event
            | getpath($field | split("."))
        )
        catch null;


    def criterion_matches($event; $field; $expected):

        field_value($event; $field) as $actual

        | if (
            ($expected | type) == "object"
            and
            ($expected | has("regex"))
          )

          then
              (
                  ($actual // "" | tostring)
                  | test($expected.regex)
              )

          else
              $actual == $expected

          end;


    def rule_matches($event; $rule):

        (
            ($event.source_type // "")
            ==
            $rule.source_type
        )

        and

        all(
            $rule.match | to_entries[];

            criterion_matches(
                $event;
                .key;
                .value
            )
        );


    . as $event

    | (
        [
            $taxonomy[0].rules[]

            | select(
                rule_matches(
                    $event;
                    .
                )
            )

            | .label
        ][0]

        // "unlabeled"
      ) as $label

    | . + {
        canonical_label: $label
      }

' "$DATA_FILE" > "$TMP_LABELED"


# ============================================================
# CALCULATE SUMMARY COUNTS
# ============================================================

RULE_COUNT=$(
    jq '.rules | length' "$TMP_TAXONOMY"
)


LABELED_COUNT=$(
    jq -r '
        select(.canonical_label != "unlabeled")
        | 1
    ' "$TMP_LABELED" |
        wc -l |
        tr -d ' '
)


UNLABELED_COUNT=$(
    jq -r '
        select(.canonical_label == "unlabeled")
        | 1
    ' "$TMP_LABELED" |
        wc -l |
        tr -d ' '
)


# ============================================================
# WRITE FINAL FILES
#
# mv replaces old outputs instead of appending to them.
# Therefore running the script twice gives the same result.
# ============================================================

mv "$TMP_TAXONOMY" "$TAXONOMY_FILE"
mv "$TMP_LABELED" "$LABELED_FILE"

# These files have already been moved.
TMP_TAXONOMY=""
TMP_LABELED=""


# ============================================================
# PRINT EXPECTED SUMMARY
# ============================================================

printf "taxonomy rules         : %s\n" "$RULE_COUNT"
printf "records labeled        : %s\n" "$LABELED_COUNT"
printf "records unlabeled      : %s\n" "$UNLABELED_COUNT"

printf "canonical label distribution (top 10):\n"


jq -r '
    select(.canonical_label != "unlabeled")
    | .canonical_label
' "$LABELED_FILE" |

    sort |

    uniq -c |

    sort -nr |

    awk '
        NR <= 10 {
            count=$1

            $1=""
            sub(/^ /, "")

            printf "  %-26s %d\n", $0, count
        }
    '


printf "event_taxonomy.json written\n"
printf "labeled_events.json written\n"
