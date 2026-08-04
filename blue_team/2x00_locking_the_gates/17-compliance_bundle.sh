#!/bin/bash

# 17-compliance_bundle.sh - Machine-Readable Compliance Evidence Bundle
#
# Reads six project evidence files and creates:
#   compliance_report.json
#
# Usage:
#   ./17-compliance_bundle.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CIS_PROFILE="$SCRIPT_DIR/cis_profile.json"
GAP_ANALYSIS="$SCRIPT_DIR/gap_analysis.json"
REMEDIATION_QUEUE="$SCRIPT_DIR/remediation_queue.json"
AUDIT_VALIDATION="$SCRIPT_DIR/audit_validation.json"
VALIDATION_RESULTS="$SCRIPT_DIR/validation_results.json"
HARDENING_IMPROVEMENT="$SCRIPT_DIR/hardening_improvement.json"

OUTPUT_FILE="$SCRIPT_DIR/compliance_report.json"

EVIDENCE_FILES=(
    "$CIS_PROFILE"
    "$GAP_ANALYSIS"
    "$REMEDIATION_QUEUE"
    "$AUDIT_VALIDATION"
    "$VALIDATION_RESULTS"
    "$HARDENING_IMPROVEMENT"
)


# ---------------------------------------------------------
# Check required commands
# ---------------------------------------------------------

for command_name in jq hostname date; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Missing required command: $command_name"
        exit 1
    fi
done


# ---------------------------------------------------------
# Check evidence files
# ---------------------------------------------------------

for evidence_file in "${EVIDENCE_FILES[@]}"; do
    if [[ ! -f "$evidence_file" ]]; then
        echo "Missing evidence file: $(basename "$evidence_file")"
        exit 1
    fi

    if ! jq empty "$evidence_file" >/dev/null 2>&1; then
        echo "Invalid JSON file: $(basename "$evidence_file")"
        exit 1
    fi
done


# ---------------------------------------------------------
# System identity
# ---------------------------------------------------------

HOSTNAME_VALUE=$(hostname)
HARDENING_DATE=$(date --iso-8601=seconds)

if [[ -f /etc/os-release ]]; then
    OS_NAME=$(
        awk -F= '
            /^PRETTY_NAME=/ {
                gsub(/^"|"$/, "", $2)
                print $2
                exit
            }
        ' /etc/os-release
    )
else
    OS_NAME="unknown"
fi

KERNEL_VERSION=$(uname -r)


# ---------------------------------------------------------
# Create the compliance bundle
# ---------------------------------------------------------

jq -n \
    --arg hostname "$HOSTNAME_VALUE" \
    --arg operating_system "$OS_NAME" \
    --arg kernel "$KERNEL_VERSION" \
    --arg hardening_date "$HARDENING_DATE" \
    --slurpfile cis "$CIS_PROFILE" \
    --slurpfile gaps "$GAP_ANALYSIS" \
    --slurpfile queue "$REMEDIATION_QUEUE" \
    --slurpfile audit "$AUDIT_VALIDATION" \
    --slurpfile validation "$VALIDATION_RESULTS" \
    --slurpfile improvement "$HARDENING_IMPROVEMENT" \
    '
    # -----------------------------------------------------
    # Normalize source documents
    # -----------------------------------------------------

    ($cis[0]) as $cis_data |
    ($gaps[0]) as $gap_data |
    ($queue[0]) as $queue_data |
    ($audit[0]) as $audit_data |
    ($validation[0]) as $validation_data |
    ($improvement[0]) as $improvement_data |

    # -----------------------------------------------------
    # Read selected controls
    # -----------------------------------------------------

    (
        $cis_data.controls //
        $cis_data.selected_controls //
        $cis_data.safeguards //
        $cis_data.profile //
        []
    ) as $selected_controls |

    # -----------------------------------------------------
    # Read remediation queue
    # -----------------------------------------------------

    (
        $queue_data.remediation_queue //
        $queue_data.remediations //
        $queue_data.controls //
        $queue_data //
        []
    ) as $remediation_items |

    # -----------------------------------------------------
    # Read gap analysis
    # -----------------------------------------------------

    (
        $gap_data.gaps //
        $gap_data.controls //
        $gap_data.findings //
        $gap_data //
        []
    ) as $gap_items |

    # -----------------------------------------------------
    # Read validation results
    # -----------------------------------------------------

    (
        $validation_data.results //
        $validation_data.controls //
        $validation_data.checks //
        $validation_data //
        []
    ) as $validation_items |

    # -----------------------------------------------------
    # Read audit validation results
    # -----------------------------------------------------

    (
        $audit_data.results //
        $audit_data.tests //
        $audit_data.controls //
        $audit_data //
        []
    ) as $audit_items |

    # -----------------------------------------------------
    # Selected controls
    # -----------------------------------------------------

    (
        $selected_controls
        | if type == "array" then . else [] end
    ) as $selected |

    # -----------------------------------------------------
    # Remediated controls
    # -----------------------------------------------------

    (
        $remediation_items
        | if type == "array" then
            [
                .[]
                | select(
                    (
                        .status //
                        .remediation_status //
                        .state //
                        ""
                    )
                    | ascii_downcase
                    | . == "completed"
                      or . == "remediated"
                      or . == "implemented"
                      or . == "fixed"
                      or . == "closed"
                )
            ]
          else
            []
          end
    ) as $remediated |

    # -----------------------------------------------------
    # Verified controls
    # -----------------------------------------------------

    (
        [
            (
                $validation_items
                | if type == "array" then .[] else empty end
            ),
            (
                $audit_items
                | if type == "array" then .[] else empty end
            )
        ]
        | [
            .[]
            | select(
                (
                    .status //
                    .result //
                    .state //
                    ""
                )
                | ascii_downcase
                | . == "pass"
                  or . == "passed"
                  or . == "verified"
                  or . == "compliant"
                  or . == "success"
            )
        ]
        | unique_by(
            .control_id //
            .id //
            .control //
            .name //
            tostring
        )
    ) as $verified |

    # -----------------------------------------------------
    # Deviations and unresolved controls
    # -----------------------------------------------------

    (
        $gap_items
        | if type == "array" then
            [
                .[]
                | select(
                    (
                        .status //
                        .state //
                        .compliance_status //
                        ""
                    )
                    | ascii_downcase
                    | . == "non_compliant"
                      or . == "partially_compliant"
                      or . == "not_remediated"
                      or . == "accepted"
                      or . == "deviation"
                      or . == "unresolved"
                )
            ]
          else
            []
          end
    ) as $unresolved |

    (
        $unresolved
        | map({
            control_id:
                (
                    .control_id //
                    .id //
                    .control //
                    "UNKNOWN"
                ),

            reason:
                (
                    .reason //
                    .deviation_reason //
                    .finding //
                    .description //
                    "Reason not documented"
                ),

            risk_accepted:
                (
                    .risk_accepted //
                    .accepted_risk //
                    .risk //
                    "Risk acceptance not documented"
                ),

            compensating_control:
                (
                    .compensating_control //
                    .compensating_controls //
                    .mitigation //
                    "Compensating control not documented"
                ),

            owner:
                (
                    .owner //
                    .risk_owner //
                    .assigned_to //
                    "Owner not documented"
                )
        })
    ) as $deviations |

    # -----------------------------------------------------
    # Counts and compliance percentage
    # -----------------------------------------------------

    ($selected | length) as $selected_count |
    ($remediated | length) as $remediated_count |
    ($verified | length) as $verified_count |
    ($deviations | length) as $deviation_count |

    (
        if $selected_count > 0 then
            (($verified_count / $selected_count) * 100)
        else
            0
        end
    ) as $compliance_percentage |

    # -----------------------------------------------------
    # Residual Lynis findings
    # -----------------------------------------------------

    (
        $improvement_data.remaining_findings //
        $improvement_data.residual_findings //
        []
    ) as $residual_findings |

    (
        $improvement_data.remaining_count //
        $improvement_data.residual_count //
        ($residual_findings | length)
    ) as $residual_count |

    # -----------------------------------------------------
    # Final compliance report
    # -----------------------------------------------------

    {
        system_identity: {
            hostname: $hostname,
            operating_system: $operating_system,
            kernel: $kernel
        },

        hardening_date: $hardening_date,

        controls: {
            selected: $selected,
            remediated: $remediated,
            verified: $verified,
            unresolved: $unresolved
        },

        deviations: $deviations,

        compensating_controls: (
            $deviations
            | map({
                control_id: .control_id,
                compensating_control: .compensating_control,
                owner: .owner
            })
        ),

        residual_lynis_findings: $residual_findings,

        summary: {
            selected_count: $selected_count,
            remediated_count: $remediated_count,
            verified_count: $verified_count,
            unresolved_count: ($unresolved | length),
            deviation_count: $deviation_count,
            residual_findings_count: $residual_count,
            final_compliance_percentage:
                ($compliance_percentage * 10 | round / 10)
        },

        evidence_files_used: [
            "cis_profile.json",
            "gap_analysis.json",
            "remediation_queue.json",
            "audit_validation.json",
            "validation_results.json",
            "hardening_improvement.json"
        ]
    }
    ' > "$OUTPUT_FILE"


# ---------------------------------------------------------
# Read summary values from the final report
# ---------------------------------------------------------

EVIDENCE_COUNT=$(
    jq '.evidence_files_used | length' "$OUTPUT_FILE"
)

SELECTED_COUNT=$(
    jq '.summary.selected_count' "$OUTPUT_FILE"
)

REMEDIATED_COUNT=$(
    jq '.summary.remediated_count' "$OUTPUT_FILE"
)

VERIFIED_COUNT=$(
    jq '.summary.verified_count' "$OUTPUT_FILE"
)

DEVIATION_COUNT=$(
    jq '.summary.deviation_count' "$OUTPUT_FILE"
)

COMPLIANCE_PERCENTAGE=$(
    jq -r '.summary.final_compliance_percentage' "$OUTPUT_FILE"
)

RESIDUAL_COUNT=$(
    jq '.summary.residual_findings_count' "$OUTPUT_FILE"
)


# ---------------------------------------------------------
# Display final summary
# ---------------------------------------------------------

echo "Evidence files loaded: $EVIDENCE_COUNT"
echo "Controls selected: $SELECTED_COUNT"
echo "Controls remediated: $REMEDIATED_COUNT"
echo "Controls verified: $VERIFIED_COUNT"
echo "Deviations documented: $DEVIATION_COUNT"
echo "Overall compliance: ${COMPLIANCE_PERCENTAGE}%"
echo "Residual findings: $RESIDUAL_COUNT"
echo "Report saved to: compliance_report.json"
