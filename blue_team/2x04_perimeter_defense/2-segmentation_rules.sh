#!/bin/bash

set -e

OUTPUT_FILE="segmentation_rules.json"
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")


# -------------------------------------------------
# Define MedDefense zones
# -------------------------------------------------

ZONES=$(jq -n '[
    {
        name: "DMZ",
        cidr: "10.10.2.0/24",
        purpose: "Public-facing services",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "INTERNAL",
        cidr: "10.10.1.0/24",
        purpose: "Clinical applications and databases",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "MGMT",
        cidr: "192.168.10.0/24",
        purpose: "Administration and management",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "MEDDEV",
        cidr: "10.10.3.0/24",
        purpose: "Medical device VLAN",
        default_inbound: "drop",
        default_outbound: "accept",
        outbound_restrictions: [
            "no_dmz_access",
            "no_public_internet_access"
        ]
    }
]')


# -------------------------------------------------
# Define allowed flows
# -------------------------------------------------
#
# MGMT -> INTERNAL tcp/22
# MGMT -> DMZ tcp/22
# INTERNAL -> INTERNAL tcp/443 and tcp/3306
# DMZ -> INTERNAL tcp/3306
# MEDDEV -> INTERNAL tcp/4242 DICOM and tcp/443
# ALL zones -> MGMT resolver on udp/53 and tcp/53
#
# No flows from MEDDEV to DMZ or public Internet.
# No flows into MEDDEV except MGMT tcp/22 and tcp/4242.
#
# -------------------------------------------------

FLOWS=$(jq -n '[

    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to INTERNAL servers"
    },

    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "DMZ",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to DMZ servers"
    },

    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 443,
        justification: "Clinical workstations to INTERNAL server hosts"
    },

    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 3306,
        justification: "Clinical workstations to INTERNAL database servers"
    },

    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 3306,
        justification: "Named DMZ application hosts to INTERNAL databases",
        exception_for: "dmz_app_hosts_only",
        src_restriction: "named_dmz_application_hosts"
    },

    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 4242,
        justification: "DICOM imaging to PACS"
    },

    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 443,
        justification: "EHR web integration for device display"
    },

    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },

    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver over tcp/53"
    },

    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },

    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver over tcp/53"
    },

    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },

    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver over tcp/53"
    },

    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "MEDDEV",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to medical devices"
    },

    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "MEDDEV",
        proto: "tcp",
        dport: 4242,
        justification: "DICOM management to medical devices"
    },


    {
        action: "deny_all",
        src_zone: "DMZ",
        dst_zone: "MEDDEV",
        proto: "any",
        dport: 0,
        justification: "No flows from DMZ to MEDDEV"
    },

    {
        action: "deny_all",
        src_zone: "INTERNAL",
        dst_zone: "DMZ",
        proto: "any",
        dport: 0,
        justification: "No flows from INTERNAL to DMZ"
    },

    {
        action: "deny_all",
        src_zone: "INTERNAL",
        dst_zone: "MEDDEV",
        proto: "any",
        dport: 0,
        justification: "No flows from INTERNAL to MEDDEV"
    },

    {
        action: "deny_all",
        src_zone: "MEDDEV",
        dst_zone: "DMZ",
        proto: "any",
        dport: 0,
        justification: "No flows from MEDDEV to DMZ or public Internet"
    }

]')


# -------------------------------------------------
# Create summary
# -------------------------------------------------

SUMMARY=$(echo "$FLOWS" | jq '{
    flow_count: length,

    allow_count:
        ([.[] | select(.action == "allow")] | length),

    deny_count:
        ([.[] | select(.action == "deny_all")] | length),

    cross_zone_pairs:
        (
            [
                .[]
                | select(.src_zone != .dst_zone)
                | (.src_zone + "->" + .dst_zone)
            ]
            | unique
            | length
        )
}')


# -------------------------------------------------
# Create final JSON
# -------------------------------------------------

jq -n \
    --arg generated_at "$GENERATED_AT" \
    --argjson zones "$ZONES" \
    --argjson flows "$FLOWS" \
    --argjson summary "$SUMMARY" \
    '{
        generated_at: $generated_at,
        zones: $zones,
        flows: $flows,
        summary: $summary
    }' > "$OUTPUT_FILE"


# -------------------------------------------------
# Show result
# -------------------------------------------------

echo "Segmentation rules generated"
echo "Output: $OUTPUT_FILE"
echo "Zones: 4"
echo "Flows: $(echo "$SUMMARY" | jq -r '.flow_count')"
echo "Allows: $(echo "$SUMMARY" | jq -r '.allow_count')"
echo "Denies: $(echo "$SUMMARY" | jq -r '.deny_count')"
