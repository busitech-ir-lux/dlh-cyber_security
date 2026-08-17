#!/bin/bash

OUTPUT="segmentation_rules.json"


# -------------------------------------------------
# Create segmentation rules
# -------------------------------------------------

cat > "$OUTPUT" << 'EOF'
{
  "zones": [
    {
      "name": "DMZ",
      "cidr": "10.10.10.0/24",
      "purpose": "Public-facing application services",
      "default_inbound": "drop",
      "default_outbound": "accept with specific restrictions"
    },
    {
      "name": "INTERNAL",
      "cidr": "10.20.0.0/16",
      "purpose": "Clinical applications, workstations and databases",
      "default_inbound": "drop",
      "default_outbound": "accept with specific restrictions"
    },
    {
      "name": "MGMT",
      "cidr": "10.30.30.0/24",
      "purpose": "Administration and management services",
      "default_inbound": "drop",
      "default_outbound": "accept with specific restrictions"
    },
    {
      "name": "MEDDEV",
      "cidr": "10.40.40.0/24",
      "purpose": "Medical device VLAN",
      "default_inbound": "drop",
      "default_outbound": "accept with specific restrictions"
    }
  ],

  "flows": [

    {
      "action": "allow",
      "src_zone": "MGMT",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 22,
      "justification": "SSH administration of internal servers"
    },

    {
      "action": "allow",
      "src_zone": "MGMT",
      "dst_zone": "DMZ",
      "proto": "tcp",
      "dport": 22,
      "justification": "SSH administration of DMZ servers"
    },

    {
      "action": "allow",
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "src_role": "clinical_workstations",
      "dst_role": "server_hosts",
      "proto": "tcp",
      "dport": 443,
      "justification": "HTTPS access from clinical workstations to internal applications"
    },

    {
      "action": "allow",
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "src_role": "clinical_workstations",
      "dst_role": "server_hosts",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Database access from approved clinical workstations"
    },

    {
      "action": "allow",
      "src_zone": "DMZ",
      "dst_zone": "INTERNAL",
      "src_host": "dmz-app-01",
      "dst_role": "database",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Database access from named DMZ application host"
    },

    {
      "action": "allow",
      "src_zone": "DMZ",
      "dst_zone": "INTERNAL",
      "src_host": "dmz-app-02",
      "dst_role": "database",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Database access from named DMZ application host"
    },

    {
      "action": "allow",
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 4242,
      "justification": "DICOM imaging to PACS"
    },

    {
      "action": "allow",
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 443,
      "justification": "EHR web integration for device display"
    },

    {
      "action": "allow",
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 22,
      "justification": "SSH administration of medical devices"
    },

    {
      "action": "allow",
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 4242,
      "justification": "DICOM administration and testing"
    },

    {
      "action": "allow",
      "src_zone": "ALL",
      "dst_zone": "MGMT",
      "dst_role": "resolver",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolver access"
    },

    {
      "action": "allow",
      "src_zone": "ALL",
      "dst_zone": "MGMT",
      "dst_role": "resolver",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolver access over TCP"
    },


    {
      "action": "deny_all",
      "src_zone": "DMZ",
      "dst_zone": "MEDDEV",
      "proto": "any",
      "dport": "any",
      "justification": "No DMZ access to medical device VLAN"
    },

    {
      "action": "deny_all",
      "src_zone": "INTERNAL",
      "dst_zone": "MEDDEV",
      "proto": "any",
      "dport": "any",
      "justification": "No INTERNAL access to MEDDEV except approved MGMT flows"
    },

    {
      "action": "deny_all",
      "src_zone": "MEDDEV",
      "dst_zone": "DMZ",
      "proto": "any",
      "dport": "any",
      "justification": "Medical devices must not access the DMZ"
    },

    {
      "action": "deny_all",
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNET",
      "proto": "any",
      "dport": "any",
      "justification": "Medical devices must not access the public Internet"
    },

    {
      "action": "deny_all",
      "src_zone": "DMZ",
      "dst_zone": "MGMT",
      "proto": "any",
      "dport": "any",
      "justification": "No direct DMZ access to management systems"
    }
  ]
}
EOF


# -------------------------------------------------
# Add summary
# -------------------------------------------------

FLOW_COUNT=$(jq '.flows | length' "$OUTPUT")

ALLOW_COUNT=$(jq '
    [.flows[] | select(.action == "allow")] | length
' "$OUTPUT")

DENY_COUNT=$(jq '
    [.flows[] | select(.action == "deny_all")] | length
' "$OUTPUT")

PAIR_COUNT=$(jq '
    [
        .flows[] |
        (.src_zone + "->" + .dst_zone)
    ]
    | unique
    | length
' "$OUTPUT")


# Create final file with summary
jq \
    --argjson flow_count "$FLOW_COUNT" \
    --argjson allow_count "$ALLOW_COUNT" \
    --argjson deny_count "$DENY_COUNT" \
    --argjson pair_count "$PAIR_COUNT" \
    '
    . + {
        summary: {
            flow_count: $flow_count,
            allow_count: $allow_count,
            deny_count: $deny_count,
            cross_zone_pairs: $pair_count
        }
    }
    ' "$OUTPUT" > "${OUTPUT}.tmp"

mv "${OUTPUT}.tmp" "$OUTPUT"


echo "Segmentation rules saved to $OUTPUT"
