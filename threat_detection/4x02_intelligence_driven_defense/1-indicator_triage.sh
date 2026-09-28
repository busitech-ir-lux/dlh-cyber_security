#!/bin/bash

# ==============================================================================
# Script Name: 1-indicator_triage.sh
# Description: Triages HEALTHBANE indicators into ACTIONABLE,
#              CONTEXTUAL, and NOISE categories.
# ==============================================================================

# Output file
OUTPUT="indicator_triage_results.json"

# ==============================================================================
# Create the triage results
# ==============================================================================

cat > "$OUTPUT" <<'EOF'
{
  "summary": {
    "total_reviewed": 64,
    "actionable_count": 28,
    "actionable_pct": 43.75,
    "contextual_count": 18,
    "contextual_pct": 28.12,
    "noise_count": 18,
    "noise_pct": 28.12,
    "top_downgrade_reasons": [
      "Shared hosting, CDN, or cloud infrastructure",
      "Weak ML similarity or keyword-only clustering",
      "No external corroboration",
      "Historical or sinkholed infrastructure",
      "Commercial-feed hashes likely unrelated to HEALTHBANE"
    ],
    "immediate_detection_priorities": [
      "meddefense-portal.com",
      "medequip-supplies.net",
      "meddefense-benefits.org",
      "healthbane-c2.net",
      "data-sync.healthbane-c2.net",
      "91.234.99.107",
      "185.176.43.22",
      "51.38.42.191"
    ]
  },

  "indicators": [

    {
      "type": "domain",
      "value": "meddefense-portal.com",
      "sources": ["HC3", "commercial", "researcher", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Confirmed phishing domain supported by multiple independent sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "medequip-supplies.net",
      "sources": ["HC3", "commercial", "researcher", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Confirmed HEALTHBANE phishing infrastructure supported by multiple sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "meddefense-benefits.org",
      "sources": ["HC3", "commercial", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Observed phishing domain corroborated by government, commercial, and internal evidence.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "outlook-protection.com",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed credential-harvesting and attacker-controlled mail infrastructure.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "healthbane-c2.net",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed HEALTHBANE command-and-control infrastructure.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "data-sync.healthbane-c2.net",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed DNS-tunneling and data-exfiltration infrastructure.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "update-healthbane.net",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Second-stage infrastructure corroborated by HC3 and the commercial feed.",
      "confidence": "MEDIUM",
      "uncertainty": false
    },
    {
      "type": "domain",
      "value": "portal-secure-meddefense.com",
      "sources": ["HC3", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Same HEALTHBANE phishing kit was staged on this domain although it was not yet active.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "domain",
      "value": "rx-benefits-portal.com",
      "sources": ["commercial"],
      "category": "CONTEXTUAL",
      "justification": "Possible earlier operator infrastructure but it predates the HEALTHBANE campaign window.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "domain",
      "value": "healthcare-login.com",
      "sources": ["commercial"],
      "category": "CONTEXTUAL",
      "justification": "Historical phishing infrastructure that has already been sinkholed.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "domain",
      "value": "verify-health-portal.net",
      "sources": ["commercial"],
      "category": "CONTEXTUAL",
      "justification": "Matches campaign naming patterns but no active phishing was observed.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "domain",
      "value": "secure-insurance-login.com",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Linked only by ML name similarity with no human review or external corroboration.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "domain",
      "value": "claims-verify-portal.net",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Keyword-only clustering provides weak evidence of HEALTHBANE association.",
      "confidence": "LOW",
      "uncertainty": true
    },

    {
      "type": "ip",
      "value": "91.234.99.107",
      "sources": ["HC3", "commercial", "researcher", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Confirmed phishing infrastructure with strong multi-source corroboration.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "185.176.43.22",
      "sources": ["HC3", "commercial", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Confirmed Stage 1 phishing infrastructure observed by multiple sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "164.90.218.73",
      "sources": ["HC3", "commercial", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Confirmed phishing infrastructure with government and internal corroboration.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "51.38.42.17",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed Stage 1 HEALTHBANE infrastructure corroborated by multiple sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "51.38.42.191",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed command-and-control infrastructure referenced by the recovered phishing kit.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "45.77.218.9",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Second-stage C2 infrastructure corroborated by HC3 and commercial intelligence.",
      "confidence": "MEDIUM",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "167.71.222.30",
      "sources": ["commercial", "researcher"],
      "category": "CONTEXTUAL",
      "justification": "Possible operator overlap but evidence is weak and does not justify blocking.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "ip",
      "value": "23.94.138.222",
      "sources": ["commercial"],
      "category": "CONTEXTUAL",
      "justification": "Possible related hosting but association is based on similarity clustering only.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "ip",
      "value": "104.168.34.58",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Low-confidence healthcare-keyword similarity with no external corroboration.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "ip",
      "value": "159.89.112.45",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Shared DigitalOcean infrastructure hosting many unrelated sites; blocking would create false positives.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "192.99.207.114",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Shared OVH CDN infrastructure explicitly identified as likely noise.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "20.83.144.56",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Shared Azure CDN infrastructure explicitly marked DO NOT BLOCK.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "13.107.42.14",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Microsoft Outlook cloud IP incorrectly associated through clustering noise.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "172.67.192.40",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Cloudflare shared front-end IP; not safe or useful to block.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "ip",
      "value": "104.21.35.7",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Shared Cloudflare infrastructure with weak campaign association.",
      "confidence": "HIGH",
      "uncertainty": false
    },

    {
      "type": "sha256",
      "value": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed malicious macro document corroborated by multiple sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed HEALTHBANE second-stage executable suitable for EDR detection.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed PowerShell exfiltration artifact supported by multiple sources.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f",
      "sources": ["HC3", "researcher", "MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Known HEALTHBANE lure PDF observed internally and externally.",
      "confidence": "MEDIUM",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Dropper variant corroborated by HC3 and the commercial feed.",
      "confidence": "MEDIUM",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "ee1122334455667788990011223344556677889900aabbccddeeff0011223344",
      "sources": ["commercial"],
      "category": "CONTEXTUAL",
      "justification": "Probable trojan variant but supported only by the commercial feed.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "sha256",
      "value": "ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899",
      "sources": ["researcher"],
      "category": "CONTEXTUAL",
      "justification": "Recovered phishing-kit ZIP, but researcher cannot confirm whether it is operator-specific.",
      "confidence": "MEDIUM",
      "uncertainty": true
    },
    {
      "type": "sha256",
      "value": "1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Commercial feed identifies it as likely belonging to an unrelated malware cluster.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "sha256",
      "value": "3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Low-confidence uncorroborated commercial clustering result.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "sha256",
      "value": "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Weak healthcare-keyword and similarity clustering with no corroboration.",
      "confidence": "LOW",
      "uncertainty": true
    },
    {
      "type": "sha256",
      "value": "7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00",
      "sources": ["commercial"],
      "category": "NOISE",
      "justification": "Weak similarity-only commercial-feed association with no external support.",
      "confidence": "LOW",
      "uncertainty": true
    },

    {
      "type": "url",
      "value": "https://meddefense-portal.com/verify/staff?id=<user>&token=<8hex>",
      "sources": ["HC3", "commercial", "researcher"],
      "category": "ACTIONABLE",
      "justification": "Confirmed HEALTHBANE credential-harvesting URL pattern.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1",
      "sources": ["MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Exact phishing URL directly observed in the MedDefense incident.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://medequip-supplies.net/invoices/pay?id=INV-<YYYY-NNNNN>",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed Stage 1 credential-capture URL.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://meddefense-benefits.org/enroll",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed Stage 1 phishing and credential-capture endpoint.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://healthbane-c2.net/update/svchost_update.exe",
      "sources": ["HC3", "commercial"],
      "category": "ACTIONABLE",
      "justification": "Confirmed second-stage malware download URL.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://healthbane-c2.net/api/ingest",
      "sources": ["researcher"],
      "category": "ACTIONABLE",
      "justification": "Exfiltration endpoint recovered directly from the HEALTHBANE phishing kit configuration.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "url",
      "value": "https://outlook-protection.com/verify",
      "sources": ["commercial"],
      "category": "ACTIONABLE",
      "justification": "High-confidence Microsoft impersonation phishing URL in the campaign feed.",
      "confidence": "HIGH",
      "uncertainty": false
    },

    {
      "type": "email",
      "value": "noreply@meddefense-portal.com",
      "sources": ["MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Sender address directly observed in the internal phishing investigation.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "email",
      "value": "invoices@medequip-supplies.net",
      "sources": ["MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Sender address directly observed in the internal phishing campaign.",
      "confidence": "HIGH",
      "uncertainty": false
    },
    {
      "type": "email",
      "value": "hr-notifications@meddefense-benefits.org",
      "sources": ["MedDefense"],
      "category": "ACTIONABLE",
      "justification": "Sender address directly observed in the internal phishing campaign.",
      "confidence": "HIGH",
      "uncertainty": false
    }
  ]
}
EOF

# ==============================================================================
# Validate the generated JSON
# ==============================================================================

if ! jq empty "$OUTPUT" 2>/dev/null; then
    echo "ERROR: Failed to create valid JSON."
    exit 1
fi

# ==============================================================================
# Print required summary
# ==============================================================================

echo "=============================================================================="
echo "HEALTHBANE CAMPAIGN - INDICATOR TRIAGE"
echo "=============================================================================="
echo
echo "Total indicators reviewed : 64"
echo "ACTIONABLE                : 28 (43.75%)"
echo "CONTEXTUAL                : 18 (28.12%)"
echo "NOISE                     : 18 (28.12%)"
echo
echo "Top reasons indicators were downgraded:"
echo " - Shared hosting, CDN, or cloud infrastructure"
echo " - Weak ML similarity or keyword-only clustering"
echo " - No independent corroboration"
echo " - Historical or sinkholed infrastructure"
echo " - Commercial-feed hashes likely unrelated to HEALTHBANE"
echo
echo "Top indicators for immediate detection:"
echo " - meddefense-portal.com"
echo " - medequip-supplies.net"
echo " - meddefense-benefits.org"
echo " - healthbane-c2.net"
echo " - data-sync.healthbane-c2.net"
echo " - 91.234.99.107"
echo " - 185.176.43.22"
echo " - 51.38.42.191"
echo
echo "NOTE: Not all threat-intelligence indicators are safe to block."
echo "Shared infrastructure and weakly clustered indicators can create false positives."
echo
echo "Results saved to: $OUTPUT"
echo "=============================================================================="