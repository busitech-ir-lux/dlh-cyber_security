#!/bin/bash

# Task 7 - Detection Engineering
# Purpose:
# Convert the investigation findings into practical detection rules.

echo "================================================================"
echo "   DETECTION ENGINEERING PLAN"
echo "================================================================"


# =========================================================
# 1. C2 BEACONING
# =========================================================

cat <<'EOF'

[*] Detection 1: C2 Beaconing

Type:
  Frequency and timing-based behavioral detection

Logic:
  Group connections by src_ip and dst_ip over 60 minutes.

  IF connection_count > 10
  AND interval_stddev < interval_mean * 0.15
  THEN alert "Possible C2 beaconing"

  interval_mean:
    average time between connections

  interval_stddev:
    how much the connection intervals vary

  Very small standard deviation means the connections happen
  at nearly regular intervals.

Data source:
  PCAP-derived connection logs
  Zeek conn.log
  NetFlow
  proxy/firewall connection logs

Test scenario:
  10.10.2.15 -> 91.234.99.107
  24 HTTPS connections
  approximately one connection every 300 seconds

Would detect:
  Phase 3 - C2 beaconing from c2_beaconing.pcap

False positives:
  Monitoring agents
  backup software
  update services
  health-check systems

Implementation options:
  SIEM:
    Group connections by source/destination and calculate intervals.

  Zeek:
    Track repeated connections and their timestamps.

  Python scheduled analysis:
    Read connection logs, calculate mean and standard deviation,
    and alert when the pattern is too regular.

  NetFlow analytics:
    Detect repeated flows between the same source and destination.

EOF


# =========================================================
# 2. DNS QUERY LENGTH
# =========================================================

cat <<'EOF'

[*] Detection 2: DNS Query Length Anomaly

Logic:
  Extract the left-most DNS label.

  Example:
    ABCDEFGHIJK.data-sync.example.com
    ^^^^^^^^^^^
    left-most label

  IF length(left_most_label) > 40
  THEN alert "Unusually long DNS query"

  Increase severity when:
    query type is TXT
    OR many long queries go to the same domain
    OR the label looks encoded

Data source:
  DNS logs
  PCAP
  Zeek dns.log
  DNS resolver logs

Test scenario:
  billing-srv-01 sends repeated DNS requests with
  44-60 character subdomain labels.

Would detect:
  Phase 7 - DNS tunneling / exfiltration

False positives:
  CDNs
  tracking services
  cloud applications
  security products using long generated hostnames

Why encoded labels matter:
  Normal DNS names are often readable.
  Long Base32/Base64-like strings may indicate data being
  carried inside DNS labels.

EOF


# =========================================================
# 3. VPN GEO-ANOMALY
# =========================================================

cat <<'EOF'

[*] Detection 3: VPN Geo-Anomaly

Logic:
  Enrich the VPN source IP with GeoIP and ASN information.

  IF source_country NOT IN expected_countries
  OR source_asn NOT IN expected_asns
  THEN alert "Unusual VPN source"

  Higher severity:
    unusual geography
    AND unusual ASN
    AND account has never logged in from this location before

Data source:
  VPN authentication logs
  source IP address
  GeoIP database
  ASN database
  user login history

Test scenario:
  Account: dmarsh
  VPN source: external IP identified in Task 5
  Source geography/ASN differs from normal organizational use.

Would detect:
  Phase 4 - VPN pivot

False positives:
  Employee travel
  mobile providers
  corporate proxies
  VPN providers
  changing ISP addresses

Important:
  GeoIP information alone does not prove malicious activity.
  It should be combined with account history and other evidence.

EOF


# =========================================================
# 4. CROSS-ROLE RDP
# =========================================================

cat <<'EOF'

[*] Detection 4: Cross-Role RDP

Logic:
  IF account_role == "clinical"
  AND destination_zone == "server"
  AND destination_port == 3389
  THEN alert "Unexpected clinical-to-server RDP"

Packet-based version:
  IF clinical_workstation -> server_subnet TCP/3389
  AND this path is not present in the normal baseline
  THEN alert

Data source:
  Firewall/network logs
  PCAP
  RDP authentication logs
  Active Directory / identity data
  asset inventory
  user-role information

Test scenario:
  WS-NURSE-04 (10.10.2.15)
      ->
  billing-srv-01 (10.10.1.10):3389

Would detect:
  Phase 5 - lateral movement through RDP

False positives:
  Authorized support activity
  administrators temporarily using another workstation
  approved remote troubleshooting

Important:
  Packet metadata can show an RDP connection.
  Authentication logs are better for proving which account
  successfully logged in.

EOF


# =========================================================
# 5. DNS TXT TUNNEL
# =========================================================

cat <<'EOF'

[*] Detection 5: DNS Tunneling TXT Query Pattern

Logic:
  Group TXT queries by:
    source_ip
    base_domain

  IF TXT_query_count > 10 within 120 seconds
  AND left_most_label_length > 40
  AND label looks encoded
  THEN alert "Possible DNS tunnel"

Simple pseudocode:

  count TXT queries from source to domain

  if count > 10 in 120 seconds:
      if label_length > 40:
          if encoded_pattern == true:
              alert

Data source:
  PCAP
  DNS resolver logs
  Zeek dns.log

Test scenario:
  billing-srv-01 repeatedly queries:

  <long-encoded-label>.data-sync.meddefense-portal.com

Would detect:
  Phase 7 - DNS exfiltration

False positives:
  Some cloud services
  DNS-based security products
  legitimate TXT validation
  automated email/security services

Difference from Detection 2:
  Detection 2 finds individual unusually long DNS names.

  Detection 5 detects the full tunnel pattern:
    TXT queries
    high frequency
    same destination domain
    encoded-looking labels

EOF


# =========================================================
# 6. TLS SNI / PHISHING IOC
# =========================================================

cat <<'EOF'

[*] Detection 6: TLS to Campaign Lookalike Domain

Logic:
  Maintain:
    known_phishing_domains
    campaign_IOC_list
    first_seen_domains

  Read TLS ClientHello SNI.

  IF tls_sni matches campaign_IOC_list
  THEN alert "Connection to phishing campaign domain"

  OR:

  IF tls_sni is a newly observed lookalike domain
  associated with an active phishing investigation
  THEN alert for review.

Data source:
  TLS ClientHello / SNI logs
  PCAP
  Zeek ssl.log
  proxy logs
  phishing investigation IOC list
  internal first-seen domain table

Test scenario:
  TLS SNI:
    meddefense-portal.com

  Campaign IOC:
    meddefense-portal.com

Would detect:
  Phase 2 - phishing-click TLS session

False positives:
  Legitimate new domains
  third-party portals
  test systems
  domains that look similar but are authorized

Important:
  A live domain-age service is not required.

  An internal IOC list or first-seen table is enough to
  correlate TLS traffic with the phishing campaign.

EOF


# =========================================================
# COVERAGE SUMMARY
# =========================================================

cat <<'EOF'

================================================================
   DETECTION COVERAGE UPDATE
================================================================

Before packet investigation:
  The campaign was mainly visible through phishing email IOCs.

After packet investigation:

  Phishing click:
    TLS SNI / campaign IOC detection

  C2:
    repeated connection + regular interval detection

  VPN pivot:
    VPN geography / ASN anomaly detection

  Lateral movement:
    clinical-to-server RDP detection

  DNS exfiltration:
    long DNS label detection
    high-frequency TXT tunnel detection


Remaining visibility gaps:

  Endpoint execution:
    Requires endpoint/EDR/process telemetry.

  Exact HTTPS credential contents:
    Cannot normally be recovered from encrypted TLS metadata.

  Successful user authentication:
    Authentication logs provide stronger evidence than TCP alone.

  Exact exfiltrated plaintext:
    DNS packet patterns may prove tunneling behavior without
    revealing all original data.


================================================================
EOF
