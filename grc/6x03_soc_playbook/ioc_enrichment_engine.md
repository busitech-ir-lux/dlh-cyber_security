# Task 1: IOC enrichment engine

**Implementation:** [enrich_ioc.py](enrich_ioc.py)  
**Input:** Unchanged copy of [ioc_feed.json](ioc_feed.json)  
**Result:** All ten rows in the supplied validation CSV matched type, class, score,
and verdict; [actual evidence](evidence/enrichment_validation_results.json).

## Behavior and interface

The module provides `detect_ioc_type`, `classify_ip`, `reverse_dns`, `check_feed`,
`score_ioc`, and `enrich_ioc`. It accepts IPv4, IPv6, domains, and HTTP(S) URLs.
URLs are reduced to their host for local-feed lookup; no URL is fetched and no
forward DNS lookup is needed. Hostnames are lowercased, trailing dots removed,
and valid international names converted to their ASCII form before matching.

Documentation ranges are checked explicitly before private classification,
including the three required IPv4 blocks. Loopback, link-local, multicast, and
RFC private ranges have distinct labels. IPv6 documentation and unique-local
addresses are also handled. Special reserved addresses outside the task's listed
categories use its fallback `public` label, meaning “no private exemption,” not a
guarantee that the address is globally routable. This avoids granting every
version-dependent `ipaddress.is_private` classification an ALLOW exemption.

The prescribed scoring order is private/loopback first, benign-list second,
malicious confidence third, and unknown last. Conflicting benign/malicious feed
entries keep that required precedence and include a warning note. Production
allowlist governance must resolve such conflicts before auto-close is enabled.
Malformed IOCs, unavailable feeds, and invalid feed data become INVESTIGATE with
an error explanation rather than being treated as clean.

## Running and validation

From this task folder:

```bash
python3 enrich_ioc.py 198.51.100.42
python3 enrich_ioc.py http://meddefense-secure.net/reset
python3 enrich_ioc.py --batch iocs.txt --output new_results.json
```

The saved [batch results](enrichment_results.json) use all ten supplied CSV values.
The exact [batch summary](evidence/enrichment_batch.stdout.txt) is:

```text
Processed: 10 | BLOCK: 5 | INVESTIGATE: 2 | ALLOW: 3
```

Existing batch output is not overwritten. Empty lines are ignored. A single IOC
prints JSON, while batch mode writes a JSON array and prints the requested counts.
Each record includes IOC, type, address class, reverse DNS, feed evidence, score,
verdict, and actual UTC enrichment time. Private and loopback exemptions include
an explanatory note. The five required anchors also matched individually:

| IOC | Score | Verdict |
| --- | --- | --- |
| 198.51.100.42 | 95 | BLOCK |
| cobalt-beacon.shop | 99 | BLOCK |
| 203.0.113.99 | 72 | INVESTIGATE |
| 192.168.1.100 | 0 | ALLOW |
| 8.8.8.8 | 0 | ALLOW |

## DNS and performance limits

`reverse_dns` sets the requested three-second default socket timeout, attempts
`gethostbyaddr`, handles herror as NXDOMAIN and timeout as TIMEOUT, and restores
the previous default afterward. Other resolver errors also leave enrichment
usable. DNS changes do not change feed-based scores or verdicts.

The measured local validation calls were below two seconds, but a three-second
socket setting cannot guarantee a two-second end-to-end deadline; operating-system
resolver behavior may differ. Production needs separately bounded workers and
measured latency. No live threat-intelligence API or TTL cache is implemented,
and historical feed freshness is not enforced. Fixed inputs and feed give stable
scores, while timestamps and DNS names may vary.
