#!/usr/bin/env python3

import dns.resolver


def query_dns_records(domain_name):
    """
    Query common DNS record types for a domain.

    Returns:
        dict: {'A': answers, 'MX': answers, ...}
        Empty dict if the domain cannot be resolved.
    """

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    records = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            records[record_type] = answers

        except dns.resolver.NoAnswer:
            continue

        except dns.resolver.NoNameservers:
            continue

        except dns.resolver.NXDOMAIN:
            return {}

    return records
