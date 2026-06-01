#!/usr/bin/env python3
import dns.resolver

def query_dns_records(domain_name):
    record_types = ['A','AAAA', 'MX', 'NS', 'TXT', 'SOA']
    results = {}

    for record_type in record_types:
        try:
            answers =  dns.resolver.resolve(domain_name, record_type)
           # print(list(answers))
            results[record_type] = [str(r) for r in answers]

        except dns.resolver.NoAnswer:
            results[record_type] =  None
        except dns.resolver.NXDOMAIN:
            return "NX Domain"
        except dns.resolver.NoNameservers:
            return "No name servers returned"
        except Exception as e:
            return f"Error: {e}"
    return results

print(query_dns_records("google.com"))
