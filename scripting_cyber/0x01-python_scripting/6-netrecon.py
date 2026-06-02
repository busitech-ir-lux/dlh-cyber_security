#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import socket
import dns.resolver

def dns_recon(domain):
    ip = socket.gethostbyname(domain)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(record.exchange) for record in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        mx_records = ['No MX records found']
    mx_list = '\n    '.join(mx_records)
    return f"""
IP Address: {ip}


MX Records: 
    {mx_list}"""

def web_recon(domain):
    url = f"http://{domain}"
    try:
        response = requests.get(url)
    except requests.RequestException as e:
        return f"Error fetching {url}: {e}"
    status_code = response.status_code
    total_links = len(BeautifulSoup(response.text, "html.parser").find_all('a'))
    return f"""Status Code: {status_code}
Important Headers:
    Content-Type: {response.headers.get('Content-Type', 'N/A')}
    Server: {response.headers.get('Server', 'N/A')}

    
Total Links Found: {total_links}"""


def port_scan(domain):
    print(f"Scanning common ports on {domain}...")
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    for port in open_ports:
        print(f"Port {port}: OPEN\n")


netrecon = __import__("6-netrecon")

print("=" * 50)
print("NETWORK RECONNAISSANCE TOOL")
print("=" * 50)

target = input("Enter target domain: ")

print("\n" + "=" * 50)
print("DNS RECONNAISSANCE")
print("=" * 50)
netrecon.dns_recon(target)

print("\n" + "=" * 50)
print("WEB RECONNAISSANCE")
print("=" * 50)
netrecon.web_recon(target)

print("\n" + "=" * 50)
print("PORT SCANNING")
print("=" * 50)
netrecon.port_scan(target)

print("\n" + "=" * 50)
print("RECONNAISSANCE COMPLETE")
print("=" * 50)