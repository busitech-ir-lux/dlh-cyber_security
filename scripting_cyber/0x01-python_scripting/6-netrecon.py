#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import socket
import dns.resolver

def dns_recon(domain):
    dom_ip = socket.gethostbyname(domain)
    try:
        dom_mx = dns.resolver.resolve(domain, 'MX')
        mx_records = '\n'.join(str(rdata) for rdata in dom_mx)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        mx_records = 'No MX records found'
    return f"""
IP Address: {dom_ip}
MX Records: {mx_records}"""

def web_recon(domain):
    url = f"http://{domain}"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    url_count = len(soup.find_all('a'))
    status_code = response.status_code
    important_headers = response.headers.get('Server', 'N/A'), response.headers.get('Content-Type', 'N/A')
    return f"""Status Code: {status_code}
    
    Important Headers: 
    Server: {important_headers[0]}
    Content-Type: {important_headers[1]}
    
    Total Links Found: {url_count}"""



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
        print(f"Port {port}: OPEN")

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")
    print(dns_recon(target_domain))
    print(web_recon(target_domain))
    port_scan(target_domain)