#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import socket

try:
    import dns.resolver
except ImportError:
    pass

def dns_recon(domain):

    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
        
    except socket.gaierror:
        return f"Error resolving {domain}: Host not found"

def web_recon(domain):
    
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print(f"    Status Code: {response.status_code}")
        
        for key in ['Content-Type', 'Server', 'X-Frame--Options']:
            if key in response.headers:
                print(f"    {key}: {response.headers[key]}")
        soup = BeautifulSoup(response.text, "html.parser")
        print(f"    Total Links Found: {len(soup.find_all('a', href=True))}")
    except requests.exceptions.RequestException as e:
        return f"Error fetching {domain}: {e}"



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
