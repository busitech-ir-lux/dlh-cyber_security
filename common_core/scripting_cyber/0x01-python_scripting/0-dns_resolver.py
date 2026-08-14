#!/usr/bin/env python3

import sys
import socket


def resolve_domain_to_ipv4(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./script.py <domain>")
        sys.exit(1)

    print(resolve_domain_to_ipv4(sys.argv[1]))
