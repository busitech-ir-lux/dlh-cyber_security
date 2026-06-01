#!/usr/bin/env python3

import requests

def get_http_headers(url):
    result = {}
    headers = {}
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}\n")
        print(f"Headers: \n")

        for r in response:
            print(f"    {r}: {response[r]}")
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
