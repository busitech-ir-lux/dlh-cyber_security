#!/usr/bin/env python3

import requests

def get_http_headers(url):
    result = {}
    headers = {}
    try:
        response = requests.get(url)
        headers = dict(response.headers)
        print(f"Status Code: {response.status_code}\n")
        print(f"Headers: \n")

        for r in headers:
            print(f"    {r}: {headers[r]}")
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
get_http_headers("https://google.com")
