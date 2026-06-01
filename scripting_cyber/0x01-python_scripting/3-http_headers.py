#!/usr/bin/env python3

import requests
def get_http_headers(url):
    try:
        response = requests.get(url)
        return response.status_code, response.headers
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
