#!/usr/bin/env python3

import requests

def get_http_headers(url):
    result = {}
    try:
        response = requests.get(url)
        result = {response.status_code, response.headers}
        return result
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
