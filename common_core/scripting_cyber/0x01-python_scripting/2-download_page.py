#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

def download_page(url):
    try:
        page = requests.get(url).text
        soup = BeautifulSoup(page, 'html.parser')
        return soup.prettify()
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

