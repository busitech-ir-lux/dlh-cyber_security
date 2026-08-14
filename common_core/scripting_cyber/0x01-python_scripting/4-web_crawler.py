#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    visited = set()

    def crawl(url, depth):
        if depth > max_depth:
            return
        if url in visited:
            return

        visited.add(url)
        print(f"Crawling: {url} (depth: {depth})")

        try:
            response = requests.get(url, timeout=5)
        except Exception:
            return

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link["href"])

            # keep only same domain
            if urlparse(next_url).netloc == urlparse(start_url).netloc:
                crawl(next_url, depth + 1)

    crawl(start_url, 0)
    return visited
