"""Smoke test: hit every endpoint of a running shop and print the status codes."""
import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

for method, path in [("GET", "/health"), ("GET", "/"), ("GET", "/search?q=desk"), ("POST", "/api/buy/SKU-100?qty=1")]:
    r = requests.request(method, BASE + path)
    print(f"{method:4} {path:28} {r.status_code}")
