"""Capture public GitHub pages (Actions runs, Dependabot PRs) with Playwright driving the installed Edge.

Usage: python shots_github.py NAME=URL [NAME=URL ...]   (NAME is the PNG name, without .png)
"""
import pathlib
import sys

from playwright.sync_api import sync_playwright

OUT = pathlib.Path(__file__).resolve().parent.parent / "screenshots"

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge")
    page = browser.new_page(viewport={"width": 1400, "height": 900}, device_scale_factor=1.25, color_scheme="light")
    for arg in sys.argv[1:]:
        name, url = arg.split("=", 1)
        full = name.endswith("!")
        name = name.rstrip("!")
        page.goto(url, wait_until="load")
        page.wait_for_timeout(3000)
        page.screenshot(path=OUT / f"{name}.png", full_page=full)
        print("wrote", name)
    browser.close()
