"""Render saved command output (evidence/) as terminal-style PNGs. Only real, captured output is shown."""
import html
import pathlib

from playwright.sync_api import sync_playwright

A9 = pathlib.Path(__file__).resolve().parent.parent
EV, OUT = A9 / "evidence", A9 / "screenshots"


def read(name: str) -> str:
    return (EV / name).read_text(encoding="utf-8").rstrip("\n")


def lines(name: str, *keep: str) -> str:
    return "\n".join(l for l in read(name).splitlines() if any(k in l for k in keep))


SEMGREP = "semgrep scan --config p/python --config p/flask --config p/secrets --error app scripts"
TRIVY = "trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 a9-shop:local"

SCREENS = {
    "A-flake8.png": [
        ("flake8 app scripts            # v1", read("v1-flake8.txt")),
        ("flake8 --statistics --count -qq app scripts", read("v1-flake8-stats.txt").split("\n")[-1] + " findings in total"),
        ("flake8 --count app scripts    # v2, after the fixes", read("v2-flake8.txt")),
    ],
    "O1-hadolint-trivy-config.png": [
        ("hadolint app/Dockerfile       # v1", read("v1-hadolint.txt")),
        ("trivy config app/             # v1", lines("v1-trivy-config.txt", "Tests:", "Failures:", "DS-0")),
        ("hadolint app/Dockerfile       # v2", read("v2-hadolint.txt")),
    ],
    "O1-semgrep-local.png": [
        (SEMGREP + "   # v2", "\n".join(read("v2-semgrep.txt").splitlines()[-8:])),
    ],
    "O1-trivy-raw.png": [
        ("trivy image --quiet --severity HIGH,CRITICAL a9-shop:v1   # v1, table output (excerpt: the two totals)",
         "\n".join(read("v1-trivy-image.txt").splitlines()[44:47]) + "\n…\n"
         + "\n".join(read("v1-trivy-image.txt").splitlines()[697:700])),
        (TRIVY + "   # v2 gate (excerpt)", "\n".join(read("v2-trivy-image-gate.txt").splitlines()[1:9]) + "\n…\n"
         + read("v2-trivy-image-gate.txt").splitlines()[-1]),
    ],
    "O2-zap-v1.png": [
        ("zap-full-scan.py -t http://shop:8000 -m 2 -r v1-zap-full.html   # v1",
         # every WARN-NEW rule, plus the URL lines of the four High alerts (file lines 158-166)
         "\n".join(l for i, l in enumerate(read("v1-zap-full.txt").splitlines(), 1)
                   if "WARN-NEW" in l or "FAIL-NEW" in l or i in (158, 160, 162, 163, 164, 166))),
    ],
    "O2-zap-v2.png": [
        ("curl -sI localhost:8000/   # v2", read("v2-headers.txt")),
        ("zap-full-scan.py -t http://shop:8000 -m 2 -r v2-zap-full.html   # v2",
         lines("v2-zap-full.txt", "WARN-NEW", "FAIL-NEW", "PASS: Cross Site Scripting (Reflected)",
               "PASS: Cross Site Scripting (DOM Based)", "PASS: SQL Injection [",
               "PASS: Source Code Disclosure - File Inclusion")),
    ],
}

CSS = """
body { margin: 0; background: #fff; }
.term { display: inline-block; max-width: 1020px; background: #0c0c0c; border-radius: 8px; overflow: hidden;
        font: 12px/1.38 'Cascadia Mono', Consolas, monospace; color: #cccccc; }
.bar { background: #2b2b2b; color: #bbb; font: 12px 'Segoe UI', sans-serif; padding: 6px 12px; }
.bar b { color: #eee; font-weight: 600; }
pre { margin: 0; padding: 10px 14px 12px; white-space: pre-wrap; font: inherit; }
.cmd { color: #6ee7a7; } .ps { color: #61afef; }
"""

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge")
    page = browser.new_page(viewport={"width": 1500, "height": 900}, device_scale_factor=1.5)
    for name, blocks in SCREENS.items():
        body = "\n".join(f'<span class="ps">PS A9&gt;</span> <span class="cmd">{html.escape(c)}</span>\n{html.escape(o)}'
                         for c, o in blocks)
        page.set_content(f'<html><head><style>{CSS}</style></head><body><div class="term">'
                         f'<div class="bar"><b>Terminal</b> — A9</div><pre>{body}</pre></div></body></html>')
        page.locator(".term").screenshot(path=OUT / name)
        print("wrote", name)
    browser.close()
