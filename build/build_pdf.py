"""Build the A9 report PDF (landscape): report.md -> report.html -> PDF via headless Edge."""
import html
import pathlib
import re
import subprocess
import sys

import markdown
from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "report.md"
OUT_HTML = HERE / "report.html"
OUT_PDF = HERE.parent / "A9_陳致安_DevSecOps.pdf"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

CSS = """
@page {
  size: A4 landscape;
  margin: 11mm 13mm 13mm 13mm;
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font: 9pt 'Segoe UI', sans-serif; color: #666; }
}
* { box-sizing: border-box; }
body { font: 9.2pt/1.36 'Segoe UI', 'Microsoft JhengHei', sans-serif; color: #1a1a1a; margin: 0; }
h1 { font-size: 18pt; margin: 0 0 6pt; }
h2 { font-size: 14pt; margin: 16pt 0 6pt; padding-bottom: 3pt; border-bottom: 1.5px solid #333; break-after: avoid; }
h2.newpage { break-before: page; margin-top: 0; }
h3 { font-size: 11.5pt; margin: 12pt 0 4pt; break-after: avoid; }
p, li { margin: 3pt 0; }
a { color: #0b57d0; text-decoration: none; }
code { font: 8.8pt Consolas, monospace; background: #f1f3f4; padding: 0 2pt; border-radius: 2px; }
pre { background: #f6f8fa; border: 1px solid #ddd; border-radius: 4px; padding: 5pt 8pt;
      white-space: pre-wrap; word-break: break-word; margin: 5pt 0; }
pre code { background: none; padding: 0; font-size: 8.2pt; }
table { border-collapse: collapse; width: 100%; margin: 5pt 0 8pt; font-size: 8.4pt; }
th, td { border: 1px solid #c8c8c8; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #eef1f4; }
figure { margin: 6pt 0 10pt; text-align: center; break-inside: avoid; }
figure img { max-width: 100%; max-height: 60mm; border: 1px solid #ccc; }
figure img.term { width: 100%; max-height: none; border: 0; }
figure.termfig { max-width: 100%; margin-left: auto; margin-right: auto; }
.wide img { max-height: 98mm; }
.pair { display: flex; gap: 6mm; align-items: flex-start; break-inside: avoid; }
.pair figure { flex: 1 1 0; min-width: 0; }
.side { display: flex; gap: 6mm; align-items: flex-start; break-inside: avoid; margin: 3pt 0 8pt; }
.side > p { flex: 1 1 0; margin: 0; }
.side figure { flex: 1.4 1 0; margin: 0; }
.pair figure.termfig { flex: 0 1 auto; margin: 6pt 0 10pt; }
.pair figure img { max-height: 57mm; }
figcaption { font-size: 8.3pt; color: #555; margin-top: 2pt; }
.meta { color: #333; margin-bottom: 8pt; }
"""

# Sections that start on a new page (by heading text prefix).
NEW_PAGE = ()

# Screenshots rendered by render_term.py from saved command output.
# Small screenshots that need less than the default figure height.
HEIGHTS = {"O1-actions-v1-fail": "50mm", "O1-codescanning-semgrep": "50mm", "E-dependabot-prs-2col": "82mm", "O2-zap-report-v1-crop": "40mm", "O1-trivy-action-pr": "52mm", "O1-actions-v2-pass": "46mm", "O1-codescanning-closed": "46mm"}
TERMINALS = {"A-flake8", "O1-hadolint-trivy-config", "O1-trivy-raw", "O2-zap-v1", "O2-zap-v2"}


def main() -> int:
    body = markdown.markdown(
        SRC.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "sane_lists", "nl2br"],
    )

    n = {"fig": 0}
    numbers = {}  # image stem -> figure number, for "Figure {stem}" references in the text

    def to_figure(m: re.Match) -> str:
        n["fig"] += 1
        numbers[pathlib.Path(m.group("src")).stem] = n["fig"]
        alt, src = html.unescape(m.group("alt")), m.group("src")
        fig, cls = "<figure>", ""
        if pathlib.Path(src).stem in TERMINALS:
            # terminal captures: print at 90% of their natural size (captured at 1.5x), so the text stays ~8pt
            fig = f'<figure class="termfig" style="width:{Image.open(HERE / src).width / 1.5 * 0.9:.0f}px">'
            cls = ' class="term"'
        elif pathlib.Path(src).stem in HEIGHTS:
            cls = f' style="max-height:{HEIGHTS[pathlib.Path(src).stem]}"'
        return (
            f'{fig}<img src="{src}" alt="{html.escape(alt)}"{cls}>'
            f"<figcaption>Figure {n['fig']}. {html.escape(alt)}</figcaption></figure>"
        )

    img = r'<img alt="(?P<alt>[^"]*)" src="(?P<src>[^"]+)"\s*/?>'
    # one pass over the document, so figures are numbered in reading order;
    # two images in one paragraph are placed side by side
    # a paragraph whose last line is an image -> text and figure side by side
    def para(m: re.Match) -> str:
        figs = [to_figure(i) for i in re.finditer(img, m.group("imgs"))]
        if m.group("text"):
            return f'<div class="side"><p>{m.group("text")}</p>{figs[0]}</div>'
        return figs[0] if len(figs) == 1 else '<div class="pair">' + "".join(figs) + "</div>"

    body = re.sub(r"<p>(?:(?P<text>(?:(?!</p>).)*?)<br />\s*)?(?P<imgs>(?:" + img.replace("(?P<alt>", "(?:").replace("(?P<src>", "(?:")
                  + r"\s*){1,2})</p>", para, body, flags=re.S)
    body = re.sub(
        r"<h2>(\d+\. )",
        lambda m: (f'<h2 class="newpage">{m.group(1)}' if m.group(1) in NEW_PAGE else f"<h2>{m.group(1)}"),
        body,
    )
    body = re.sub(r"Figure \{([\w-]+)\}", lambda m: f"Figure {numbers[m.group(1)]}", body)
    body = body.replace("<p><strong>Name:</strong>", '<p class="meta"><strong>Name:</strong>', 1)

    missing = [s for s in re.findall(r'<img src="([^"]+)"', body) if not (HERE / s).exists()]
    if missing:
        print("Missing images:", *missing, sep="\n  ")
        return 1

    OUT_HTML.write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>A9 DevSecOps Report</title><style>{CSS}</style></head><body>{body}</body></html>",
        encoding="utf-8",
    )
    print(f"HTML written with {n['fig']} figures")
    subprocess.run(
        [EDGE, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--print-to-pdf-no-header",
         "--virtual-time-budget=15000", f"--print-to-pdf={OUT_PDF}", OUT_HTML.as_uri()],
        check=True, timeout=180,
    )
    print("PDF written:", OUT_PDF, OUT_PDF.stat().st_size, "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
