"""Summarize a Trivy JSON report: findings per target and severity, plus the fixable Python packages."""
import collections
import json
import sys

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
report = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"{'target':34} {'total':>5} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'fixable':>8}")
for r in report["Results"]:
    vulns = r.get("Vulnerabilities") or []
    if not vulns:
        continue
    sev = collections.Counter(v["Severity"] for v in vulns)
    fixable = sum(1 for v in vulns if v.get("FixedVersion"))
    counts = " ".join(f"{sev[s]:5}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    print(f"{r['Target'][:34]:34} {len(vulns):5} {counts} {fixable:8}")
print()
pkgs = collections.defaultdict(list)
for r in report["Results"]:
    if r.get("Type") == "python-pkg":
        for v in r.get("Vulnerabilities") or []:
            pkgs[(v["PkgName"], v["InstalledVersion"])].append(v)
for (name, ver), vulns in sorted(pkgs.items(), key=lambda kv: -len(kv[1])):
    worst = min(vulns, key=lambda v: ORDER.index(v["Severity"]))
    print(f"{name:12} {ver:11} {len(vulns):2} CVEs, worst {worst['Severity']:8} {worst['VulnerabilityID']:20}",
          f"fixed in {worst.get('FixedVersion')}")
