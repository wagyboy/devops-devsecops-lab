# DevOps A9: Practicing DevSecOps Fundamentals

Owner: 陳致安 (B11309058) · Course: DevOps

A small Flask shop, first committed as written (v1: injectable search, 2022-era dependencies, root container),
then fixed (v2) under the security gates below. Every gate runs on every push and pull request.

| Level | Practice | Tool | Where |
| --- | --- | --- | --- |
| A | Static analysis via linting | Flake8 + flake8-bandit + flake8-bugbear | `.flake8`, `lint` job |
| E | Software composition analysis | GitHub Dependabot (alerts, security updates, version updates) | `.github/dependabot.yml` |
| O | SAST | Semgrep (`p/python`, `p/flask`, `p/secrets`) → Code scanning | `sast` job |
| O | Dockerfile lint and container image scan | Hadolint, Trivy → Code scanning | `dockerfile`, `image-scan` jobs |
| O | DAST | OWASP ZAP (baseline in CI, full scan locally) | `dast` job, `zap/` |

| Folder | Contents |
| --- | --- |
| `app/` | The shop: `shop.py`, templates, `requirements.txt`, `Dockerfile` |
| `.github/` | `workflows/devsecops.yml` (pipeline) and `dependabot.yml` |
| `evidence/` | Saved output of every local scan, v1 and v2 |
| `zap/` | OWASP ZAP full-scan reports (HTML and JSON), v1 and v2 |
| `build/` | Report source and the scripts that build the PDF and capture screenshots |

## Run locally

```bash
python -m venv .venv
.venv/Scripts/pip install flake8 flake8-bandit flake8-bugbear requests
.venv/Scripts/flake8 app scripts                                   # A: lint
docker compose up -d --build                                       # shop on http://localhost:8000
.venv/Scripts/python scripts/smoke_test.py
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.183.0 semgrep scan --config p/python --config p/flask --config p/secrets --error app scripts
docker run --rm -i hadolint/hadolint:v2.12.0 hadolint - < app/Dockerfile
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.69.3 image --severity HIGH,CRITICAL --ignore-unfixed a9-shop:local
docker run --rm --network a9-devsecops_default -v "$PWD/zap:/zap/wrk" zaproxy/zap-stable:2.17.0 zap-full-scan.py -t http://shop:8000 -m 2 -r report.html
docker compose down
```
