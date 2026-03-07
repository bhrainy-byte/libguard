# LibGuard 
### Library Vulnerability Scanner

LibGuard scans your project's dependencies against the [OSV (Open Source Vulnerabilities)](https://osv.dev) database and reports known CVEs with severity ratings.

## Supported File Types
| File | Ecosystem |
|---|---|
| `requirements.txt` | Python / PyPI |
| `package.json` | Node.js / npm |


## Usage
```bash
# Scan Python dependencies
python scanner/scanner.py requirements.txt
# Scan Node.js dependencies
python scanner/scanner.py package.json
``
`
## Example Output
```
🔍 Scanning 7 packages from requirements.txt...
============================================================
         LibGuard - Vulnerability Scan Report
         2026-03-07 16:00:00
============================================================
🔴 django 2.2.0
   63 vulnerabilities found:
   ├─ [CRITICAL] GHSA-2gwj-7jmv-h26r (CVE-2021-35042)
   │   SQL Injection in Django
------------------------------------------------------------
  Scanned:    7 packages
  Vulnerable: 7 packages
  Clean:      0 packages
============================================================
```
## CI/CD Integration
LibGuard exits with code `1` when vulnerabilities found:
```yaml
- name: Security scan
  run: python scanner/scanner.py requirements.txt
```
## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=scanner
```

## Monitoring
All scans are logged to `libguard.log` with timestamps. A health check runs before every scan to verify OSV API connectivity.
---

## Project Structure
```
libguard/
├── scanner/
│   └── scanner.py          # Core scanner logic
├── tests/
│   └── test_scanner.py     # Unit tests (18 tests)
├── sample/
│   ├── requirements.txt    # Sample Python deps
│   └── package.json        # Sample Node deps
├── .github/
│   └── workflows/
│       └── main.yml        # CI/CD pipeline
├── conftest.py             # Pytest configuration
└── README.md
```
## Sprint Summary
| Sprint | Delivered |
|---|---|
| Sprint 0 | Planning, backlog, CI/CD setup |
| Sprint 1 | Python scanning, OSV API, report formatting |
| Sprint 2 | Node.js scanning, monitoring, health check |