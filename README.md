# LibGuard 🔒
### Library Vulnerability Scanner

LibGuard scans your project's dependencies against the [OSV (Open Source Vulnerabilities)](https://osv.dev) database and reports known CVEs with severity ratings.

---

## Supported File Types

| File | Ecosystem |
|---|---|
| `requirements.txt` | Python / PyPI |
| `package.json` | Node.js / npm |

---

## Usage

```bash
# Scan Python dependencies
python scanner/scanner.py requirements.txt

# Scan Node.js dependencies
python scanner/scanner.py package.json
```

## Example Output

```
============================================================
         LibGuard - Vulnerability Scan Report
         2026-03-06 10:00:00
============================================================

🔴 django 2.2.0
   2 vulnerability/vulnerabilities found:
   ├─ [HIGH] CVE-2021-35042
   │   SQL injection via unsanitized QuerySet.order_by() input

------------------------------------------------------------
  Scanned: 7 packages
  Vulnerable: 1 packages
  Clean: 6 packages
============================================================
```

## CI/CD Integration

LibGuard exits with code `1` when vulnerabilities are found, making it easy to fail your pipeline:

```yaml
- name: Security scan
  run: python scanner/scanner.py requirements.txt
```

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=scanner
```

---

## Project Structure

```
libguard/
├── scanner/
│   └── scanner.py          # Core scanner logic
├── tests/
│   └── test_scanner.py     # Unit tests
├── sample/
│   ├── requirements.txt    # Sample Python deps
│   └── package.json        # Sample Node deps
├── .github/
│   └── workflows/
│       └── main.yml        # CI/CD pipeline
└── README.md
```
