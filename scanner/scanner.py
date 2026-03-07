"""
LibGuard - Library Vulnerability Scanner
=========================================
Scans project dependencies against the OSV (Open Source Vulnerabilities) database.

Supported file types:
    - requirements.txt  (Python / PyPI)
    - package.json      (Node.js / npm)

Usage:
    python scanner.py <requirements.txt|package.json>

Exit codes:
    0 = No vulnerabilities found
    1 = Vulnerabilities detected
"""

import json
import sys
import logging
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# Setup logging — structured monitoring for scan activity
logging.basicConfig(
    filename="libguard.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def health_check() -> bool:
    """Check OSV API is reachable before scanning."""
    import urllib.request
    try:
        urllib.request.urlopen("https://api.osv.dev", timeout=5)
        logging.info("Health check passed — OSV API reachable")
        return True
    except Exception:
        logging.warning("Health check failed — OSV API unreachable")
        return False

OSV_API_URL = "https://api.osv.dev/v1/query"


def parse_requirements_txt(filepath: str) -> list[dict]:
    """
    Parse a requirements.txt file and return list of {name, version} dicts.
    Handles pinned (==), minimum (>=), maximum (<=), compatible (~=) versions.
    Skips blank lines and comments.
    """
    packages = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Handle formats: package==1.0, package>=1.0, package
                for sep in ["==", ">=", "<=", "~=", "!="]:
                    if sep in line:
                        name, version = line.split(sep, 1)
                        packages.append({"name": name.strip(), "version": version.strip()})
                        break
                else:
                    packages.append({"name": line.strip(), "version": None})
        logging.info(f"Parsed {len(packages)} packages from {filepath}")
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    return packages


def parse_package_json(filepath: str) -> list[dict]:
    """Parse a package.json file and return list of {name, version} dicts."""
    packages = []
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for name, version in deps.items():
            # Strip semver prefixes like ^, ~
            clean_version = version.lstrip("^~>=<")
            packages.append({"name": name, "version": clean_version})
        logging.info(f"Parsed {len(packages)} packages from {filepath}")
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON in {filepath}")
        sys.exit(1)
    return packages


def check_vulnerability(package: dict, ecosystem: str = "PyPI") -> list[dict]:
    """
    Query the OSV (Open Source Vulnerabilities) API for a given package.
    Returns a list of vulnerability dicts, empty list if none found.
    Handles network timeouts and connection errors gracefully.
    """
    payload = {
        "package": {
            "name": package["name"],
            "ecosystem": ecosystem
        }
    }
    if package.get("version"):
        payload["version"] = package["version"]

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OSV_API_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            result = json.loads(response.read().decode("utf-8"))
            vulns = result.get("vulns", [])
            logging.info(f"Found {len(vulns)} vulnerabilities for {package['name']}")
            return vulns
    except urllib.error.URLError as e:
        logging.warning(f"Network error checking {package['name']}: {e}")
        return []


def get_severity(vuln: dict) -> str:
    """Extract highest severity from a vulnerability entry."""
    severities = vuln.get("severity", [])

    if not severities:
        db = vuln.get("database_specific", {})
        return db.get("severity", "UNKNOWN")
    for s in severities:
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            try:
                # CVSS scores look like "CVSS:3.1/AV:N/AC:L/..." — extract numeric score
                if "CVSS" in score_str:
                    db = vuln.get("database_specific", {})
                    return db.get("severity", "UNKNOWN")
                score = float(score_str)
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"
            except ValueError:
                db = vuln.get("database_specific", {})
                return db.get("severity", "UNKNOWN")
    return "UNKNOWN"


def format_report(results: list[dict], total_scanned: int) -> str:
    """
    Format the vulnerability report for terminal output.
    Shows each vulnerable package with CVE ID, severity, and summary.
    Prints a final summary of total scanned, vulnerable, and clean packages.
    Returns the full report as a string.
    """
    lines = []
    lines.append("\n" + "="*60)
    lines.append("         LibGuard - Vulnerability Scan Report")
    lines.append(f"         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("="*60)

    vulnerable_count = sum(1 for r in results if r["vulnerabilities"])

    if not any(r["vulnerabilities"] for r in results):
        lines.append("\n✅  No vulnerabilities found!\n")
    else:
        for result in results:
            if not result["vulnerabilities"]:
                continue
            pkg = result["package"]
            lines.append(f"\n🔴 {pkg['name']} {pkg.get('version', 'unknown')}")
            lines.append(f"   {len(result['vulnerabilities'])} vulnerability/vulnerabilities found:")
            for vuln in result["vulnerabilities"]:
                vuln_id = vuln.get("id", "N/A")
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                display_id = f"{vuln_id} ({cve_id})" if cve_id else vuln_id
                severity = get_severity(vuln)
                summary = vuln.get("summary", "No summary available")[:80]
                lines.append(f"   ├─ [{severity}] {display_id}")
                lines.append(f"   │   {summary}")

    lines.append("\n" + "-"*60)
    lines.append(f"  Scanned: {total_scanned} packages")
    lines.append(f"  Vulnerable: {vulnerable_count} packages")
    lines.append(f"  Clean: {total_scanned - vulnerable_count} packages")
    lines.append("="*60 + "\n")
    return "\n".join(lines)


def scan(filepath: str) -> int:
    """
    Main scan function. Returns exit code:
    0 = no vulnerabilities found
    1 = vulnerabilities found
    """
    path = Path(filepath)
    logging.info(f"Starting scan on {filepath}")
    if not health_check():
        print("[WARNING] OSV API may be unreachable — results may be incomplete")

    # Detect file type
    if path.name == "requirements.txt":
        packages = parse_requirements_txt(filepath)
        ecosystem = "PyPI"
    elif path.name == "package.json":
        packages = parse_package_json(filepath)
        ecosystem = "npm"
    else:
        print(f"[ERROR] Unsupported file: {path.name}")
        print("Supported files: requirements.txt, package.json")
        sys.exit(1)

    print(f"\n🔍 Scanning {len(packages)} packages from {path.name}...")

    results = []
    for pkg in packages:
        print(f"   Checking {pkg['name']}...", end="\r")
        vulns = check_vulnerability(pkg, ecosystem)
        results.append({"package": pkg, "vulnerabilities": vulns})

    report = format_report(results, len(packages))
    print(report)
    logging.info("Scan complete")
    logging.info(f"Total scanned: {len(packages)}")
    logging.info(f"Total vulnerable: {sum(1 for r in results if r['vulnerabilities'])}")
    logging.info(f"Total clean: {len(packages) - sum(1 for r in results if r['vulnerabilities'])}")

    # Exit code 1 if vulnerabilities found (for CI/CD pipeline integration)
    vulnerable = any(r["vulnerabilities"] for r in results)
    return 1 if vulnerable else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <requirements.txt|package.json>")
        sys.exit(1)
    exit_code = scan(sys.argv[1])
    sys.exit(exit_code)
