"""
Unit tests for LibGuard vulnerability scanner.
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))
from scanner import (
    parse_requirements_txt,
    parse_package_json,
    get_severity,
    format_report
)


# ── Parser Tests ────────────────────────────────────────────

def test_parse_requirements_txt_basic(tmp_path):
    """Test basic requirements.txt parsing with == pinned versions."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.0\nflask==2.0.1\n")
    result = parse_requirements_txt(str(req_file))
    assert len(result) == 2
    assert result[0] == {"name": "requests", "version": "2.28.0"}
    assert result[1] == {"name": "flask", "version": "2.0.1"}


def test_parse_requirements_txt_ignores_comments(tmp_path):
    """Test that comments and blank lines are ignored."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("# This is a comment\n\nrequests==2.28.0\n")
    result = parse_requirements_txt(str(req_file))
    assert len(result) == 1
    assert result[0]["name"] == "requests"


def test_parse_requirements_txt_no_version(tmp_path):
    """Test package with no pinned version."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\n")
    result = parse_requirements_txt(str(req_file))
    assert result[0]["name"] == "requests"
    assert result[0]["version"] is None


def test_parse_requirements_txt_file_not_found():
    """Test that missing file triggers sys.exit."""
    with pytest.raises(SystemExit):
        parse_requirements_txt("/nonexistent/requirements.txt")


def test_parse_package_json_basic(tmp_path):
    """Test basic package.json parsing."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
        "devDependencies": {"jest": "^29.0.0"}
    }))
    result = parse_package_json(str(pkg_file))
    names = [p["name"] for p in result]
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names


def test_parse_package_json_strips_semver_prefix(tmp_path):
    """Test that ^ and ~ prefixes are stripped from versions."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "dependencies": {"express": "^4.18.0"}
    }))
    result = parse_package_json(str(pkg_file))
    assert result[0]["version"] == "4.18.0"


def test_parse_package_json_empty_deps(tmp_path):
    """Test package.json with no dependencies."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({"name": "myapp", "version": "1.0.0"}))
    result = parse_package_json(str(pkg_file))
    assert result == []


def test_parse_package_json_invalid_json(tmp_path):
    """Test that invalid JSON triggers sys.exit."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text("this is not json {{{")
    with pytest.raises(SystemExit):
        parse_package_json(str(pkg_file))


# ── Severity Tests ───────────────────────────────────────────

def test_get_severity_unknown_when_empty():
    """Test that empty severity returns UNKNOWN."""
    vuln = {"severity": []}
    assert get_severity(vuln) == "UNKNOWN"


def test_get_severity_from_database_specific():
    """Test severity extraction from database_specific field."""
    vuln = {"severity": [], "database_specific": {"severity": "HIGH"}}
    assert get_severity(vuln) == "HIGH"


# ── Report Formatting Tests ──────────────────────────────────

def test_format_report_no_vulns():
    """Test report shows clean message when no vulnerabilities."""
    results = [
        {"package": {"name": "requests", "version": "2.28.0"}, "vulnerabilities": []}
    ]
    report = format_report(results, 1)
    assert "No vulnerabilities found" in report


def test_format_report_shows_summary():
    """Test report includes scanned/vulnerable summary."""
    results = [
        {"package": {"name": "requests", "version": "2.28.0"}, "vulnerabilities": []},
        {"package": {"name": "flask", "version": "1.0.0"}, "vulnerabilities": [
            {"id": "CVE-2023-1234", "summary": "Test vuln", "severity": []}
        ]}
    ]
    report = format_report(results, 2)
    assert "Scanned: 2" in report
    assert "Vulnerable: 1" in report
    assert "Clean: 1" in report


def test_format_report_shows_cve_id():
    """Test that CVE IDs appear in the report."""
    results = [
        {"package": {"name": "django", "version": "3.0.0"}, "vulnerabilities": [
            {"id": "CVE-2023-9999", "summary": "SQL injection", "severity": []}
        ]}
    ]
    report = format_report(results, 1)
    assert "CVE-2023-9999" in report
    assert "django" in report
def test_format_report_shows_package_version():
    """Test that package version appears in the report."""
    results = [
        {"package": {"name": "flask", "version": "0.12.0"}, "vulnerabilities": [
            {"id": "CVE-2023-1111", "summary": "Test vulnerability", "severity": []}
        ]}
    ]
    report = format_report(results, 1)
    assert "flask" in report
    assert "0.12.0" in report


def test_format_report_multiple_packages():
    """Test report handles multiple packages correctly."""
    results = [
        {"package": {"name": "requests", "version": "2.18.0"}, "vulnerabilities": []},
        {"package": {"name": "django", "version": "2.2.0"}, "vulnerabilities": []},
        {"package": {"name": "flask", "version": "0.12.0"}, "vulnerabilities": []},
    ]
    report = format_report(results, 3)
    assert "Scanned: 3" in report
    assert "Vulnerable: 0" in report
    assert "Clean: 3" in report


def test_parse_requirements_txt_greater_than_version(tmp_path):
    """Test parsing >= version format."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests>=2.28.0\n")
    result = parse_requirements_txt(str(req_file))
    assert result[0]["name"] == "requests"
    assert result[0]["version"] == "2.28.0"
    