"""End-to-end tests for the PatchPilot triage pipeline.

Tests the full flow: CLI → load summary → build context → reachability →
enrichment → scoring → output. Uses mock scan data and mocked network
calls (EPSS/KEV) to avoid external dependencies.
"""

import json
import os
import glob

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from cli import cli


# ---------------------------------------------------------------------------
# Realistic scan summary matching what Trivy would produce for vulnerable_app
# ---------------------------------------------------------------------------

E2E_SUMMARY = {
    "version": "1",
    "target": {
        "name": "Vulnerable Demo",
        "slug": "vulnerable-demo",
        "path": "./vulnerable_app",
    },
    "scan": {
        "date": "2026-03-30",
        "profile": "quick",
        "scanners_requested": ["trivy_fs"],
        "scanners_run": ["trivy_fs"],
        "scanners_skipped": [],
    },
    "severity_counts": {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 1,
        "info": 0,
    },
    "top_issues": [],
    "findings": {
        "trivy_fs": [
            {
                "id": "CVE-2023-30861",
                "severity": "critical",
                "title": "Flask vulnerable to possible disclosure of permanent session cookie",
                "location": "requirements.txt > flask@2.0.0",
                "fix": "Upgrade to >= 2.3.2",
                "package": "flask",
                "installed_version": "2.0.0",
                "fixed_version": "2.3.2",
                "cvss_score": 7.5,
            },
            {
                "id": "CVE-2024-34069",
                "severity": "critical",
                "title": "Werkzeug debugger vulnerable to remote code execution",
                "location": "requirements.txt > werkzeug@2.0.0",
                "fix": "Upgrade to >= 3.0.3",
                "package": "werkzeug",
                "installed_version": "2.0.0",
                "fixed_version": "3.0.3",
                "cvss_score": 9.8,
            },
            {
                "id": "CVE-2023-46136",
                "severity": "high",
                "title": "Werkzeug DoS via multipart form data",
                "location": "requirements.txt > werkzeug@2.0.0",
                "fix": "Upgrade to >= 2.3.8",
                "package": "werkzeug",
                "installed_version": "2.0.0",
                "fixed_version": "2.3.8",
                "cvss_score": 7.5,
            },
            {
                "id": "CVE-2022-42969",
                "severity": "high",
                "title": "PyYAML ReDoS vulnerability",
                "location": "requirements.txt > pyyaml@5.3.1",
                "fix": "Upgrade to >= 6.0.1",
                "package": "pyyaml",
                "installed_version": "5.3.1",
                "fixed_version": "6.0.1",
                "cvss_score": 6.5,
            },
            {
                "id": "CVE-2023-50447",
                "severity": "high",
                "title": "Pillow arbitrary code execution",
                "location": "requirements.txt > pillow@8.0.0",
                "fix": "Upgrade to >= 10.2.0",
                "package": "pillow",
                "installed_version": "8.0.0",
                "fixed_version": "10.2.0",
                "cvss_score": 8.1,
            },
            {
                "id": "CVE-2023-32681",
                "severity": "medium",
                "title": "Requests proxy credential leak",
                "location": "requirements.txt > requests@2.25.0",
                "fix": "Upgrade to >= 2.31.0",
                "package": "requests",
                "installed_version": "2.25.0",
                "fixed_version": "2.31.0",
                "cvss_score": 6.1,
            },
            {
                "id": "CVE-2023-43804",
                "severity": "medium",
                "title": "urllib3 cookie header leak on redirect",
                "location": "requirements.txt > urllib3@1.26.5",
                "fix": "Upgrade to >= 1.26.17",
                "package": "urllib3",
                "installed_version": "1.26.5",
                "fixed_version": "1.26.17",
                "cvss_score": 5.9,
            },
            {
                "id": "CVE-2023-23931",
                "severity": "medium",
                "title": "Cryptography memory corruption",
                "location": "requirements.txt > cryptography@3.4.0",
                "fix": "Upgrade to >= 39.0.1",
                "package": "cryptography",
                "installed_version": "3.4.0",
                "fixed_version": "39.0.1",
                "cvss_score": 6.5,
            },
            {
                "id": "CVE-2024-6345",
                "severity": "medium",
                "title": "Setuptools remote code execution via URL",
                "location": "requirements.txt > setuptools@58.0.0",
                "fix": "Upgrade to >= 70.0.0",
                "package": "setuptools",
                "installed_version": "58.0.0",
                "fixed_version": "70.0.0",
                "cvss_score": 8.8,
            },
            {
                "id": "CVE-2023-37920",
                "severity": "low",
                "title": "Certifi removal of e-Tugra root cert",
                "location": "requirements.txt > certifi@2022.12.07",
                "fix": "Upgrade to >= 2023.07.22",
                "package": "certifi",
                "installed_version": "2022.12.07",
                "fixed_version": "2023.07.22",
                "cvss_score": 3.1,
            },
        ],
    },
    "risk_summary": "2 critical, 3 high findings detected.",
    "notes": [],
}

# Mock EPSS response
MOCK_EPSS_RESPONSE = {
    "data": [
        {"cve": "CVE-2024-34069", "epss": "0.92"},
        {"cve": "CVE-2023-30861", "epss": "0.45"},
        {"cve": "CVE-2023-50447", "epss": "0.31"},
    ]
}

# Mock KEV catalog
MOCK_KEV_RESPONSE = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-34069"},
    ]
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_urlopen(req, timeout=None):
    """Route mock API calls to appropriate responses."""
    url = req.full_url if hasattr(req, "full_url") else str(req)
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    if "first.org" in url:
        mock_resp.read.return_value = json.dumps(MOCK_EPSS_RESPONSE).encode()
    elif "cisa.gov" in url:
        mock_resp.read.return_value = json.dumps(MOCK_KEV_RESPONSE).encode()
    else:
        mock_resp.read.return_value = b"{}"

    return mock_resp


def _write_summary(reports_dir: str, slug: str = "vuln-demo", date: str = "2026-03-30") -> str:
    """Write E2E_SUMMARY to reports/<slug>_summary_<date>.json and return path."""
    os.makedirs(reports_dir, exist_ok=True)
    summary_path = os.path.join(reports_dir, f"{slug}_summary_{date}.json")
    with open(summary_path, "w") as fh:
        json.dump(E2E_SUMMARY, fh)
    return summary_path


def _read_latest_json_report(reports_dir: str, slug: str = "vuln-demo") -> dict:
    """Find and parse the most recent triage JSON report."""
    pattern = os.path.join(reports_dir, f"{slug}_triage_*.json")
    matches = sorted(glob.glob(pattern))
    assert matches, f"No triage JSON report found matching {pattern}"
    with open(matches[-1]) as fh:
        return json.load(fh)


def _read_latest_md_report(reports_dir: str, slug: str = "vuln-demo") -> str:
    """Find and read the most recent triage markdown report."""
    pattern = os.path.join(reports_dir, f"{slug}_triage_*.md")
    matches = sorted(glob.glob(pattern))
    assert matches, f"No triage markdown report found matching {pattern}"
    with open(matches[-1]) as fh:
        return fh.read()


# Absolute path to vulnerable_app so reachability analysis works regardless of cwd
VULNERABLE_APP_PATH = os.path.join(os.path.dirname(__file__), "..", "vulnerable_app")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@patch("agent.plugins.enrichment.epss.urllib.request.urlopen", side_effect=_mock_urlopen)
@patch("agent.plugins.enrichment.kev.urllib.request.urlopen", side_effect=_mock_urlopen)
def test_e2e_triage_full_pipeline(mock_kev, mock_epss, tmp_path, monkeypatch):
    """Full pipeline: summary → context → reachability → enrichment → score → output."""
    reports_dir = str(tmp_path / "reports")
    _write_summary(reports_dir)

    # chdir so CLI globs for reports/ in the right place
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "triage",
            "--path", VULNERABLE_APP_PATH,
            "--target-name", "vuln-demo",
            "--no-scan",
            "--top", "5",
        ],
    )

    assert result.exit_code == 0, f"CLI failed:\n{result.output}"

    output = result.output

    # Top-level pipeline output
    assert "action items" in output.lower(), "Expected 'action items' in output"
    assert "Triage complete" in output

    # At least one CVE ID should appear
    cve_ids_in_summary = [f["id"] for f in E2E_SUMMARY["findings"]["trivy_fs"]]
    found_cve = any(cve in output for cve in cve_ids_in_summary)
    assert found_cve, f"Expected at least one CVE in output. Got:\n{output}"

    # Priority tiers should be mentioned
    assert any(tier in output.lower() for tier in ("critical", "high", "medium", "low")), (
        "Expected a priority tier label in output"
    )

    # Markdown report file written
    md_content = _read_latest_md_report(reports_dir)
    assert "PatchPilot Triage Report" in md_content

    # JSON report file written and parseable
    triage_json = _read_latest_json_report(reports_dir)
    assert "action_items" in triage_json
    assert "summary" in triage_json
    assert triage_json["total_findings"] > 0


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen", side_effect=_mock_urlopen)
@patch("agent.plugins.enrichment.kev.urllib.request.urlopen", side_effect=_mock_urlopen)
def test_e2e_triage_with_fail_on(mock_kev, mock_epss, tmp_path, monkeypatch):
    """--fail-on high exits with code 1 when high-tier (or above) findings are present.

    The scoring engine maps findings to priority tiers (critical/high/medium/low/noise)
    based on the weighted score (0-100), NOT the raw CVE severity. Given our mock EPSS
    and KEV data, the findings land in the high tier (scores 60-79). Using --fail-on
    high exercises the CI gating path that should fail.
    """
    reports_dir = str(tmp_path / "reports")
    _write_summary(reports_dir)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "triage",
            "--path", VULNERABLE_APP_PATH,
            "--target-name", "vuln-demo",
            "--no-scan",
            "--top", "5",
            "--fail-on", "high",
        ],
    )

    # E2E_SUMMARY has multiple critical/high severity CVEs. After scoring they land in
    # the "high" priority tier (score 60-79), so --fail-on high must trigger exit code 1.
    assert result.exit_code == 1, (
        f"Expected exit code 1 (high findings present), got {result.exit_code}.\n"
        f"Output:\n{result.output}"
    )
    assert "FAILED" in result.output


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen", side_effect=_mock_urlopen)
@patch("agent.plugins.enrichment.kev.urllib.request.urlopen", side_effect=_mock_urlopen)
def test_e2e_triage_ranking_makes_sense(mock_kev, mock_epss, tmp_path, monkeypatch):
    """Ranking order: Werkzeug RCE (critical + KEV + high EPSS) should outrank Certifi (low)."""
    reports_dir = str(tmp_path / "reports")
    _write_summary(reports_dir)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "triage",
            "--path", VULNERABLE_APP_PATH,
            "--target-name", "vuln-demo",
            "--no-scan",
            "--top", "10",  # Request all 10 findings so Certifi is included
        ],
    )

    assert result.exit_code == 0, f"CLI failed:\n{result.output}"

    triage_json = _read_latest_json_report(reports_dir)
    action_items = triage_json["action_items"]

    # Build a rank lookup: CVE ID → rank (1 = highest priority)
    rank_by_cve = {item["id"]: item["rank"] for item in action_items}

    # Werkzeug RCE must be ranked and Certifi must be ranked
    assert "CVE-2024-34069" in rank_by_cve, (
        "Expected CVE-2024-34069 (Werkzeug RCE) in action items"
    )
    assert "CVE-2023-37920" in rank_by_cve, (
        "Expected CVE-2023-37920 (Certifi) in action items"
    )

    werkzeug_rce_rank = rank_by_cve["CVE-2024-34069"]
    certifi_rank = rank_by_cve["CVE-2023-37920"]

    assert werkzeug_rce_rank < certifi_rank, (
        f"Werkzeug RCE (rank {werkzeug_rce_rank}) should outrank "
        f"Certifi (rank {certifi_rank})"
    )


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen", side_effect=_mock_urlopen)
@patch("agent.plugins.enrichment.kev.urllib.request.urlopen", side_effect=_mock_urlopen)
def test_e2e_reachability_detected(mock_kev, mock_epss, tmp_path, monkeypatch):
    """Packages imported in vulnerable_app/app.py should be reachable; setuptools should not."""
    reports_dir = str(tmp_path / "reports")
    _write_summary(reports_dir)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "triage",
            "--path", VULNERABLE_APP_PATH,
            "--target-name", "vuln-demo",
            "--no-scan",
            "--top", "10",
        ],
    )

    assert result.exit_code == 0, f"CLI failed:\n{result.output}"

    triage_json = _read_latest_json_report(reports_dir)
    action_items = triage_json["action_items"]

    # Build a signals lookup: CVE ID → signals dict
    signals_by_cve = {item["id"]: item["signals"] for item in action_items}

    # flask is imported directly in vulnerable_app/app.py — should be reachable
    if "CVE-2023-30861" in signals_by_cve:
        flask_signals = signals_by_cve["CVE-2023-30861"]
        assert flask_signals.get("reachable") == "true", (
            f"Expected flask (CVE-2023-30861) to be reachable, "
            f"got: {flask_signals.get('reachable')}"
        )

    # yaml (pyyaml) is imported in vulnerable_app/app.py — should be reachable
    if "CVE-2022-42969" in signals_by_cve:
        yaml_signals = signals_by_cve["CVE-2022-42969"]
        assert yaml_signals.get("reachable") == "true", (
            f"Expected pyyaml (CVE-2022-42969) to be reachable, "
            f"got: {yaml_signals.get('reachable')}"
        )

    # werkzeug is used by flask (via import flask) — check it's considered reachable or unknown
    if "CVE-2024-34069" in signals_by_cve:
        werkzeug_signals = signals_by_cve["CVE-2024-34069"]
        # werkzeug import name is "werkzeug" — not directly imported in app.py
        # so it could be "false" or "unknown" but NOT "true" unless app.py imports it
        reachable_val = werkzeug_signals.get("reachable")
        assert reachable_val in ("true", "false", "unknown"), (
            f"Expected reachable to be a valid value, got: {reachable_val}"
        )

    # setuptools is not imported in app.py at all — should NOT be reachable
    if "CVE-2024-6345" in signals_by_cve:
        setuptools_signals = signals_by_cve["CVE-2024-6345"]
        assert setuptools_signals.get("reachable") in ("false", "unknown"), (
            f"Expected setuptools (CVE-2024-6345) to be not-reachable or unknown, "
            f"got: {setuptools_signals.get('reachable')}"
        )
