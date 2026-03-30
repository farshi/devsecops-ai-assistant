"""
Tests for agent/security_summary.py — report generation logic.
"""

import json
import os
import pytest
from unittest.mock import patch, mock_open

from agent import security_summary


MINIMAL_SUMMARY = {
    "version": "1",
    "target": {"name": "Test App", "slug": "test-app", "path": "/app"},
    "scan": {
        "date": "2026-03-27",
        "profile": "standard",
        "scanners_requested": ["trivy_fs"],
        "scanners_run": ["trivy_fs"],
        "scanners_skipped": [],
    },
    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    "top_issues": [],
    "findings": {"trivy_fs": []},
    "risk_summary": "No findings detected across all scanners.",
    "notes": [],
}


def test_no_summary_file_raises(tmp_path, monkeypatch):
    """run() raises FileNotFoundError when no summary JSON exists for the target."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError, match="Run `scan` first"):
        security_summary.run("Test App", "test-app")


def test_missing_api_key_raises(tmp_path, monkeypatch):
    """run() raises RuntimeError when ANTHROPIC_API_KEY is not set."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        security_summary.run("Test App", "test-app")


def test_report_written_on_success(tmp_path, monkeypatch):
    """run() writes a markdown report file and returns its path."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.claude_client.call", return_value="## Risk Overview\nNo findings."):
        out_path = security_summary.run("Test App", "test-app")

    assert os.path.exists(out_path)
    content = open(out_path).read()
    assert "# Security Report — Test App" in content
    assert "No findings." in content


# ---------------------------------------------------------------------------
# run_with_triage() tests
# ---------------------------------------------------------------------------

MOCK_TRIAGE = {
    "triage": {
        "total_findings": 1,
        "action_items": [{"rank": 1, "id": "CVE-2024-0001", "priority_tier": "critical",
                          "priority_score": 90, "title": "Test", "action": "Upgrade",
                          "effort": "trivial", "signals": {}}],
        "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "noise": 0},
    },
    "markdown": "# PatchPilot Triage\n\nTest",
}


def test_run_with_triage_writes_report(tmp_path, monkeypatch):
    """run_with_triage() writes a markdown report file and returns its path."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         patch("agent.claude_client.call", return_value="## Action Plan\nFix it."):
        out_path = security_summary.run_with_triage("Test App", "test-app", str(tmp_path))

    assert os.path.exists(out_path)
    content = open(out_path).read()
    assert "# Security Report — Test App" in content
    assert "Fix it." in content


def test_run_with_triage_sends_triage_to_claude(tmp_path, monkeypatch):
    """run_with_triage() sends a user_message containing 'triage' and 'instructions' to Claude."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    captured = {}

    def fake_call(system_prompt, user_message):
        captured["user_message"] = user_message
        return "## Report"

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         patch("agent.claude_client.call", side_effect=fake_call):
        security_summary.run_with_triage("Test App", "test-app", str(tmp_path))

    assert "triage" in captured["user_message"]
    assert "instructions" in captured["user_message"]


def test_run_with_triage_missing_api_key(tmp_path, monkeypatch):
    """run_with_triage() raises RuntimeError when ANTHROPIC_API_KEY is not set."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        security_summary.run_with_triage("Test App", "test-app", str(tmp_path))
