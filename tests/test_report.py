"""
Tests for agent/security_summary.py — report generation logic.
"""

import json
import os
import pytest
from click.testing import CliRunner
from unittest.mock import patch, mock_open

from cli import cli
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
    """run() raises RuntimeError when OPENAI_API_KEY is not set by default."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("PATCHPILOT_LLM_PROVIDER", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        security_summary.run("Test App", "test-app")


def test_report_written_on_success(tmp_path, monkeypatch):
    """run() writes a markdown report file and returns its path."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.llm_client.call", return_value="## Risk Overview\nNo findings."):
        out_path = security_summary.run("Test App", "test-app")

    assert os.path.exists(out_path)
    content = open(out_path).read()
    assert "# Security Report — Test App" in content
    assert "No findings." in content


def test_report_uses_openai_provider_from_env(tmp_path, monkeypatch):
    """run() can use OpenAI when PATCHPILOT_LLM_PROVIDER=openai."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATCHPILOT_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    captured = {}

    def fake_call(system_prompt, user_message, provider="claude"):
        captured["provider"] = provider
        return "## Risk Overview\nNo findings."

    with patch("agent.llm_client.call", side_effect=fake_call):
        security_summary.run("Test App", "test-app")

    assert captured["provider"] == "openai"


def test_report_cli_derives_target_name_from_path(tmp_path):
    """report --path derives target-name instead of crashing on None."""
    runner = CliRunner()
    app_dir = tmp_path / "my-app"
    app_dir.mkdir()

    with patch("agent.security_summary.run_with_triage", return_value="reports/my-app.md"):
        result = runner.invoke(
            cli,
            ["report", "--path", str(app_dir), "--dry-run"],
        )

    assert result.exit_code == 0
    assert "target-name : my-app" in result.output


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
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         patch("agent.llm_client.call", return_value="## Action Plan\nFix it."):
        out_path = security_summary.run_with_triage("Test App", "test-app", str(tmp_path))

    assert os.path.exists(out_path)
    content = open(out_path).read()
    assert "# Security Report — Test App" in content
    assert "Fix it." in content


def test_run_with_triage_sends_triage_to_llm(tmp_path, monkeypatch):
    """run_with_triage() sends a user_message containing 'triage' and 'instructions' to the LLM."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    captured = {}

    def fake_call(system_prompt, user_message, provider="claude"):
        captured["user_message"] = user_message
        return "## Report"

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         patch("agent.llm_client.call", side_effect=fake_call):
        security_summary.run_with_triage("Test App", "test-app", str(tmp_path))

    assert "triage" in captured["user_message"]
    assert "instructions" in captured["user_message"]


def test_run_with_triage_missing_api_key(tmp_path, monkeypatch):
    """run_with_triage() raises RuntimeError when OPENAI_API_KEY is not set by default."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        security_summary.run_with_triage("Test App", "test-app", str(tmp_path))


def test_run_with_triage_uses_openai_provider_from_config(tmp_path, monkeypatch):
    """run_with_triage() can use OpenAI from .patchpilot/config.yaml."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    summary_file = reports_dir / "test-app_summary_2026-03-27.json"
    summary_file.write_text(json.dumps(MINIMAL_SUMMARY))

    config_dir = tmp_path / ".patchpilot"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text("llm_provider: openai\n")

    captured = {}

    def fake_call(system_prompt, user_message, provider="claude"):
        captured["provider"] = provider
        return "## Action Plan\nFix it."

    with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE), \
         patch("agent.llm_client.call", side_effect=fake_call):
        security_summary.run_with_triage("Test App", "test-app", str(tmp_path))

    assert captured["provider"] == "openai"
