"""Tests for the `triage` CLI command."""

import json
import os
import tempfile

import pytest
from click.testing import CliRunner

from cli import cli


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

MOCK_TRIAGE_RESULT = {
    "triage": {
        "total_findings": 3,
        "top_n": 3,
        "action_items": [
            {
                "rank": 1,
                "id": "CVE-2024-0001",
                "priority_tier": "critical",
                "priority_score": 92,
                "package": "test-pkg",
                "installed_version": "1.0",
                "fixed_version": "2.0",
                "severity": "critical",
                "title": "Test vuln",
                "action": "Upgrade test-pkg",
                "effort": "trivial",
                "signals": {
                    "reachable": "true",
                    "reachability_confidence": "high",
                    "epss_score": 0.9,
                    "in_kev": True,
                    "fix_available": True,
                },
            }
        ],
        "summary": {"critical": 1, "high": 1, "medium": 1, "low": 0, "noise": 0},
    },
    "markdown": "# PatchPilot Triage Report\n\nTest output",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_triage_dry_run():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "--path", "./sample_app", "--target-name", "test", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would run" in result.output


def test_triage_no_scan_no_summary_errors():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "triage",
            "--path", "./sample_app",
            "--target-name", "nonexistent",
            "--no-scan",
        ],
    )
    assert result.exit_code != 0
    assert "No summary found" in result.output


def test_triage_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["triage", "--help"])
    assert result.exit_code == 0
    assert "Smart vulnerability triage" in result.output
    assert "--top" in result.output
    assert "--scan" in result.output


def test_triage_with_existing_summary(tmp_path):
    """Picks up an existing summary and outputs results (mocked pipeline)."""
    from unittest.mock import patch

    # Create a minimal summary JSON where run_triage can find it
    summary_data = {
        "scan_meta": {
            "target": "test",
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
            "total_findings": 3,
        },
        "findings": [],
    }

    # Write summary into reports/ relative to cwd (CliRunner uses os.getcwd)
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_file = os.path.join(reports_dir, "test_summary_2026-03-30.json")
    with open(summary_file, "w") as f:
        json.dump(summary_data, f)

    try:
        runner = CliRunner()
        with patch("agent.prioritizer.run_triage", return_value=MOCK_TRIAGE_RESULT):
            result = runner.invoke(
                cli,
                [
                    "triage",
                    "--path", ".",
                    "--target-name", "test",
                    "--no-scan",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "Triage complete" in result.output
        assert "Total findings" in result.output
        assert "CVE-2024-0001" in result.output
    finally:
        # Clean up the summary file we created
        if os.path.exists(summary_file):
            os.remove(summary_file)


def test_cli_group_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "PatchPilot" in result.output


# ---------------------------------------------------------------------------
# Helper to build a summary file and invoke triage with a mocked pipeline
# ---------------------------------------------------------------------------

def _make_summary_file(reports_dir, target_slug="test"):
    summary_data = {
        "scan_meta": {
            "target": target_slug,
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
            "total_findings": 5,
        },
        "findings": [],
    }
    summary_file = os.path.join(reports_dir, f"{target_slug}_summary_2026-03-30.json")
    with open(summary_file, "w") as f:
        json.dump(summary_data, f)
    return summary_file


def _make_triage_result(summary_override=None):
    result = {
        "triage": {
            "total_findings": 5,
            "top_n": 5,
            "action_items": [],
            "summary": summary_override or {"critical": 0, "high": 0, "medium": 0, "low": 0, "noise": 0},
        },
        "markdown": "# PatchPilot Triage Report\n\nTest output",
    }
    return result


# ---------------------------------------------------------------------------
# --fail-on tests
# ---------------------------------------------------------------------------

def test_triage_fail_on_critical_no_findings(tmp_path):
    """--fail-on critical with no critical findings → exit 0, output PASSED."""
    from unittest.mock import patch

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_file = _make_summary_file(reports_dir)

    triage_result = _make_triage_result({"critical": 0, "high": 0, "medium": 0, "low": 0, "noise": 0})

    try:
        runner = CliRunner()
        with patch("agent.prioritizer.run_triage", return_value=triage_result):
            result = runner.invoke(
                cli,
                ["triage", "--path", ".", "--target-name", "test", "--no-scan", "--fail-on", "critical"],
            )
        assert result.exit_code == 0, result.output
        assert "PASSED" in result.output
    finally:
        if os.path.exists(summary_file):
            os.remove(summary_file)


def test_triage_fail_on_critical_with_findings(tmp_path):
    """--fail-on critical with 1 critical finding → exit 1, output FAILED."""
    from unittest.mock import patch

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_file = _make_summary_file(reports_dir)

    triage_result = _make_triage_result({"critical": 1, "high": 0, "medium": 0, "low": 0, "noise": 0})

    try:
        runner = CliRunner()
        with patch("agent.prioritizer.run_triage", return_value=triage_result):
            result = runner.invoke(
                cli,
                ["triage", "--path", ".", "--target-name", "test", "--no-scan", "--fail-on", "critical"],
            )
        assert result.exit_code == 1, result.output
        assert "FAILED" in result.output
    finally:
        if os.path.exists(summary_file):
            os.remove(summary_file)


def test_triage_fail_on_high_includes_critical(tmp_path):
    """--fail-on high with a critical finding → exit 1 (critical is above high threshold)."""
    from unittest.mock import patch

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_file = _make_summary_file(reports_dir)

    triage_result = _make_triage_result({"critical": 1, "high": 0, "medium": 0, "low": 0, "noise": 0})

    try:
        runner = CliRunner()
        with patch("agent.prioritizer.run_triage", return_value=triage_result):
            result = runner.invoke(
                cli,
                ["triage", "--path", ".", "--target-name", "test", "--no-scan", "--fail-on", "high"],
            )
        assert result.exit_code == 1, result.output
        assert "FAILED" in result.output
    finally:
        if os.path.exists(summary_file):
            os.remove(summary_file)


def test_triage_fail_on_medium_passes_with_only_low(tmp_path):
    """--fail-on medium with only low findings → exit 0 (low is below medium threshold)."""
    from unittest.mock import patch

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_file = _make_summary_file(reports_dir)

    triage_result = _make_triage_result({"critical": 0, "high": 0, "medium": 0, "low": 3, "noise": 0})

    try:
        runner = CliRunner()
        with patch("agent.prioritizer.run_triage", return_value=triage_result):
            result = runner.invoke(
                cli,
                ["triage", "--path", ".", "--target-name", "test", "--no-scan", "--fail-on", "medium"],
            )
        assert result.exit_code == 0, result.output
        assert "PASSED" in result.output
    finally:
        if os.path.exists(summary_file):
            os.remove(summary_file)


def test_triage_fail_on_in_dry_run():
    """--fail-on with --dry-run mentions the exit gating step, no real execution."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["triage", "--path", "./sample_app", "--target-name", "test", "--dry-run", "--fail-on", "critical"],
    )
    assert result.exit_code == 0, result.output
    assert "Would run" in result.output
    assert "critical" in result.output
    assert "exit 1" in result.output


def test_triage_missing_trivy_gives_clear_error():
    """When trivy is not installed, triage should give a clear install message."""
    from unittest.mock import patch

    runner = CliRunner()
    with patch("cli.check_trivy_installed", return_value=False):
        result = runner.invoke(cli, [
            "triage", "--path", ".", "--target-name", "test"
        ])
        assert result.exit_code != 0
        assert "Trivy is not installed" in result.output
        assert "brew install trivy" in result.output
