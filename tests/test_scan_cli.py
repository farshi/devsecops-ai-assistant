"""Tests for the `scan` CLI command and trivy check utility."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cli import cli
from agent.utils import check_trivy_installed


# ---------------------------------------------------------------------------
# check_trivy_installed
# ---------------------------------------------------------------------------

def test_check_trivy_installed():
    """check_trivy_installed returns a boolean."""
    result = check_trivy_installed()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

def test_scan_dry_run():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--path", "./sample_app", "--target-name", "test", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would run" in result.output


def test_scan_missing_trivy_gives_clear_error():
    """When trivy is not installed, scan should give a clear install message."""
    runner = CliRunner()
    with patch("cli.check_trivy_installed", return_value=False):
        result = runner.invoke(cli, [
            "scan", "--path", ".", "--target-name", "test"
        ])
        assert result.exit_code != 0
        assert "Trivy is not installed" in result.output
        assert "brew install trivy" in result.output


def test_scan_trivy_check_skipped_in_dry_run():
    """Trivy check must not block --dry-run (no scanning happens)."""
    runner = CliRunner()
    with patch("cli.check_trivy_installed", return_value=False):
        result = runner.invoke(cli, [
            "scan", "--path", ".", "--target-name", "test", "--dry-run"
        ])
        # dry-run exits 0 — trivy check is never reached
        assert result.exit_code == 0
        assert "Would run" in result.output
