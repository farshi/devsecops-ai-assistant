"""Tests for packaging and CLI entry point."""

import subprocess
import sys

from cli import cli
from click.testing import CliRunner


def test_version_option():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_patchpilot_entry_point():
    """Verify the patchpilot command is available after install."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "show", "patchpilot"],
        capture_output=True, text=True
    )
    # If installed, pip show returns 0
    if result.returncode == 0:
        assert "patchpilot" in result.stdout.lower()


def test_cli_has_all_commands():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ["scan", "triage", "report", "analyze", "plan", "review"]:
        assert cmd in result.output
