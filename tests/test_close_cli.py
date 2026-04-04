"""Tests for the `close` CLI command."""

import json
import os

from click.testing import CliRunner

from cli import cli


def test_close_basic(tmp_path):
    """close command writes CVE to state.json closed section."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["close", "--path", str(tmp_path), "--cve", "CVE-2023-1234", "--reason", "upgraded"],
    )
    assert result.exit_code == 0
    assert "Closed CVE-2023-1234" in result.output
    assert "upgraded" in result.output

    state_file = tmp_path / ".patchpilot" / "state.json"
    assert state_file.is_file()
    state = json.loads(state_file.read_text())
    assert "CVE-2023-1234" in state["closed"]
    assert state["closed"]["CVE-2023-1234"]["reason"] == "upgraded"


def test_close_no_reason(tmp_path):
    """close command works without --reason."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["close", "--path", str(tmp_path), "--cve", "CVE-2023-5678"],
    )
    assert result.exit_code == 0
    assert "Closed CVE-2023-5678" in result.output

    state_file = tmp_path / ".patchpilot" / "state.json"
    state = json.loads(state_file.read_text())
    assert "CVE-2023-5678" in state["closed"]
    assert state["closed"]["CVE-2023-5678"]["reason"] == ""


def test_close_requires_cve():
    """close command fails without --cve."""
    runner = CliRunner()
    result = runner.invoke(cli, ["close"])
    assert result.exit_code != 0
    assert "Missing" in result.output or "required" in result.output.lower() or "Error" in result.output
