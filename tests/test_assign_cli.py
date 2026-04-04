"""Tests for the `assign` and `unassign` CLI commands."""

import json

from click.testing import CliRunner

from cli import cli


def test_assign_basic(tmp_path):
    """assign command writes CVE assignment to state.json."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["assign", "--path", str(tmp_path), "--cve", "CVE-2023-1234",
         "--to", "alice@company.com", "--reason", "owns auth module"],
    )
    assert result.exit_code == 0
    assert "Assigned CVE-2023-1234" in result.output
    assert "alice@company.com" in result.output
    assert "owns auth module" in result.output

    state_file = tmp_path / ".patchpilot" / "state.json"
    assert state_file.is_file()
    state = json.loads(state_file.read_text())
    assert "CVE-2023-1234" in state["assignments"]
    assert state["assignments"]["CVE-2023-1234"]["assigned_to"] == "alice@company.com"


def test_assign_no_reason(tmp_path):
    """assign command works without --reason."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["assign", "--path", str(tmp_path), "--cve", "CVE-2023-5678",
         "--to", "@security-team"],
    )
    assert result.exit_code == 0
    assert "Assigned CVE-2023-5678" in result.output
    assert "@security-team" in result.output


def test_assign_requires_cve():
    """assign command fails without --cve."""
    runner = CliRunner()
    result = runner.invoke(cli, ["assign", "--to", "alice@co.com"])
    assert result.exit_code != 0


def test_assign_requires_to():
    """assign command fails without --to."""
    runner = CliRunner()
    result = runner.invoke(cli, ["assign", "--cve", "CVE-2023-1234"])
    assert result.exit_code != 0


def test_unassign_basic(tmp_path):
    """unassign command removes CVE assignment from state.json."""
    runner = CliRunner()
    # First assign
    runner.invoke(
        cli,
        ["assign", "--path", str(tmp_path), "--cve", "CVE-2023-9999",
         "--to", "alice@company.com"],
    )
    # Then unassign
    result = runner.invoke(
        cli,
        ["unassign", "--path", str(tmp_path), "--cve", "CVE-2023-9999"],
    )
    assert result.exit_code == 0
    assert "Unassigned CVE-2023-9999" in result.output

    state_file = tmp_path / ".patchpilot" / "state.json"
    state = json.loads(state_file.read_text())
    assert "CVE-2023-9999" not in state["assignments"]


def test_unassign_requires_cve():
    """unassign command fails without --cve."""
    runner = CliRunner()
    result = runner.invoke(cli, ["unassign"])
    assert result.exit_code != 0
