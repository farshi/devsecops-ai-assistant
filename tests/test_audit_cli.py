"""Tests for the `audit` CLI command."""

import json

from click.testing import CliRunner

from cli import cli


def _seed_audit(tmp_path):
    """Create some audit entries via state operations."""
    runner = CliRunner()
    runner.invoke(cli, ["dismiss", "--path", str(tmp_path), "--cve", "CVE-2023-001", "--reason", "noise"])
    runner.invoke(cli, ["close", "--path", str(tmp_path), "--cve", "CVE-2023-002", "--reason", "upgraded"])
    runner.invoke(cli, ["assign", "--path", str(tmp_path), "--cve", "CVE-2023-003", "--to", "alice@co.com"])


def test_audit_basic(tmp_path):
    """audit command shows entries."""
    _seed_audit(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "CVE-2023-001" in result.output
    assert "CVE-2023-002" in result.output
    assert "dismiss" in result.output
    assert "close" in result.output


def test_audit_json(tmp_path):
    """audit --json outputs valid JSON."""
    _seed_audit(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    entries = json.loads(result.output)
    assert len(entries) == 3


def test_audit_filter_cve(tmp_path):
    """audit --cve filters to specific CVE."""
    _seed_audit(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--path", str(tmp_path), "--cve", "CVE-2023-002"])
    assert result.exit_code == 0
    assert "CVE-2023-002" in result.output
    assert "CVE-2023-001" not in result.output


def test_audit_empty(tmp_path):
    """audit with no entries shows message."""
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "No audit entries" in result.output


def test_audit_limit(tmp_path):
    """audit --limit caps output."""
    _seed_audit(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--path", str(tmp_path), "--json", "--limit", "1"])
    assert result.exit_code == 0
    entries = json.loads(result.output)
    assert len(entries) == 1
