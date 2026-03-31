"""Tests for agent/review.py — security review of git diffs."""

import os
import pytest
from unittest.mock import patch

from click.testing import CliRunner

from agent import review
from cli import cli


# ---------------------------------------------------------------------------
# Unit tests: agent/review.py
# ---------------------------------------------------------------------------

def test_review_empty_diff(monkeypatch):
    """When the diff is empty, verdict is PASS and review_text says no changes."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    with patch("agent.review._get_diff", return_value=("", [])):
        result = review.run(".", "test")
    assert result["verdict"] == "PASS"
    assert "No changes" in result["review_text"]
    assert result["changed_files"] == []
    assert result["diff_stats"] == {"insertions": 0, "deletions": 0}


@patch("agent.review._get_diff", return_value=("diff content here", ["file1.py"]))
@patch("agent.review.llm_client.call", return_value="## Verdict\n**PASS**\nLooks good.")
def test_review_extracts_pass(mock_call, mock_diff, monkeypatch):
    """Verdict PASS is extracted correctly from LLM response."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    result = review.run(".", "test")
    assert result["verdict"] == "PASS"


@patch("agent.review._get_diff", return_value=("diff content here", ["file1.py"]))
@patch("agent.review.llm_client.call", return_value="## Verdict\n**WARN**\nMinor issues found.")
def test_review_extracts_warn(mock_call, mock_diff, monkeypatch):
    """Verdict WARN is extracted correctly from LLM response."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    result = review.run(".", "test")
    assert result["verdict"] == "WARN"


@patch("agent.review._get_diff", return_value=("diff content here", ["file1.py"]))
@patch("agent.review.llm_client.call", return_value="## Verdict\n**BLOCK**\nCritical issue found.")
def test_review_extracts_block(mock_call, mock_diff, monkeypatch):
    """Verdict BLOCK is extracted correctly from LLM response."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    result = review.run(".", "test")
    assert result["verdict"] == "BLOCK"


@patch("agent.review._get_diff", return_value=("diff content here", ["file1.py", "file2.py", "file3.py"]))
@patch("agent.review.llm_client.call", return_value="## Verdict\n**PASS**\nLooks good.")
def test_review_returns_changed_files(mock_call, mock_diff, monkeypatch):
    """Result contains the changed_files list from the diff."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    result = review.run(".", "test")
    assert result["changed_files"] == ["file1.py", "file2.py", "file3.py"]
    assert len(result["changed_files"]) == 3


def test_review_missing_api_key(monkeypatch):
    """RuntimeError is raised when API key is not set."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with patch("agent.review._get_diff", return_value=("some diff content", ["file1.py"])):
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            review.run(".", "test")


@patch("agent.review._get_diff", return_value=("x" * 100000, ["file1.py"]))
@patch("agent.review.llm_client.call", return_value="## Verdict\n**PASS**\nLooks good.")
def test_review_caps_diff_size(mock_call, mock_diff, monkeypatch):
    """Huge diffs are capped at 50k chars and do not crash."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    result = review.run(".", "test")
    # Should not raise and should return a valid result
    assert result["verdict"] == "PASS"
    # Verify the call was made (diff was capped internally)
    mock_call.assert_called_once()
    import json
    call_args = mock_call.call_args[0]
    user_message = json.loads(call_args[1])
    assert len(user_message["diff"]["patch"]) <= 50000


# ---------------------------------------------------------------------------
# Unit tests: _extract_verdict
# ---------------------------------------------------------------------------

def test_extract_verdict_pass():
    assert review._extract_verdict("## Verdict\n**PASS**\nAll good.") == "PASS"


def test_extract_verdict_warn():
    assert review._extract_verdict("## Verdict\n**WARN**\nMinor issues.") == "WARN"


def test_extract_verdict_block():
    assert review._extract_verdict("## Verdict\n**BLOCK**\nCritical issue.") == "BLOCK"


def test_extract_verdict_defaults_to_pass():
    """When no verdict keyword is found, defaults to PASS."""
    assert review._extract_verdict("Some generic text with no verdict.") == "PASS"


def test_extract_verdict_case_insensitive():
    """Verdict detection is case-insensitive."""
    assert review._extract_verdict("**block** — must fix") == "BLOCK"
    assert review._extract_verdict("**warn** — check this") == "WARN"


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

def test_review_cli_dry_run():
    """--dry-run exits 0 and shows what would run without executing."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["review", "--path", ".", "--target-name", "test", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would run" in result.output


def test_review_cli_block_exits_1(monkeypatch, tmp_path):
    """When review returns verdict=BLOCK, CLI exits with code 1."""
    runner = CliRunner()
    with patch("agent.review.run", return_value={
        "verdict": "BLOCK",
        "review_text": "Critical issue found.",
        "changed_files": ["file1.py"],
        "diff_stats": {"insertions": 5, "deletions": 2},
    }):
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--path", ".", "--target-name", "test"],
            )
    assert result.exit_code == 1


def test_review_cli_pass_exits_0(monkeypatch, tmp_path):
    """When review returns verdict=PASS, CLI exits with code 0."""
    runner = CliRunner()
    with patch("agent.review.run", return_value={
        "verdict": "PASS",
        "review_text": "No issues found.",
        "changed_files": ["file1.py"],
        "diff_stats": {"insertions": 3, "deletions": 1},
    }):
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--path", ".", "--target-name", "test"],
            )
    assert result.exit_code == 0
    assert "PASS" in result.output
    assert "Review written" in result.output


def test_review_cli_runtime_error_becomes_click_exception(monkeypatch):
    """RuntimeError from review agent is shown as a ClickException (not a traceback)."""
    runner = CliRunner()
    with patch("agent.review.run", side_effect=RuntimeError("ANTHROPIC_API_KEY not set")):
        result = runner.invoke(
            cli,
            ["review", "--path", ".", "--target-name", "test"],
        )
    assert result.exit_code != 0
    assert "ANTHROPIC_API_KEY" in result.output


def test_review_cli_mutually_exclusive_flags():
    """--diff and --branch cannot be used together."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["review", "--path", ".", "--target-name", "test", "--diff", "--branch", "main"],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output
