"""Tests for agent/ownership.py — finding ownership resolution."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from agent.ownership import (
    _extract_file_path,
    _git_blame_owner,
    _match_codeowners,
    _parse_blame_output,
    _parse_codeowners,
    resolve_owners,
)

# ---------------------------------------------------------------------------
# Sample git blame porcelain output
# ---------------------------------------------------------------------------

BLAME_OUTPUT = """\
abc123def456789 1 1 1
author John Doe
author-mail <john@example.com>
author-time 1711900000
author-tz +0000
committer John Doe
committer-mail <john@example.com>
committer-time 1711900000
committer-tz +0000
summary Some commit message
filename requirements.txt
\tfastapi==0.104.1
def456789abc123 2 2 1
author Jane Smith
author-mail <jane@example.com>
author-time 1711800000
author-tz +0000
committer Jane Smith
committer-mail <jane@example.com>
committer-time 1711800000
committer-tz +0000
summary Another commit
filename requirements.txt
\tuvicorn==0.24.0
abc123def456789 3 3 1
author John Doe
author-mail <john@example.com>
author-time 1711900000
author-tz +0000
committer John Doe
committer-mail <john@example.com>
committer-time 1711900000
committer-tz +0000
summary Some commit message
filename requirements.txt
\tpydantic==2.5.0
"""

# ---------------------------------------------------------------------------
# _extract_file_path tests
# ---------------------------------------------------------------------------

def test_extract_file_path_plain():
    assert _extract_file_path("requirements.txt") == "requirements.txt"


def test_extract_file_path_with_package():
    assert _extract_file_path("requirements.txt > fastapi@0.104.1") == "requirements.txt"


def test_extract_file_path_with_line():
    assert _extract_file_path("app/main.py:42") == "app/main.py"


def test_extract_file_path_empty():
    assert _extract_file_path("") is None


# ---------------------------------------------------------------------------
# _parse_codeowners tests
# ---------------------------------------------------------------------------

CODEOWNERS_CONTENT = """\
# This is a comment
*.py @dev-team
docs/ @docs-team
*.md @docs-team @dev-team
"""

def test_parse_codeowners(tmp_path):
    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    codeowners_file = github_dir / "CODEOWNERS"
    codeowners_file.write_text(CODEOWNERS_CONTENT)

    rules = _parse_codeowners(str(tmp_path))
    assert len(rules) == 3
    assert rules[0] == ("*.py", "@dev-team")
    assert rules[1] == ("docs/", "@docs-team")
    assert rules[2] == ("*.md", "@docs-team")


def test_parse_codeowners_not_found(tmp_path):
    rules = _parse_codeowners(str(tmp_path))
    assert rules == []


# ---------------------------------------------------------------------------
# _match_codeowners tests
# ---------------------------------------------------------------------------

def test_match_codeowners_glob():
    rules = [("*.py", "@dev-team")]
    assert _match_codeowners("app/main.py", rules) == "@dev-team"


def test_match_codeowners_directory():
    rules = [("docs/", "@docs-team")]
    assert _match_codeowners("docs/README.md", rules) == "@docs-team"


def test_match_codeowners_last_wins():
    rules = [
        ("*.py", "@dev-team"),
        ("app/main.py", "@backend-team"),
    ]
    assert _match_codeowners("app/main.py", rules) == "@backend-team"


# ---------------------------------------------------------------------------
# _git_blame_owner tests
# ---------------------------------------------------------------------------

def test_git_blame_owner(tmp_path):
    """Mock subprocess to return blame output; verify top author is returned."""
    # Create a fake file so the existence check passes
    fake_file = tmp_path / "requirements.txt"
    fake_file.write_text("fastapi==0.104.1\n")

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = BLAME_OUTPUT

    with patch("subprocess.run", return_value=mock_result):
        owner = _git_blame_owner("requirements.txt", str(tmp_path))

    assert owner is not None
    assert owner["name"] == "John Doe"
    assert owner["email"] == "john@example.com"
    assert owner["source"] == "git_blame"


def test_git_blame_timeout(tmp_path):
    """subprocess.TimeoutExpired should return None gracefully."""
    fake_file = tmp_path / "requirements.txt"
    fake_file.write_text("fastapi==0.104.1\n")

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10)):
        owner = _git_blame_owner("requirements.txt", str(tmp_path))

    assert owner is None


def test_git_blame_file_not_found(tmp_path):
    """If file does not exist in repo_path, return None without calling subprocess."""
    with patch("subprocess.run") as mock_run:
        owner = _git_blame_owner("nonexistent.txt", str(tmp_path))

    assert owner is None
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# _parse_blame_output tests
# ---------------------------------------------------------------------------

def test_parse_blame_output():
    result = _parse_blame_output(BLAME_OUTPUT)
    assert result is not None
    assert result["name"] == "John Doe"
    assert result["email"] == "john@example.com"
    assert result["source"] == "git_blame"


def test_parse_blame_output_empty():
    result = _parse_blame_output("")
    assert result is None


# ---------------------------------------------------------------------------
# resolve_owners tests
# ---------------------------------------------------------------------------

def test_resolve_owners_codeowners_priority(tmp_path):
    """CODEOWNERS match takes priority over git blame."""
    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    (github_dir / "CODEOWNERS").write_text("*.txt @security-team\n")

    # Create a fake requirements.txt so the blame existence check passes
    (tmp_path / "requirements.txt").write_text("fastapi\n")

    action_items = [
        {"location": "requirements.txt", "id": "CVE-2024-0001"},
    ]

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = BLAME_OUTPUT

    with patch("subprocess.run", return_value=mock_result):
        result = resolve_owners(action_items, str(tmp_path))

    assert result[0]["owner"]["name"] == "@security-team"
    assert result[0]["owner"]["source"] == "codeowners"


def test_resolve_owners_fallback_to_blame(tmp_path):
    """No CODEOWNERS match, falls back to git blame."""
    # No CODEOWNERS file
    (tmp_path / "requirements.txt").write_text("fastapi\n")

    action_items = [
        {"location": "requirements.txt", "id": "CVE-2024-0001"},
    ]

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = BLAME_OUTPUT

    with patch("subprocess.run", return_value=mock_result):
        result = resolve_owners(action_items, str(tmp_path))

    assert result[0]["owner"]["name"] == "John Doe"
    assert result[0]["owner"]["source"] == "git_blame"


def test_resolve_owners_no_owner(tmp_path):
    """No CODEOWNERS, no blame match -> source: 'none'."""
    action_items = [
        {"location": "requirements.txt", "id": "CVE-2024-0001"},
    ]

    # requirements.txt does not exist => blame returns None
    result = resolve_owners(action_items, str(tmp_path))

    assert result[0]["owner"]["name"] is None
    assert result[0]["owner"]["source"] == "none"


def test_resolve_owners_caps_at_20_files(tmp_path):
    """With 25 items mapping to unique files, only the first 20 get blamed."""
    # Create 25 distinct files
    for i in range(25):
        (tmp_path / f"file_{i}.txt").write_text(f"content {i}\n")

    action_items = [
        {"location": f"file_{i}.txt", "id": f"CVE-2024-{i:04d}"}
        for i in range(25)
    ]

    call_count = 0
    original_run = subprocess.run

    def counting_run(cmd, **kwargs):
        nonlocal call_count
        if "blame" in cmd:
            call_count += 1
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        return mock_result

    with patch("subprocess.run", side_effect=counting_run):
        resolve_owners(action_items, str(tmp_path))

    assert call_count == 20
