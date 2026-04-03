"""Tests for agent/pr_commenter.py — PR comment integration."""

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from agent.pr_commenter import (
    COMMENT_MARKER,
    post_pr_comment,
    _check_gh_available,
    _detect_pr_number,
    _find_existing_comment,
    _build_comment_body,
    _create_comment,
    _update_comment,
)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_TRIAGE = {
    "summary": {"critical": 1, "high": 2, "medium": 3, "low": 1, "noise": 0},
    "action_items": [{"id": "CVE-2024-0001", "rank": 1}],
}

SAMPLE_MARKDOWN = "# PatchPilot Triage Report\n\n**Total:** 7 findings"


# ---------------------------------------------------------------------------
# _check_gh_available
# ---------------------------------------------------------------------------

class TestCheckGhAvailable:
    @patch("agent.pr_commenter.subprocess.run")
    def test_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert _check_gh_available() is True

    @patch("agent.pr_commenter.subprocess.run")
    def test_not_authenticated(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert _check_gh_available() is False

    @patch("agent.pr_commenter.subprocess.run", side_effect=FileNotFoundError)
    def test_not_installed(self, mock_run):
        assert _check_gh_available() is False


# ---------------------------------------------------------------------------
# _detect_pr_number
# ---------------------------------------------------------------------------

class TestDetectPrNumber:
    @patch.dict("os.environ", {"GITHUB_REF": "refs/pull/42/merge"})
    @patch("agent.pr_commenter.subprocess.run")
    def test_from_github_ref(self, mock_run):
        assert _detect_pr_number() == 42

    @patch.dict("os.environ", {"GITHUB_REF": ""})
    @patch("agent.pr_commenter.subprocess.run")
    def test_from_gh_pr_view(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"number": 99}),
        )
        assert _detect_pr_number() == 99

    @patch.dict("os.environ", {"GITHUB_REF": ""})
    @patch("agent.pr_commenter.subprocess.run")
    def test_no_pr_context(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert _detect_pr_number() is None

    @patch.dict("os.environ", {"GITHUB_REF": "refs/heads/main"})
    @patch("agent.pr_commenter.subprocess.run")
    def test_non_pr_ref(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert _detect_pr_number() is None


# ---------------------------------------------------------------------------
# _build_comment_body
# ---------------------------------------------------------------------------

class TestBuildCommentBody:
    def test_includes_markdown(self):
        body = _build_comment_body(SAMPLE_MARKDOWN)
        assert SAMPLE_MARKDOWN in body

    def test_includes_marker(self):
        body = _build_comment_body(SAMPLE_MARKDOWN)
        assert COMMENT_MARKER in body

    def test_includes_patchpilot_link(self):
        body = _build_comment_body(SAMPLE_MARKDOWN)
        assert "PatchPilot" in body


# ---------------------------------------------------------------------------
# _find_existing_comment
# ---------------------------------------------------------------------------

class TestFindExistingComment:
    @patch("agent.pr_commenter.subprocess.run")
    def test_found(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="12345\n")
        assert _find_existing_comment(42) == 12345

    @patch("agent.pr_commenter.subprocess.run")
    def test_not_found(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="\n")
        assert _find_existing_comment(42) is None

    @patch("agent.pr_commenter.subprocess.run")
    def test_api_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert _find_existing_comment(42) is None

    @patch("agent.pr_commenter.subprocess.run", side_effect=FileNotFoundError)
    def test_gh_not_installed(self, mock_run):
        assert _find_existing_comment(42) is None


# ---------------------------------------------------------------------------
# _create_comment
# ---------------------------------------------------------------------------

class TestCreateComment:
    @patch("agent.pr_commenter.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="https://github.com/owner/repo/pull/42#issuecomment-123\n",
        )
        result = _create_comment(42, "body text")
        assert result["comment_url"].startswith("https://")
        assert result["updated"] is False

    @patch("agent.pr_commenter.subprocess.run")
    def test_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
        result = _create_comment(42, "body")
        assert "error" in result

    @patch("agent.pr_commenter.subprocess.run")
    def test_with_repo(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="url\n")
        _create_comment(42, "body", repo="owner/repo")
        cmd = mock_run.call_args[0][0]
        assert "--repo" in cmd
        assert "owner/repo" in cmd

    @patch("agent.pr_commenter.subprocess.run")
    def test_uses_body_file(self, mock_run):
        """Should use --body-file to avoid CLI arg length limits."""
        mock_run.return_value = MagicMock(returncode=0, stdout="url\n")
        _create_comment(42, "body text")
        cmd = mock_run.call_args[0][0]
        assert "--body-file" in cmd
        assert "--body" not in cmd or "--body-file" in cmd


# ---------------------------------------------------------------------------
# _update_comment
# ---------------------------------------------------------------------------

class TestUpdateComment:
    @patch("agent.pr_commenter.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"html_url": "https://github.com/owner/repo/pull/42#issuecomment-123"}),
        )
        result = _update_comment(123, "new body")
        assert result["updated"] is True
        assert "github.com" in result["comment_url"]

    @patch("agent.pr_commenter.subprocess.run")
    def test_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="not found")
        result = _update_comment(123, "body")
        assert "error" in result


# ---------------------------------------------------------------------------
# post_pr_comment (integration)
# ---------------------------------------------------------------------------

class TestPostPrComment:
    def test_dry_run(self):
        result = post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN, dry_run=True)
        assert "dry-run" in result["comment_url"]
        assert result["updated"] is False

    @patch("agent.pr_commenter._check_gh_available", return_value=False)
    def test_gh_not_available(self, mock_gh):
        result = post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN)
        assert "error" in result
        assert "gh CLI" in result["error"]

    @patch("agent.pr_commenter._check_gh_available", return_value=True)
    @patch("agent.pr_commenter._detect_pr_number", return_value=None)
    def test_no_pr_context(self, mock_detect, mock_gh):
        result = post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN)
        assert "error" in result
        assert "PR context" in result["error"]
        assert "GITHUB_REF=" in result["error"]

    @patch("agent.pr_commenter._check_gh_available", return_value=True)
    @patch("agent.pr_commenter._detect_pr_number", return_value=42)
    @patch("agent.pr_commenter._find_existing_comment", return_value=None)
    @patch("agent.pr_commenter._create_comment")
    def test_creates_new_comment(self, mock_create, mock_find, mock_detect, mock_gh):
        mock_create.return_value = {"comment_url": "https://example.com", "updated": False}
        result = post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN)
        assert result["updated"] is False
        mock_create.assert_called_once()

    @patch("agent.pr_commenter._check_gh_available", return_value=True)
    @patch("agent.pr_commenter._detect_pr_number", return_value=42)
    @patch("agent.pr_commenter._find_existing_comment", return_value=999)
    @patch("agent.pr_commenter._update_comment")
    def test_updates_existing_comment(self, mock_update, mock_find, mock_detect, mock_gh):
        mock_update.return_value = {"comment_url": "https://example.com", "updated": True}
        result = post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN)
        assert result["updated"] is True
        mock_update.assert_called_once()

    @patch("agent.pr_commenter._check_gh_available", return_value=True)
    @patch("agent.pr_commenter._find_existing_comment", return_value=None)
    @patch("agent.pr_commenter._create_comment")
    def test_explicit_pr_number(self, mock_create, mock_find, mock_gh):
        mock_create.return_value = {"comment_url": "url", "updated": False}
        post_pr_comment(SAMPLE_TRIAGE, SAMPLE_MARKDOWN, pr_number=55)
        mock_find.assert_called_once_with(55, None)
