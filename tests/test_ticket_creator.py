"""
Tests for agent/ticket_creator.py

All gh CLI calls are mocked — never actually invoked.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from agent.models import Finding
from agent.ticket_creator import (
    _build_issue_body,
    _build_issue_title,
    _check_gh_available,
    _create_single_issue,
    _find_existing_issue,
    _fingerprint_from_item,
    create_issues_from_triage,
)


# ---------------------------------------------------------------------------
# Sample fixture
# ---------------------------------------------------------------------------

SAMPLE_ITEM = {
    "rank": 1,
    "id": "CVE-2024-1234",
    "priority_tier": "critical",
    "priority_score": 92,
    "package": "fastapi",
    "installed_version": "0.104.1",
    "fixed_version": "0.110.0",
    "severity": "critical",
    "title": "Path traversal in fastapi",
    "action": "Upgrade fastapi from 0.104.1 to >= 0.110.0",
    "effort": "trivial",
    "signals": {
        "reachable": "true",
        "reachability_confidence": "high",
        "epss_score": 0.85,
        "in_kev": True,
        "fix_available": True,
    },
    "fix_suggestion": {
        "command": "pip install fastapi>=0.110.0",
        "confidence": "high",
        "breaking_change_risk": "low",
        "caveats": [],
        "suggestion_type": "upgrade",
    },
}


# ---------------------------------------------------------------------------
# 1. Fingerprint matches Finding.fingerprint()
# ---------------------------------------------------------------------------

def test_fingerprint_matches_finding():
    finding = Finding(
        id="CVE-2024-1234",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="critical",
        title="Path traversal in fastapi",
        package="fastapi",
        installed_version="0.104.1",
    )
    assert _fingerprint_from_item(SAMPLE_ITEM) == finding.fingerprint()


# ---------------------------------------------------------------------------
# 2. Issue title format
# ---------------------------------------------------------------------------

def test_build_issue_title():
    title = _build_issue_title(SAMPLE_ITEM)
    assert title.startswith("[CRITICAL]")
    assert "CVE-2024-1234" in title
    assert "Upgrade fastapi" in title


def test_build_issue_title_truncates_long_action():
    long_item = {**SAMPLE_ITEM, "action": "A" * 200}
    title = _build_issue_title(long_item)
    # Title should not be excessively long
    assert len(title) < 250


# ---------------------------------------------------------------------------
# 3 & 4. Issue body structure and fingerprint
# ---------------------------------------------------------------------------

def test_build_issue_body_contains_fingerprint():
    body = _build_issue_body(SAMPLE_ITEM)
    fingerprint = _fingerprint_from_item(SAMPLE_ITEM)
    assert f"<!-- patchpilot:fingerprint:{fingerprint} -->" in body


def test_build_issue_body_structure():
    body = _build_issue_body(SAMPLE_ITEM)
    assert "CRITICAL" in body
    assert "92/100" in body
    assert "fastapi" in body
    assert "0.104.1" in body
    assert "0.110.0" in body
    assert "### Action" in body
    assert "### Signals" in body
    assert "Reachable: true" in body
    assert "EPSS: 0.85" in body
    assert "CISA KEV: Yes" in body
    assert "### Fix Suggestion" in body
    assert "pip install fastapi>=0.110.0" in body
    assert "PatchPilot" in body


# ---------------------------------------------------------------------------
# 5 & 6. _check_gh_available
# ---------------------------------------------------------------------------

def test_check_gh_available_success():
    mock_result = MagicMock()
    mock_result.returncode = 0
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        assert _check_gh_available() is True
        mock_run.assert_called_once_with(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
        )


def test_check_gh_available_failure():
    mock_result = MagicMock()
    mock_result.returncode = 1
    with patch("subprocess.run", return_value=mock_result):
        assert _check_gh_available() is False


def test_check_gh_available_not_installed():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert _check_gh_available() is False


# ---------------------------------------------------------------------------
# 7 & 8. _find_existing_issue
# ---------------------------------------------------------------------------

def test_find_existing_issue_found():
    issue_url = "https://github.com/owner/repo/issues/42"
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps([{"number": 42, "url": issue_url}])
    with patch("subprocess.run", return_value=mock_result):
        result = _find_existing_issue("abc123def456")
        assert result == issue_url


def test_find_existing_issue_not_found():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "[]"
    with patch("subprocess.run", return_value=mock_result):
        result = _find_existing_issue("abc123def456")
        assert result is None


def test_find_existing_issue_gh_error():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    with patch("subprocess.run", return_value=mock_result):
        result = _find_existing_issue("abc123def456")
        assert result is None


# ---------------------------------------------------------------------------
# 9 & 10. _create_single_issue
# ---------------------------------------------------------------------------

def test_create_single_issue_success():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "https://github.com/owner/repo/issues/99\n"
    with patch("subprocess.run", return_value=mock_result):
        result = _create_single_issue(SAMPLE_ITEM)
        assert "issue_url" in result
        assert result["issue_url"] == "https://github.com/owner/repo/issues/99"


def test_create_single_issue_gh_error():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "repository not found"
    mock_result.stdout = ""
    with patch("subprocess.run", return_value=mock_result):
        result = _create_single_issue(SAMPLE_ITEM)
        assert "error" in result
        assert "repository not found" in result["error"]


def test_create_single_issue_gh_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _create_single_issue(SAMPLE_ITEM)
        assert "error" in result
        assert "gh CLI not found" in result["error"]


# ---------------------------------------------------------------------------
# 11. Full flow: skips duplicates
# ---------------------------------------------------------------------------

def test_create_issues_skips_duplicates():
    existing_url = "https://github.com/owner/repo/issues/10"

    auth_ok = MagicMock()
    auth_ok.returncode = 0

    search_result = MagicMock()
    search_result.returncode = 0
    search_result.stdout = json.dumps([{"number": 10, "url": existing_url}])

    label_result = MagicMock()
    label_result.returncode = 0

    triage_data = {"action_items": [SAMPLE_ITEM]}

    def side_effect(cmd, **kwargs):
        if cmd[1] == "auth":
            return auth_ok
        if cmd[1] == "label":
            return label_result
        if cmd[1] == "issue" and cmd[2] == "list":
            return search_result
        return MagicMock(returncode=0, stdout="")

    with patch("subprocess.run", side_effect=side_effect):
        result = create_issues_from_triage(triage_data)

    assert len(result["created"]) == 0
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["id"] == "CVE-2024-1234"
    assert "duplicate" in result["skipped"][0]["reason"]


# ---------------------------------------------------------------------------
# 12. Dry run
# ---------------------------------------------------------------------------

def test_create_issues_dry_run():
    triage_data = {"action_items": [SAMPLE_ITEM]}
    with patch("subprocess.run") as mock_run:
        result = create_issues_from_triage(triage_data, dry_run=True)
        # gh should never be called in dry_run mode
        mock_run.assert_not_called()

    assert len(result["created"]) == 1
    assert result["created"][0]["id"] == "CVE-2024-1234"
    assert "[dry-run]" in result["created"][0]["issue_url"]
    assert len(result["skipped"]) == 0
    assert len(result["errors"]) == 0


# ---------------------------------------------------------------------------
# 13. Graceful error when gh not available
# ---------------------------------------------------------------------------

def test_create_issues_gh_not_available():
    triage_data = {"action_items": [SAMPLE_ITEM]}
    mock_result = MagicMock()
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        result = create_issues_from_triage(triage_data)

    assert len(result["errors"]) == 1
    assert result["errors"][0]["id"] == "CVE-2024-1234"
    assert "gh CLI" in result["errors"][0]["error"]
    assert len(result["created"]) == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_create_issues_empty_action_items():
    result = create_issues_from_triage({"action_items": []})
    assert result == {"created": [], "skipped": [], "errors": []}


def test_create_issues_missing_action_items_key():
    result = create_issues_from_triage({})
    assert result == {"created": [], "skipped": [], "errors": []}


def test_build_issue_body_no_epss():
    item = {**SAMPLE_ITEM, "signals": {**SAMPLE_ITEM["signals"], "epss_score": None}}
    body = _build_issue_body(item)
    assert "EPSS" not in body


def test_build_issue_body_no_fix_suggestion():
    item = {**SAMPLE_ITEM, "fix_suggestion": {}}
    body = _build_issue_body(item)
    assert "### Fix Suggestion" not in body
