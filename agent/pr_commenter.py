"""
pr_commenter.py — Post PatchPilot triage results as a GitHub PR comment.

Uses the `gh` CLI to create or update PR comments with dedup via HTML marker.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import date
from typing import Optional


COMMENT_MARKER = "<!-- patchpilot:triage -->"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def post_pr_comment(
    triage_data: dict,
    markdown: str,
    pr_number: Optional[int] = None,
    repo: Optional[str] = None,
    dry_run: bool = False,
) -> dict:
    """Post triage results as a PR comment.

    Args:
        triage_data: The triage dict from run_triage()["triage"].
        markdown: Pre-generated markdown from run_triage()["markdown"].
        pr_number: PR number. Auto-detected if None.
        repo: Optional "owner/repo" override.
        dry_run: If True, show what would be posted.

    Returns:
        {"comment_url": "...", "updated": bool} or {"error": "..."}
    """
    body = _build_comment_body(markdown)

    if dry_run:
        summary = triage_data.get("summary", {})
        total = sum(summary.get(t, 0) for t in ("critical", "high", "medium", "low", "noise"))
        return {
            "comment_url": f"[dry-run] would post triage ({total} findings) to PR",
            "updated": False,
        }

    if not _check_gh_available():
        return {"error": "gh CLI not found or not authenticated"}

    if pr_number is None:
        pr_number = _detect_pr_number()
    if pr_number is None:
        return {
            "error": "Not in a PR context. Use --pr-comment from a PR branch, "
                     "or set GITHUB_REF=refs/pull/<number>/merge."
        }

    # Check for existing PatchPilot comment to update
    existing_id = _find_existing_comment(pr_number, repo)

    if existing_id:
        return _update_comment(existing_id, body, repo)
    else:
        return _create_comment(pr_number, body, repo)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_gh_available() -> bool:
    """Check if gh CLI is installed and authenticated."""
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _detect_pr_number() -> Optional[int]:
    """Auto-detect the current PR number.

    Tries:
    1. GITHUB_REF_NAME env var (e.g., "refs/pull/42/merge" → 42)
    2. `gh pr view --json number` (works when on a PR branch locally)
    """
    # Try GitHub Actions env var
    ref = os.environ.get("GITHUB_REF", "")
    if "/pull/" in ref:
        try:
            # refs/pull/42/merge → 42
            parts = ref.split("/")
            idx = parts.index("pull")
            return int(parts[idx + 1])
        except (ValueError, IndexError):
            pass

    # Try gh pr view
    try:
        result = subprocess.run(
            ["gh", "pr", "view", "--json", "number"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("number")
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    return None


def _find_existing_comment(
    pr_number: int, repo: Optional[str] = None
) -> Optional[int]:
    """Search PR comments for an existing PatchPilot triage comment.

    Returns the comment ID if found, None otherwise.
    """
    cmd = [
        "gh", "api",
        f"repos/{{owner}}/{{repo}}/issues/{pr_number}/comments",
        "--jq", f'[.[] | select(.body | contains("{COMMENT_MARKER}"))][0].id',
    ]
    if repo:
        cmd = [
            "gh", "api",
            f"repos/{repo}/issues/{pr_number}/comments",
            "--jq", f'[.[] | select(.body | contains("{COMMENT_MARKER}"))][0].id',
        ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
    except (FileNotFoundError, ValueError):
        pass

    return None


def _build_comment_body(markdown: str) -> str:
    """Wrap triage markdown with PatchPilot header and dedup marker."""
    today = date.today().isoformat()
    return (
        f"{markdown}\n\n"
        f"---\n"
        f"*Posted by [PatchPilot](https://github.com/farshi/devsecops-ai-assistant) — {today}*\n"
        f"{COMMENT_MARKER}\n"
    )


def _create_comment(
    pr_number: int, body: str, repo: Optional[str] = None
) -> dict:
    """Create a new PR comment.

    Uses --body-file to avoid CLI argument length limits on large reports.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(body)
        body_file = f.name

    try:
        cmd = ["gh", "pr", "comment", str(pr_number), "--body-file", body_file]
        if repo:
            cmd += ["--repo", repo]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "gh pr comment failed"}
        return {
            "comment_url": result.stdout.strip(),
            "updated": False,
        }
    except FileNotFoundError:
        return {"error": "gh CLI not found"}
    finally:
        os.unlink(body_file)


def _update_comment(
    comment_id: int, body: str, repo: Optional[str] = None
) -> dict:
    """Update an existing PR comment.

    Uses stdin to pass body to avoid CLI argument length limits.
    """
    if repo:
        endpoint = f"repos/{repo}/issues/comments/{comment_id}"
    else:
        endpoint = f"repos/{{owner}}/{{repo}}/issues/comments/{comment_id}"

    # Pass body via --input to avoid arg length limits
    payload = json.dumps({"body": body})
    cmd = [
        "gh", "api", endpoint,
        "-X", "PATCH",
        "--input", "-",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, input=payload)
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "gh api PATCH failed"}
        # Parse response for HTML URL
        try:
            data = json.loads(result.stdout)
            url = data.get("html_url", "")
        except json.JSONDecodeError:
            url = "(updated)"
        return {
            "comment_url": url,
            "updated": True,
        }
    except FileNotFoundError:
        return {"error": "gh CLI not found"}
