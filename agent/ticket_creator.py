"""
ticket_creator.py — Create GitHub Issues from triage action items.

Uses the `gh` CLI to create issues with dedup via fingerprint search.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from typing import Optional


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_issues_from_triage(
    triage_data: dict,
    repo: Optional[str] = None,
    labels: bool = True,
    dry_run: bool = False,
) -> dict:
    """Create GitHub Issues from triage action items.

    Args:
        triage_data: The triage dict from run_triage()["triage"] — has "action_items" list.
        repo: Optional "owner/repo" override. If None, uses current git repo.
        labels: Whether to auto-create labels (patchpilot:critical, etc.)
        dry_run: If True, show what would be created without creating.

    Returns:
        {"created": [...], "skipped": [...], "errors": [...]}
    """
    created = []
    skipped = []
    errors = []

    action_items = triage_data.get("action_items", [])
    if not action_items:
        return {"created": created, "skipped": skipped, "errors": errors}

    if dry_run:
        for item in action_items:
            title = _build_issue_title(item)
            created.append({
                "rank": item.get("rank", 0),
                "id": item.get("id", ""),
                "issue_url": f"[dry-run] would create: {title}",
            })
        return {"created": created, "skipped": skipped, "errors": errors}

    if not _check_gh_available():
        for item in action_items:
            errors.append({
                "rank": item.get("rank", 0),
                "id": item.get("id", ""),
                "error": "gh CLI not found or not authenticated",
            })
        return {"created": created, "skipped": skipped, "errors": errors}

    if labels:
        _create_labels_if_needed(repo)

    for item in action_items:
        rank = item.get("rank", 0)
        cve_id = item.get("id", "")
        fingerprint = _fingerprint_from_item(item)

        existing = _find_existing_issue(fingerprint, repo)
        if existing:
            skipped.append({
                "rank": rank,
                "id": cve_id,
                "reason": f"duplicate — existing issue: {existing}",
            })
            continue

        result = _create_single_issue(item, repo=repo, labels=labels)
        if "error" in result:
            errors.append({"rank": rank, "id": cve_id, "error": result["error"]})
        else:
            created.append({"rank": rank, "id": cve_id, "issue_url": result["issue_url"]})

    return {"created": created, "skipped": skipped, "errors": errors}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_gh_available() -> bool:
    """Check if gh CLI is installed and authenticated."""
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _fingerprint_from_item(item: dict) -> str:
    """Compute Finding fingerprint from an action_item dict.

    Must match Finding.fingerprint() — sha256 of "id:package:installed_version"[:16]
    """
    key = f"{item['id']}:{item.get('package', '')}:{item.get('installed_version', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _find_existing_issue(fingerprint: str, repo: Optional[str] = None) -> Optional[str]:
    """Search open issues for one containing this fingerprint.

    Returns issue URL if found, None otherwise.
    """
    search_term = f"patchpilot:fingerprint:{fingerprint}"
    cmd = [
        "gh", "issue", "list",
        "--search", search_term,
        "--state", "open",
        "--json", "number,url",
        "--limit", "1",
    ]
    if repo:
        cmd += ["--repo", repo]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return None
        issues = json.loads(result.stdout or "[]")
        if issues:
            return issues[0].get("url")
        return None
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _build_issue_title(item: dict) -> str:
    """Build issue title like: [CRITICAL] CVE-2024-1234: package-name upgrade needed"""
    tier = item.get("priority_tier", "unknown").upper()
    cve_id = item.get("id", "")
    action = item.get("action", "remediation needed")
    # Trim action to keep title concise
    short_action = action[:80] if len(action) > 80 else action
    return f"[{tier}] {cve_id}: {short_action}"


def _build_issue_body(item: dict) -> str:
    """Build structured markdown body for a GitHub Issue from an action_item."""
    cve_id = item.get("id", "")
    tier = item.get("priority_tier", "unknown").upper()
    score = item.get("priority_score", 0)
    package = item.get("package", "unknown")
    installed = item.get("installed_version", "unknown")
    fixed = item.get("fixed_version", "N/A")
    action = item.get("action", "")

    signals = item.get("signals", {})
    reachable = signals.get("reachable", "unknown")
    reach_conf = signals.get("reachability_confidence", "unknown")
    epss = signals.get("epss_score")
    in_kev = signals.get("in_kev", False)
    fix_available = signals.get("fix_available", False)

    fix = item.get("fix_suggestion", {})
    fix_cmd = fix.get("command", "")
    fix_conf = fix.get("confidence", "unknown")
    fix_risk = fix.get("breaking_change_risk", "unknown")

    fingerprint = _fingerprint_from_item(item)

    lines = [
        f"## Security Finding: {cve_id}",
        "",
        f"**Priority:** {tier} (score: {score}/100)",
        f"**Package:** {package} {installed}",
        f"**Fixed Version:** {fixed}",
        "",
        "### Action",
        action,
        "",
        "### Signals",
        f"- Reachable: {reachable} (confidence: {reach_conf})",
    ]

    if epss is not None:
        lines.append(f"- EPSS: {epss} (30-day exploitation probability)")

    lines.append(f"- CISA KEV: {'Yes' if in_kev else 'No'}")
    lines.append(f"- Fix available: {'Yes' if fix_available else 'No'}")

    if fix_cmd:
        lines += [
            "",
            "### Fix Suggestion",
            "```",
            fix_cmd,
            "```",
            f"Confidence: {fix_conf} | Breaking change risk: {fix_risk}",
        ]

    lines += [
        "",
        "---",
        "*Created by [PatchPilot](https://github.com/farshi/devsecops-ai-assistant)*",
        f"<!-- patchpilot:fingerprint:{fingerprint} -->",
    ]

    return "\n".join(lines)


def _create_labels_if_needed(repo: Optional[str] = None):
    """Create patchpilot: labels if they don't exist."""
    label_specs = [
        ("patchpilot", "Security findings managed by PatchPilot", "0052cc"),
        ("patchpilot:critical", "Critical severity — immediate action required", "b60205"),
        ("patchpilot:high", "High severity", "d93f0b"),
        ("patchpilot:medium", "Medium severity", "e4e669"),
        ("patchpilot:low", "Low severity", "0e8a16"),
    ]

    for name, description, color in label_specs:
        cmd = ["gh", "label", "create", name,
               "--description", description,
               "--color", color,
               "--force"]
        if repo:
            cmd += ["--repo", repo]
        try:
            subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            break


def _create_single_issue(
    item: dict,
    repo: Optional[str] = None,
    labels: bool = True,
) -> dict:
    """Create one GitHub Issue. Returns {"issue_url": "..."} or {"error": "..."}"""
    title = _build_issue_title(item)
    body = _build_issue_body(item)
    tier = item.get("priority_tier", "").lower()

    cmd = ["gh", "issue", "create", "--title", title, "--body", body]

    if labels:
        label_list = "patchpilot"
        if tier in ("critical", "high", "medium", "low"):
            label_list += f",patchpilot:{tier}"
        cmd += ["--label", label_list]

    if repo:
        cmd += ["--repo", repo]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "gh issue create failed"
            return {"error": error_msg}
        issue_url = result.stdout.strip()
        return {"issue_url": issue_url}
    except FileNotFoundError:
        return {"error": "gh CLI not found"}
