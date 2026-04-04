"""Multi-repo portfolio aggregation — unified view across multiple .patchpilot/ repos."""

import os
from typing import Optional

from agent.state import load_state, load_baseline, load_deadlines
from agent.trends import load_history
from agent.deadlines import summarize_deadlines


def load_repo_summary(repo_path: str) -> dict:
    """Load a single repo's .patchpilot/ data into a summary dict.

    Returns:
        {
            "path": str,
            "name": str,
            "has_data": bool,
            "state": {...},
            "baseline": {...},
            "deadlines": {...},
            "deadline_summary": {...},
            "latest_snapshot": {...} or None,
            "snapshot_count": int,
        }
    """
    name = os.path.basename(os.path.abspath(repo_path))
    patchpilot_dir = os.path.join(repo_path, ".patchpilot")
    has_data = os.path.isdir(patchpilot_dir)

    state = load_state(repo_path) if has_data else {}
    baseline = load_baseline(repo_path) if has_data else {}
    deadlines = load_deadlines(repo_path) if has_data else {}
    history = load_history(repo_path) if has_data else {"snapshots": []}

    snapshots = history.get("snapshots", [])
    latest_snapshot = snapshots[-1] if snapshots else None

    deadline_summary = summarize_deadlines(deadlines) if deadlines else {
        "total": 0, "overdue": 0, "warning": 0, "open": 0, "met": 0,
        "overdue_findings": [], "warning_findings": [],
    }

    return {
        "path": repo_path,
        "name": name,
        "has_data": has_data,
        "state": state,
        "baseline": baseline,
        "deadlines": deadlines,
        "deadline_summary": deadline_summary,
        "latest_snapshot": latest_snapshot,
        "snapshot_count": len(snapshots),
    }


def aggregate_repos(repo_paths: list) -> dict:
    """Aggregate .patchpilot/ data from multiple repos.

    Args:
        repo_paths: List of filesystem paths to repos.

    Returns:
        {
            "repos": [repo_summary, ...],
            "totals": {
                "repos": int,
                "repos_with_data": int,
                "total_findings": int,
                "summary": {"critical": N, "high": N, ...},
                "dismissed": int,
                "accepted": int,
                "closed": int,
                "deadlines": {"total": N, "overdue": N, "warning": N, ...},
            },
        }
    """
    repos = []
    totals = {
        "repos": len(repo_paths),
        "repos_with_data": 0,
        "total_findings": 0,
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "noise": 0},
        "dismissed": 0,
        "accepted": 0,
        "closed": 0,
        "deadlines": {"total": 0, "overdue": 0, "warning": 0, "open": 0, "met": 0},
    }

    for path in repo_paths:
        repo = load_repo_summary(path)
        repos.append(repo)

        if not repo["has_data"]:
            continue

        totals["repos_with_data"] += 1

        # Aggregate from latest snapshot
        snap = repo["latest_snapshot"]
        if snap:
            totals["total_findings"] += snap.get("total_findings", 0)
            for tier in ("critical", "high", "medium", "low", "noise"):
                totals["summary"][tier] += snap.get("summary", {}).get(tier, 0)

        # Aggregate state counts
        state = repo["state"]
        totals["dismissed"] += len(state.get("dismissed", {}))
        totals["accepted"] += len(state.get("accepted_risks", {}))
        totals["closed"] += len(state.get("closed", {}))

        # Aggregate deadlines
        ds = repo["deadline_summary"]
        for key in ("total", "overdue", "warning", "open", "met"):
            totals["deadlines"][key] += ds.get(key, 0)

    return {"repos": repos, "totals": totals}


def format_portfolio_table(agg: dict) -> str:
    """Format aggregated portfolio data as a human-readable table."""
    lines = []
    totals = agg["totals"]

    lines.append(f"  Portfolio: {totals['repos']} repos ({totals['repos_with_data']} with data)")
    lines.append(f"  Total findings: {totals['total_findings']}")

    s = totals["summary"]
    parts = []
    for tier in ("critical", "high", "medium", "low"):
        if s[tier] > 0:
            parts.append(f"{tier}: {s[tier]}")
    if parts:
        lines.append(f"  Breakdown: {' | '.join(parts)}")

    dl = totals["deadlines"]
    if dl["total"] > 0:
        dl_parts = []
        if dl["overdue"] > 0:
            dl_parts.append(f"{dl['overdue']} overdue")
        if dl["warning"] > 0:
            dl_parts.append(f"{dl['warning']} due soon")
        if dl["met"] > 0:
            dl_parts.append(f"{dl['met']} met")
        lines.append(f"  CRA deadlines: {dl['total']} tracked ({', '.join(dl_parts)})")

    lines.append("")
    lines.append(f"  {'Repo':<30} {'Findings':>10} {'Crit':>6} {'High':>6} {'Overdue':>8} {'Scans':>6}")
    lines.append(f"  {'─' * 30} {'─' * 10} {'─' * 6} {'─' * 6} {'─' * 8} {'─' * 6}")

    for repo in agg["repos"]:
        name = repo["name"][:30]
        if not repo["has_data"]:
            lines.append(f"  {name:<30} {'(no data)':>10}")
            continue

        snap = repo["latest_snapshot"] or {}
        findings = snap.get("total_findings", 0)
        crit = snap.get("summary", {}).get("critical", 0)
        high = snap.get("summary", {}).get("high", 0)
        overdue = repo["deadline_summary"].get("overdue", 0)
        scans = repo["snapshot_count"]

        overdue_str = str(overdue) if overdue > 0 else "—"
        lines.append(f"  {name:<30} {findings:>10} {crit:>6} {high:>6} {overdue_str:>8} {scans:>6}")

    lines.append("")
    return "\n".join(lines) + "\n"
