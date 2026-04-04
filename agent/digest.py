"""PatchPilot weekly digest — concise triage summary from existing data."""

import glob
import json
import os
from datetime import date, timedelta
from typing import Optional

from agent.state import load_state, load_baseline
from agent.trends import load_history, compute_trends, sparkline
from agent.utils import slugify


def generate_digest(
    path: str,
    target_name: str,
    days: int = 7,
) -> dict:
    """Generate a weekly digest from existing .patchpilot/ data.

    No scan needed — reads history, baseline, state, and latest triage.

    Returns:
        {"markdown": str, "data": dict} or {"error": str}
    """
    target_slug = slugify(target_name)

    # Load all data sources
    history = load_history(path)
    snapshots = history.get("snapshots", [])
    state = load_state(path)
    baseline = load_baseline(path)
    latest_triage = _load_latest_triage(target_slug)

    if not snapshots and not latest_triage:
        return {"error": "No scan history found. Run `patchpilot triage` first."}

    # Compute trends (needs 2+ snapshots)
    closed = state.get("closed", {})
    trends = compute_trends(history, closed=closed) if len(snapshots) >= 2 else {}

    # Build digest data
    data = _build_digest_data(
        snapshots=snapshots,
        trends=trends,
        state=state,
        baseline=baseline,
        latest_triage=latest_triage,
        target_name=target_name,
        days=days,
    )

    markdown = _format_digest_markdown(data)
    return {"markdown": markdown, "data": data}


def format_digest_json(data: dict) -> str:
    """Render digest data as JSON."""
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_latest_triage(target_slug: str) -> Optional[dict]:
    """Find and load the most recent triage JSON for this target."""
    pattern = f"reports/{target_slug}_triage_*.json"
    matches = sorted(glob.glob(pattern))
    if not matches:
        return None
    with open(matches[-1]) as f:
        return json.load(f)


def _build_digest_data(
    snapshots: list,
    trends: dict,
    state: dict,
    baseline: dict,
    latest_triage: Optional[dict],
    target_name: str,
    days: int,
) -> dict:
    """Assemble all digest data into a single dict."""
    today = date.today()
    period_start = str(today - timedelta(days=days))
    period_end = str(today)

    # Current status from latest snapshot or triage
    if snapshots:
        latest_snap = snapshots[-1]
        total = latest_snap.get("total_findings", 0)
        summary = latest_snap.get("summary", {})
    elif latest_triage:
        total = latest_triage.get("total_findings", 0)
        summary = latest_triage.get("summary", {})
    else:
        total = 0
        summary = {}

    # Trend direction and sparkline
    totals_over_time = trends.get("total_findings_over_time", [])
    direction = trends.get("total_findings_direction", "unknown")
    spark = sparkline(totals_over_time) if totals_over_time else ""

    # New, resolved, and regressions since last scan
    new_findings = trends.get("new_since_last", [])
    resolved_findings = trends.get("resolved_since_last", [])
    regressions = trends.get("regressions", [])

    # Top priorities from latest triage
    action_items = []
    if latest_triage:
        action_items = latest_triage.get("action_items", [])[:5]

    # State counts
    dismissed_count = len(state.get("dismissed", {}))
    accepted_count = len(state.get("accepted_risks", {}))

    # MTTR
    mttr = trends.get("mttr_days")

    # Fix coverage
    fixable = 0
    if latest_triage:
        for item in latest_triage.get("action_items", []):
            if item.get("signals", {}).get("fix_available"):
                fixable += 1

    # Recurring packages
    recurring = trends.get("top_recurring_packages", [])

    # Snapshot count
    snapshot_count = trends.get("snapshot_count", len(snapshots))

    # CRA deadlines
    from agent.deadlines import summarize_deadlines
    cra_deadlines = state.get("cra_deadlines", {})
    deadline_summary = summarize_deadlines(cra_deadlines) if cra_deadlines else None

    return {
        "target_name": target_name,
        "period": {"start": period_start, "end": period_end, "days": days},
        "generated_at": period_end,
        "total_findings": total,
        "summary": summary,
        "direction": direction,
        "sparkline": spark,
        "snapshot_count": snapshot_count,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "regressions": regressions,
        "top_priorities": action_items,
        "mttr_days": mttr,
        "fix_coverage": {"fixable": fixable, "total": total},
        "decisions": {"dismissed": dismissed_count, "accepted": accepted_count},
        "recurring_packages": recurring,
        "cra_deadlines": deadline_summary,
    }


def _format_digest_markdown(data: dict) -> str:
    """Render digest data as concise markdown."""
    lines = []

    # Header
    period = data["period"]
    lines += [
        "# PatchPilot Weekly Digest",
        "",
        f"**Period:** {period['start']} to {period['end']} | "
        f"**Product:** {data['target_name']} | "
        f"**Scans:** {data['snapshot_count']}",
        "",
    ]

    # Status at a glance
    summary = data["summary"]
    spark = data["sparkline"]
    direction = data["direction"]
    total = data["total_findings"]

    lines += [
        "## Status at a Glance",
        "",
        f"**Total:** {total} findings {spark} ({direction})",
    ]

    tier_parts = []
    for tier in ("critical", "high", "medium", "low"):
        count = summary.get(tier, 0)
        if count > 0:
            tier_parts.append(f"{tier.capitalize()}: {count}")
    if tier_parts:
        lines.append(" | ".join(tier_parts))
    lines.append("")

    # What changed
    new = data["new_findings"]
    resolved = data["resolved_findings"]
    regressions = data.get("regressions", [])

    if new or resolved or regressions:
        lines += ["## What Changed", ""]

        if regressions:
            lines.append(f"### Regressions ({len(regressions)})")
            lines.append("*Findings that were resolved but came back:*")
            for item in regressions:
                lines.append(f"- {item['id']} ({item.get('package', '?')})")
            lines.append("")

        if new:
            lines.append(f"### New ({len(new)})")
            for item in new:
                lines.append(f"- {item['id']} ({item.get('package', '?')})")
            lines.append("")

        if resolved:
            lines.append(f"### Resolved ({len(resolved)})")
            for item in resolved:
                lines.append(f"- {item['id']} ({item.get('package', '?')})")
            lines.append("")
    if not new and not resolved and not regressions:
        lines += ["## What Changed", "", "No changes since last scan.", ""]

    # Top priorities
    priorities = data["top_priorities"]
    if priorities:
        lines += ["## Top Priorities", ""]
        for item in priorities:
            tier = item.get("priority_tier", "?").upper()
            cve = item.get("id", "?")
            action = item.get("action", "investigate")
            lines.append(f"1. **[{tier}]** {cve}: {action}")
        lines.append("")

    # Remediation velocity
    mttr = data["mttr_days"]
    fix_cov = data["fix_coverage"]
    if mttr is not None or fix_cov["total"] > 0:
        lines += ["## Remediation Velocity", ""]
        parts = []
        if mttr is not None:
            parts.append(f"MTTR: {mttr} days")
        if fix_cov["total"] > 0:
            pct = round(fix_cov["fixable"] / fix_cov["total"] * 100)
            parts.append(f"Fix coverage: {fix_cov['fixable']}/{fix_cov['total']} ({pct}%)")
        lines.append(" | ".join(parts))
        lines.append("")

    # Decisions
    decisions = data["decisions"]
    if decisions["dismissed"] > 0 or decisions["accepted"] > 0:
        lines += ["## Decisions", ""]
        parts = []
        if decisions["dismissed"] > 0:
            parts.append(f"{decisions['dismissed']} dismissed")
        if decisions["accepted"] > 0:
            parts.append(f"{decisions['accepted']} risks accepted")
        lines.append(" | ".join(parts))
        lines.append("")

    # CRA Deadlines
    dl = data.get("cra_deadlines")
    if dl and (dl.get("overdue", 0) > 0 or dl.get("warning", 0) > 0):
        lines += ["## CRA Deadlines", ""]
        if dl["overdue"] > 0:
            lines.append(f"**⚠ {dl['overdue']} OVERDUE** — past remediation deadline")
            for item in dl.get("overdue_findings", [])[:5]:
                lines.append(
                    f"- {item['cve']} ({item['severity']}) — "
                    f"{item['days_overdue']}d overdue, deadline: {item['deadline']}"
                )
            lines.append("")
        if dl["warning"] > 0:
            lines.append(f"**⏰ {dl['warning']} DUE SOON** — within 3 days of deadline")
            for item in dl.get("warning_findings", [])[:5]:
                lines.append(
                    f"- {item['cve']} ({item['severity']}) — "
                    f"{item['days_remaining']}d remaining, deadline: {item['deadline']}"
                )
            lines.append("")

    # Recurring packages
    recurring = data["recurring_packages"]
    if recurring:
        lines += [
            "## Recurring Problem Packages",
            "",
            "| Package | CVEs | Appearances |",
            "|---------|------|-------------|",
        ]
        for pkg in recurring[:5]:
            lines.append(
                f"| {pkg['package']} | {pkg['cve_count']} | {pkg['appearances']} |"
            )
        lines.append("")

    # Footer
    lines += [
        "---",
        f"*Generated by PatchPilot — {data['generated_at']}*",
    ]

    return "\n".join(lines)
