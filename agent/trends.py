"""PatchPilot trend tracking — historical scan snapshots and trend analysis."""

import json
import os
from datetime import date, datetime
from typing import Dict, List, Optional

from agent.models import Finding


STATE_DIR = ".patchpilot"
HISTORY_FILE = "history.json"

SPARKLINE_CHARS = " ▁▂▃▄▅▆▇█"


def _history_path(project_path: str) -> str:
    return os.path.join(project_path, STATE_DIR, HISTORY_FILE)


def load_history(project_path: str) -> dict:
    """Load trend history from .patchpilot/history.json.

    Returns empty default if file is missing or corrupt.
    """
    path = _history_path(project_path)
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and "snapshots" in data:
            return data
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return {"version": 1, "snapshots": []}


def append_snapshot(
    project_path: str, triage_data: dict, findings: List[Finding]
) -> None:
    """Append a scan snapshot to trend history.

    Called automatically after each triage run.
    """
    history = load_history(project_path)

    fingerprints = {}
    for f in findings:
        fp = f.fingerprint()
        fingerprints[fp] = {"id": f.id, "package": f.package or ""}

    snapshot = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_findings": triage_data.get("total_findings", len(findings)),
        "summary": triage_data.get("summary", {}),
        "fingerprints": fingerprints,
    }

    history["snapshots"].append(snapshot)

    dir_path = os.path.join(project_path, STATE_DIR)
    os.makedirs(dir_path, exist_ok=True)
    with open(_history_path(project_path), "w") as f:
        json.dump(history, f, indent=2)


def compute_trends(history: dict) -> dict:
    """Compute trend metrics from historical snapshots.

    Requires at least 2 snapshots for meaningful results.
    """
    snapshots = history.get("snapshots", [])
    if not snapshots:
        return {}

    dates = [s["date"] for s in snapshots]
    totals = [s.get("total_findings", 0) for s in snapshots]

    tiers = ["critical", "high", "medium", "low", "noise"]
    tier_over_time = {}
    for tier in tiers:
        tier_over_time[tier] = [s.get("summary", {}).get(tier, 0) for s in snapshots]

    # Direction: compare last to first
    def _direction(values):
        if len(values) < 2:
            return "stable"
        first, last = values[0], values[-1]
        if first == 0:
            return "increasing" if last > 0 else "stable"
        change = (last - first) / first
        if change < -0.10:
            return "decreasing"
        elif change > 0.10:
            return "increasing"
        return "stable"

    # New and resolved since last scan
    new_since_last = []
    resolved_since_last = []
    if len(snapshots) >= 2:
        prev_fps = set(snapshots[-2].get("fingerprints", {}).keys())
        curr_fps = set(snapshots[-1].get("fingerprints", {}).keys())

        curr_fingerprints = snapshots[-1].get("fingerprints", {})
        prev_fingerprints = snapshots[-2].get("fingerprints", {})

        for fp in curr_fps - prev_fps:
            info = curr_fingerprints.get(fp, {})
            new_since_last.append({"id": info.get("id", ""), "package": info.get("package", "")})

        for fp in prev_fps - curr_fps:
            info = prev_fingerprints.get(fp, {})
            resolved_since_last.append({"id": info.get("id", ""), "package": info.get("package", "")})

    # MTTR: mean time to remediate
    mttr_days = _compute_mttr(snapshots)

    # Top recurring packages
    top_recurring = _compute_recurring_packages(snapshots)

    return {
        "snapshot_count": len(snapshots),
        "date_range": {"first": dates[0], "last": dates[-1]},
        "dates": dates,
        "total_findings_over_time": totals,
        "total_findings_direction": _direction(totals),
        "tier_breakdown_over_time": tier_over_time,
        "tier_directions": {t: _direction(tier_over_time[t]) for t in tiers},
        "new_since_last": new_since_last,
        "resolved_since_last": resolved_since_last,
        "mttr_days": mttr_days,
        "top_recurring_packages": top_recurring,
    }


def _compute_mttr(snapshots: List[dict]) -> Optional[float]:
    """Compute mean time to remediate across all resolved findings.

    A finding is "resolved" if it appears in some snapshots then disappears
    and never returns.
    """
    if len(snapshots) < 2:
        return None

    # Track first-seen and last-seen dates for each fingerprint
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}

    for snap in snapshots:
        snap_date = snap["date"]
        for fp in snap.get("fingerprints", {}):
            if fp not in first_seen:
                first_seen[fp] = snap_date
            last_seen[fp] = snap_date

    # A fingerprint is resolved if its last_seen is before the last snapshot date
    final_date = snapshots[-1]["date"]
    final_fps = set(snapshots[-1].get("fingerprints", {}).keys())

    remediation_days = []
    for fp, first in first_seen.items():
        if fp not in final_fps:
            # Resolved — compute duration
            try:
                d_first = date.fromisoformat(first)
                d_last = date.fromisoformat(last_seen[fp])
                days = (d_last - d_first).days
                remediation_days.append(days)
            except ValueError:
                continue

    if not remediation_days:
        return None

    return round(sum(remediation_days) / len(remediation_days), 1)


def _compute_recurring_packages(snapshots: List[dict], top_n: int = 5) -> List[dict]:
    """Find packages that appear most frequently across snapshots with distinct CVEs."""
    # package → set of CVE IDs
    package_cves: dict[str, set[str]] = {}
    # package → number of snapshots it appeared in
    package_appearances: dict[str, int] = {}

    for snap in snapshots:
        seen_packages_this_snap: set[str] = set()
        for _fp, info in snap.get("fingerprints", {}).items():
            pkg = info.get("package", "")
            cve = info.get("id", "")
            if not pkg:
                continue
            if pkg not in package_cves:
                package_cves[pkg] = set()
            package_cves[pkg].add(cve)
            seen_packages_this_snap.add(pkg)

        for pkg in seen_packages_this_snap:
            package_appearances[pkg] = package_appearances.get(pkg, 0) + 1

    # Sort by number of distinct CVEs descending, then by appearances
    ranked = sorted(
        package_cves.keys(),
        key=lambda p: (len(package_cves[p]), package_appearances.get(p, 0)),
        reverse=True,
    )

    return [
        {
            "package": pkg,
            "cve_count": len(package_cves[pkg]),
            "appearances": package_appearances.get(pkg, 0),
            "cves": sorted(package_cves[pkg]),
        }
        for pkg in ranked[:top_n]
    ]


def sparkline(values: list) -> str:
    """Render a list of numbers as an ASCII sparkline."""
    if not values:
        return ""
    mn = min(values)
    mx = max(values)
    rng = mx - mn
    chars = SPARKLINE_CHARS
    last_idx = len(chars) - 1
    result = []
    for v in values:
        if rng == 0:
            idx = last_idx // 2
        else:
            idx = round((v - mn) / rng * last_idx)
        result.append(chars[idx])
    return "".join(result)


def format_trend_report_markdown(trends: dict) -> str:
    """Render trends as a markdown report with sparklines and tables."""
    if not trends:
        return "No trend data available."

    lines = []
    lines.append("# PatchPilot Trend Report")
    lines.append("")

    dr = trends["date_range"]
    count = trends["snapshot_count"]
    lines.append(f"**Period:** {dr['first']} to {dr['last']} ({count} scans)")
    lines.append("")

    # Total findings
    totals = trends["total_findings_over_time"]
    direction = trends["total_findings_direction"]
    spark = sparkline(totals)
    lines.append("## Total Findings")
    lines.append(f"{spark}  {totals[0]} → {totals[-1]} ({direction})")
    lines.append("")

    # Tier breakdown
    lines.append("## Tier Breakdown")
    lines.append("| Tier | First | Last | Trend | Sparkline |")
    lines.append("|----------|-------|------|-------------|-----------|")
    for tier in ["critical", "high", "medium", "low", "noise"]:
        vals = trends["tier_breakdown_over_time"].get(tier, [])
        if not vals:
            continue
        d = trends["tier_directions"].get(tier, "stable")
        s = sparkline(vals)
        lines.append(f"| {tier.capitalize():<8} | {vals[0]:>5} | {vals[-1]:>4} | {d:<11} | {s:<9} |")
    lines.append("")

    # Changes since last scan
    new = trends.get("new_since_last", [])
    resolved = trends.get("resolved_since_last", [])
    if new or resolved:
        lines.append("## Changes Since Last Scan")
        if new:
            lines.append(f"### New ({len(new)})")
            for item in new:
                lines.append(f"- {item['id']} ({item['package']})")
            lines.append("")
        if resolved:
            lines.append(f"### Resolved ({len(resolved)})")
            for item in resolved:
                lines.append(f"- {item['id']} ({item['package']})")
            lines.append("")

    # MTTR
    mttr = trends.get("mttr_days")
    if mttr is not None:
        lines.append("## Remediation Velocity")
        lines.append(f"Mean time to remediate: {mttr} days")
        lines.append("")

    # Top recurring packages
    recurring = trends.get("top_recurring_packages", [])
    if recurring:
        lines.append("## Top Recurring Packages")
        lines.append("| Package | CVE Count | Appearances |")
        lines.append("|----------|-----------|-------------|")
        for entry in recurring:
            lines.append(
                f"| {entry['package']:<8} | {entry['cve_count']:>9} | {entry['appearances']:>11} |"
            )
        lines.append("")

    return "\n".join(lines)


def format_trend_report_json(trends: dict) -> str:
    """Render trends as JSON."""
    return json.dumps(trends, indent=2)
