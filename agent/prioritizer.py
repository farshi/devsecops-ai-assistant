"""PatchPilot triage engine — scores findings and generates ranked output."""

from datetime import date
from typing import Optional

from agent.models import Finding
from agent.plugins.scoring.default import DefaultScoringStrategy


def _build_action(finding: Finding) -> str:
    """Generate a one-line action recommendation."""
    if finding.fix_available and finding.fixed_version:
        return f"Upgrade {finding.package or '?'} from {finding.installed_version or '?'} to >= {finding.fixed_version}"
    elif finding.fix_available:
        return f"Update {finding.package or '?'} to latest patched version"
    else:
        return f"Investigate {finding.id} — no fix available yet, assess workarounds"


def _extract_effort(finding: Finding) -> str:
    """Extract effort estimate from fix_evidence."""
    if finding.fix_evidence and "effort:" in finding.fix_evidence:
        # Parse "effort: trivial" from pipe-delimited fix_evidence
        for part in finding.fix_evidence.split("|"):
            part = part.strip()
            if part.startswith("effort:"):
                return part.split(":", 1)[1].strip()
    if not finding.fix_available:
        return "investigation"
    return "moderate"  # default


def _generate_markdown(
    action_items: list[dict],
    tier_summary: dict,
    context: dict,
) -> str:
    """Generate a markdown triage report."""
    scan_meta = context.get("scan_meta", {})
    scan_date = scan_meta.get("date", "unknown")
    scanners = scan_meta.get("scanners_run", [])
    scanner = ", ".join(scanners) if scanners else "unknown"
    total = scan_meta.get("total_findings", 0)

    lines = [
        "# PatchPilot Triage Report",
        "",
        f"**Scan date:** {scan_date} | **Scanner:** {scanner} | **Total findings:** {total}",
        "",
        "## Priority Summary",
        "| Tier | Count |",
        "|------|-------|",
    ]

    for tier in ("critical", "high", "medium", "low", "noise"):
        count = tier_summary.get(tier, 0)
        lines.append(f"| {tier.capitalize()} | {count} |")

    lines.append("")
    lines.append(f"## Top {len(action_items)} Action Items")
    lines.append("")

    for item in action_items:
        rank = item["rank"]
        cve_id = item["id"]
        tier = item["priority_tier"]
        score = item["priority_score"]
        pkg = item.get("package") or "unknown"
        installed = item.get("installed_version") or "?"
        fixed = item.get("fixed_version") or "?"
        action = item["action"]
        effort = item["effort"]
        signals = item.get("signals", {})

        lines.append(f"### #{rank} — {cve_id} ({tier}, score: {score})")
        lines.append(f"**Package:** {pkg} {installed} → {fixed}")
        lines.append(f"**Action:** {action}")
        lines.append(f"**Effort:** {effort}")

        # Build signals string
        signal_parts = []
        reachable = signals.get("reachable", "unknown")
        confidence = signals.get("reachability_confidence", "none")
        if reachable == "true":
            signal_parts.append(f"reachable ({confidence} confidence)")
        elif reachable == "false":
            signal_parts.append("not reachable")
        else:
            signal_parts.append(f"reachability: {reachable}")

        epss = signals.get("epss_score")
        if epss is not None:
            signal_parts.append(f"EPSS: {epss}")

        in_kev = signals.get("in_kev", False)
        signal_parts.append(f"KEV: {'yes' if in_kev else 'no'}")

        fix_avail = signals.get("fix_available", False)
        signal_parts.append("fix available" if fix_avail else "no fix available")

        lines.append(f"**Signals:** {' | '.join(signal_parts)}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def generate_triage(
    findings: list[Finding],
    context: dict,
    top_n: int = 5,
) -> dict:
    """Generate a ranked triage output from scored findings.

    Args:
        findings: List of Finding objects (enriched with reachability, EPSS, KEV, fix info)
        context: Context bundle from build_context()
        top_n: Number of top findings to include in the action list

    Returns:
        {
            "triage": {
                "generated_at": "2026-03-30",
                "total_findings": 15,
                "top_n": 5,
                "action_items": [...],
                "summary": {"critical": 1, "high": 3, ...},
                "scan_date": "2026-03-27",
                "scanner": "trivy_fs",
            },
            "markdown": "# PatchPilot Triage Report\n..."
        }
    """
    # Step 1: Score findings
    strategy = DefaultScoringStrategy()
    scored = strategy.score(findings)  # mutates + sorts

    # Step 2: Build action items (top N)
    action_items = []
    for rank, finding in enumerate(scored[:top_n], start=1):
        item = {
            "rank": rank,
            "id": finding.id,
            "priority_tier": finding.priority_tier,
            "priority_score": finding.priority_score,
            "package": finding.package,
            "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version,
            "severity": finding.severity,
            "title": finding.title,
            "action": _build_action(finding),
            "effort": _extract_effort(finding),
            "signals": {
                "reachable": finding.reachable,
                "reachability_confidence": finding.reachability_confidence,
                "epss_score": finding.epss_score,
                "in_kev": finding.in_kev,
                "fix_available": finding.fix_available,
            },
        }
        action_items.append(item)

    # Step 3: Build tier summary
    tier_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "noise": 0}
    for f in scored:
        tier = f.priority_tier
        if tier in tier_summary:
            tier_summary[tier] += 1

    # Step 4: Extract scan metadata from context
    scan_meta = context.get("scan_meta", {})
    scan_date = scan_meta.get("date", "")
    scanners_run = scan_meta.get("scanners_run", [])
    scanner = ", ".join(scanners_run) if scanners_run else ""

    # Step 5: Generate markdown
    markdown = _generate_markdown(action_items, tier_summary, context)

    # Step 6: Assemble return dict
    return {
        "triage": {
            "generated_at": str(date.today()),
            "total_findings": len(scored),
            "top_n": top_n,
            "action_items": action_items,
            "summary": tier_summary,
            "scan_date": scan_date,
            "scanner": scanner,
        },
        "markdown": markdown,
    }


def _finding_from_dict(d: dict) -> Finding:
    """Convert a serialized finding dict back to a Finding object."""
    return Finding(
        id=d.get("id", ""),
        source_scanner=d.get("source_scanner", ""),
        finding_type=d.get("finding_type", "language_dep"),
        severity=d.get("severity", "info"),
        title=d.get("title", ""),
        package=d.get("package"),
        installed_version=d.get("installed_version"),
        fixed_version=d.get("fixed_version"),
        location=d.get("location", ""),
        cvss_score=d.get("cvss_score"),
        reachable=d.get("reachable", "unknown"),
        reachability_confidence=d.get("reachability_confidence", "none"),
        reachability_evidence=d.get("reachability_evidence"),
        direct_dep=d.get("direct_dep"),
        epss_score=d.get("epss_score"),
        in_kev=d.get("in_kev", False),
        fix_available=d.get("fix_available", False),
        fix_evidence=d.get("fix_evidence"),
        priority_score=d.get("priority_score", 0),
        priority_tier=d.get("priority_tier", "unscored"),
    )


def run_triage(path: str, scan_summary_path: str, top_n: int = 5) -> dict:
    """Full triage pipeline: build context → score → generate output.

    This is the main entry point for the triage command.
    """
    from agent.context_builder import build_context

    ctx = build_context(path, scan_summary_path)

    # Convert context findings (dicts) back to Finding objects
    findings = [_finding_from_dict(fd) for fd in ctx["findings"]]

    # Run fix availability enrichment (in case build_context didn't)
    from agent.plugins.enrichment.fix_availability import FixAvailabilityPlugin
    FixAvailabilityPlugin().enrich(findings, ctx)

    result = generate_triage(findings, ctx, top_n=top_n)
    return result
