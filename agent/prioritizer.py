"""PatchPilot triage engine — scores findings and generates ranked output."""

import json
import logging
import os
from datetime import date
from typing import Optional

from agent.models import Finding
from agent.plugins.scoring.default import DefaultScoringStrategy

log = logging.getLogger(__name__)

NARRATIVE_SYSTEM_PROMPT = """You are a security analyst explaining vulnerability triage results to a developer.
For each finding, provide:
1. "why_it_matters" — 1-2 sentences explaining the real-world risk in plain English. Be specific to THIS codebase.
2. "recommendation" — 1-2 sentences with concrete next steps. Not generic advice.

Rules:
- Do NOT re-rank or re-score findings. The ranking is already determined.
- Reference the reachability status if available (e.g., "This package is imported in your code").
- Reference EPSS/KEV if available (e.g., "This CVE has a 92% chance of being exploited in 30 days").
- Be concise. Developers won't read paragraphs.
- Return valid JSON array matching the input order."""


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

        why = item.get("why_it_matters")
        rec = item.get("recommendation")
        if why:
            lines.append(f"**Why it matters:** {why}")
        if rec:
            lines.append(f"**Recommendation:** {rec}")

        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def enhance_triage_with_llm(triage_result: dict, context: dict) -> dict:
    """Add LLM-generated narratives to triage action items.

    For each action item, adds:
    - "why_it_matters": plain-English explanation of risk
    - "recommendation": specific next-step guidance

    Does NOT change ranking, scores, or tiers. LLM explains, doesn't re-rank.

    Requires ANTHROPIC_API_KEY. If missing or LLM fails, returns triage unchanged
    (narratives are enhancement, not requirement).

    Args:
        triage_result: Output from generate_triage() — has "triage" and "markdown" keys
        context: Context bundle from build_context()

    Returns:
        Same triage_result dict with narratives added to action_items.
    """
    provider = context.get("config", {}).get("llm_provider", "claude")

    # Guard: require the appropriate API key before attempting LLM call
    if provider == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        log.info("ANTHROPIC_API_KEY not set — skipping LLM narrative enhancement")
        return triage_result
    if provider in ("openai", "gpt") and not os.environ.get("OPENAI_API_KEY"):
        log.info("OPENAI_API_KEY not set — skipping LLM narrative enhancement")
        return triage_result

    action_items = triage_result["triage"]["action_items"]
    if not action_items:
        return triage_result

    try:
        from agent.llm_client import call as llm_call

        user_msg = json.dumps({
            "action_items": action_items,
            "repo_context": {
                "languages": context.get("repo", {}).get("languages", []),
                "frameworks": context.get("repo", {}).get("frameworks", []),
                "dependencies_count": len(context.get("dependencies", {}).get("direct", [])),
            },
        })

        response = llm_call(NARRATIVE_SYSTEM_PROMPT, user_msg, provider=provider)

        # Parse JSON array from response
        narratives = json.loads(response)
        if not isinstance(narratives, list):
            log.warning("LLM narrative response was not a JSON array — skipping enhancement")
            return triage_result

        # Build lookup by id
        narrative_by_id = {n["id"]: n for n in narratives if isinstance(n, dict) and "id" in n}

        # Merge narratives into action items (preserving order and scores)
        for item in action_items:
            narrative = narrative_by_id.get(item["id"])
            if narrative:
                if "why_it_matters" in narrative:
                    item["why_it_matters"] = narrative["why_it_matters"]
                if "recommendation" in narrative:
                    item["recommendation"] = narrative["recommendation"]

        # Regenerate markdown with narratives included
        triage_data = triage_result["triage"]
        tier_summary = triage_data.get("summary", {})
        triage_result["markdown"] = _generate_markdown(action_items, tier_summary, context)

    except json.JSONDecodeError as exc:
        log.warning("Failed to parse LLM narrative response as JSON: %s — skipping enhancement", exc)
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM narrative enhancement failed: %s — returning triage unchanged", exc)

    return triage_result


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


def run_triage(
    path: str,
    scan_summary_path: str,
    top_n: int = 5,
    enhance: bool = False,
    new_only: bool = False,
) -> dict:
    """Full triage pipeline: build context → score → generate output.

    This is the main entry point for the triage command.

    Args:
        path: Path to the project directory.
        scan_summary_path: Path to the scan summary JSON file.
        top_n: Number of top findings to include in the action list.
        enhance: If True and ANTHROPIC_API_KEY is set, add LLM narratives to action items.
        new_only: If True, only surface findings that are new since the last baseline.
    """
    from agent.context_builder import build_context
    from agent.config import load_config, apply_config_filters
    from agent.state import filter_dismissed, filter_new_only, save_baseline

    ctx = build_context(path, scan_summary_path)

    config = load_config(path)

    # Config can override top_n if not explicitly set by CLI
    if top_n == 5:  # default value — let config override
        top_n = config.get("top_n", 5)

    # Convert context findings (dicts) back to Finding objects
    findings = [_finding_from_dict(fd) for fd in ctx["findings"]]

    # Apply config filters before scoring
    findings = apply_config_filters(findings, config)

    # Filter dismissed/accepted findings
    findings = filter_dismissed(findings, path)

    # Filter to new-only if requested
    if new_only:
        findings = filter_new_only(findings, path)

    # Run fix availability enrichment (in case build_context didn't)
    from agent.plugins.enrichment.fix_availability import FixAvailabilityPlugin
    FixAvailabilityPlugin().enrich(findings, ctx)

    result = generate_triage(findings, ctx, top_n=top_n)

    # Save current findings as baseline for next run
    save_baseline(path, findings)

    if enhance:
        result = enhance_triage_with_llm(result, ctx)

    return result
