"""Executive summary formatter — one-page security posture for non-technical stakeholders."""

from datetime import date

from agent.models import Finding
from agent.plugins.base import OutputFormatter


def _posture_score(findings: list[Finding]) -> int:
    """Compute a 0-100 posture score. Higher = better.

    Starts at 100, deducts points per finding based on severity and risk signals.
    """
    score = 100
    for f in findings:
        if f.severity == "critical":
            deduction = 15
        elif f.severity == "high":
            deduction = 8
        elif f.severity == "medium":
            deduction = 3
        elif f.severity == "low":
            deduction = 1
        else:
            deduction = 0

        # Amplify for actively exploited or reachable
        if f.in_kev:
            deduction *= 2
        elif f.reachable == "true":
            deduction = int(deduction * 1.5)

        # Reduce deduction if fix is available (easier to resolve)
        if f.fix_available and deduction > 0:
            deduction = max(1, deduction - 1)

        score -= deduction

    return max(0, min(100, score))


def _posture_grade(score: int) -> str:
    """Convert score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def _risk_level(score: int) -> str:
    """Convert score to risk level description."""
    if score >= 90:
        return "Low Risk"
    elif score >= 70:
        return "Moderate Risk"
    elif score >= 50:
        return "Elevated Risk"
    return "High Risk"


def _top_actions(findings: list[Finding], limit: int = 3) -> list[dict]:
    """Extract top action items from scored findings."""
    sorted_findings = sorted(findings, key=lambda f: f.priority_score, reverse=True)
    actions = []
    for f in sorted_findings[:limit]:
        action = {
            "id": f.id,
            "severity": f.severity,
            "package": f.package or "unknown",
            "score": f.priority_score,
        }
        if f.fix_available and f.fixed_version:
            action["action"] = f"Upgrade {f.package} to >= {f.fixed_version}"
        elif f.fix_available:
            action["action"] = f"Update {f.package} to latest patched version"
        else:
            action["action"] = f"Investigate {f.id} — no fix available"
        actions.append(action)
    return actions


class ExecutiveSummaryFormatter(OutputFormatter):
    """Generates a one-page executive security summary.

    Designed for CTOs, board members, and auditors who need a quick
    posture overview without technical detail.
    """

    @property
    def name(self) -> str:
        return "executive"

    def format(self, findings: list[Finding], context: dict) -> str:
        """Generate executive summary markdown.

        Args:
            findings: Scored Finding objects.
            context: Context bundle from build_context().

        Returns:
            Markdown string — designed to fit on one printed page.
        """
        scan_meta = context.get("scan_meta", {})
        target = scan_meta.get("target", context.get("target", "unknown"))
        today = date.today().isoformat()

        # Counts
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        kev_count = sum(1 for f in findings if f.in_kev)
        reachable = sum(1 for f in findings if f.reachable == "true")
        fixable = sum(1 for f in findings if f.fix_available)

        # Score
        score = _posture_score(findings)
        grade = _posture_grade(score)
        risk = _risk_level(score)

        # Top actions
        actions = _top_actions(findings)

        # Build markdown
        lines = [
            f"# Security Posture Summary — {target}",
            "",
            f"**Date:** {today} | **Risk Level:** {risk} | **Score:** {score}/100 ({grade})",
            "",
            "---",
            "",
            "## Key Metrics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Findings | {total} |",
            f"| Critical | {critical} |",
            f"| High | {high} |",
            f"| Medium | {medium} |",
            f"| Low | {low} |",
            f"| Actively Exploited (KEV) | {kev_count} |",
            f"| Reachable in Code | {reachable} |",
            f"| Fix Available | {fixable} ({_pct(fixable, total)}) |",
            "",
        ]

        # Top actions
        if actions:
            lines += [
                "## Recommended Actions",
                "",
            ]
            for i, a in enumerate(actions, 1):
                lines.append(
                    f"{i}. **[{a['severity'].upper()}]** {a['id']}: {a['action']}"
                )
            lines.append("")

        # Risk summary
        lines += [
            "## Risk Assessment",
            "",
        ]

        if kev_count > 0:
            lines.append(
                f"- **{kev_count} finding(s) are actively exploited** in the wild "
                f"(CISA Known Exploited Vulnerabilities catalog). Immediate action required."
            )

        if reachable > 0:
            lines.append(
                f"- **{reachable} finding(s) are reachable** — the vulnerable code "
                f"is imported and callable in this application."
            )

        unreachable = sum(1 for f in findings if f.reachable == "false")
        if unreachable > 0:
            lines.append(
                f"- {unreachable} finding(s) are in dependencies that are **not imported** "
                f"(lower risk, but should still be tracked)."
            )

        if fixable > 0:
            lines.append(
                f"- {fixable} finding(s) have **patches available** — "
                f"remediation is straightforward for these."
            )

        unfixable = total - fixable
        if unfixable > 0:
            lines.append(
                f"- {unfixable} finding(s) have **no fix available** yet — "
                f"monitor for updates and assess workarounds."
            )

        lines.append("")

        # Compliance note
        lines += [
            "## Compliance Status",
            "",
            f"- Vulnerability scan completed: {today}",
            f"- Findings triaged and scored: {total}",
            f"- Posture score: {score}/100 ({grade})",
        ]

        if score >= 70:
            lines.append("- Assessment: Organization demonstrates active vulnerability management.")
        else:
            lines.append("- Assessment: Remediation action required to meet compliance standards.")

        lines += [
            "",
            "---",
            f"*Generated by PatchPilot on {today}. "
            f"This report covers {total} findings from automated security scanning.*",
        ]

        return "\n".join(lines)


def _pct(part: int, total: int) -> str:
    """Format a percentage string."""
    if total == 0:
        return "0%"
    return f"{round(part / total * 100)}%"
