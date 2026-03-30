"""
Build the v1 summary.json from normalized scanner findings.
"""

from agent.utils import timestamp

SEVERITIES = ["critical", "high", "medium", "low", "info"]
TOP_ISSUES_LIMIT = 5


def _severity(f) -> str:
    """Extract severity from a Finding object or a plain dict."""
    if hasattr(f, "severity"):
        return f.severity
    return f.get("severity", "info")


def _to_dict(f) -> dict:
    """Serialize a Finding object or plain dict to a dict."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    return f


def build(
    target_name: str,
    target_slug: str,
    path: str,
    profile: str,
    scanners_requested: list[str],
    scanners_run: list[str],
    scanners_skipped: list[dict],
    findings_by_scanner: dict[str, list],
    notes: list[str],
) -> dict:
    """
    Assemble the v1 summary.json structure.

    findings_by_scanner : { "trivy_fs": [Finding, ...], "checkov": [] }
    scanners_skipped    : [ {"scanner": "checkov", "reason": "no .tf files"} ]
    """
    all_findings = [f for items in findings_by_scanner.values() for f in items]

    severity_counts = {s: 0 for s in SEVERITIES}
    for f in all_findings:
        severity_counts[_severity(f)] += 1

    # Top issues: sort by severity order, take first N
    severity_order = {s: i for i, s in enumerate(SEVERITIES)}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: severity_order.get(_severity(f), 99),
    )
    top_issues = []
    for f in sorted_findings[:TOP_ISSUES_LIMIT]:
        # find which scanner produced this finding
        scanner_label = next(
            (s for s, items in findings_by_scanner.items() if f in items),
            "unknown",
        )
        top_issues.append({"scanner": scanner_label, **_to_dict(f)})

    risk_summary = _risk_summary(severity_counts, scanners_skipped)

    return {
        "version": "1",
        "target": {
            "name": target_name,
            "slug": target_slug,
            "path": path,
        },
        "scan": {
            "date":               timestamp(),
            "profile":            profile,
            "scanners_requested": scanners_requested,
            "scanners_run":       scanners_run,
            "scanners_skipped":   scanners_skipped,
        },
        "severity_counts": severity_counts,
        "top_issues":       top_issues,
        "findings":         {s: [_to_dict(f) for f in items] for s, items in findings_by_scanner.items()},
        "risk_summary":     risk_summary,
        "notes":            notes,
    }


def _risk_summary(severity_counts: dict, scanners_skipped: list[dict]) -> str:
    critical = severity_counts["critical"]
    high     = severity_counts["high"]
    total    = sum(severity_counts.values())

    if total == 0:
        level = "No findings"
    elif critical > 0:
        level = f"{critical} critical finding{'s' if critical > 1 else ''}"
    elif high > 0:
        level = f"{high} high-severity finding{'s' if high > 1 else ''}"
    else:
        level = f"{total} finding{'s' if total > 1 else ''} (no critical or high)"

    skipped_note = ""
    if scanners_skipped:
        names = ", ".join(s["scanner"] for s in scanners_skipped)
        skipped_note = f" Scanners skipped: {names}."

    return f"{level} detected across all scanners.{skipped_note}"
