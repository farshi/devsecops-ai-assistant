"""CRA deadline tracking — 24h/72h/14d notification deadlines per finding."""

from datetime import date, datetime, timedelta
from typing import Optional

from agent.models import Finding


# CRA remediation deadlines by severity (days)
DEADLINE_DAYS = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
    "info": 90,
}

# Warning threshold: flag findings within this many days of deadline
WARNING_THRESHOLD_DAYS = 3


def compute_deadline(severity: str, discovered_at: str) -> str:
    """Return ISO date string for the remediation deadline.

    Args:
        severity: Finding severity (critical/high/medium/low/info).
        discovered_at: ISO date string (YYYY-MM-DD) when finding was first seen.

    Returns:
        ISO date string for the deadline.
    """
    days = DEADLINE_DAYS.get(severity.lower(), 90)
    disc_date = date.fromisoformat(discovered_at)
    return str(disc_date + timedelta(days=days))


def deadline_status(deadline_date: str, as_of: Optional[str] = None) -> str:
    """Determine deadline status: open, warning, overdue, or met.

    Args:
        deadline_date: ISO date string (YYYY-MM-DD).
        as_of: Optional ISO date to evaluate against (defaults to today).

    Returns:
        One of: "overdue", "warning", "open".
    """
    dl = date.fromisoformat(deadline_date)
    today = date.fromisoformat(as_of) if as_of else date.today()
    days_remaining = (dl - today).days

    if days_remaining < 0:
        return "overdue"
    elif days_remaining <= WARNING_THRESHOLD_DAYS:
        return "warning"
    return "open"


def days_remaining(deadline_date: str, as_of: Optional[str] = None) -> int:
    """Return number of days until deadline (negative = overdue)."""
    dl = date.fromisoformat(deadline_date)
    today = date.fromisoformat(as_of) if as_of else date.today()
    return (dl - today).days


def build_deadline_entry(finding: Finding, discovered_at: str) -> dict:
    """Create a deadline tracking entry for a finding.

    Args:
        finding: The Finding object.
        discovered_at: ISO date string when finding was first seen.

    Returns:
        Dict suitable for storage in state.json cra_deadlines section.
    """
    dl = compute_deadline(finding.severity, discovered_at)
    return {
        "cve": finding.id,
        "package": finding.package,
        "severity": finding.severity,
        "discovered_at": discovered_at,
        "deadline": dl,
        "deadline_days": DEADLINE_DAYS.get(finding.severity.lower(), 90),
    }


def compute_deadlines_for_findings(
    findings: list,
    existing_deadlines: dict,
    today: Optional[str] = None,
) -> dict:
    """Compute deadline entries for a list of findings.

    Preserves existing deadline entries (first-seen date is stable).
    Only adds new entries for findings not yet tracked.

    Args:
        findings: List of Finding objects from triage.
        existing_deadlines: Current cra_deadlines dict from state.json.
        today: Optional ISO date override (defaults to today).

    Returns:
        Updated cra_deadlines dict.
    """
    now = today or date.today().isoformat()
    updated = dict(existing_deadlines)

    for f in findings:
        fp = f.fingerprint()
        if fp not in updated:
            updated[fp] = build_deadline_entry(f, now)

    return updated


def summarize_deadlines(deadlines: dict, as_of: Optional[str] = None) -> dict:
    """Produce a summary of deadline statuses.

    Returns:
        {
            "total": int,
            "overdue": int,
            "warning": int,
            "open": int,
            "met": int,
            "overdue_findings": [{"cve": ..., "deadline": ..., "days_overdue": ...}],
            "warning_findings": [{"cve": ..., "deadline": ..., "days_remaining": ...}],
        }
    """
    counts = {"total": 0, "overdue": 0, "warning": 0, "open": 0, "met": 0}
    overdue_list = []
    warning_list = []

    for fp, entry in deadlines.items():
        status = entry.get("status")
        if status == "met":
            counts["met"] += 1
            counts["total"] += 1
            continue

        dl = entry.get("deadline")
        if not dl:
            continue

        counts["total"] += 1
        s = deadline_status(dl, as_of)
        counts[s] += 1
        dr = days_remaining(dl, as_of)

        if s == "overdue":
            overdue_list.append({
                "cve": entry.get("cve", ""),
                "package": entry.get("package", ""),
                "severity": entry.get("severity", ""),
                "deadline": dl,
                "days_overdue": abs(dr),
            })
        elif s == "warning":
            warning_list.append({
                "cve": entry.get("cve", ""),
                "package": entry.get("package", ""),
                "severity": entry.get("severity", ""),
                "deadline": dl,
                "days_remaining": dr,
            })

    # Sort: most overdue first, then most urgent warning first
    overdue_list.sort(key=lambda x: x["days_overdue"], reverse=True)
    warning_list.sort(key=lambda x: x["days_remaining"])

    return {
        **counts,
        "overdue_findings": overdue_list,
        "warning_findings": warning_list,
    }


def format_deadlines_table(deadlines: dict, as_of: Optional[str] = None) -> str:
    """Format deadline entries as a human-readable table.

    Returns markdown-formatted string.
    """
    if not deadlines:
        return "  No CRA deadlines tracked yet.\n"

    lines = []
    entries = []

    for fp, entry in deadlines.items():
        status = entry.get("status", "")
        dl = entry.get("deadline", "")
        if status == "met":
            entries.append((fp, entry, "met", 0))
            continue
        if dl:
            s = deadline_status(dl, as_of)
            dr = days_remaining(dl, as_of)
            entries.append((fp, entry, s, dr))

    # Sort: overdue first (most overdue), then warning, then open
    status_order = {"overdue": 0, "warning": 1, "open": 2, "met": 3}
    entries.sort(key=lambda x: (status_order.get(x[2], 9), x[3]))

    for fp, entry, status, dr in entries:
        cve = entry.get("cve", "?")
        pkg = entry.get("package", "")
        sev = entry.get("severity", "?")
        dl = entry.get("deadline", "?")

        if status == "overdue":
            flag = f"OVERDUE ({abs(dr)}d)"
        elif status == "warning":
            flag = f"DUE SOON ({dr}d)"
        elif status == "met":
            flag = "MET"
        else:
            flag = f"OK ({dr}d)"

        pkg_str = f" ({pkg})" if pkg else ""
        lines.append(f"  {flag:<18} {sev:<9} {cve}{pkg_str}  deadline: {dl}")

    return "\n".join(lines) + "\n"
