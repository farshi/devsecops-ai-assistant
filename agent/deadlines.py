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

# CRA Article 14 mandatory notification milestones (days from discovery)
NOTIFICATION_MILESTONES = {
    "early_warning_24h": 1,   # days
    "notification_72h": 3,
    "final_report_14d": 14,
}


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


def compute_notification_milestones(discovered_at: str) -> dict:
    """Return ISO date strings for each CRA Article 14 notification milestone.

    Args:
        discovered_at: ISO date string (YYYY-MM-DD) when finding was first seen.

    Returns:
        Dict mapping milestone name → ISO date string.
        Example: {"early_warning_24h": "2026-04-05", "notification_72h": "2026-04-07",
                  "final_report_14d": "2026-04-18"}
    """
    disc_date = date.fromisoformat(discovered_at)
    return {
        name: str(disc_date + timedelta(days=days))
        for name, days in NOTIFICATION_MILESTONES.items()
    }


def escalation_level(entry: dict, as_of: Optional[str] = None) -> str:
    """Determine escalation level for a deadline entry based on overdue notification milestones.

    Args:
        entry: Deadline entry dict (from state.json cra_deadlines section).
        as_of: Optional ISO date to evaluate against (defaults to today).

    Returns:
        One of: "none", "warning", "escalated", "critical"
        - "critical" if early_warning_24h is overdue and not sent
        - "escalated" if notification_72h is overdue and not sent
        - "warning" if final_report_14d is overdue and not sent
        - "none" if no milestones are overdue or all sent
    """
    today = date.fromisoformat(as_of) if as_of else date.today()
    notifications = entry.get("notifications", {})

    # Check most urgent first — return highest level
    for milestone, level in [
        ("early_warning_24h", "critical"),
        ("notification_72h", "escalated"),
        ("final_report_14d", "warning"),
    ]:
        milestone_data = notifications.get(milestone, {})
        sent = milestone_data.get("sent")
        due_str = milestone_data.get("due")
        if sent is not None:
            continue
        if due_str and date.fromisoformat(due_str) < today:
            return level

    return "none"


def format_escalation_summary(deadlines: dict, as_of: Optional[str] = None) -> str:
    """Generate a markdown-formatted escalation report for overdue notification milestones.

    Groups findings by escalation level (critical first, then escalated, then warning).
    Shows CVE, package, which milestone is overdue, and how long overdue.

    Args:
        deadlines: cra_deadlines dict from state.json.
        as_of: Optional ISO date override (defaults to today).

    Returns:
        Markdown string.
    """
    today = date.fromisoformat(as_of) if as_of else date.today()

    buckets: dict[str, list[dict]] = {"critical": [], "escalated": [], "warning": []}

    for fp, entry in deadlines.items():
        level = escalation_level(entry, as_of)
        if level == "none":
            continue

        notifications = entry.get("notifications", {})
        # Find the highest-priority overdue milestone
        overdue_milestone = None
        for milestone in ("early_warning_24h", "notification_72h", "final_report_14d"):
            milestone_data = notifications.get(milestone, {})
            sent = milestone_data.get("sent")
            due_str = milestone_data.get("due")
            if sent is not None:
                continue
            if due_str and date.fromisoformat(due_str) < today:
                overdue_milestone = milestone
                due_date = date.fromisoformat(due_str)
                delta = today - due_date
                overdue_hours = delta.days * 24
                break

        if overdue_milestone is None:
            continue

        buckets[level].append({
            "cve": entry.get("cve", "?"),
            "package": entry.get("package", ""),
            "overdue_milestone": overdue_milestone,
            "overdue_hours": overdue_hours,
        })

    if not any(buckets.values()):
        return "No escalation alerts — all notification milestones are on track.\n"

    lines = ["## CRA Notification Escalation Report", ""]

    level_labels = {
        "critical": "CRITICAL — Early Warning (24h) Overdue",
        "escalated": "ESCALATED — 72h Notification Overdue",
        "warning": "WARNING — Final Report (14d) Overdue",
    }
    milestone_labels = {
        "early_warning_24h": "Early Warning (24h)",
        "notification_72h": "72h Notification",
        "final_report_14d": "Final Report (14d)",
    }

    for level in ("critical", "escalated", "warning"):
        entries = buckets[level]
        if not entries:
            continue
        lines += [f"### {level_labels[level]}", ""]
        for e in entries:
            pkg_str = f" ({e['package']})" if e["package"] else ""
            milestone_label = milestone_labels.get(e["overdue_milestone"], e["overdue_milestone"])
            overdue_str = (
                f"{e['overdue_hours']}h overdue"
                if e["overdue_hours"] < 48
                else f"{e['overdue_hours'] // 24}d overdue"
            )
            lines.append(f"- **{e['cve']}**{pkg_str} — {milestone_label} — {overdue_str}")
        lines.append("")

    return "\n".join(lines)


def build_deadline_entry(finding: Finding, discovered_at: str) -> dict:
    """Create a deadline tracking entry for a finding.

    Args:
        finding: The Finding object.
        discovered_at: ISO date string when finding was first seen.

    Returns:
        Dict suitable for storage in state.json cra_deadlines section.
    """
    dl = compute_deadline(finding.severity, discovered_at)
    milestones = compute_notification_milestones(discovered_at)
    notifications = {
        name: {"due": due_date, "sent": None}
        for name, due_date in milestones.items()
    }
    return {
        "cve": finding.id,
        "package": finding.package,
        "severity": finding.severity,
        "discovered_at": discovered_at,
        "deadline": dl,
        "deadline_days": DEADLINE_DAYS.get(finding.severity.lower(), 90),
        "notifications": notifications,
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

    # Escalation counts and findings
    escalation_counts = {"critical": 0, "escalated": 0, "warning": 0}
    escalation_findings = []
    for fp, entry in deadlines.items():
        level = escalation_level(entry, as_of)
        if level != "none":
            escalation_counts[level] += 1
            escalation_findings.append({
                "cve": entry.get("cve", ""),
                "package": entry.get("package", ""),
                "level": level,
            })

    return {
        **counts,
        "overdue_findings": overdue_list,
        "warning_findings": warning_list,
        "escalation_counts": escalation_counts,
        "escalation_findings": escalation_findings,
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
