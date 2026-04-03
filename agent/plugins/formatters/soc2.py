"""SOC2 compliance formatter — maps findings to Trust Service Criteria controls."""

from datetime import date

from agent.models import Finding
from agent.plugins.base import OutputFormatter

# SOC2 Trust Service Criteria relevant to vulnerability management
CONTROLS = {
    "CC6.1": {
        "title": "Logical and Physical Access Controls",
        "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
        "maps_to": lambda f: f.reachable == "true",
    },
    "CC6.8": {
        "title": "Controls Against Malicious Software",
        "description": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
        "maps_to": lambda f: True,  # all vulnerability findings
    },
    "CC7.1": {
        "title": "Detection and Monitoring",
        "description": "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
        "maps_to": lambda f: True,  # all findings demonstrate monitoring
    },
    "CC7.2": {
        "title": "Incident Response",
        "description": "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.",
        "maps_to": lambda f: f.in_kev or f.severity in ("critical", "high"),
    },
    "CC8.1": {
        "title": "Change Management",
        "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
        "maps_to": lambda f: f.fix_available,
    },
}

_VERSION = "0.1.0"


def _posture_rating(findings: list[Finding]) -> str:
    """Rate overall compliance posture based on findings severity."""
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    kev = sum(1 for f in findings if f.in_kev)

    if critical == 0 and high == 0 and kev == 0:
        return "Strong"
    elif critical == 0 and kev == 0:
        return "Adequate"
    elif critical <= 2 and kev == 0:
        return "Needs Improvement"
    else:
        return "At Risk"


def _control_status(findings: list[Finding]) -> str:
    """Determine control status based on mapped findings."""
    if not findings:
        return "Effective"
    critical = sum(1 for f in findings if f.severity == "critical")
    if critical > 0:
        return "Deficient"
    high = sum(1 for f in findings if f.severity == "high")
    if high > 0:
        return "Partially Effective"
    return "Effective with Observations"


class SOC2ComplianceFormatter(OutputFormatter):
    """Maps triage findings to SOC2 Trust Service Criteria controls.

    Generates an audit-ready compliance report that maps each finding
    to relevant SOC2 controls and assesses control effectiveness.
    """

    @property
    def name(self) -> str:
        return "soc2"

    def format(self, findings: list[Finding], context: dict) -> str:
        today = date.today()
        today_str = str(today)

        scan_meta = context.get("scan_meta", {})
        target_name = scan_meta.get("target", context.get("target", "Unknown Product"))
        scan_date = scan_meta.get("date", "unknown")
        scanners = scan_meta.get("scanners_run", [])
        scanner_str = ", ".join(scanners) if scanners else "unknown"

        total = len(findings)
        ordered = sorted(findings, key=lambda f: f.priority_score, reverse=True)
        posture = _posture_rating(findings)

        # Map findings to controls
        control_findings: dict[str, list[Finding]] = {}
        for ctrl_id in CONTROLS:
            predicate = CONTROLS[ctrl_id]["maps_to"]
            control_findings[ctrl_id] = [f for f in findings if predicate(f)]

        lines: list[str] = []

        # Header
        lines += [
            "# SOC2 Compliance Report",
            "## Trust Service Criteria — Security Assessment",
            "",
            f"**Date:** {today_str}",
            f"**Product:** {target_name}",
            f"**Scan Date:** {scan_date}",
            f"**Assessment Posture:** {posture}",
            "",
            "---",
            "",
        ]

        # Section 1 — Executive Summary
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        kev = sum(1 for f in findings if f.in_kev)
        fixable = sum(1 for f in findings if f.fix_available)

        lines += [
            "## 1. Executive Summary",
            "",
            f"{total} security findings identified across {target_name}.",
            f"- **Critical:** {critical}",
            f"- **High:** {high}",
            f"- **Medium:** {medium}",
            f"- **Low:** {low}",
            f"- **Actively exploited (KEV):** {kev}",
            f"- **Fix available:** {fixable} of {total}",
            "",
        ]

        # Section 2 — Control Mapping Table
        lines += [
            "## 2. Control Mapping",
            "",
            "| Control | Title | Findings | Status |",
            "|---------|-------|----------|--------|",
        ]
        for ctrl_id, ctrl in CONTROLS.items():
            mapped = control_findings[ctrl_id]
            status = _control_status(mapped)
            lines.append(f"| {ctrl_id} | {ctrl['title']} | {len(mapped)} | {status} |")
        lines.append("")

        # Section 3 — Findings by Control
        lines += [
            "## 3. Findings by Control",
            "",
        ]
        for ctrl_id, ctrl in CONTROLS.items():
            mapped = control_findings[ctrl_id]
            lines += [
                f"### {ctrl_id}: {ctrl['title']}",
                "",
                f"*{ctrl['description']}*",
                "",
            ]
            if not mapped:
                lines += ["No findings mapped to this control.", ""]
                continue

            lines += [
                "| ID | Severity | Package | Fix Available | Score |",
                "|----|----------|---------|---------------|-------|",
            ]
            for f in sorted(mapped, key=lambda x: x.priority_score, reverse=True):
                pkg = f.package or "N/A"
                fix = "Yes" if f.fix_available else "No"
                lines.append(f"| {f.id} | {f.severity.upper()} | {pkg} | {fix} | {f.priority_score} |")
            lines.append("")

        # Section 4 — Remediation Status
        lines += [
            "## 4. Remediation Status",
            "",
        ]
        if not findings:
            lines += ["No findings require remediation.", ""]
        else:
            fix_pct = round(fixable / total * 100) if total > 0 else 0
            lines += [
                f"**Remediation coverage:** {fixable}/{total} findings have fixes available ({fix_pct}%)",
                "",
            ]
            if ordered:
                lines += [
                    "**Top priority remediation actions:**",
                    "",
                ]
                for f in ordered[:5]:
                    action = f"Upgrade {f.package or '?'} to >= {f.fixed_version}" if f.fix_available and f.fixed_version else f"Investigate {f.id}"
                    lines.append(f"1. [{f.severity.upper()}] {f.id} — {action}")
                lines.append("")

        # Section 5 — Evidence of Monitoring
        lines += [
            "## 5. Evidence of Monitoring",
            "",
            f"**Scanners used:** {scanner_str}",
            f"**Scan date:** {scan_date}",
            f"**Report generated:** {today_str}",
            f"**Total findings detected:** {total}",
            "",
            "This report demonstrates active vulnerability detection and monitoring",
            "as required by SOC2 Trust Service Criteria CC7.1.",
            "",
            "---",
            "",
            f"*Generated by PatchPilot v{_VERSION} — https://github.com/farshi/devsecops-ai-assistant*",
        ]

        return "\n".join(lines)
