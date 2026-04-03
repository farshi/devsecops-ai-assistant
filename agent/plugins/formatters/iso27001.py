"""ISO 27001 compliance formatter — maps findings to Annex A controls."""

from datetime import date

from agent.models import Finding
from agent.plugins.base import OutputFormatter

# ISO 27001:2022 Annex A controls relevant to vulnerability management
CONTROLS = {
    "A.8.8": {
        "title": "Management of Technical Vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.",
        "maps_to": lambda f: True,  # all vulnerability findings
    },
    "A.8.9": {
        "title": "Configuration Management",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        "maps_to": lambda f: f.finding_type == "iac_misconfig",
    },
    "A.8.25": {
        "title": "Secure Development Life Cycle",
        "description": "Rules for the secure development of software and systems shall be established and applied.",
        "maps_to": lambda f: f.finding_type in ("code_pattern", "language_dep"),
    },
    "A.8.28": {
        "title": "Secure Coding",
        "description": "Secure coding principles shall be applied to software development.",
        "maps_to": lambda f: f.finding_type == "code_pattern",
    },
    "A.5.7": {
        "title": "Threat Intelligence",
        "description": "Information relating to information security threats shall be collected and analyzed to produce threat intelligence.",
        "maps_to": lambda f: f.in_kev or (f.epss_score is not None and f.epss_score > 0.1),
    },
    "A.8.16": {
        "title": "Monitoring Activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behavior and appropriate actions taken to evaluate potential information security incidents.",
        "maps_to": lambda f: True,  # all findings demonstrate monitoring
    },
}

_VERSION = "0.1.0"


def _risk_level(finding: Finding) -> str:
    """Map finding severity to ISO risk level."""
    mapping = {
        "critical": "Very High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Very Low",
    }
    return mapping.get(finding.severity, "Medium")


def _treatment_status(finding: Finding) -> str:
    """Determine risk treatment status."""
    if finding.fix_available and finding.fixed_version:
        return "Mitigate"
    elif finding.fix_available:
        return "Mitigate"
    return "Accept / Monitor"


class ISO27001ComplianceFormatter(OutputFormatter):
    """Maps triage findings to ISO 27001:2022 Annex A controls.

    Generates an audit-ready report with vulnerability register,
    control mapping, and risk treatment plan.
    """

    @property
    def name(self) -> str:
        return "iso27001"

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

        # Map findings to controls
        control_findings: dict[str, list[Finding]] = {}
        for ctrl_id in CONTROLS:
            predicate = CONTROLS[ctrl_id]["maps_to"]
            control_findings[ctrl_id] = [f for f in findings if predicate(f)]

        lines: list[str] = []

        # Header
        lines += [
            "# ISO 27001 Compliance Report",
            "## Annex A Control Assessment — Technical Vulnerabilities",
            "",
            f"**Date:** {today_str}",
            f"**Scope:** {target_name}",
            f"**Scan Date:** {scan_date}",
            f"**Standard:** ISO/IEC 27001:2022",
            "",
            "---",
            "",
        ]

        # Section 1 — Executive Summary
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        fixable = sum(1 for f in findings if f.fix_available)
        controls_with_findings = sum(1 for c in control_findings.values() if c)

        lines += [
            "## 1. Executive Summary",
            "",
            f"{total} technical vulnerabilities identified in {target_name}.",
            f"- **Critical:** {critical}",
            f"- **High:** {high}",
            f"- **Medium:** {medium}",
            f"- **Low:** {low}",
            f"- **Controls affected:** {controls_with_findings} of {len(CONTROLS)}",
            f"- **Fix available:** {fixable} of {total}",
            "",
        ]

        # Section 2 — Annex A Control Mapping
        lines += [
            "## 2. Annex A Control Mapping",
            "",
            "| Control | Title | Findings | Compliance |",
            "|---------|-------|----------|------------|",
        ]
        for ctrl_id, ctrl in CONTROLS.items():
            mapped = control_findings[ctrl_id]
            if not mapped:
                status = "Conforming"
            elif any(f.severity in ("critical", "high") for f in mapped):
                status = "Non-conformity"
            else:
                status = "Observation"
            lines.append(f"| {ctrl_id} | {ctrl['title']} | {len(mapped)} | {status} |")
        lines.append("")

        # Section 3 — Vulnerability Register (required by A.8.8)
        lines += [
            "## 3. Vulnerability Register",
            "",
            "*Required by ISO 27001:2022, Control A.8.8*",
            "",
        ]
        if not ordered:
            lines += ["No vulnerabilities registered.", ""]
        else:
            lines += [
                "| ID | Component | Severity | Risk Level | EPSS | Treatment | Status |",
                "|----|-----------|----------|------------|------|-----------|--------|",
            ]
            for f in ordered:
                component = f"{f.package or 'N/A'}@{f.installed_version or '?'}"
                risk = _risk_level(f)
                epss = f"{f.epss_score:.2f}" if f.epss_score is not None else "N/A"
                treatment = _treatment_status(f)
                fix_status = "Fix available" if f.fix_available else "Open"
                lines.append(
                    f"| {f.id} | {component} | {f.severity.upper()} | {risk} | {epss} | {treatment} | {fix_status} |"
                )
            lines.append("")

        # Section 4 — Risk Treatment Plan
        lines += [
            "## 4. Risk Treatment Plan",
            "",
        ]
        if not ordered:
            lines += ["No findings require treatment.", ""]
        else:
            lines += [
                "**Priority remediation actions (ranked by risk):**",
                "",
            ]
            for i, f in enumerate(ordered[:10], 1):
                action = (
                    f"Upgrade {f.package or '?'} to >= {f.fixed_version}"
                    if f.fix_available and f.fixed_version
                    else f"Investigate {f.id} — assess workarounds"
                )
                lines.append(f"{i}. **[{f.severity.upper()}]** {f.id} — {action}")
            lines.append("")

        # Section 5 — Continuous Improvement Evidence
        lines += [
            "## 5. Continuous Improvement Evidence",
            "",
            f"**Scanning tools:** {scanner_str}",
            f"**Last scan:** {scan_date}",
            f"**Report generated:** {today_str}",
            f"**Total findings tracked:** {total}",
            "",
            "This report provides evidence of continuous vulnerability management",
            "as required by ISO 27001:2022, Clause 10 (Improvement) and",
            "Annex A Control A.8.8 (Management of Technical Vulnerabilities).",
            "",
            "---",
            "",
            f"*Generated by PatchPilot v{_VERSION} — https://github.com/farshi/devsecops-ai-assistant*",
        ]

        return "\n".join(lines)
