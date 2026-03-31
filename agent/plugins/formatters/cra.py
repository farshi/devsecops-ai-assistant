"""CRA vulnerability disclosure formatter — EU Cyber Resilience Act compliance."""

from datetime import date, timedelta

from agent.models import Finding
from agent.plugins.base import OutputFormatter

# Remediation target timelines per severity
REMEDIATION_TIMELINES = {
    "critical": "24h",
    "high":     "7d",
    "medium":   "30d",
    "low":      "90d",
    "info":     "90d",
}

# Days to add for "target remediation" date
REMEDIATION_DAYS = {
    "critical": 1,
    "high":     7,
    "medium":   30,
    "low":      90,
    "info":     90,
}

_VERSION = "0.1.0"


def _target_remediation(severity: str, from_date: date) -> str:
    """Return ISO target remediation date based on severity."""
    days = REMEDIATION_DAYS.get(severity.lower(), 90)
    return str(from_date + timedelta(days=days))


def _fix_status(finding: Finding) -> str:
    if finding.fix_available and finding.fixed_version:
        return "Fix available"
    elif finding.fix_available:
        return "Fix available (version unknown)"
    return "No fix available"


def _action(finding: Finding) -> str:
    if finding.fix_available and finding.fixed_version:
        return f"Upgrade {finding.package or '?'} to >= {finding.fixed_version}"
    elif finding.fix_available:
        return f"Update {finding.package or '?'} to latest patched version"
    return f"Investigate {finding.id} — no fix available yet, assess workarounds"


def _extract_effort(finding: Finding) -> str:
    if finding.fix_evidence and "effort:" in finding.fix_evidence:
        for part in finding.fix_evidence.split("|"):
            part = part.strip()
            if part.startswith("effort:"):
                return part.split(":", 1)[1].strip()
    if not finding.fix_available:
        return "investigation"
    return "moderate"


class CRADisclosureFormatter(OutputFormatter):
    """Generates CRA-compliant vulnerability disclosure documents.

    Follows EU Cyber Resilience Act (Regulation 2024/2847) requirements
    for vulnerability disclosure. Produces structured markdown that can
    be submitted to ENISA or included in product documentation.
    """

    @property
    def name(self) -> str:
        return "cra"

    def format(self, findings: list[Finding], context: dict) -> str:
        """Generate CRA disclosure document from scored findings.

        Args:
            findings: Scored Finding objects (from prioritizer or scoring strategy)
            context: Context bundle from build_context()

        Returns:
            Markdown string with CRA disclosure document
        """
        today = date.today()
        today_str = str(today)

        # Extract context metadata
        scan_meta = context.get("scan_meta", {})
        target_name = scan_meta.get("target", context.get("target", "Unknown Product"))
        version = context.get("version", scan_meta.get("version", "N/A"))
        scan_date = scan_meta.get("date", "unknown")
        scanners = scan_meta.get("scanners_run", [])
        scanner_str = ", ".join(scanners) if scanners else "unknown"

        # Slugify target for document ID
        target_slug = target_name.replace(" ", "-").upper()

        # Repo / stack context
        repo = context.get("repo", {})
        languages = repo.get("languages", [])
        frameworks = repo.get("frameworks", [])
        has_docker = repo.get("docker", False)
        deps_ctx = context.get("dependencies", {})
        direct_deps = deps_ctx.get("direct", [])
        has_lockfile = bool(deps_ctx.get("lockfile"))

        # Categorize findings
        kev_findings = [f for f in findings if f.in_kev]
        total = len(findings)
        critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in findings if f.severity.lower() == "high")

        # Sort all findings by priority_score descending (should already be sorted, but be safe)
        ordered = sorted(findings, key=lambda f: f.priority_score, reverse=True)

        lines = []

        # ------------------------------------------------------------------ #
        # Header
        # ------------------------------------------------------------------ #
        lines += [
            "# Vulnerability Disclosure Report",
            "## CRA Compliance Document",
            "",
            f"**Document ID:** CRA-DISC-{today_str}-{target_slug}",
            f"**Date:** {today_str}",
            f"**Product:** {target_name}",
            f"**Version:** {version}",
            "**Classification:** EU Cyber Resilience Act — Article 14 Vulnerability Handling",
            "",
            "---",
            "",
        ]

        # ------------------------------------------------------------------ #
        # Section 1 — Executive Summary
        # ------------------------------------------------------------------ #
        lines += [
            "## 1. Executive Summary",
            "",
        ]

        if total == 0:
            lines += [
                f"0 vulnerabilities identified in {target_name}.",
                "No security findings detected in this scan.",
                "",
            ]
        else:
            kev_note = (
                f"{len(kev_findings)} actively exploited vulnerabilities requiring immediate attention."
                if kev_findings
                else "No actively exploited vulnerabilities detected."
            )
            lines += [
                f"{total} vulnerabilities identified in {target_name}.",
                f"{critical_count} critical, {high_count} high severity.",
                kev_note,
                "",
            ]

        # ------------------------------------------------------------------ #
        # Section 2 — Actively Exploited Vulnerabilities (KEV)
        # ------------------------------------------------------------------ #
        lines += [
            "## 2. Actively Exploited Vulnerabilities",
            "",
            "*Per CRA Article 14(2)(a): actively exploited vulnerabilities must be reported within 24 hours.*",
            "",
        ]

        if kev_findings:
            lines += [
                "| CVE ID | Component | Severity | EPSS | Status | Remediation |",
                "|--------|-----------|----------|------|--------|-------------|",
            ]
            for f in kev_findings:
                cve_id = f.id
                component = f"{f.package or '?'}@{f.installed_version or '?'}"
                severity = f.severity.upper()
                epss = f"{f.epss_score:.2f}" if f.epss_score is not None else "N/A"
                status = "IN KEV"
                remediation = _action(f)
                lines.append(f"| {cve_id} | {component} | {severity} | {epss} | {status} | {remediation} |")
            lines.append("")
        else:
            lines += [
                "No actively exploited vulnerabilities detected in this scan.",
                "",
            ]

        # ------------------------------------------------------------------ #
        # Section 3 — Vulnerability Details
        # ------------------------------------------------------------------ #
        lines += [
            "## 3. Vulnerability Details",
            "",
        ]

        if not ordered:
            lines += ["No vulnerabilities to detail.", ""]
        else:
            for i, f in enumerate(ordered, start=1):
                title_suffix = f" — {f.title}" if f.title else ""
                lines += [
                    f"### 3.{i} {f.id}{title_suffix}",
                    "",
                    f"**Component:** {f.package or 'N/A'} {f.installed_version or ''}".rstrip(),
                    f"**Severity:** {f.severity.upper()} (CVSS: {f.cvss_score if f.cvss_score is not None else 'N/A'})",
                    "**Exploitability:**",
                ]

                epss_display = f"{f.epss_score:.4f}" if f.epss_score is not None else "N/A"
                epss_flag = ""
                if f.epss_score is not None and f.epss_score > 0.5:
                    epss_flag = " *(high exploitation probability)*"

                lines += [
                    f"- EPSS (30-day exploitation probability): {epss_display}{epss_flag}",
                    f"- CISA KEV (known exploited): {'Yes' if f.in_kev else 'No'}",
                    f"- Reachability in product: {f.reachable} (confidence: {f.reachability_confidence})",
                    "",
                    "**Remediation:**",
                    f"- Status: {_fix_status(f)}",
                    f"- Fixed version: {f.fixed_version or 'N/A'}",
                    f"- Effort: {_extract_effort(f)}",
                    f"- Action: {_action(f)}",
                    "",
                    "**Discovery Timeline:**",
                    f"- Scan date: {scan_date}",
                    f"- Disclosure: {today_str}",
                    f"- Target remediation: {_target_remediation(f.severity, today)} "
                    f"({REMEDIATION_TIMELINES.get(f.severity.lower(), '90d')} from disclosure)",
                    "",
                    "---",
                    "",
                ]

        # ------------------------------------------------------------------ #
        # Section 4 — Product Context
        # ------------------------------------------------------------------ #
        lang_str = ", ".join(languages) if languages else "unknown"
        fw_str = ", ".join(frameworks) if frameworks else "none detected"
        runtime_str = "Docker container" if has_docker else "none"
        lockfile_str = "yes" if has_lockfile else "no"
        dep_count = len(direct_deps)

        lines += [
            "## 4. Product Context",
            "",
            f"**Technology Stack:** {lang_str}",
            f"**Frameworks:** {fw_str}",
            f"**Runtime:** {runtime_str}",
            f"**Dependencies:** {dep_count} direct, lockfile: {lockfile_str}",
            f"**Scan Coverage:** {scanner_str}",
            "",
        ]

        # ------------------------------------------------------------------ #
        # Section 5 — Compliance Statement
        # ------------------------------------------------------------------ #
        next_assessment = str(today + timedelta(days=30))

        lines += [
            "## 5. Compliance Statement",
            "",
            "This disclosure is generated in accordance with EU Regulation 2024/2847",
            "(Cyber Resilience Act), Articles 14 and 15. Vulnerability handling follows",
            "the coordinated vulnerability disclosure process as required by the Act.",
            "",
            "**Contact:** *placeholder — to be configured*",
            f"**Next scheduled assessment:** {next_assessment}",
            "",
            "---",
            "",
            f"*Generated by PatchPilot v{_VERSION} — https://github.com/farshi/devsecops-ai-assistant*",
        ]

        return "\n".join(lines)
