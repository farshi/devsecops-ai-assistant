"""
SemgrepScannerAdapter — implements ScannerAdapter for Semgrep JSON output.

Normalizes Semgrep SAST findings (code patterns, security rules, custom rules)
into canonical Finding instances.

Semgrep JSON format (--json flag):
{
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "app/main.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 55},
            "extra": {
                "message": "Dangerous subprocess use with shell=True",
                "severity": "WARNING",  # ERROR, WARNING, INFO
                "metadata": {
                    "cwe": ["CWE-78"],
                    "owasp": ["A03:2021"],
                    "confidence": "HIGH",
                    "impact": "HIGH",
                    "likelihood": "MEDIUM",
                    "semgrep.dev": {"rule": {...}},
                    "references": ["https://..."],
                    "category": "security",
                    "technology": ["python"],
                    "vulnerability_class": ["Command Injection"],
                }
            }
        }
    ],
    "errors": [...],
    "version": "1.x.x"
}
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import ScannerAdapter

# Semgrep uses ERROR/WARNING/INFO; map to our severity model
SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}

# If metadata has impact field, use it for more granular mapping
IMPACT_SEVERITY_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
}


class SemgrepScannerAdapter(ScannerAdapter):
    """Normalizes Semgrep JSON output into canonical Finding instances."""

    @property
    def name(self) -> str:
        return "semgrep"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a Semgrep JSON output file and return normalized Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        return self.parse_dict(raw)

    def parse_dict(self, raw: dict) -> list[Finding]:
        """Parse a pre-loaded Semgrep JSON dict into Findings."""
        findings: list[Finding] = []

        for result in raw.get("results", []):
            finding = self._parse_result(result)
            if finding:
                findings.append(finding)

        return findings

    @staticmethod
    def _parse_result(result: dict) -> Finding:
        """Convert a single Semgrep result into a Finding."""
        check_id = result.get("check_id", "unknown")
        path = result.get("path", "unknown")
        start = result.get("start", {})
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        message = extra.get("message", "")

        # Build a readable rule ID from the check_id
        # e.g. "python.lang.security.audit.dangerous-subprocess-use" → last segment
        rule_short = check_id.rsplit(".", 1)[-1] if "." in check_id else check_id

        # Title
        title = message or rule_short
        if len(title) > 120:
            title = title[:117] + "..."

        # Location
        line = start.get("line", 0)
        location = f"{path}:{line}" if line else path

        # Severity: prefer metadata.impact, fall back to extra.severity
        raw_severity = extra.get("severity", "WARNING")
        impact = metadata.get("impact", "")
        if impact and impact.upper() in IMPACT_SEVERITY_MAP:
            severity = IMPACT_SEVERITY_MAP[impact.upper()]
        else:
            severity = SEVERITY_MAP.get(raw_severity.upper(), "medium")

        # If metadata indicates critical confidence + high impact, escalate
        confidence = metadata.get("confidence", "").upper()
        if severity == "high" and confidence == "HIGH" and impact.upper() == "HIGH":
            severity = "critical"

        # CWE as the finding ID if available, otherwise use check_id
        cwes = metadata.get("cwe", [])
        finding_id = cwes[0] if cwes else check_id

        # OWASP references as fix evidence
        owasp = metadata.get("owasp", [])
        vuln_class = metadata.get("vulnerability_class", [])
        references = metadata.get("references", [])

        evidence_parts = []
        if owasp:
            evidence_parts.append(f"OWASP: {', '.join(owasp)}")
        if vuln_class:
            evidence_parts.append(f"Class: {', '.join(vuln_class)}")
        if references:
            evidence_parts.append(f"Ref: {references[0]}")
        fix_evidence = " | ".join(evidence_parts) if evidence_parts else None

        return Finding(
            id=finding_id,
            source_scanner="semgrep",
            finding_type="code_pattern",
            severity=severity,
            title=title,
            location=location,
            reachable="not_applicable",
            reachability_confidence="none",
            fix_available=bool(references),
            fix_evidence=fix_evidence,
        )
