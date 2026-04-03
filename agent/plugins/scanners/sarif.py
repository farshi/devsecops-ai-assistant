"""
SARIFScannerAdapter — implements ScannerAdapter for generic SARIF 2.1.0 JSON output.

Normalizes findings from any SARIF-producing scanner (Semgrep, CodeQL, Bandit,
Checkov, etc.) into canonical Finding instances.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from agent.models import Finding
from agent.plugins.base import ScannerAdapter

LEVEL_MAP = {
    "error":   "critical",
    "warning": "high",
    "note":    "low",
    "none":    "info",
}

# Maps known tool names (lowercase) to Finding.finding_type
TOOL_FINDING_TYPE_MAP = {
    "semgrep":  "code_pattern",
    "codeql":   "code_pattern",
    "bandit":   "code_pattern",
    "eslint":   "code_pattern",
    "checkov":  "iac_misconfig",
    "tfsec":    "iac_misconfig",
    "tflint":   "iac_misconfig",
    "trivy":    "language_dep",
    "grype":    "language_dep",
    "snyk":     "language_dep",
    "gitleaks": "secret",
}


def _infer_finding_type(tool_name: str) -> str:
    """Infer finding_type from the SARIF tool name."""
    return TOOL_FINDING_TYPE_MAP.get(tool_name.lower(), "code_pattern")


class SARIFScannerAdapter(ScannerAdapter):
    """Normalizes SARIF 2.1.0 JSON output into canonical Finding instances."""

    @property
    def name(self) -> str:
        return "sarif"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a SARIF JSON output file and return normalized Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        return self.parse_dict(raw)

    def parse_dict(self, raw: dict) -> list[Finding]:
        """Parse a pre-loaded SARIF 2.1.0 dict into Findings.

        Flattens all runs — each run may come from a different tool.
        """
        findings: list[Finding] = []

        for run in raw.get("runs", []):
            tool_name = (
                run.get("tool", {}).get("driver", {}).get("name", "unknown")
            )
            rules_by_id = self._index_rules(run)
            finding_type = _infer_finding_type(tool_name)
            source = f"sarif:{tool_name.lower()}"

            for result in run.get("results", []):
                finding = self._parse_result(
                    result, source, finding_type, rules_by_id
                )
                if finding:
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _index_rules(run: dict) -> dict[str, dict]:
        """Build a lookup of rule ID → rule metadata from tool.driver.rules."""
        rules: dict[str, dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id")
            if rid:
                rules[rid] = rule
        return rules

    def _parse_result(
        self,
        result: dict,
        source_scanner: str,
        finding_type: str,
        rules_by_id: dict[str, dict],
    ) -> Optional[Finding]:
        """Convert a single SARIF result into a Finding."""
        rule_id = result.get("ruleId", "unknown")

        # Severity: SARIF default level is "warning" when absent
        level = result.get("level", "warning")
        severity = LEVEL_MAP.get(level, "high")

        # Title: prefer message.text, fall back to rule shortDescription
        title = result.get("message", {}).get("text", "")
        if not title:
            rule_meta = rules_by_id.get(rule_id, {})
            title = rule_meta.get("shortDescription", {}).get("text", "")
        if not title:
            title = f"Rule {rule_id} triggered"
        if len(title) > 120:
            title = title[:117] + "..."

        location = self._extract_location(result.get("locations", []))

        return Finding(
            id=rule_id,
            source_scanner=source_scanner,
            finding_type=finding_type,
            severity=severity,
            title=title,
            location=location,
            reachable="unknown",
        )

    @staticmethod
    def _extract_location(locations: list) -> str:
        """Extract file path and line number from SARIF locations array."""
        if not locations:
            return "unknown"

        phys = locations[0].get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "unknown")
        line = phys.get("region", {}).get("startLine")

        if line:
            return f"{uri}:{line}"
        return uri
