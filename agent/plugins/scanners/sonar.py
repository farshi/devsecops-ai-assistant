"""
SonarScannerAdapter — implements ScannerAdapter for SonarQube / SonarCloud output.

Sonar does not run as a local CLI like Trivy or Checkov; it analyses code on a
server and exposes findings through its REST API:

    GET api/issues/search      → issues (VULNERABILITY / BUG / CODE_SMELL)
    GET api/hotspots/search    → security hotspots

This adapter normalizes a saved ``api/issues/search`` JSON response (and, when
present, the merged SECURITY_HOTSPOT issues that newer Sonar versions return
from the same endpoint) into canonical Finding instances. Fetch the JSON with a
project token, save it to a file, then point this adapter at it — the rest of
the PatchPilot pipeline (enrich, score, rank, compliance-map) is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from agent.models import Finding
from agent.plugins.base import ScannerAdapter

# Sonar issue severity → canonical severity.
# Covers both the legacy (BLOCKER..INFO) and the newer software-quality
# (HIGH/MEDIUM/LOW) impact scales.
SEVERITY_MAP = {
    "BLOCKER":  "critical",
    "CRITICAL": "high",
    "MAJOR":    "medium",
    "MINOR":    "low",
    "INFO":     "info",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
}

# Sonar issue type → canonical finding_type. Sonar is a code analyser, so all
# of its findings map to code-level types.
TYPE_FINDING_TYPE_MAP = {
    "VULNERABILITY":    "code_pattern",
    "SECURITY_HOTSPOT": "code_pattern",
    "BUG":              "code_pattern",
    "CODE_SMELL":       "code_pattern",
}

# Security hotspots report a vulnerabilityProbability instead of a severity.
HOTSPOT_PROBABILITY_MAP = {
    "HIGH":   "high",
    "MEDIUM": "medium",
    "LOW":    "low",
}


def _map_severity(raw_severity: Optional[str]) -> str:
    """Map a Sonar severity/impact string to canonical severity."""
    if not raw_severity:
        return "medium"
    return SEVERITY_MAP.get(str(raw_severity).upper(), "medium")


def _strip_component(component: Optional[str]) -> str:
    """Sonar component keys look like ``projectKey:src/app.py`` — keep the path."""
    if not component:
        return "unknown"
    # Project key is everything before the first ':'; the path follows it.
    return component.split(":", 1)[1] if ":" in component else component


class SonarScannerAdapter(ScannerAdapter):
    """Normalizes SonarQube/SonarCloud api/issues/search JSON into Findings."""

    @property
    def name(self) -> str:
        return "sonar"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a saved Sonar issues-search JSON file and return Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        return self.parse_dict(raw)

    def parse_dict(self, raw: dict) -> list[Finding]:
        """Parse a pre-loaded Sonar API response dict into Findings.

        Accepts the ``api/issues/search`` shape (``{"issues": [...]}``) and the
        ``api/hotspots/search`` shape (``{"hotspots": [...]}``). Either or both
        keys may be present; both are flattened into the returned list.
        """
        findings: list[Finding] = []

        for issue in raw.get("issues", []):
            finding = self._parse_issue(issue)
            if finding:
                findings.append(finding)

        for hotspot in raw.get("hotspots", []):
            finding = self._parse_hotspot(hotspot)
            if finding:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_issue(self, issue: dict) -> Optional[Finding]:
        """Convert one ``api/issues/search`` issue into a Finding."""
        rule = issue.get("rule", "unknown")
        issue_type = issue.get("type", "VULNERABILITY")
        finding_type = TYPE_FINDING_TYPE_MAP.get(issue_type, "code_pattern")

        # Hotspots returned inline from issues/search carry a probability.
        if issue_type == "SECURITY_HOTSPOT":
            severity = HOTSPOT_PROBABILITY_MAP.get(
                str(issue.get("vulnerabilityProbability", "")).upper(),
                _map_severity(issue.get("severity")),
            )
        else:
            severity = _map_severity(issue.get("severity"))

        title = issue.get("message") or f"Sonar rule {rule} triggered"
        if len(title) > 120:
            title = title[:117] + "..."

        location = self._build_location(
            issue.get("component"), issue.get("line")
        )

        return Finding(
            id=rule,
            source_scanner="sonar",
            finding_type=finding_type,
            severity=severity,
            title=title,
            location=location,
            reachable="unknown",
        )

    def _parse_hotspot(self, hotspot: dict) -> Optional[Finding]:
        """Convert one ``api/hotspots/search`` hotspot into a Finding."""
        rule = hotspot.get("ruleKey") or hotspot.get("rule", "unknown")
        severity = HOTSPOT_PROBABILITY_MAP.get(
            str(hotspot.get("vulnerabilityProbability", "")).upper(), "medium"
        )

        title = hotspot.get("message") or f"Sonar hotspot {rule}"
        if len(title) > 120:
            title = title[:117] + "..."

        location = self._build_location(
            hotspot.get("component"), hotspot.get("line")
        )

        return Finding(
            id=rule,
            source_scanner="sonar",
            finding_type="code_pattern",
            severity=severity,
            title=title,
            location=location,
            reachable="unknown",
        )

    @staticmethod
    def _build_location(component: Optional[str], line) -> str:
        """Build a ``path:line`` location from a Sonar component + line."""
        path = _strip_component(component)
        if line:
            return f"{path}:{line}"
        return path
