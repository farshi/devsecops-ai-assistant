"""
TrivyScannerAdapter — implements ScannerAdapter for `trivy fs` JSON output.

Normalizes raw Trivy findings into canonical Finding instances.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from agent.models import Finding
from agent.plugins.base import ScannerAdapter

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "info",
}

# Maps Trivy's Class field to our canonical finding_type
CLASS_MAP = {
    "os-pkgs":   "os_package",
    "lang-pkgs": "language_dep",
}


def _extract_cvss(vuln: dict) -> Optional[float]:
    """Return the first available V3Score from CVSS data, preferring nvd."""
    cvss = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat"):
        score = cvss.get(source, {}).get("V3Score")
        if score is not None:
            return float(score)
    return None


class TrivyScannerAdapter(ScannerAdapter):
    """Normalizes raw `trivy fs` JSON output into canonical Finding instances."""

    @property
    def name(self) -> str:
        return "trivy_fs"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a Trivy JSON output file and return normalized Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        return self.parse_dict(raw)

    def parse_dict(self, raw: dict) -> list[Finding]:
        """
        Parse a pre-loaded Trivy JSON dict and return normalized Findings.

        Exists for backward compatibility with callers that load JSON separately
        (e.g., agent/scan.py via the parse_trivy thin wrapper).

        finding_type is derived from Trivy's Class field:
            "os-pkgs"   → os_package  (reachable = not_applicable)
            "lang-pkgs" → language_dep
            (missing)   → language_dep (default)
        """
        findings: list[Finding] = []

        for result in raw.get("Results", []):
            target = result.get("Target", "unknown")
            trivy_class = result.get("Class", "")
            finding_type = CLASS_MAP.get(trivy_class, "language_dep")
            is_os = finding_type == "os_package"

            for vuln in result.get("Vulnerabilities") or []:
                pkg_name      = vuln.get("PkgName", "?")
                installed_ver = vuln.get("InstalledVersion", "?")
                fixed_ver     = vuln.get("FixedVersion") or None
                severity      = SEVERITY_MAP.get(vuln.get("Severity", "").upper(), "info")
                cvss_score    = _extract_cvss(vuln)

                finding = Finding(
                    id=vuln.get("VulnerabilityID", "unknown"),
                    source_scanner="trivy_fs",
                    finding_type=finding_type,
                    severity=severity,
                    title=vuln.get("Title") or vuln.get("Description", "")[:120],
                    package=pkg_name,
                    installed_version=installed_ver,
                    fixed_version=fixed_ver,
                    location=f"{target} > {pkg_name}@{installed_ver}",
                    cvss_score=cvss_score,
                    reachable="not_applicable" if is_os else "unknown",
                    fix_available=fixed_ver is not None,
                    fix_evidence=f"Upgrade to >= {fixed_ver}" if fixed_ver else None,
                )
                findings.append(finding)

        return findings
