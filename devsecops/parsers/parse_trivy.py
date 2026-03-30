"""
Normalize raw trivy fs JSON output into a flat list of Finding instances.
"""

from __future__ import annotations

from typing import Optional
from agent.models import Finding

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


def parse(raw: dict) -> list[Finding]:
    """
    Convert trivy fs JSON → list of normalized Finding instances.

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
            pkg_name         = vuln.get("PkgName", "?")
            installed_ver    = vuln.get("InstalledVersion", "?")
            fixed_ver        = vuln.get("FixedVersion") or None
            severity         = SEVERITY_MAP.get(vuln.get("Severity", "").upper(), "info")
            cvss_score       = _extract_cvss(vuln)

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
