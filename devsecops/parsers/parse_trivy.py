"""
Normalize raw trivy fs JSON output into a flat list of findings.
"""

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "info",
}


def parse(raw: dict) -> list[dict]:
    """
    Convert trivy fs JSON → list of normalized finding dicts.

    Each finding:
        id       : CVE or advisory ID
        severity : critical | high | medium | low | info
        title    : short description
        location : "target > package@version"
        fix      : fixed version string, or omitted if not available
    """
    findings = []

    for result in raw.get("Results", []):
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            finding = {
                "id":       vuln.get("VulnerabilityID", "unknown"),
                "severity": SEVERITY_MAP.get(vuln.get("Severity", "").upper(), "info"),
                "title":    vuln.get("Title") or vuln.get("Description", "")[:120],
                "location": f"{target} > {vuln.get('PkgName', '?')}@{vuln.get('InstalledVersion', '?')}",
            }
            fixed = vuln.get("FixedVersion")
            if fixed:
                finding["fix"] = f"Upgrade to >= {fixed}"
            findings.append(finding)

    return findings
