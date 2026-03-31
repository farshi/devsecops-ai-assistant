"""Fix suggestion engine — generates actionable upgrade commands for findings."""

from agent.models import Finding


def generate_fix_suggestions(findings: list[Finding], context: dict) -> list[dict]:
    """Generate fix suggestions for scored findings.

    For each finding, produces:
    {
        "id": "CVE-2024-xxx",
        "package": "werkzeug",
        "suggestion_type": "upgrade" | "investigate" | "accept_risk",
        "command": "pip install 'werkzeug>=3.0.3'",
        "description": "Upgrade werkzeug from 2.0.0 to 3.0.3 (major bump)",
        "confidence": "high" | "medium" | "low",
        "caveats": ["Major version bump — test thoroughly", ...],
        "breaking_change_risk": "high" | "low" | "none",
    }

    Only generates suggestions for findings with fix_available=True.
    For findings without fixes, suggests investigation or risk acceptance.
    """
    package_manager = context.get("dependencies", {}).get("package_manager", "pip")
    suggestions = []

    for finding in findings:
        suggestion = _suggest_for_finding(finding, package_manager)
        suggestions.append(suggestion)

    return suggestions


def _suggest_for_finding(finding: Finding, package_manager: str) -> dict:
    """Generate fix suggestion for a single finding."""
    base = {
        "id": finding.id,
        "package": finding.package,
    }

    if not finding.fix_available or not finding.fixed_version:
        return {
            **base,
            "suggestion_type": "investigate",
            "command": None,
            "description": f"No fix available for {finding.id} in {finding.package or '?'}. Monitor for updates.",
            "confidence": "low",
            "caveats": [
                "No patched version exists yet",
                "Consider workarounds or alternative packages",
                "Check vendor advisories for mitigation guidance",
            ],
            "breaking_change_risk": "none",
        }

    # Determine bump type and risk
    bump = _get_bump_type(finding)
    risk = _bump_to_risk(bump)
    confidence = _determine_confidence(finding, bump)
    command = _generate_command(finding, package_manager)
    caveats = _generate_caveats(finding, bump, risk)

    return {
        **base,
        "suggestion_type": "upgrade",
        "command": command,
        "description": f"Upgrade {finding.package} from {finding.installed_version} to {finding.fixed_version} ({bump} bump)",
        "confidence": confidence,
        "caveats": caveats,
        "breaking_change_risk": risk,
    }


def _get_bump_type(finding: Finding) -> str:
    """Extract bump type from fix_evidence or compute it."""
    if finding.fix_evidence and "version bump" in finding.fix_evidence:
        for part in finding.fix_evidence.split("|"):
            part = part.strip()
            if "version bump" in part:
                if "major" in part:
                    return "major"
                if "minor" in part:
                    return "minor"
                if "patch" in part:
                    return "patch"
    return "unknown"


def _bump_to_risk(bump: str) -> str:
    return {"major": "high", "minor": "low", "patch": "none", "unknown": "low"}.get(bump, "low")


def _determine_confidence(finding: Finding, bump: str) -> str:
    """How confident are we in the suggestion?"""
    if bump == "patch":
        return "high"   # Patch bumps are almost always safe
    elif bump == "minor":
        return "medium"  # Minor bumps might have API changes
    elif bump == "major":
        return "low"    # Major bumps likely have breaking changes
    return "medium"


def _generate_command(finding: Finding, package_manager: str) -> str:
    """Generate the upgrade command for the package manager."""
    pkg = finding.package or "?"
    ver = finding.fixed_version or "latest"

    if package_manager == "pip":
        return f"pip install '{pkg}>={ver}'"
    elif package_manager == "npm":
        return f"npm install {pkg}@{ver}"
    elif package_manager == "go":
        return f"go get {pkg}@v{ver}"
    else:
        return f"# Upgrade {pkg} to >= {ver}"


def _generate_caveats(finding: Finding, bump: str, risk: str) -> list[str]:
    """Generate relevant caveats for the suggestion."""
    caveats = []

    if bump == "major":
        caveats.append("Major version bump — likely breaking API changes. Test thoroughly.")
    elif bump == "minor":
        caveats.append("Minor version bump — usually backward compatible, but verify.")

    if risk == "high":
        caveats.append("Run your test suite before deploying this upgrade.")

    if finding.reachable == "true":
        caveats.append(
            f"This package is actively used in your code ({finding.reachability_evidence or 'imported'})."
        )
    elif finding.reachable == "false":
        caveats.append("This package is not imported in your code — consider removing it entirely.")

    if finding.in_kev:
        caveats.append("This CVE is in CISA's Known Exploited Vulnerabilities list — prioritize this fix.")

    if finding.epss_score and finding.epss_score > 0.5:
        caveats.append(f"High exploitation probability (EPSS: {finding.epss_score:.0%}).")

    if not caveats:
        caveats.append("Low-risk upgrade. Safe to apply.")

    return caveats
