"""Fix availability enrichment — assesses fix effort and breaking change risk."""

import re
from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


class FixAvailabilityPlugin(EnrichmentPlugin):
    """Enriches findings with fix effort assessment.

    For each finding that has a fixed_version:
    - Determines if the upgrade is a major/minor/patch bump
    - Flags potential breaking changes (major bumps)
    - Estimates effort: trivial (patch), moderate (minor), complex (major)
    - Updates fix_evidence with detailed info

    For findings WITHOUT a fixed_version:
    - Sets fix_available=False
    - Sets fix_evidence="No fix available"
    """

    @property
    def name(self) -> str:
        return "fix_availability"

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Assess fix availability for all findings."""
        for finding in findings:
            self._assess(finding)
        return findings

    def _assess(self, finding: Finding) -> None:
        """Assess a single finding's fix availability."""
        if not finding.fixed_version:
            finding.fix_available = False
            finding.fix_evidence = "No fix available"
            return

        finding.fix_available = True

        installed = finding.installed_version or ""
        fixed = finding.fixed_version or ""

        bump = _classify_version_bump(installed, fixed)
        effort = _bump_to_effort(bump)
        breaking = bump == "major"

        # Build detailed evidence
        parts = [f"Upgrade {finding.package or '?'} from {installed} to >= {fixed}"]
        parts.append(f"{bump} version bump")
        if breaking:
            parts.append("⚠ potential breaking change")
        parts.append(f"effort: {effort}")

        finding.fix_evidence = " | ".join(parts)


def _parse_version(version_str: str) -> tuple:
    """Parse a version string into (major, minor, patch) tuple.

    Handles: "1.2.3", "1.2", "1", "1.2.3-beta", "1.2.3+build"
    Returns (major, minor, patch) as ints, defaulting missing parts to 0.
    """
    # Strip leading v, trailing pre-release/build metadata
    clean = re.sub(r'^v', '', version_str.strip())
    clean = re.split(r'[-+]', clean)[0]  # remove -beta, +build

    parts = clean.split('.')
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _classify_version_bump(installed: str, fixed: str) -> str:
    """Classify the version bump between installed and fixed.

    Returns: "major", "minor", "patch", or "unknown"
    """
    if not installed or not fixed:
        return "unknown"

    inst = _parse_version(installed)
    fix = _parse_version(fixed)

    if inst == (0, 0, 0) or fix == (0, 0, 0):
        return "unknown"

    if fix[0] > inst[0]:
        return "major"
    elif fix[1] > inst[1]:
        return "minor"
    elif fix[2] > inst[2]:
        return "patch"
    else:
        return "unknown"


def _bump_to_effort(bump: str) -> str:
    """Map version bump type to effort estimate."""
    return {
        "patch": "trivial",
        "minor": "moderate",
        "major": "complex",
        "unknown": "moderate",  # default to moderate when unsure
    }.get(bump, "moderate")
