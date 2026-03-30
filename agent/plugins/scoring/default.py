"""Default prioritization strategy — weighted scoring model."""

from agent.models import Finding
from agent.plugins.base import PrioritizationStrategy


# Weight profiles per finding type
LANGUAGE_DEP_WEIGHTS = {
    "severity": 0.20,
    "reachability": 0.25,
    "epss": 0.15,
    "fix": 0.15,
    "direct_dep": 0.10,
    "kev": 0.15,
}

OS_PACKAGE_WEIGHTS = {
    "severity": 0.35,
    "epss": 0.20,
    "fix": 0.20,
    "kev": 0.25,
}

DEFAULT_WEIGHTS = {
    "severity": 0.60,
    "fix": 0.40,
}


def _severity_score(finding: Finding) -> float:
    """Normalize severity to 0.0-1.0.

    Uses cvss_score if available (0-10 -> 0.0-1.0).
    Falls back to severity string mapping.
    """
    if finding.cvss_score is not None:
        return min(finding.cvss_score / 10.0, 1.0)

    return {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.0,
    }.get(finding.severity, 0.0)


def _reachability_score(finding: Finding) -> float:
    """Score reachability signal.

    Reachable = full score.
    Not reachable = 0.
    Unknown = 0.5 (don't penalize but don't boost).
    Not applicable = 0.5 (neutral for OS packages etc).

    Confidence adjusts the signal:
    - high confidence: use full signal
    - medium: dampen slightly (multiply by 0.8)
    - low/none: dampen more (multiply by 0.5)
    """
    base = {
        "true": 1.0,
        "false": 0.0,
        "unknown": 0.5,
        "not_applicable": 0.5,
    }.get(finding.reachable, 0.5)

    confidence_factor = {
        "high": 1.0,
        "medium": 0.8,
        "low": 0.5,
        "none": 0.5,
    }.get(finding.reachability_confidence, 0.5)

    # For "unknown" and "not_applicable", don't apply confidence dampening
    if finding.reachable in ("unknown", "not_applicable"):
        return base

    return base * confidence_factor


def _epss_score(finding: Finding) -> float:
    """Normalize EPSS to 0.0-1.0. Already in that range from API."""
    if finding.epss_score is not None:
        return min(max(finding.epss_score, 0.0), 1.0)
    return 0.3  # default: moderate when unknown


def _fix_score(finding: Finding) -> float:
    """Score fix availability. Having a fix is GOOD (higher priority to fix it)."""
    return 1.0 if finding.fix_available else 0.3


def _direct_dep_score(finding: Finding) -> float:
    """Direct dependencies are higher priority than transitive."""
    if finding.direct_dep is True:
        return 1.0
    elif finding.direct_dep is False:
        return 0.3
    return 0.5  # unknown


def _kev_score(finding: Finding) -> float:
    """Known Exploited Vulnerability — binary signal, high impact."""
    return 1.0 if finding.in_kev else 0.0


class DefaultScoringStrategy(PrioritizationStrategy):
    """Deterministic weighted scoring model.

    Scores each finding 0-100 based on multiple signals, with weights
    varying by finding_type. Rankings are algorithmic, explainable,
    and reproducible.
    """

    @property
    def name(self) -> str:
        return "default"

    def score(self, findings: list[Finding]) -> list[Finding]:
        """Score all findings and return sorted by priority_score descending."""
        for finding in findings:
            finding.priority_score = self._compute_score(finding)
            finding.priority_tier = self._score_to_tier(finding.priority_score)

        # Sort: highest score first
        findings.sort(key=lambda f: f.priority_score, reverse=True)
        return findings

    def _compute_score(self, finding: Finding) -> int:
        """Compute priority score (0-100) for a finding."""
        # Select weight profile
        if finding.finding_type == "language_dep":
            weights = LANGUAGE_DEP_WEIGHTS
        elif finding.finding_type == "os_package":
            weights = OS_PACKAGE_WEIGHTS
        else:
            weights = DEFAULT_WEIGHTS

        # Compute weighted sum
        signals = {
            "severity": _severity_score(finding),
            "reachability": _reachability_score(finding),
            "epss": _epss_score(finding),
            "fix": _fix_score(finding),
            "direct_dep": _direct_dep_score(finding),
            "kev": _kev_score(finding),
        }

        total = sum(
            signals.get(signal, 0.0) * weight
            for signal, weight in weights.items()
        )

        return round(total * 100)

    def _score_to_tier(self, score: int) -> str:
        """Map a numeric score (0-100) to a priority tier string."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "noise"
