"""Tests for DefaultScoringStrategy — weighted scoring model."""

import pytest
from agent.models import Finding
from agent.plugins.base import PrioritizationStrategy
from agent.plugins.scoring.default import DefaultScoringStrategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**kwargs) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    defaults = dict(
        id="CVE-2024-test",
        source_scanner="grype",
        finding_type="language_dep",
        severity="medium",
        title="Test finding",
        reachable="unknown",
        reachability_confidence="none",
        fix_available=False,
        in_kev=False,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# 1. Critical, reachable, KEV finding scores high
# ---------------------------------------------------------------------------

def test_critical_reachable_kev_finding_scores_high():
    """A finding with maximum signals across the board should score 80+."""
    finding = make_finding(
        finding_type="language_dep",
        severity="critical",
        reachable="true",
        reachability_confidence="high",
        in_kev=True,
        epss_score=0.95,
        fix_available=True,
        direct_dep=True,
    )
    strategy = DefaultScoringStrategy()
    results = strategy.score([finding])
    assert results[0].priority_score >= 80


# ---------------------------------------------------------------------------
# 2. Low severity, unreachable, no fix scores low
# ---------------------------------------------------------------------------

def test_low_unreachable_no_fix_scores_low():
    """A finding with all weak signals should score under 30."""
    finding = make_finding(
        finding_type="language_dep",
        severity="low",
        reachable="false",
        reachability_confidence="none",
        in_kev=False,
        epss_score=0.01,
        fix_available=False,
        direct_dep=False,
    )
    strategy = DefaultScoringStrategy()
    results = strategy.score([finding])
    assert results[0].priority_score < 30


# ---------------------------------------------------------------------------
# 3. Medium severity, unknown reachability scores moderate
# ---------------------------------------------------------------------------

def test_medium_unknown_reachability():
    """Medium severity with unknown reachability should land in 40-60 range."""
    finding = make_finding(
        finding_type="language_dep",
        severity="medium",
        reachable="unknown",
        fix_available=True,  # fix available pushes score into the moderate band
    )
    strategy = DefaultScoringStrategy()
    results = strategy.score([finding])
    assert 40 <= results[0].priority_score <= 60


# ---------------------------------------------------------------------------
# 4. os_package findings use different weights (no reachability)
# ---------------------------------------------------------------------------

def test_os_package_uses_different_weights():
    """os_package findings should not use the reachability signal."""
    # Two os_package findings identical except reachable — scores should be the same
    # because reachability is NOT in OS_PACKAGE_WEIGHTS
    f_reachable = make_finding(
        finding_type="os_package",
        severity="high",
        reachable="true",
        reachability_confidence="high",
        epss_score=0.5,
        fix_available=True,
        in_kev=False,
    )
    f_not_reachable = make_finding(
        finding_type="os_package",
        severity="high",
        reachable="false",
        reachability_confidence="high",
        epss_score=0.5,
        fix_available=True,
        in_kev=False,
    )
    strategy = DefaultScoringStrategy()
    strategy.score([f_reachable, f_not_reachable])
    assert f_reachable.priority_score == f_not_reachable.priority_score


# ---------------------------------------------------------------------------
# 5. iac_misconfig uses default weights (severity + fix only)
# ---------------------------------------------------------------------------

def test_iac_misconfig_uses_default_weights():
    """iac_misconfig findings use severity (50%), fix (35%), compliance (15%).

    The previous profile was severity(60) + fix(40); adding the compliance
    signal reduced both to make room for it.
    """
    # No compliance hit: severity=critical (1.0)*0.50 + fix=True (1.0)*0.35
    #   + compliance=0 * 0.15 = 0.85 -> 85
    finding_max = make_finding(
        finding_type="iac_misconfig",
        severity="critical",
        fix_available=True,
    )
    # Min: severity=info (0.0)*0.50 + fix=False (0.3)*0.35 + compliance=0*0.15
    #   = 0.105 -> 10 (Python banker's rounding of 0.105*100)
    finding_min = make_finding(
        finding_type="iac_misconfig",
        severity="info",
        fix_available=False,
    )
    strategy = DefaultScoringStrategy()
    strategy.score([finding_max, finding_min])
    assert finding_max.priority_score == 85
    assert finding_min.priority_score == 10

    # A compliance-mapped finding reaches a higher ceiling. With two
    # frameworks hit: 1.0*0.50 + 1.0*0.35 + 0.75*0.15 = 0.9625 -> 96
    finding_max.compliance_controls = {
        "nist_800_53_rev5": ["SC-8"],
        "pci_dss_4_0": ["4.2.1"],
    }
    strategy.score([finding_max])
    assert finding_max.priority_score == 96


# ---------------------------------------------------------------------------
# 6. Findings are sorted by score descending
# ---------------------------------------------------------------------------

def test_findings_sorted_by_score_descending():
    """score() must return findings sorted highest priority_score first."""
    severities = ["info", "low", "high", "critical", "medium"]
    findings = [
        make_finding(id=f"CVE-{i}", severity=sev, fix_available=False)
        for i, sev in enumerate(severities)
    ]
    strategy = DefaultScoringStrategy()
    results = strategy.score(findings)
    scores = [f.priority_score for f in results]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# 7. Priority tier boundaries
# ---------------------------------------------------------------------------

def test_priority_tiers():
    """Tier boundaries: 80+=critical, 60-79=high, 40-59=medium, 20-39=low, <20=noise."""
    strategy = DefaultScoringStrategy()

    assert strategy._score_to_tier(85) == "critical"
    assert strategy._score_to_tier(80) == "critical"
    assert strategy._score_to_tier(65) == "high"
    assert strategy._score_to_tier(60) == "high"
    assert strategy._score_to_tier(45) == "medium"
    assert strategy._score_to_tier(40) == "medium"
    assert strategy._score_to_tier(25) == "low"
    assert strategy._score_to_tier(20) == "low"
    assert strategy._score_to_tier(10) == "noise"
    assert strategy._score_to_tier(0) == "noise"


# ---------------------------------------------------------------------------
# 8. cvss_score is preferred over severity string
# ---------------------------------------------------------------------------

def test_cvss_score_preferred_over_severity_string():
    """When cvss_score is set, it should override the severity string for scoring."""
    # cvss=9.8 -> 0.98; severity=medium -> 0.5
    # With DEFAULT_WEIGHTS (iac_misconfig) the severity contributes 60%
    # cvss version: 0.98 * 0.60 = 0.588; medium version: 0.5 * 0.60 = 0.30
    finding_cvss = make_finding(
        finding_type="iac_misconfig",
        severity="medium",
        cvss_score=9.8,
        fix_available=False,
    )
    finding_string = make_finding(
        id="CVE-2024-other",
        finding_type="iac_misconfig",
        severity="medium",
        cvss_score=None,
        fix_available=False,
    )
    strategy = DefaultScoringStrategy()
    strategy.score([finding_cvss, finding_string])
    assert finding_cvss.priority_score > finding_string.priority_score


# ---------------------------------------------------------------------------
# 9. Reachability confidence dampens signal
# ---------------------------------------------------------------------------

def test_reachability_confidence_dampens_signal():
    """High confidence reachability should score higher than low confidence."""
    f_high = make_finding(
        finding_type="language_dep",
        severity="medium",
        reachable="true",
        reachability_confidence="high",
        fix_available=False,
    )
    f_low = make_finding(
        id="CVE-2024-low",
        finding_type="language_dep",
        severity="medium",
        reachable="true",
        reachability_confidence="low",
        fix_available=False,
    )
    strategy = DefaultScoringStrategy()
    strategy.score([f_high, f_low])
    assert f_high.priority_score > f_low.priority_score


# ---------------------------------------------------------------------------
# 10. KEV significantly boosts score
# ---------------------------------------------------------------------------

def test_kev_significantly_boosts_score():
    """A finding in the KEV catalog should score meaningfully higher than an identical non-KEV finding."""
    f_kev = make_finding(
        finding_type="language_dep",
        severity="high",
        in_kev=True,
        fix_available=True,
        reachable="unknown",
    )
    f_no_kev = make_finding(
        id="CVE-2024-nokev",
        finding_type="language_dep",
        severity="high",
        in_kev=False,
        fix_available=True,
        reachable="unknown",
    )
    strategy = DefaultScoringStrategy()
    strategy.score([f_kev, f_no_kev])
    # KEV weight is 15% of 100 = 15 points difference
    assert f_kev.priority_score - f_no_kev.priority_score >= 10


# ---------------------------------------------------------------------------
# 11. Implements PrioritizationStrategy ABC
# ---------------------------------------------------------------------------

def test_implements_prioritization_strategy():
    """DefaultScoringStrategy must be an instance of PrioritizationStrategy."""
    strategy = DefaultScoringStrategy()
    assert isinstance(strategy, PrioritizationStrategy)


# ---------------------------------------------------------------------------
# 12. Empty findings list
# ---------------------------------------------------------------------------

def test_empty_findings():
    """score() with an empty list should return an empty list without errors."""
    strategy = DefaultScoringStrategy()
    result = strategy.score([])
    assert result == []
