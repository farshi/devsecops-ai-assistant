"""
Tests for agent/models.py — Finding dataclass and constants.
"""

import pytest
from agent.models import Finding, FINDING_TYPES, SEVERITIES, PRIORITY_TIERS, REACHABLE_VALUES


def test_finding_required_fields_only():
    """Finding can be created with only the five required fields."""
    f = Finding(
        id="CVE-2024-0001",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="critical",
        title="Remote code execution in example-pkg",
    )
    assert f.id == "CVE-2024-0001"
    assert f.source_scanner == "trivy_fs"
    assert f.finding_type == "language_dep"
    assert f.severity == "critical"
    assert f.title == "Remote code execution in example-pkg"


def test_finding_default_values():
    """Finding defaults are set correctly."""
    f = Finding(
        id="CVE-2024-0001",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title="Test",
    )
    assert f.package is None
    assert f.installed_version is None
    assert f.fixed_version is None
    assert f.location == ""
    assert f.cvss_score is None
    assert f.reachable == "unknown"
    assert f.reachability_confidence == "none"
    assert f.reachability_evidence is None
    assert f.direct_dep is None
    assert f.epss_score is None
    assert f.in_kev is False
    assert f.fix_available is False
    assert f.fix_evidence is None
    assert f.priority_score == 0
    assert f.priority_tier == "unscored"


def test_finding_all_fields():
    """Finding accepts and stores all optional fields correctly."""
    f = Finding(
        id="CVE-2024-9999",
        source_scanner="grype",
        finding_type="os_package",
        severity="medium",
        title="Buffer overflow in libssl",
        package="libssl3",
        installed_version="3.0.13-1",
        fixed_version="3.0.14-1",
        location="python3.11 > libssl3@3.0.13-1",
        cvss_score=6.5,
        reachable="not_applicable",
        reachability_confidence="high",
        reachability_evidence="OS package — not callable from app code",
        direct_dep=False,
        epss_score=0.003,
        in_kev=True,
        fix_available=True,
        fix_evidence="Upgrade to >= 3.0.14-1",
        priority_score=42,
        priority_tier="high",
    )
    assert f.package == "libssl3"
    assert f.cvss_score == 6.5
    assert f.reachable == "not_applicable"
    assert f.in_kev is True
    assert f.fix_available is True
    assert f.priority_score == 42
    assert f.priority_tier == "high"


def test_to_dict_drops_none_values():
    """to_dict() omits keys whose value is None."""
    f = Finding(
        id="CVE-2024-0001",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="low",
        title="Test",
    )
    d = f.to_dict()
    # These are None by default and should be absent
    assert "package" not in d
    assert "installed_version" not in d
    assert "fixed_version" not in d
    assert "cvss_score" not in d
    assert "reachability_evidence" not in d
    assert "direct_dep" not in d
    assert "epss_score" not in d
    assert "fix_evidence" not in d


def test_to_dict_includes_non_none_values():
    """to_dict() retains all non-None fields, including falsy ones."""
    f = Finding(
        id="CVE-2024-0001",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="low",
        title="Test",
        fix_available=False,  # falsy but not None — must be kept
        priority_score=0,     # falsy but not None — must be kept
        in_kev=False,         # falsy but not None — must be kept
    )
    d = f.to_dict()
    assert "fix_available" in d
    assert d["fix_available"] is False
    assert "priority_score" in d
    assert d["priority_score"] == 0
    assert "in_kev" in d
    assert d["in_kev"] is False


def test_constants_are_defined():
    """Ensure constant collections are present and non-empty."""
    assert "os_package" in FINDING_TYPES
    assert "language_dep" in FINDING_TYPES
    assert "iac_misconfig" in FINDING_TYPES
    assert "secret" in FINDING_TYPES
    assert "code_pattern" in FINDING_TYPES

    assert "critical" in SEVERITIES
    assert "info" in SEVERITIES

    assert "unscored" in PRIORITY_TIERS
    assert "noise" in PRIORITY_TIERS

    assert "unknown" in REACHABLE_VALUES
    assert "not_applicable" in REACHABLE_VALUES
