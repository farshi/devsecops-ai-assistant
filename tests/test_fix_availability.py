"""Tests for the FixAvailabilityPlugin enrichment plugin."""

import pytest
from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin
from agent.plugins.enrichment.fix_availability import (
    FixAvailabilityPlugin,
    _parse_version,
    _classify_version_bump,
)


def _make_finding(cve_id="CVE-2024-0001", **kwargs):
    """Helper to create a Finding with minimal required fields."""
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title=f"Test vuln {cve_id}",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Plugin integration tests
# ---------------------------------------------------------------------------

def test_fix_available_patch_bump():
    finding = _make_finding(
        package="requests",
        installed_version="1.0.0",
        fixed_version="1.0.1",
    )
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich([finding], {})
    f = result[0]
    assert f.fix_available is True
    assert "patch version bump" in f.fix_evidence
    assert "trivial" in f.fix_evidence


def test_fix_available_minor_bump():
    finding = _make_finding(
        package="requests",
        installed_version="1.0.0",
        fixed_version="1.1.0",
    )
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich([finding], {})
    f = result[0]
    assert f.fix_available is True
    assert "minor version bump" in f.fix_evidence
    assert "moderate" in f.fix_evidence


def test_fix_available_major_bump():
    finding = _make_finding(
        package="requests",
        installed_version="1.0.0",
        fixed_version="2.0.0",
    )
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich([finding], {})
    f = result[0]
    assert f.fix_available is True
    assert "major version bump" in f.fix_evidence
    assert "complex" in f.fix_evidence
    assert "breaking change" in f.fix_evidence


def test_no_fix_available():
    finding = _make_finding(fixed_version=None)
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich([finding], {})
    f = result[0]
    assert f.fix_available is False
    assert f.fix_evidence == "No fix available"


# ---------------------------------------------------------------------------
# _parse_version unit tests
# ---------------------------------------------------------------------------

def test_parse_version_standard():
    assert _parse_version("1.2.3") == (1, 2, 3)


def test_parse_version_with_prefix():
    assert _parse_version("v2.1.0") == (2, 1, 0)


def test_parse_version_with_prerelease():
    assert _parse_version("1.2.3-beta.1") == (1, 2, 3)


def test_parse_version_two_parts():
    assert _parse_version("1.2") == (1, 2, 0)


# ---------------------------------------------------------------------------
# _classify_version_bump unit tests
# ---------------------------------------------------------------------------

def test_classify_unknown_versions():
    assert _classify_version_bump("", "1.0.0") == "unknown"
    assert _classify_version_bump("1.0.0", "") == "unknown"


# ---------------------------------------------------------------------------
# Multi-finding and edge case tests
# ---------------------------------------------------------------------------

def test_enriches_multiple_findings():
    findings = [
        _make_finding("CVE-2024-0001", package="pkgA", installed_version="1.0.0", fixed_version="1.0.1"),
        _make_finding("CVE-2024-0002", package="pkgB", installed_version="1.0.0", fixed_version="1.1.0"),
        _make_finding("CVE-2024-0003", package="pkgC", fixed_version=None),
    ]
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich(findings, {})

    assert result[0].fix_available is True
    assert "trivial" in result[0].fix_evidence

    assert result[1].fix_available is True
    assert "moderate" in result[1].fix_evidence

    assert result[2].fix_available is False
    assert result[2].fix_evidence == "No fix available"


def test_implements_enrichment_plugin():
    assert isinstance(FixAvailabilityPlugin(), EnrichmentPlugin)


def test_existing_fix_evidence_overwritten():
    finding = _make_finding(
        package="requests",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        fix_evidence="Upgrade to >= 1.0.1",  # pre-set by Trivy adapter
    )
    plugin = FixAvailabilityPlugin()
    result = plugin.enrich([finding], {})
    f = result[0]
    # Should be overwritten with detailed assessment, not the Trivy string
    assert f.fix_evidence != "Upgrade to >= 1.0.1"
    assert "patch version bump" in f.fix_evidence
    assert "trivial" in f.fix_evidence
