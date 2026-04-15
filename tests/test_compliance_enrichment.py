"""Tests for the compliance enrichment plugin."""

from agent.models import Finding
from agent.plugins.enrichment.compliance import (
    ComplianceEnrichmentPlugin,
    framework_filter,
    _parse_version,
    _version_less_than,
    _pattern_matches_finding,
)


def _mk_finding(**kw) -> Finding:
    """Minimal finding factory for tests."""
    defaults = dict(
        id="CVE-2024-00000",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title="Test finding",
    )
    defaults.update(kw)
    return Finding(**defaults)


# ---------- version helpers ----------

def test_parse_version_handles_prefix_and_suffix():
    assert _parse_version("v1.2.3") == (1, 2, 3)
    assert _parse_version("1.2.3-rc1") == (1, 2, 3, 1)
    assert _parse_version("2.0.0.post1") == (2, 0, 0, 1)
    assert _parse_version("") == (0,)
    assert _parse_version("garbage") == (0,)
    # Ordering works correctly even for pre-release suffixes
    assert _parse_version("1.2.3-rc1") < _parse_version("1.2.4")
    assert _parse_version("1.2.3") < _parse_version("1.2.3-rc1")  # documented caveat


def test_version_less_than():
    assert _version_less_than("40.0.0", "41.0.0") is True
    assert _version_less_than("41.0.0", "41.0.0") is False
    assert _version_less_than("42.0.0", "41.0.0") is False
    assert _version_less_than(None, "1.0.0") is False


# ---------- pattern matching ----------

def test_pattern_with_empty_match_never_matches():
    pattern = {"match": {}, "controls": {}}
    finding = _mk_finding(package="whatever", installed_version="1.0")
    assert _pattern_matches_finding(pattern, finding) is False


def test_pattern_matches_package_and_version_below():
    pattern = {
        "match": {
            "package": "cryptography",
            "ecosystem": "pypi",
            "version_below": "41.0.0",
        }
    }
    good = _mk_finding(package="cryptography", installed_version="40.0.0",
                       finding_type="language_dep")
    bad_version = _mk_finding(package="cryptography", installed_version="42.0.0",
                              finding_type="language_dep")
    bad_package = _mk_finding(package="requests", installed_version="1.0",
                              finding_type="language_dep")
    assert _pattern_matches_finding(pattern, good) is True
    assert _pattern_matches_finding(pattern, bad_version) is False
    assert _pattern_matches_finding(pattern, bad_package) is False


def test_pattern_matches_cve_id():
    pattern = {"match": {"cve_ids": ["CVE-2021-44228"]}}
    match = _mk_finding(id="CVE-2021-44228")
    miss = _mk_finding(id="CVE-2021-99999")
    assert _pattern_matches_finding(pattern, match) is True
    assert _pattern_matches_finding(pattern, miss) is False


def test_package_match_is_case_insensitive():
    pattern = {"match": {"package": "Flask", "ecosystem": "pypi",
                         "version_below": "2.3.2"}}
    finding = _mk_finding(package="flask", installed_version="2.0.0",
                          finding_type="language_dep")
    assert _pattern_matches_finding(pattern, finding) is True


def test_os_ecosystem_matches_os_package_findings():
    pattern = {"match": {"package": "openssl", "ecosystem": "os",
                         "version_below": "3.0.13"}}
    finding = _mk_finding(package="openssl", installed_version="3.0.12",
                          finding_type="os_package")
    assert _pattern_matches_finding(pattern, finding) is True


# ---------- end-to-end with real seed mappings ----------

def test_plugin_loads_seed_patterns():
    plugin = ComplianceEnrichmentPlugin()
    # We seeded 10 real patterns; guard against accidental mapping deletions.
    assert plugin.pattern_count >= 10


def test_plugin_attaches_controls_for_known_cve():
    plugin = ComplianceEnrichmentPlugin()
    # CVE-2021-44228 (log4shell) is seeded as PP-0002 with extensive mappings
    finding = _mk_finding(
        id="CVE-2021-44228",
        package="log4j-core",
        installed_version="2.14.0",
        finding_type="language_dep",
        severity="critical",
    )
    [enriched] = plugin.enrich([finding], context={})
    assert "PP-0002" in enriched.compliance_patterns_matched
    assert "SI-2" in enriched.compliance_controls.get("nist_800_53_rev5", [])
    assert "6.3.3" in enriched.compliance_controls.get("pci_dss_4_0", [])


def test_plugin_attaches_controls_for_outdated_library():
    plugin = ComplianceEnrichmentPlugin()
    finding = _mk_finding(
        id="CVE-2023-99999",
        package="cryptography",
        installed_version="40.0.1",
        finding_type="language_dep",
    )
    [enriched] = plugin.enrich([finding], context={})
    assert "PP-0001" in enriched.compliance_patterns_matched
    assert enriched.compliance_controls.get("pci_dss_4_0")


def test_plugin_leaves_unrelated_findings_untouched():
    plugin = ComplianceEnrichmentPlugin()
    finding = _mk_finding(
        id="CVE-2099-00001",
        package="totally-unknown-package",
        installed_version="1.0.0",
        finding_type="language_dep",
    )
    [enriched] = plugin.enrich([finding], context={})
    assert enriched.compliance_patterns_matched == []
    assert enriched.compliance_controls == {}


# ---------- framework filter ----------

def test_framework_filter_keeps_only_findings_with_framework_hits():
    f_with_nist = _mk_finding()
    f_with_nist.compliance_controls = {"nist_800_53_rev5": ["SC-8"]}
    f_with_pci = _mk_finding()
    f_with_pci.compliance_controls = {"pci_dss_4_0": ["4.2.1"]}
    f_without = _mk_finding()

    result = framework_filter([f_with_nist, f_with_pci, f_without], "nist_800_53_rev5")
    assert result == [f_with_nist]
