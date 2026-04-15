"""Tests for the compliance enrichment plugin."""

import json
from pathlib import Path

import pytest

from agent.models import Finding
from agent.plugins.enrichment.compliance import (
    ComplianceEnrichmentPlugin,
    framework_filter,
    _version_less_than,
    _normalise_for_packaging,
    _numeric_tuple,
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


# ---------- version comparison ----------

class TestVersionLessThan:
    def test_simple_semver(self):
        assert _version_less_than("1.2.3", "1.2.4") is True
        assert _version_less_than("1.2.4", "1.2.3") is False
        assert _version_less_than("1.2.3", "1.2.3") is False

    def test_v_prefix(self):
        assert _version_less_than("v1.2.3", "1.2.4") is True
        assert _version_less_than("V2.0.0", "v2.0.1") is True

    def test_pep_440_pre_release_ordering(self):
        # Pre-releases sort *before* the release per PEP 440
        assert _version_less_than("1.2.3a1", "1.2.3") is True
        assert _version_less_than("1.2.3rc1", "1.2.3") is True
        assert _version_less_than("1.2.3", "1.2.3rc1") is False

    def test_pep_440_post_release(self):
        assert _version_less_than("1.2.3", "1.2.3.post1") is True
        assert _version_less_than("1.2.3.post1", "1.2.4") is True

    def test_pep_440_epoch(self):
        # Epoch takes precedence: 1!1.0 > 9.9.9
        assert _version_less_than("9.9.9", "1!1.0.0") is True
        assert _version_less_than("1!2.0.0", "1!1.0.0") is False

    def test_distro_suffixes_stripped(self):
        # Real OS-package versions from Debian/Ubuntu/RHEL
        assert _version_less_than("3.0.12-1ubuntu2.3", "3.0.13") is True
        assert _version_less_than("8.3.0-1.el8_4.1", "8.4.0") is True
        assert _version_less_than("1.14.2-deb11u1", "1.15.0") is True

    def test_tilde_pre_release_distro(self):
        # "1.0~beta1" denotes a pre-release in Debian; should be < 1.0
        assert _version_less_than("1.0~beta1", "1.0") is True

    def test_empty_or_missing(self):
        assert _version_less_than(None, "1.0") is False
        assert _version_less_than("", "1.0") is False
        assert _version_less_than("1.0", "") is False

    def test_unparseable_falls_back_to_numeric(self):
        # Garbage inputs should not raise — fall back path must cope
        assert _version_less_than("garbage", "1.0") is True  # numeric tuple: (0,) < (1,0)
        assert _version_less_than("1.0", "garbage") is False


class TestNormaliseHelper:
    def test_strips_v_prefix(self):
        assert _normalise_for_packaging("v1.2.3") == "1.2.3"

    def test_strips_distro_suffix(self):
        assert _normalise_for_packaging("3.0.12-1ubuntu2.3") == "3.0.12"
        assert _normalise_for_packaging("8.3.0-1.el8_4.1") == "8.3.0"
        assert _normalise_for_packaging("1.14.2-deb11u1") == "1.14.2"

    def test_tilde_becomes_pep440_pre_release(self):
        # Debian "~beta1" → PEP 440 "b1" (pre-release < 1.0)
        assert _normalise_for_packaging("1.0~beta1") == "1.0b1"
        assert _normalise_for_packaging("1.0~alpha") == "1.0a0"
        assert _normalise_for_packaging("1.0~rc2") == "1.0rc2"

    def test_numeric_tuple_fallback(self):
        assert _numeric_tuple("1.2.3") == (1, 2, 3)
        assert _numeric_tuple("garbage") == (0,)
        assert _numeric_tuple("") == (0,)


# ---------- pattern matching ----------

class TestPatternMatching:
    def test_empty_match_never_matches(self):
        pattern = {"match": {}, "controls": {}}
        finding = _mk_finding(package="whatever", installed_version="1.0")
        assert _pattern_matches_finding(pattern, finding) is False

    def test_package_case_insensitive(self):
        pattern = {"match": {"package": "Flask", "ecosystem": "pypi",
                             "version_below": "2.3.2"}}
        finding = _mk_finding(package="flask", installed_version="2.0.0",
                              finding_type="language_dep")
        assert _pattern_matches_finding(pattern, finding) is True

    def test_package_and_version(self):
        pattern = {"match": {"package": "cryptography", "ecosystem": "pypi",
                             "version_below": "41.0.0"}}
        good = _mk_finding(package="cryptography", installed_version="40.0.0",
                           finding_type="language_dep")
        bad_version = _mk_finding(package="cryptography", installed_version="42.0.0",
                                  finding_type="language_dep")
        bad_package = _mk_finding(package="requests", installed_version="1.0",
                                  finding_type="language_dep")
        assert _pattern_matches_finding(pattern, good) is True
        assert _pattern_matches_finding(pattern, bad_version) is False
        assert _pattern_matches_finding(pattern, bad_package) is False

    def test_cve_id_match(self):
        pattern = {"match": {"cve_ids": ["CVE-2021-44228"]}}
        assert _pattern_matches_finding(pattern, _mk_finding(id="CVE-2021-44228")) is True
        assert _pattern_matches_finding(pattern, _mk_finding(id="CVE-2021-99999")) is False

    def test_os_ecosystem_requires_os_finding_type(self):
        pattern = {"match": {"package": "openssl", "ecosystem": "os",
                             "version_below": "3.0.13"}}
        os_finding = _mk_finding(package="openssl", installed_version="3.0.12",
                                 finding_type="os_package")
        lang_finding = _mk_finding(package="openssl", installed_version="3.0.12",
                                   finding_type="language_dep")
        assert _pattern_matches_finding(pattern, os_finding) is True
        assert _pattern_matches_finding(pattern, lang_finding) is False

    def test_cwe_only_pattern_is_skipped(self):
        # CWE matching is unsupported in v1 — patterns relying on it must
        # not spuriously match every finding.
        pattern = {"match": {"cwe_ids": ["CWE-89"]}}
        finding = _mk_finding(id="CVE-2024-11111")
        assert _pattern_matches_finding(pattern, finding) is False


# ---------- end-to-end with seed mappings ----------

class TestSeedMappings:
    def test_loads_expected_number_of_seeds(self):
        plugin = ComplianceEnrichmentPlugin()
        # Seeded 9 valid patterns after PP-0009 removal in the pivot.
        assert plugin.pattern_count >= 9

    def test_log4shell_cve_maps_to_nist_and_pci(self):
        plugin = ComplianceEnrichmentPlugin()
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
        # Regression: AU-2 was overclaimed — must not reappear
        assert "AU-2" not in enriched.compliance_controls.get("nist_800_53_rev5", [])

    def test_spring4shell_does_not_reference_mobile_code(self):
        # Regression test for the SC-18 overclaim Codex flagged
        plugin = ComplianceEnrichmentPlugin()
        finding = _mk_finding(
            id="CVE-2022-22965",
            package="spring-core",
            installed_version="5.3.17",
            finding_type="language_dep",
        )
        [enriched] = plugin.enrich([finding], context={})
        assert "PP-0003" in enriched.compliance_patterns_matched
        assert "SC-18" not in enriched.compliance_controls.get("nist_800_53_rev5", [])

    def test_os_package_openssl_matches(self):
        plugin = ComplianceEnrichmentPlugin()
        finding = _mk_finding(
            id="CVE-2024-00001",
            package="openssl",
            installed_version="3.0.12-1ubuntu2.3",  # real Ubuntu version shape
            finding_type="os_package",
        )
        [enriched] = plugin.enrich([finding], context={})
        assert "PP-0007" in enriched.compliance_patterns_matched

    def test_unrelated_finding_unchanged(self):
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


# ---------- loader robustness ----------

class TestPatternLoader:
    def test_missing_directory_returns_empty(self, tmp_path):
        plugin = ComplianceEnrichmentPlugin(mappings_dir=tmp_path / "nonexistent")
        assert plugin.pattern_count == 0

    def test_malformed_json_is_skipped_not_raised(self, tmp_path, caplog):
        (tmp_path / "broken.json").write_text("{not valid json")
        good = {
            "pattern_id": "PP-9000",
            "name": "test",
            "match": {"package": "x", "ecosystem": "pypi", "version_below": "1.0"},
            "controls": {"nist_800_53_rev5": ["SC-8"]},
            "rationale": "Test rationale with enough length to pass schema checks.",
        }
        (tmp_path / "good.json").write_text(json.dumps(good))
        plugin = ComplianceEnrichmentPlugin(mappings_dir=tmp_path)
        assert plugin.pattern_count == 1

    def test_pattern_missing_required_field_is_skipped(self, tmp_path):
        bad = {"pattern_id": "PP-9001", "name": "incomplete"}
        (tmp_path / "bad.json").write_text(json.dumps(bad))
        plugin = ComplianceEnrichmentPlugin(mappings_dir=tmp_path)
        assert plugin.pattern_count == 0

    def test_pattern_with_empty_match_is_skipped(self, tmp_path):
        bad = {
            "pattern_id": "PP-9002",
            "name": "empty match",
            "match": {},
            "controls": {"nist_800_53_rev5": ["SC-8"]},
            "rationale": "Valid length rationale for testing the loader behaviour.",
        }
        (tmp_path / "bad.json").write_text(json.dumps(bad))
        plugin = ComplianceEnrichmentPlugin(mappings_dir=tmp_path)
        assert plugin.pattern_count == 0


# ---------- framework filter ----------

class TestFrameworkFilter:
    def test_keeps_only_findings_with_framework_hits(self):
        f_nist = _mk_finding()
        f_nist.compliance_controls = {"nist_800_53_rev5": ["SC-8"]}
        f_pci = _mk_finding()
        f_pci.compliance_controls = {"pci_dss_4_0": ["4.2.1"]}
        f_empty = _mk_finding()
        assert framework_filter(
            [f_nist, f_pci, f_empty], "nist_800_53_rev5"
        ) == [f_nist]


# ---------- round-trip through to_dict / _finding_from_dict ----------

class TestRoundTrip:
    def test_compliance_fields_survive_serialisation_cycle(self):
        from agent.prioritizer import _finding_from_dict

        original = _mk_finding(package="flask", installed_version="2.0.0")
        original.compliance_controls = {"nist_800_53_rev5": ["SC-8"], "pci_dss_4_0": ["4.2.1"]}
        original.compliance_patterns_matched = ["PP-0005"]

        restored = _finding_from_dict(original.to_dict())
        assert restored.compliance_controls == original.compliance_controls
        assert restored.compliance_patterns_matched == original.compliance_patterns_matched

    def test_defaults_when_absent_from_dict(self):
        from agent.prioritizer import _finding_from_dict

        d = {
            "id": "CVE-2024-00000",
            "source_scanner": "trivy_fs",
            "finding_type": "language_dep",
            "severity": "high",
            "title": "x",
        }
        restored = _finding_from_dict(d)
        assert restored.compliance_controls == {}
        assert restored.compliance_patterns_matched == []
