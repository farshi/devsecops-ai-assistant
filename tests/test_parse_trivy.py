"""
Tests for devsecops/parsers/parse_trivy.py — Finding classification and extraction.
"""

import pytest
from agent.models import Finding
from devsecops.parsers.parse_trivy import parse


SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution in example-pkg",
                    "PkgName": "example-pkg",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    "VulnerabilityID": "CVE-2024-0002",
                    "Severity": "LOW",
                    "Title": "Info disclosure in another-pkg",
                    "PkgName": "another-pkg",
                    "InstalledVersion": "2.0.0",
                },
            ],
        },
        {
            "Target": "python3.11",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0003",
                    "Severity": "HIGH",
                    "Title": "Buffer overflow in libssl",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.13-1",
                    "FixedVersion": "3.0.14-1",
                    "CVSS": {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 7.0}},
                },
            ],
        },
    ]
}


def test_parse_returns_finding_instances():
    """parse() returns a list of Finding objects, not dicts."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    assert len(findings) == 3
    for f in findings:
        assert isinstance(f, Finding)


def test_lang_pkgs_class_maps_to_language_dep():
    """lang-pkgs class produces finding_type='language_dep'."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    lang_findings = [f for f in findings if f.id in ("CVE-2024-0001", "CVE-2024-0002")]
    assert len(lang_findings) == 2
    for f in lang_findings:
        assert f.finding_type == "language_dep"


def test_lang_pkgs_reachable_is_unknown():
    """language_dep findings default to reachable='unknown'."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    lang_findings = [f for f in findings if f.finding_type == "language_dep"]
    for f in lang_findings:
        assert f.reachable == "unknown"


def test_os_pkgs_class_maps_to_os_package():
    """os-pkgs class produces finding_type='os_package'."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    os_findings = [f for f in findings if f.id == "CVE-2024-0003"]
    assert len(os_findings) == 1
    assert os_findings[0].finding_type == "os_package"


def test_os_pkgs_reachable_is_not_applicable():
    """os_package findings have reachable='not_applicable'."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    os_finding = next(f for f in findings if f.finding_type == "os_package")
    assert os_finding.reachable == "not_applicable"


def test_cvss_extraction_nvd_preferred():
    """CVSS V3Score from nvd is extracted correctly."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.cvss_score == 9.8


def test_cvss_extraction_nvd_preferred_over_redhat():
    """nvd V3Score is preferred over redhat when both are present."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0003")
    # nvd=7.5, redhat=7.0 — should return 7.5
    assert f.cvss_score == 7.5


def test_cvss_none_when_absent():
    """cvss_score is None when CVSS data is not present."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0002")
    assert f.cvss_score is None


def test_fix_available_true_when_fixed_version_present():
    """fix_available is True when FixedVersion is provided."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.fix_available is True
    assert f.fixed_version == "1.0.1"
    assert f.fix_evidence == "Upgrade to >= 1.0.1"


def test_fix_available_false_when_no_fixed_version():
    """fix_available is False and fix_evidence is None when no FixedVersion."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0002")
    assert f.fix_available is False
    assert f.fixed_version is None
    assert f.fix_evidence is None


def test_package_and_installed_version_extracted():
    """package and installed_version fields are populated from PkgName/InstalledVersion."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.package == "example-pkg"
    assert f.installed_version == "1.0.0"


def test_location_format():
    """location follows the 'target > pkg@version' format."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.location == "requirements.txt > example-pkg@1.0.0"


def test_source_scanner_is_trivy_fs():
    """All findings from parse() have source_scanner='trivy_fs'."""
    findings = parse(SAMPLE_TRIVY_OUTPUT)
    for f in findings:
        assert f.source_scanner == "trivy_fs"


def test_missing_vulnerabilities_key_returns_empty():
    """A result with no Vulnerabilities key produces zero findings for that result."""
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                # Intentionally missing "Vulnerabilities" key
            }
        ]
    }
    findings = parse(raw)
    assert findings == []


def test_empty_results_returns_empty():
    """Empty Results list produces an empty findings list."""
    assert parse({"Results": []}) == []


def test_missing_results_key_returns_empty():
    """Missing Results key produces an empty findings list."""
    assert parse({}) == []


def test_default_class_missing_maps_to_language_dep():
    """When Class is absent, finding_type defaults to 'language_dep'."""
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
                # No "Class" key
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-9999",
                        "Severity": "MEDIUM",
                        "Title": "Test",
                        "PkgName": "somepkg",
                        "InstalledVersion": "1.0.0",
                    }
                ],
            }
        ]
    }
    findings = parse(raw)
    assert len(findings) == 1
    assert findings[0].finding_type == "language_dep"
