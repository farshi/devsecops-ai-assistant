"""
Tests for agent/plugins/scanners/trivy.py — TrivyScannerAdapter.
"""

import json
import pytest
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.trivy import TrivyScannerAdapter


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


# ---------------------------------------------------------------------------
# Interface contract
# ---------------------------------------------------------------------------

def test_trivy_adapter_implements_scanner_adapter():
    """TrivyScannerAdapter is a subclass of ScannerAdapter."""
    assert issubclass(TrivyScannerAdapter, ScannerAdapter)


def test_name_property_returns_trivy_fs():
    adapter = TrivyScannerAdapter()
    assert adapter.name == "trivy_fs"


# ---------------------------------------------------------------------------
# parse_dict() — core parsing via pre-loaded dict
# ---------------------------------------------------------------------------

def test_parse_dict_returns_finding_instances():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    assert len(findings) == 3
    for f in findings:
        assert isinstance(f, Finding)


def test_parse_dict_lang_pkgs_maps_to_language_dep():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    lang_findings = [f for f in findings if f.id in ("CVE-2024-0001", "CVE-2024-0002")]
    assert len(lang_findings) == 2
    for f in lang_findings:
        assert f.finding_type == "language_dep"


def test_parse_dict_lang_pkgs_reachable_is_unknown():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    lang_findings = [f for f in findings if f.finding_type == "language_dep"]
    for f in lang_findings:
        assert f.reachable == "unknown"


def test_parse_dict_os_pkgs_maps_to_os_package():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    os_findings = [f for f in findings if f.id == "CVE-2024-0003"]
    assert len(os_findings) == 1
    assert os_findings[0].finding_type == "os_package"


def test_parse_dict_os_pkgs_reachable_is_not_applicable():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    os_finding = next(f for f in findings if f.finding_type == "os_package")
    assert os_finding.reachable == "not_applicable"


def test_parse_dict_cvss_nvd_preferred():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.cvss_score == 9.8


def test_parse_dict_cvss_nvd_preferred_over_redhat():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0003")
    assert f.cvss_score == 7.5


def test_parse_dict_cvss_none_when_absent():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0002")
    assert f.cvss_score is None


def test_parse_dict_fix_available_true_when_fixed_version_present():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0001")
    assert f.fix_available is True
    assert f.fixed_version == "1.0.1"
    assert f.fix_evidence == "Upgrade to >= 1.0.1"


def test_parse_dict_fix_available_false_when_no_fixed_version():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    f = next(f for f in findings if f.id == "CVE-2024-0002")
    assert f.fix_available is False
    assert f.fixed_version is None
    assert f.fix_evidence is None


def test_parse_dict_source_scanner_is_trivy_fs():
    adapter = TrivyScannerAdapter()
    findings = adapter.parse_dict(SAMPLE_TRIVY_OUTPUT)
    for f in findings:
        assert f.source_scanner == "trivy_fs"


def test_parse_dict_empty_results():
    adapter = TrivyScannerAdapter()
    assert adapter.parse_dict({"Results": []}) == []


def test_parse_dict_missing_results_key():
    adapter = TrivyScannerAdapter()
    assert adapter.parse_dict({}) == []


def test_parse_dict_missing_vulnerabilities_key():
    adapter = TrivyScannerAdapter()
    raw = {
        "Results": [
            {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip"}
        ]
    }
    assert adapter.parse_dict(raw) == []


def test_parse_dict_default_class_maps_to_language_dep():
    """When Class is absent, finding_type defaults to 'language_dep'."""
    adapter = TrivyScannerAdapter()
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
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
    findings = adapter.parse_dict(raw)
    assert len(findings) == 1
    assert findings[0].finding_type == "language_dep"


# ---------------------------------------------------------------------------
# parse() — reads from a file path
# ---------------------------------------------------------------------------

def test_parse_reads_file_and_returns_findings(tmp_path):
    """parse() reads a JSON file, parses it, and returns Finding instances."""
    raw_file = tmp_path / "trivy_output.json"
    raw_file.write_text(json.dumps(SAMPLE_TRIVY_OUTPUT))

    adapter = TrivyScannerAdapter()
    findings = adapter.parse(raw_file)
    assert len(findings) == 3
    for f in findings:
        assert isinstance(f, Finding)


def test_parse_accepts_string_path(tmp_path):
    """parse() accepts a string path in addition to a Path object."""
    raw_file = tmp_path / "trivy_output.json"
    raw_file.write_text(json.dumps(SAMPLE_TRIVY_OUTPUT))

    adapter = TrivyScannerAdapter()
    findings = adapter.parse(str(raw_file))
    assert len(findings) == 3


def test_parse_empty_file(tmp_path):
    """parse() with an empty Results list returns no findings."""
    raw_file = tmp_path / "trivy_empty.json"
    raw_file.write_text(json.dumps({"Results": []}))

    adapter = TrivyScannerAdapter()
    assert adapter.parse(raw_file) == []
