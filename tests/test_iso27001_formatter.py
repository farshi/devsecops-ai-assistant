"""Tests for ISO27001ComplianceFormatter."""

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.iso27001 import (
    ISO27001ComplianceFormatter,
    _risk_level,
    _treatment_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id="CVE-2024-00001",
    severity="high",
    package="testpkg",
    installed_version="1.0.0",
    fixed_version="1.2.0",
    in_kev=False,
    epss_score=0.1,
    reachable="unknown",
    fix_available=True,
    priority_score=60,
    finding_type="language_dep",
) -> Finding:
    return Finding(
        id=id,
        source_scanner="trivy_fs",
        finding_type=finding_type,
        severity=severity,
        title=f"Test {id}",
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        in_kev=in_kev,
        epss_score=epss_score,
        reachable=reachable,
        fix_available=fix_available,
        priority_score=priority_score,
        priority_tier=severity,
    )


def _base_context(**overrides) -> dict:
    ctx = {
        "scan_meta": {
            "target": "myapp",
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs", "checkov"],
        },
        "repo": {"languages": ["Python"], "frameworks": ["FastAPI"], "docker": False},
        "dependencies": {"direct": ["requests"], "lockfile": True},
    }
    ctx.update(overrides)
    return ctx


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class TestInterface:
    def test_implements_output_formatter(self):
        assert issubclass(ISO27001ComplianceFormatter, OutputFormatter)

    def test_name_property(self):
        assert ISO27001ComplianceFormatter().name == "iso27001"


# ---------------------------------------------------------------------------
# Document structure
# ---------------------------------------------------------------------------

class TestDocumentStructure:
    def test_contains_title(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "# ISO 27001 Compliance Report" in doc

    def test_contains_standard_reference(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "ISO/IEC 27001:2022" in doc

    def test_contains_executive_summary(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "## 1. Executive Summary" in doc

    def test_contains_control_mapping(self):
        findings = [_make_finding()]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "## 2. Annex A Control Mapping" in doc

    def test_contains_vulnerability_register(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "## 3. Vulnerability Register" in doc

    def test_contains_risk_treatment(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "## 4. Risk Treatment Plan" in doc

    def test_contains_improvement_evidence(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "## 5. Continuous Improvement Evidence" in doc

    def test_contains_product_name(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "myapp" in doc


# ---------------------------------------------------------------------------
# Control mapping
# ---------------------------------------------------------------------------

class TestControlMapping:
    def test_a88_maps_all_findings(self):
        findings = [_make_finding(id="CVE-1"), _make_finding(id="CVE-2")]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "A.8.8" in doc
        assert "Management of Technical Vulnerabilities" in doc

    def test_a89_maps_iac_findings(self):
        findings = [
            _make_finding(id="CKV_AWS_18", finding_type="iac_misconfig"),
            _make_finding(id="CVE-1", finding_type="language_dep"),
        ]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "A.8.9" in doc
        assert "Configuration Management" in doc

    def test_a828_maps_code_pattern_findings(self):
        findings = [_make_finding(id="RULE-1", finding_type="code_pattern")]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "A.8.28" in doc
        assert "Secure Coding" in doc

    def test_a57_maps_kev_and_high_epss(self):
        findings = [
            _make_finding(id="CVE-KEV", in_kev=True),
            _make_finding(id="CVE-EPSS", epss_score=0.5),
        ]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "A.5.7" in doc
        assert "Threat Intelligence" in doc

    def test_control_table_present(self):
        findings = [_make_finding()]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "| Control | Title | Findings | Compliance |" in doc

    def test_nonconformity_for_critical(self):
        findings = [_make_finding(severity="critical")]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "Non-conformity" in doc

    def test_conforming_no_findings(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "Conforming" in doc


# ---------------------------------------------------------------------------
# Vulnerability register
# ---------------------------------------------------------------------------

class TestVulnerabilityRegister:
    def test_register_contains_cve_ids(self):
        findings = [_make_finding(id="CVE-2024-99999")]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "CVE-2024-99999" in doc

    def test_register_table_headers(self):
        findings = [_make_finding()]
        doc = ISO27001ComplianceFormatter().format(findings, _base_context())
        assert "| ID | Component | Severity | Risk Level |" in doc

    def test_register_a88_reference(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "A.8.8" in doc


# ---------------------------------------------------------------------------
# Risk level and treatment
# ---------------------------------------------------------------------------

class TestRiskLevel:
    def test_critical_very_high(self):
        f = _make_finding(severity="critical")
        assert _risk_level(f) == "Very High"

    def test_high_high(self):
        f = _make_finding(severity="high")
        assert _risk_level(f) == "High"

    def test_medium_medium(self):
        f = _make_finding(severity="medium")
        assert _risk_level(f) == "Medium"

    def test_low_low(self):
        f = _make_finding(severity="low")
        assert _risk_level(f) == "Low"


class TestTreatmentStatus:
    def test_mitigate_with_fix(self):
        f = _make_finding(fix_available=True, fixed_version="2.0.0")
        assert _treatment_status(f) == "Mitigate"

    def test_accept_no_fix(self):
        f = _make_finding(fix_available=False, fixed_version=None)
        assert _treatment_status(f) == "Accept / Monitor"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_findings(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "0 technical vulnerabilities" in doc

    def test_missing_context(self):
        doc = ISO27001ComplianceFormatter().format([], {})
        assert "ISO 27001" in doc

    def test_scanners_in_evidence(self):
        doc = ISO27001ComplianceFormatter().format([], _base_context())
        assert "trivy_fs" in doc
        assert "checkov" in doc
