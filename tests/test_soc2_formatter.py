"""Tests for SOC2ComplianceFormatter."""

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.soc2 import SOC2ComplianceFormatter, _posture_rating, _control_status


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
            "scanners_run": ["trivy_fs"],
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
        assert issubclass(SOC2ComplianceFormatter, OutputFormatter)

    def test_name_property(self):
        assert SOC2ComplianceFormatter().name == "soc2"


# ---------------------------------------------------------------------------
# Document structure
# ---------------------------------------------------------------------------

class TestDocumentStructure:
    def test_contains_title(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "# SOC2 Compliance Report" in doc

    def test_contains_executive_summary(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "## 1. Executive Summary" in doc

    def test_contains_control_mapping(self):
        findings = [_make_finding()]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "## 2. Control Mapping" in doc

    def test_contains_findings_by_control(self):
        findings = [_make_finding()]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "## 3. Findings by Control" in doc

    def test_contains_remediation_status(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "## 4. Remediation Status" in doc

    def test_contains_monitoring_evidence(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "## 5. Evidence of Monitoring" in doc

    def test_contains_product_name(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "myapp" in doc


# ---------------------------------------------------------------------------
# Control mapping
# ---------------------------------------------------------------------------

class TestControlMapping:
    def test_cc68_maps_all_findings(self):
        findings = [_make_finding(id="CVE-1"), _make_finding(id="CVE-2")]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "CC6.8" in doc
        assert "Controls Against Malicious Software" in doc

    def test_cc72_maps_kev_findings(self):
        findings = [
            _make_finding(id="CVE-KEV", in_kev=True, severity="critical"),
            _make_finding(id="CVE-LOW", severity="low"),
        ]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        # CC7.2 section should contain the KEV finding
        assert "CC7.2" in doc

    def test_cc61_maps_reachable_findings(self):
        findings = [
            _make_finding(id="CVE-REACH", reachable="true"),
            _make_finding(id="CVE-NOREACH", reachable="false"),
        ]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "CC6.1" in doc

    def test_cc81_maps_fixable_findings(self):
        findings = [
            _make_finding(id="CVE-FIX", fix_available=True),
            _make_finding(id="CVE-NOFIX", fix_available=False),
        ]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "CC8.1" in doc

    def test_control_table_present(self):
        findings = [_make_finding()]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "| Control | Title | Findings | Status |" in doc


# ---------------------------------------------------------------------------
# Posture rating
# ---------------------------------------------------------------------------

class TestPostureRating:
    def test_strong_no_findings(self):
        assert _posture_rating([]) == "Strong"

    def test_strong_only_low(self):
        findings = [_make_finding(severity="low")]
        assert _posture_rating(findings) == "Strong"

    def test_adequate_high_no_critical(self):
        findings = [_make_finding(severity="high")]
        assert _posture_rating(findings) == "Adequate"

    def test_needs_improvement_few_critical(self):
        findings = [_make_finding(severity="critical")]
        assert _posture_rating(findings) == "Needs Improvement"

    def test_at_risk_kev(self):
        findings = [_make_finding(in_kev=True)]
        assert _posture_rating(findings) == "At Risk"


# ---------------------------------------------------------------------------
# Control status
# ---------------------------------------------------------------------------

class TestControlStatus:
    def test_effective_no_findings(self):
        assert _control_status([]) == "Effective"

    def test_deficient_critical(self):
        findings = [_make_finding(severity="critical")]
        assert _control_status(findings) == "Deficient"

    def test_partially_effective_high(self):
        findings = [_make_finding(severity="high")]
        assert _control_status(findings) == "Partially Effective"

    def test_observations_medium(self):
        findings = [_make_finding(severity="medium")]
        assert _control_status(findings) == "Effective with Observations"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_findings(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "0 security findings" in doc

    def test_missing_context(self):
        doc = SOC2ComplianceFormatter().format([], {})
        assert "SOC2" in doc

    def test_cve_ids_in_output(self):
        findings = [_make_finding(id="CVE-2024-99999")]
        doc = SOC2ComplianceFormatter().format(findings, _base_context())
        assert "CVE-2024-99999" in doc

    def test_scanner_in_monitoring(self):
        doc = SOC2ComplianceFormatter().format([], _base_context())
        assert "trivy_fs" in doc
