"""Tests for CRADisclosureFormatter."""

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.cra import CRADisclosureFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id="CVE-2024-00001",
    severity="high",
    title="Test vuln",
    package="testpkg",
    installed_version="1.0.0",
    fixed_version="1.2.0",
    in_kev=False,
    epss_score=0.1,
    reachable="unknown",
    reachability_confidence="none",
    fix_available=True,
    priority_score=60,
    priority_tier="high",
    cvss_score=7.5,
    finding_type="language_dep",
    source_scanner="trivy_fs",
) -> Finding:
    return Finding(
        id=id,
        source_scanner=source_scanner,
        finding_type=finding_type,
        severity=severity,
        title=title,
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        in_kev=in_kev,
        epss_score=epss_score,
        reachable=reachable,
        reachability_confidence=reachability_confidence,
        fix_available=fix_available,
        priority_score=priority_score,
        priority_tier=priority_tier,
        cvss_score=cvss_score,
    )


def _base_context(**overrides) -> dict:
    ctx = {
        "scan_meta": {
            "target": "myapp",
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
        },
        "repo": {
            "languages": ["Python"],
            "frameworks": ["FastAPI"],
            "docker": False,
        },
        "dependencies": {
            "direct": ["requests", "fastapi"],
            "lockfile": True,
        },
    }
    ctx.update(overrides)
    return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCRAFormatterBasic:
    def test_cra_format_basic(self):
        """Basic output contains required header sections and all CVE IDs."""
        findings = [
            _make_finding(id="CVE-2024-00001"),
            _make_finding(id="CVE-2024-00002", severity="medium", priority_score=45),
            _make_finding(id="CVE-2024-00003", severity="critical", priority_score=90),
        ]
        ctx = _base_context()
        formatter = CRADisclosureFormatter()
        doc = formatter.format(findings, ctx)

        assert "Vulnerability Disclosure Report" in doc
        assert "CRA Compliance" in doc
        assert "CVE-2024-00001" in doc
        assert "CVE-2024-00002" in doc
        assert "CVE-2024-00003" in doc

    def test_cra_format_sections_present(self):
        """All 5 required sections are present in the document."""
        findings = [_make_finding()]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "## 1. Executive Summary" in doc
        assert "## 2. Actively Exploited Vulnerabilities" in doc
        assert "## 3. CRA Notification Timeline" in doc
        assert "## 4. Vulnerability Details" in doc
        assert "## 5. Product Context" in doc
        assert "## 6. Compliance Statement" in doc

    def test_cra_document_id_contains_date_and_target(self):
        """Document ID is formatted with date and target slug."""
        findings = [_make_finding()]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "CRA-DISC-" in doc
        assert "MYAPP" in doc


class TestCRAKEVSection:
    def test_cra_kev_section(self):
        """Finding with in_kev=True appears in section 2 and mentions 24 hours."""
        findings = [_make_finding(id="CVE-2024-KEV-001", in_kev=True, priority_score=95)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "CVE-2024-KEV-001" in doc
        assert "24 hours" in doc
        assert "IN KEV" in doc

    def test_cra_no_kev_findings(self):
        """When no KEV findings exist, section 2 shows the 'no actively exploited' message."""
        findings = [_make_finding(in_kev=False)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "No actively exploited vulnerabilities detected in this scan." in doc
        # Should still mention 24 hours from the article reference
        assert "24 hours" in doc


class TestCRARemediationTimeline:
    def test_cra_critical_timeline(self):
        """Critical findings should have 24h target remediation."""
        findings = [_make_finding(severity="critical", priority_score=95)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "24h" in doc

    def test_cra_high_timeline(self):
        """High findings should have 7d target remediation."""
        findings = [_make_finding(severity="high", priority_score=70)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "7d" in doc

    def test_cra_medium_timeline(self):
        """Medium findings should have 30d target remediation."""
        findings = [_make_finding(severity="medium", priority_score=45)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "30d" in doc

    def test_cra_low_timeline(self):
        """Low findings should have 90d target remediation."""
        findings = [_make_finding(severity="low", priority_score=25)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        assert "90d" in doc


class TestCRAFullDisclosure:
    def test_cra_includes_all_findings(self):
        """CRA requires full disclosure — all 10 findings must appear."""
        findings = [_make_finding(id=f"CVE-2024-{i:05d}") for i in range(10)]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        for i in range(10):
            assert f"CVE-2024-{i:05d}" in doc


class TestCRAProductContext:
    def test_cra_product_context(self):
        """Section 4 includes languages and frameworks from context."""
        ctx = _base_context()
        ctx["repo"]["languages"] = ["Python", "TypeScript"]
        ctx["repo"]["frameworks"] = ["FastAPI", "React"]

        findings = [_make_finding()]
        doc = CRADisclosureFormatter().format(findings, ctx)

        assert "Python" in doc
        assert "TypeScript" in doc
        assert "FastAPI" in doc
        assert "React" in doc

    def test_cra_product_context_dep_count(self):
        """Section 4 shows dependency count."""
        ctx = _base_context()
        ctx["dependencies"]["direct"] = ["requests", "fastapi", "sqlalchemy"]

        findings = [_make_finding()]
        doc = CRADisclosureFormatter().format(findings, ctx)

        assert "3 direct" in doc

    def test_cra_product_context_scanner(self):
        """Section 4 shows scanners used."""
        ctx = _base_context()
        ctx["scan_meta"]["scanners_run"] = ["trivy_fs", "checkov"]

        findings = [_make_finding()]
        doc = CRADisclosureFormatter().format(findings, ctx)

        assert "trivy_fs" in doc
        assert "checkov" in doc


class TestCRAInterface:
    def test_cra_implements_output_formatter(self):
        """CRADisclosureFormatter must be a subclass of OutputFormatter."""
        formatter = CRADisclosureFormatter()
        assert isinstance(formatter, OutputFormatter)

    def test_cra_name_property(self):
        """name property returns 'cra'."""
        assert CRADisclosureFormatter().name == "cra"


class TestCRAEdgeCases:
    def test_cra_empty_findings(self):
        """Empty findings list produces a valid document with 0 vulnerabilities."""
        doc = CRADisclosureFormatter().format([], _base_context())

        assert "Vulnerability Disclosure Report" in doc
        assert "0 vulnerabilities" in doc
        assert "## 6. Compliance Statement" in doc

    def test_cra_no_fixed_version(self):
        """Finding with no fixed_version shows 'N/A' for fixed version."""
        f = _make_finding(fixed_version=None, fix_available=False)
        doc = CRADisclosureFormatter().format([f], _base_context())

        # Fixed version should show N/A
        assert "N/A" in doc

    def test_cra_high_epss_flagged(self):
        """EPSS > 0.5 is flagged as 'high exploitation probability'."""
        f = _make_finding(epss_score=0.92)
        doc = CRADisclosureFormatter().format([f], _base_context())

        assert "high exploitation probability" in doc

    def test_cra_low_epss_not_flagged(self):
        """EPSS <= 0.5 does not get the high exploitation probability flag."""
        f = _make_finding(epss_score=0.3)
        doc = CRADisclosureFormatter().format([f], _base_context())

        assert "high exploitation probability" not in doc

    def test_cra_compliance_statement_present(self):
        """Compliance statement references Regulation 2024/2847."""
        doc = CRADisclosureFormatter().format([], _base_context())

        assert "2024/2847" in doc
        assert "Articles 14 and 15" in doc

    def test_cra_ordered_by_priority_score(self):
        """Findings in section 3 are ordered by priority_score descending."""
        findings = [
            _make_finding(id="CVE-LOW",    priority_score=20),
            _make_finding(id="CVE-MEDIUM", priority_score=50),
            _make_finding(id="CVE-HIGH",   priority_score=80),
        ]
        doc = CRADisclosureFormatter().format(findings, _base_context())

        # CVE-HIGH should appear before CVE-MEDIUM, which should appear before CVE-LOW
        pos_high   = doc.index("CVE-HIGH")
        pos_medium = doc.index("CVE-MEDIUM")
        pos_low    = doc.index("CVE-LOW")
        assert pos_high < pos_medium < pos_low
