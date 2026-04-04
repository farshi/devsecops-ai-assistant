"""Tests for ExecutiveSummaryFormatter."""

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.executive import (
    ExecutiveSummaryFormatter,
    _posture_score,
    _posture_grade,
    _risk_level,
    _top_actions,
)


def _make_finding(
    id="CVE-2024-00001",
    severity="high",
    package="testpkg",
    installed_version="1.0.0",
    fixed_version="1.2.0",
    reachable="unknown",
    fix_available=True,
    in_kev=False,
    priority_score=60,
    cvss_score=7.5,
) -> Finding:
    return Finding(
        id=id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=f"Test vuln in {package}",
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        reachable=reachable,
        fix_available=fix_available,
        in_kev=in_kev,
        priority_score=priority_score,
        cvss_score=cvss_score,
    )


_CTX = {"scan_meta": {"target": "test-app"}, "dependencies": {}}


class TestPostureScore:
    def test_perfect_score_no_findings(self):
        assert _posture_score([]) == 100

    def test_critical_deducts_heavily(self):
        f = _make_finding(severity="critical")
        score = _posture_score([f])
        assert score < 90

    def test_kev_amplifies(self):
        f_normal = _make_finding(severity="high", in_kev=False)
        f_kev = _make_finding(severity="high", in_kev=True)
        assert _posture_score([f_kev]) < _posture_score([f_normal])

    def test_reachable_amplifies(self):
        f_unknown = _make_finding(reachable="unknown")
        f_reachable = _make_finding(reachable="true")
        assert _posture_score([f_reachable]) < _posture_score([f_unknown])

    def test_fix_available_reduces_deduction(self):
        f_fixable = _make_finding(fix_available=True)
        f_unfixable = _make_finding(fix_available=False)
        assert _posture_score([f_fixable]) >= _posture_score([f_unfixable])

    def test_floor_at_zero(self):
        findings = [_make_finding(severity="critical", in_kev=True) for _ in range(20)]
        assert _posture_score(findings) == 0

    def test_low_findings_barely_move_score(self):
        findings = [_make_finding(severity="low") for _ in range(5)]
        assert _posture_score(findings) >= 90


class TestGradeAndRisk:
    def test_grade_a(self):
        assert _posture_grade(95) == "A"

    def test_grade_f(self):
        assert _posture_grade(30) == "F"

    def test_risk_low(self):
        assert _risk_level(95) == "Low Risk"

    def test_risk_high(self):
        assert _risk_level(40) == "High Risk"


class TestTopActions:
    def test_returns_top_3(self):
        findings = [
            _make_finding(id=f"CVE-{i}", priority_score=i * 10)
            for i in range(5)
        ]
        actions = _top_actions(findings)
        assert len(actions) == 3
        assert actions[0]["score"] == 40  # highest first

    def test_empty_findings(self):
        assert _top_actions([]) == []

    def test_action_has_upgrade_text(self):
        f = _make_finding(fix_available=True, fixed_version="2.0.0")
        actions = _top_actions([f])
        assert "Upgrade" in actions[0]["action"]

    def test_action_investigate_when_no_fix(self):
        f = _make_finding(fix_available=False, fixed_version=None)
        actions = _top_actions([f])
        assert "Investigate" in actions[0]["action"]


class TestExecutiveSummaryFormatter:
    def test_implements_output_formatter(self):
        assert isinstance(ExecutiveSummaryFormatter(), OutputFormatter)

    def test_name(self):
        assert ExecutiveSummaryFormatter().name == "executive"

    def test_output_contains_target(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "test-app" in output

    def test_output_contains_score(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "/100" in output

    def test_output_contains_metrics_table(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "Total Findings" in output
        assert "Critical" in output

    def test_output_contains_actions(self):
        f = _make_finding(priority_score=80)
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "Recommended Actions" in output

    def test_output_contains_risk_assessment(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "Risk Assessment" in output

    def test_output_contains_compliance(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "Compliance Status" in output

    def test_kev_warning(self):
        f = _make_finding(in_kev=True)
        output = ExecutiveSummaryFormatter().format([f], _CTX)
        assert "actively exploited" in output

    def test_empty_findings(self):
        output = ExecutiveSummaryFormatter().format([], _CTX)
        assert "100/100" in output
        assert "Low Risk" in output

    def test_empty_context(self):
        f = _make_finding()
        output = ExecutiveSummaryFormatter().format([f], {})
        assert "Security Posture Summary" in output
