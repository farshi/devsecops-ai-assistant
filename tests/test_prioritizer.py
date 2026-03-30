"""Tests for agent/prioritizer.py — ranked triage output."""

import pytest

from agent.models import Finding
from agent.prioritizer import (
    _build_action,
    _extract_effort,
    _finding_from_dict,
    generate_triage,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_finding(cve_id, severity="high", reachable="true", fix_available=True, **kwargs):
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=f"Vuln {cve_id}",
        package="test-pkg",
        installed_version="1.0.0",
        fixed_version="2.0.0" if fix_available else None,
        fix_available=fix_available,
        reachable=reachable,
        reachability_confidence="high",
        **kwargs,
    )


def _make_context(**overrides):
    ctx = {
        "scan_meta": {
            "date": "2026-03-27",
            "scanners_run": ["trivy_fs"],
            "total_findings": 0,
        },
        "repo": {},
        "dependencies": {},
        "findings": [],
        "token_budget": {},
    }
    ctx["scan_meta"].update(overrides)
    return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_generate_triage_returns_expected_keys():
    findings = [_make_finding(f"CVE-2024-000{i}") for i in range(3)]
    context = _make_context(total_findings=3)

    result = generate_triage(findings, context, top_n=5)

    assert "triage" in result
    assert "markdown" in result
    triage = result["triage"]
    assert "action_items" in triage
    assert "summary" in triage
    assert "total_findings" in triage
    assert "top_n" in triage


def test_action_items_ranked_by_score():
    # Create findings with different characteristics that produce different scores
    findings = [
        _make_finding("CVE-2024-0001", severity="low", reachable="false", fix_available=False),
        _make_finding("CVE-2024-0002", severity="medium", reachable="unknown"),
        _make_finding("CVE-2024-0003", severity="critical", reachable="true", in_kev=True, epss_score=0.95),
        _make_finding("CVE-2024-0004", severity="high", reachable="true"),
        _make_finding("CVE-2024-0005", severity="high", reachable="false"),
    ]
    context = _make_context(total_findings=5)

    result = generate_triage(findings, context, top_n=5)
    items = result["triage"]["action_items"]

    assert len(items) == 5
    # Verify ranks are sequential
    assert [i["rank"] for i in items] == [1, 2, 3, 4, 5]
    # Verify sorted by score descending
    scores = [i["priority_score"] for i in items]
    assert scores == sorted(scores, reverse=True)


def test_top_n_limits_output():
    findings = [_make_finding(f"CVE-2024-{i:04d}") for i in range(10)]
    context = _make_context(total_findings=10)

    result = generate_triage(findings, context, top_n=3)

    assert len(result["triage"]["action_items"]) == 3
    assert result["triage"]["top_n"] == 3


def test_action_item_has_all_fields():
    findings = [_make_finding("CVE-2024-0001")]
    context = _make_context(total_findings=1)

    result = generate_triage(findings, context, top_n=5)
    item = result["triage"]["action_items"][0]

    required_fields = {
        "rank", "id", "priority_tier", "priority_score",
        "package", "severity", "title", "action", "effort", "signals",
    }
    assert required_fields.issubset(set(item.keys()))
    signal_fields = {"reachable", "reachability_confidence", "epss_score", "in_kev", "fix_available"}
    assert signal_fields.issubset(set(item["signals"].keys()))


def test_action_with_fix():
    finding = _make_finding("CVE-2024-0001", fix_available=True)
    finding.fixed_version = "2.0.0"

    action = _build_action(finding)

    assert action.startswith("Upgrade")
    assert "test-pkg" in action
    assert "2.0.0" in action


def test_action_without_fix():
    finding = _make_finding("CVE-2024-0001", fix_available=False)
    finding.fixed_version = None

    action = _build_action(finding)

    assert action.startswith("Investigate")
    assert "CVE-2024-0001" in action


def test_action_fix_available_no_fixed_version():
    finding = _make_finding("CVE-2024-0001", fix_available=True)
    finding.fixed_version = None

    action = _build_action(finding)

    assert action.startswith("Update")
    assert "latest patched version" in action


def test_effort_extracted_from_fix_evidence():
    finding = _make_finding("CVE-2024-0001")
    finding.fix_evidence = "Upgrade test-pkg from 1.0.0 to >= 2.0.0 | patch version bump | effort: trivial"

    effort = _extract_effort(finding)

    assert effort == "trivial"


def test_effort_investigation_when_no_fix():
    finding = _make_finding("CVE-2024-0001", fix_available=False)
    finding.fix_evidence = "No fix available"

    effort = _extract_effort(finding)

    assert effort == "investigation"


def test_effort_default_moderate():
    finding = _make_finding("CVE-2024-0001", fix_available=True)
    finding.fix_evidence = None

    effort = _extract_effort(finding)

    assert effort == "moderate"


def test_tier_summary_counts():
    findings = [
        _make_finding("CVE-2024-0001", severity="critical", reachable="true", in_kev=True, epss_score=0.95),
        _make_finding("CVE-2024-0002", severity="high", reachable="true", epss_score=0.8),
        _make_finding("CVE-2024-0003", severity="high", reachable="true", epss_score=0.7),
        _make_finding("CVE-2024-0004", severity="medium", reachable="unknown"),
        _make_finding("CVE-2024-0005", severity="low", reachable="false", fix_available=False),
    ]
    context = _make_context(total_findings=5)

    result = generate_triage(findings, context, top_n=5)
    summary = result["triage"]["summary"]

    # All tiers should be present
    assert "critical" in summary
    assert "high" in summary
    assert "medium" in summary
    assert "low" in summary
    assert "noise" in summary
    # Total count should match total findings
    total = sum(summary.values())
    assert total == 5


def test_markdown_output_contains_headers():
    findings = [_make_finding("CVE-2024-0001")]
    context = _make_context(total_findings=1)

    result = generate_triage(findings, context, top_n=5)
    md = result["markdown"]

    assert "# PatchPilot Triage Report" in md
    assert "## Priority Summary" in md
    assert "## Top" in md


def test_markdown_contains_action_items():
    findings = [
        _make_finding("CVE-2024-0001", severity="critical", reachable="true", in_kev=True),
    ]
    findings[0].fix_evidence = "Upgrade test-pkg | effort: trivial"
    context = _make_context(total_findings=1)

    result = generate_triage(findings, context, top_n=5)
    md = result["markdown"]

    assert "CVE-2024-0001" in md
    assert "Upgrade" in md or "Investigate" in md or "Update" in md


def test_empty_findings():
    context = _make_context(total_findings=0)

    result = generate_triage([], context, top_n=5)

    assert result["triage"]["action_items"] == []
    assert result["triage"]["total_findings"] == 0
    assert "triage" in result
    assert "markdown" in result
    assert isinstance(result["markdown"], str)


def test_finding_from_dict_roundtrip():
    original = Finding(
        id="CVE-2024-0001",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title="Test vuln",
        package="test-pkg",
        installed_version="1.0.0",
        fixed_version="2.0.0",
        location="requirements.txt",
        cvss_score=7.5,
        reachable="true",
        reachability_confidence="high",
        reachability_evidence="import found in app.py:10",
        direct_dep=True,
        epss_score=0.45,
        in_kev=True,
        fix_available=True,
        fix_evidence="Upgrade test-pkg | effort: moderate",
        priority_score=72,
        priority_tier="high",
    )

    serialized = original.to_dict()
    restored = _finding_from_dict(serialized)

    assert restored.id == original.id
    assert restored.source_scanner == original.source_scanner
    assert restored.finding_type == original.finding_type
    assert restored.severity == original.severity
    assert restored.title == original.title
    assert restored.package == original.package
    assert restored.installed_version == original.installed_version
    assert restored.fixed_version == original.fixed_version
    assert restored.cvss_score == original.cvss_score
    assert restored.reachable == original.reachable
    assert restored.reachability_confidence == original.reachability_confidence
    assert restored.epss_score == original.epss_score
    assert restored.in_kev == original.in_kev
    assert restored.fix_available == original.fix_available
    assert restored.fix_evidence == original.fix_evidence
    assert restored.priority_score == original.priority_score
    assert restored.priority_tier == original.priority_tier
