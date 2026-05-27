"""Tests for agent/plugins/scanners/sonar.py — SonarQube/SonarCloud adapter."""

import json

import pytest

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.sonar import (
    SonarScannerAdapter,
    SEVERITY_MAP,
    TYPE_FINDING_TYPE_MAP,
    HOTSPOT_PROBABILITY_MAP,
    _map_severity,
    _strip_component,
)


# ---------------------------------------------------------------------------
# Sample Sonar data (shape of api/issues/search and api/hotspots/search)
# ---------------------------------------------------------------------------

SAMPLE_ISSUES = {
    "total": 3,
    "p": 1,
    "ps": 100,
    "issues": [
        {
            "key": "AYxxxxxxxxxxxxxxxxxx1",
            "rule": "python:S2076",
            "severity": "BLOCKER",
            "component": "my-project:src/app/handler.py",
            "project": "my-project",
            "line": 42,
            "message": "Make sure OS commands are not vulnerable to injection.",
            "type": "VULNERABILITY",
            "status": "OPEN",
        },
        {
            "key": "AYxxxxxxxxxxxxxxxxxx2",
            "rule": "python:S1481",
            "severity": "MINOR",
            "component": "my-project:src/app/util.py",
            "project": "my-project",
            "line": 7,
            "message": "Remove this unused local variable.",
            "type": "CODE_SMELL",
            "status": "OPEN",
        },
        {
            "key": "AYxxxxxxxxxxxxxxxxxx3",
            "rule": "python:S2070",
            "severity": "CRITICAL",
            "component": "my-project:src/app/crypto.py",
            "line": 19,
            "message": "Use a stronger hashing algorithm than MD5.",
            "type": "SECURITY_HOTSPOT",
            "vulnerabilityProbability": "HIGH",
            "status": "TO_REVIEW",
        },
    ],
}

SAMPLE_HOTSPOTS = {
    "paging": {"total": 1},
    "hotspots": [
        {
            "key": "hsxxxxxxxxxxxxxxxxxx1",
            "ruleKey": "python:S5443",
            "component": "my-project:src/app/tmpfile.py",
            "line": 88,
            "message": "Make sure publicly writable directories are used safely.",
            "vulnerabilityProbability": "MEDIUM",
            "status": "TO_REVIEW",
        }
    ],
}


@pytest.fixture
def adapter():
    return SonarScannerAdapter()


# ---------------------------------------------------------------------------
# Contract / basics
# ---------------------------------------------------------------------------

def test_is_scanner_adapter(adapter):
    assert isinstance(adapter, ScannerAdapter)


def test_name(adapter):
    assert adapter.name == "sonar"


# ---------------------------------------------------------------------------
# parse_dict — issues
# ---------------------------------------------------------------------------

def test_parses_all_issues(adapter):
    findings = adapter.parse_dict(SAMPLE_ISSUES)
    assert len(findings) == 3
    assert all(isinstance(f, Finding) for f in findings)


def test_issue_fields_mapped(adapter):
    findings = adapter.parse_dict(SAMPLE_ISSUES)
    vuln = findings[0]
    assert vuln.id == "python:S2076"
    assert vuln.source_scanner == "sonar"
    assert vuln.finding_type == "code_pattern"
    assert vuln.severity == "critical"  # BLOCKER → critical
    assert vuln.location == "src/app/handler.py:42"
    assert "OS commands" in vuln.title


def test_severity_mapping(adapter):
    findings = adapter.parse_dict(SAMPLE_ISSUES)
    sev_by_rule = {f.id: f.severity for f in findings}
    assert sev_by_rule["python:S2076"] == "critical"  # BLOCKER
    assert sev_by_rule["python:S1481"] == "low"        # MINOR


def test_hotspot_inline_uses_probability(adapter):
    """A SECURITY_HOTSPOT returned inline from issues/search uses probability."""
    findings = adapter.parse_dict(SAMPLE_ISSUES)
    hotspot = next(f for f in findings if f.id == "python:S2070")
    assert hotspot.severity == "high"  # vulnerabilityProbability HIGH
    assert hotspot.finding_type == "code_pattern"


# ---------------------------------------------------------------------------
# parse_dict — hotspots endpoint
# ---------------------------------------------------------------------------

def test_parses_hotspots_endpoint(adapter):
    findings = adapter.parse_dict(SAMPLE_HOTSPOTS)
    assert len(findings) == 1
    hs = findings[0]
    assert hs.id == "python:S5443"
    assert hs.severity == "medium"  # probability MEDIUM
    assert hs.location == "src/app/tmpfile.py:88"


def test_merges_issues_and_hotspots(adapter):
    merged = {**SAMPLE_ISSUES, "hotspots": SAMPLE_HOTSPOTS["hotspots"]}
    findings = adapter.parse_dict(merged)
    assert len(findings) == 4


# ---------------------------------------------------------------------------
# parse — file round-trip
# ---------------------------------------------------------------------------

def test_parse_reads_file(adapter, tmp_path):
    f = tmp_path / "sonar_issues.json"
    f.write_text(json.dumps(SAMPLE_ISSUES))
    findings = adapter.parse(f)
    assert len(findings) == 3


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_response(adapter):
    assert adapter.parse_dict({}) == []
    assert adapter.parse_dict({"issues": []}) == []


def test_missing_severity_defaults_medium(adapter):
    findings = adapter.parse_dict(
        {"issues": [{"rule": "x:Y", "component": "p:a.py", "type": "BUG"}]}
    )
    assert findings[0].severity == "medium"


def test_missing_line_omits_line_suffix(adapter):
    findings = adapter.parse_dict(
        {"issues": [{"rule": "x:Y", "component": "p:a.py", "type": "BUG",
                     "message": "m"}]}
    )
    assert findings[0].location == "a.py"


def test_component_without_project_prefix(adapter):
    findings = adapter.parse_dict(
        {"issues": [{"rule": "x:Y", "component": "bare/path.py", "line": 3,
                     "type": "BUG", "message": "m"}]}
    )
    assert findings[0].location == "bare/path.py:3"


def test_long_title_truncated(adapter):
    long_msg = "A" * 200
    findings = adapter.parse_dict(
        {"issues": [{"rule": "x:Y", "component": "p:a.py", "type": "BUG",
                     "message": long_msg}]}
    )
    assert len(findings[0].title) == 120
    assert findings[0].title.endswith("...")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_map_severity_helper():
    assert _map_severity("BLOCKER") == "critical"
    assert _map_severity("major") == "medium"  # case-insensitive
    assert _map_severity(None) == "medium"
    assert _map_severity("WEIRD") == "medium"


def test_strip_component_helper():
    assert _strip_component("proj:src/a.py") == "src/a.py"
    assert _strip_component("bare.py") == "bare.py"
    assert _strip_component(None) == "unknown"


def test_lookup_tables_present():
    assert SEVERITY_MAP["BLOCKER"] == "critical"
    assert TYPE_FINDING_TYPE_MAP["VULNERABILITY"] == "code_pattern"
    assert HOTSPOT_PROBABILITY_MAP["HIGH"] == "high"
