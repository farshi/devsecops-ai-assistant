"""Tests for SemgrepScannerAdapter."""

import json
import pytest
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.semgrep import SemgrepScannerAdapter


# ---------------------------------------------------------------------------
# Sample Semgrep output
# ---------------------------------------------------------------------------

SAMPLE_RESULT = {
    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
    "path": "app/main.py",
    "start": {"line": 42, "col": 5},
    "end": {"line": 42, "col": 55},
    "extra": {
        "message": "Dangerous subprocess use with shell=True",
        "severity": "ERROR",
        "metadata": {
            "cwe": ["CWE-78"],
            "owasp": ["A03:2021"],
            "confidence": "HIGH",
            "impact": "HIGH",
            "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            "category": "security",
            "technology": ["python"],
            "vulnerability_class": ["Command Injection"],
        },
    },
}

SAMPLE_WARNING = {
    "check_id": "python.lang.best-practice.open-never-closed",
    "path": "utils/io.py",
    "start": {"line": 10, "col": 1},
    "end": {"line": 10, "col": 30},
    "extra": {
        "message": "File opened but never closed",
        "severity": "WARNING",
        "metadata": {},
    },
}

SAMPLE_INFO = {
    "check_id": "python.lang.style.long-function",
    "path": "app/views.py",
    "start": {"line": 1, "col": 1},
    "end": {"line": 200, "col": 1},
    "extra": {
        "message": "Function exceeds 100 lines",
        "severity": "INFO",
        "metadata": {},
    },
}

SAMPLE_OUTPUT = {
    "results": [SAMPLE_RESULT, SAMPLE_WARNING, SAMPLE_INFO],
    "errors": [],
    "version": "1.56.0",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSemgrepAdapter:
    def test_implements_scanner_adapter(self):
        assert isinstance(SemgrepScannerAdapter(), ScannerAdapter)

    def test_name(self):
        assert SemgrepScannerAdapter().name == "semgrep"

    def test_parse_dict_returns_findings(self):
        findings = SemgrepScannerAdapter().parse_dict(SAMPLE_OUTPUT)
        assert len(findings) == 3
        assert all(isinstance(f, Finding) for f in findings)

    def test_source_scanner(self):
        findings = SemgrepScannerAdapter().parse_dict(SAMPLE_OUTPUT)
        assert all(f.source_scanner == "semgrep" for f in findings)

    def test_finding_type_is_code_pattern(self):
        findings = SemgrepScannerAdapter().parse_dict(SAMPLE_OUTPUT)
        assert all(f.finding_type == "code_pattern" for f in findings)

    def test_reachable_is_not_applicable(self):
        findings = SemgrepScannerAdapter().parse_dict(SAMPLE_OUTPUT)
        assert all(f.reachable == "not_applicable" for f in findings)


class TestSeverityMapping:
    def test_error_with_high_impact_and_confidence_is_critical(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert findings[0].severity == "critical"

    def test_warning_maps_to_medium(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_WARNING]})
        assert findings[0].severity == "medium"

    def test_info_maps_to_low(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_INFO]})
        assert findings[0].severity == "low"

    def test_impact_overrides_base_severity(self):
        result = dict(SAMPLE_WARNING)
        result["extra"] = dict(SAMPLE_WARNING["extra"])
        result["extra"]["metadata"] = {"impact": "HIGH"}
        findings = SemgrepScannerAdapter().parse_dict({"results": [result]})
        assert findings[0].severity == "high"


class TestFindingFields:
    def test_id_uses_cwe_when_available(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert findings[0].id == "CWE-78"

    def test_id_falls_back_to_check_id(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_WARNING]})
        assert findings[0].id == "python.lang.best-practice.open-never-closed"

    def test_title_from_message(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert "subprocess" in findings[0].title.lower()

    def test_location_includes_line(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert findings[0].location == "app/main.py:42"

    def test_fix_evidence_includes_owasp(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert "OWASP" in findings[0].fix_evidence

    def test_fix_evidence_includes_vuln_class(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert "Command Injection" in findings[0].fix_evidence

    def test_fix_available_when_references_exist(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_RESULT]})
        assert findings[0].fix_available is True

    def test_fix_not_available_without_references(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": [SAMPLE_WARNING]})
        assert findings[0].fix_available is False


class TestEdgeCases:
    def test_empty_results(self):
        findings = SemgrepScannerAdapter().parse_dict({"results": []})
        assert findings == []

    def test_missing_results_key(self):
        findings = SemgrepScannerAdapter().parse_dict({})
        assert findings == []

    def test_missing_extra(self):
        result = {"check_id": "test.rule", "path": "file.py", "start": {}, "extra": {}}
        findings = SemgrepScannerAdapter().parse_dict({"results": [result]})
        assert len(findings) == 1

    def test_long_message_truncated(self):
        result = dict(SAMPLE_RESULT)
        result["extra"] = dict(SAMPLE_RESULT["extra"])
        result["extra"]["message"] = "x" * 200
        findings = SemgrepScannerAdapter().parse_dict({"results": [result]})
        assert len(findings[0].title) <= 120

    def test_parse_reads_file(self, tmp_path):
        p = tmp_path / "semgrep.json"
        p.write_text(json.dumps(SAMPLE_OUTPUT))
        findings = SemgrepScannerAdapter().parse(p)
        assert len(findings) == 3
