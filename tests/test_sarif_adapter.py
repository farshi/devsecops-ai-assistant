"""Tests for agent/plugins/scanners/sarif.py — SARIF 2.1.0 generic adapter."""

import json

import pytest

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.sarif import (
    SARIFScannerAdapter,
    LEVEL_MAP,
    TOOL_FINDING_TYPE_MAP,
    _infer_finding_type,
)


# ---------------------------------------------------------------------------
# Sample SARIF data
# ---------------------------------------------------------------------------

SAMPLE_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.exec-detected",
                            "shortDescription": {"text": "Detected exec() call"},
                            "fullDescription": {"text": "Use of exec is dangerous."},
                        },
                        {
                            "id": "python.lang.security.audit.eval-detected",
                            "shortDescription": {"text": "Detected eval() call"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.exec-detected",
                    "level": "error",
                    "message": {"text": "exec() call with user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/main.py"},
                                "region": {"startLine": 42, "startColumn": 5},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "python.lang.security.audit.eval-detected",
                    "level": "warning",
                    "message": {"text": "eval() detected in handler"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/utils.py"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}

SAMPLE_MULTI_RUN = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Semgrep", "rules": []}},
            "results": [
                {
                    "ruleId": "rule-1",
                    "level": "error",
                    "message": {"text": "Finding from Semgrep"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}
                    ],
                }
            ],
        },
        {
            "tool": {"driver": {"name": "Checkov", "rules": []}},
            "results": [
                {
                    "ruleId": "CKV_AWS_1",
                    "level": "warning",
                    "message": {"text": "S3 bucket is public"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 5}}}
                    ],
                }
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Interface contract
# ---------------------------------------------------------------------------

class TestInterface:
    def test_subclass_of_scanner_adapter(self):
        assert issubclass(SARIFScannerAdapter, ScannerAdapter)

    def test_name_property(self):
        assert SARIFScannerAdapter().name == "sarif"


# ---------------------------------------------------------------------------
# Core field mapping
# ---------------------------------------------------------------------------

class TestFieldMapping:
    def test_rule_id_becomes_finding_id(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].id == "python.lang.security.audit.exec-detected"

    def test_source_scanner_prefixed(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].source_scanner == "sarif:semgrep"

    def test_finding_type_inferred_from_tool(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].finding_type == "code_pattern"

    def test_severity_error_maps_to_critical(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].severity == "critical"

    def test_severity_warning_maps_to_high(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[1].severity == "high"

    def test_title_from_message_text(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].title == "exec() call with user input"

    def test_location_file_and_line(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert findings[0].location == "app/main.py:42"

    def test_reachable_always_unknown(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert all(f.reachable == "unknown" for f in findings)

    def test_returns_finding_instances(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert all(isinstance(f, Finding) for f in findings)

    def test_finding_count(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_SARIF)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Multi-run flattening
# ---------------------------------------------------------------------------

class TestMultiRun:
    def test_flattens_multiple_runs(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_MULTI_RUN)
        assert len(findings) == 2

    def test_different_source_scanners(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_MULTI_RUN)
        sources = {f.source_scanner for f in findings}
        assert sources == {"sarif:semgrep", "sarif:checkov"}

    def test_different_finding_types(self):
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(SAMPLE_MULTI_RUN)
        types = {f.finding_type for f in findings}
        assert types == {"code_pattern", "iac_misconfig"}


# ---------------------------------------------------------------------------
# Rule metadata fallback
# ---------------------------------------------------------------------------

class TestRuleMetadata:
    def test_title_falls_back_to_rule_short_description(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "TestTool",
                    "rules": [{"id": "R1", "shortDescription": {"text": "Rule R1 desc"}}],
                }},
                "results": [{
                    "ruleId": "R1",
                    "level": "warning",
                    "message": {},  # empty message
                    "locations": [],
                }],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].title == "Rule R1 desc"

    def test_title_falls_back_to_generic(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "TestTool", "rules": []}},
                "results": [{
                    "ruleId": "R1",
                    "message": {},
                    "locations": [],
                }],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].title == "Rule R1 triggered"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_runs(self):
        adapter = SARIFScannerAdapter()
        assert adapter.parse_dict({"runs": []}) == []

    def test_missing_runs_key(self):
        adapter = SARIFScannerAdapter()
        assert adapter.parse_dict({}) == []

    def test_empty_results(self):
        sarif = {"runs": [{"tool": {"driver": {"name": "X", "rules": []}}, "results": []}]}
        adapter = SARIFScannerAdapter()
        assert adapter.parse_dict(sarif) == []

    def test_missing_rule_id(self):
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "X", "rules": []}},
                "results": [{"level": "warning", "message": {"text": "hi"}, "locations": []}],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].id == "unknown"

    def test_missing_level_defaults_to_high(self):
        """SARIF spec says default level is 'warning' which maps to 'high'."""
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "X", "rules": []}},
                "results": [{"ruleId": "R1", "message": {"text": "hi"}, "locations": []}],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].severity == "high"

    def test_no_locations_returns_unknown(self):
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "X", "rules": []}},
                "results": [{"ruleId": "R1", "level": "note", "message": {"text": "hi"}}],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].location == "unknown"

    def test_location_without_line(self):
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "X", "rules": []}},
                "results": [{
                    "ruleId": "R1",
                    "level": "note",
                    "message": {"text": "hi"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "foo.py"}}}],
                }],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].location == "foo.py"

    def test_long_message_truncated(self):
        long_msg = "A" * 200
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "X", "rules": []}},
                "results": [{"ruleId": "R1", "message": {"text": long_msg}, "locations": []}],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert len(findings[0].title) == 120
        assert findings[0].title.endswith("...")

    def test_missing_tool_name_defaults(self):
        sarif = {
            "runs": [{
                "tool": {"driver": {}},
                "results": [{"ruleId": "R1", "message": {"text": "hi"}, "locations": []}],
            }],
        }
        adapter = SARIFScannerAdapter()
        findings = adapter.parse_dict(sarif)
        assert findings[0].source_scanner == "sarif:unknown"


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

class TestFileIO:
    def test_parse_reads_file(self, tmp_path):
        sarif_file = tmp_path / "results.sarif"
        sarif_file.write_text(json.dumps(SAMPLE_SARIF))
        adapter = SARIFScannerAdapter()
        findings = adapter.parse(sarif_file)
        assert len(findings) == 2
        assert findings[0].id == "python.lang.security.audit.exec-detected"

    def test_parse_from_string_path(self, tmp_path):
        sarif_file = tmp_path / "results.sarif"
        sarif_file.write_text(json.dumps(SAMPLE_SARIF))
        adapter = SARIFScannerAdapter()
        findings = adapter.parse(str(sarif_file))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Tool → finding_type inference
# ---------------------------------------------------------------------------

class TestFindingTypeInference:
    @pytest.mark.parametrize("tool,expected", [
        ("Semgrep", "code_pattern"),
        ("CodeQL", "code_pattern"),
        ("Bandit", "code_pattern"),
        ("Checkov", "iac_misconfig"),
        ("tfsec", "iac_misconfig"),
        ("Trivy", "language_dep"),
        ("grype", "language_dep"),
        ("Gitleaks", "secret"),
        ("UnknownTool", "code_pattern"),
    ])
    def test_tool_type_mapping(self, tool, expected):
        assert _infer_finding_type(tool) == expected

    def test_level_note_maps_to_low(self):
        assert LEVEL_MAP["note"] == "low"

    def test_level_none_maps_to_info(self):
        assert LEVEL_MAP["none"] == "info"
