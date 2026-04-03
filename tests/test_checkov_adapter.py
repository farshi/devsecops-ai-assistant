"""Tests for agent/plugins/scanners/checkov.py — Checkov IaC adapter."""

import json

import pytest

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.checkov import CheckovScannerAdapter, SEVERITY_MAP


# ---------------------------------------------------------------------------
# Sample Checkov data
# ---------------------------------------------------------------------------

SAMPLE_CHECKOV_OUTPUT = [
    {
        "check_type": "terraform",
        "results": {
            "passed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_result": {"result": "PASSED"},
                    "resource": "aws_instance.web",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 5],
                }
            ],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure the S3 bucket has access logging enabled",
                    "check_result": {"result": "FAILED"},
                    "resource": "aws_s3_bucket.data",
                    "check_class": "checkov.terraform.checks.resource.aws.S3AccessLogs",
                    "guideline": "https://docs.bridgecrew.io/docs/s3_13-enable-logging",
                    "file_path": "/storage.tf",
                    "file_line_range": [10, 20],
                    "bc_check_id": "BC_AWS_S3_13",
                    "severity": "LOW",
                },
                {
                    "check_id": "CKV_AWS_145",
                    "check_name": "Ensure S3 bucket is encrypted with KMS",
                    "check_result": {"result": "FAILED"},
                    "resource": "aws_s3_bucket.data",
                    "check_class": "checkov.terraform.checks.resource.aws.S3Encryption",
                    "guideline": "https://docs.bridgecrew.io/docs/ensure-that-s3-buckets-are-encrypted-with-kms",
                    "file_path": "/storage.tf",
                    "file_line_range": [10, 20],
                    "severity": "HIGH",
                },
            ],
            "skipped_checks": [],
        },
    }
]

SAMPLE_MULTI_FRAMEWORK = [
    {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "S3 logging",
                    "resource": "aws_s3_bucket.data",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 5],
                    "severity": "LOW",
                }
            ],
        },
    },
    {
        "check_type": "dockerfile",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_2",
                    "check_name": "Ensure that HEALTHCHECK instructions have been added",
                    "resource": "/Dockerfile.",
                    "file_path": "/Dockerfile",
                    "file_line_range": [1, 15],
                    "severity": "MEDIUM",
                }
            ],
        },
    },
]


# ---------------------------------------------------------------------------
# Interface contract
# ---------------------------------------------------------------------------

class TestInterface:
    def test_subclass_of_scanner_adapter(self):
        assert issubclass(CheckovScannerAdapter, ScannerAdapter)

    def test_name_property(self):
        assert CheckovScannerAdapter().name == "checkov"


# ---------------------------------------------------------------------------
# Core field mapping
# ---------------------------------------------------------------------------

class TestFieldMapping:
    def test_returns_finding_instances(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert all(isinstance(f, Finding) for f in findings)

    def test_only_failed_checks(self):
        """Should only process failed_checks, not passed or skipped."""
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert len(findings) == 2

    def test_check_id_becomes_finding_id(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert findings[0].id == "CKV_AWS_18"

    def test_source_scanner(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert all(f.source_scanner == "checkov" for f in findings)

    def test_finding_type_iac_misconfig(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert all(f.finding_type == "iac_misconfig" for f in findings)

    def test_severity_mapping(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert findings[0].severity == "low"
        assert findings[1].severity == "high"

    def test_title_includes_check_id_and_name(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert "CKV_AWS_18" in findings[0].title
        assert "access logging" in findings[0].title

    def test_title_includes_resource(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert "aws_s3_bucket.data" in findings[0].title

    def test_location_file_and_line(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert findings[0].location == "storage.tf:10"

    def test_location_strips_leading_slash(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert not findings[0].location.startswith("/")

    def test_reachable_not_applicable(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert all(f.reachable == "not_applicable" for f in findings)

    def test_fix_available_always_true(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert all(f.fix_available for f in findings)

    def test_guideline_as_fix_evidence(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_CHECKOV_OUTPUT)
        assert "docs.bridgecrew.io" in findings[0].fix_evidence


# ---------------------------------------------------------------------------
# Multi-framework
# ---------------------------------------------------------------------------

class TestMultiFramework:
    def test_flattens_multiple_frameworks(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_MULTI_FRAMEWORK)
        assert len(findings) == 2

    def test_different_check_ids(self):
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(SAMPLE_MULTI_FRAMEWORK)
        ids = {f.id for f in findings}
        assert ids == {"CKV_AWS_18", "CKV_DOCKER_2"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_list(self):
        adapter = CheckovScannerAdapter()
        assert adapter.parse_list([]) == []

    def test_none_input(self):
        adapter = CheckovScannerAdapter()
        assert adapter.parse_list(None) == []

    def test_no_failed_checks(self):
        data = [{"check_type": "terraform", "results": {"failed_checks": [], "passed_checks": []}}]
        adapter = CheckovScannerAdapter()
        assert adapter.parse_list(data) == []

    def test_missing_results_key(self):
        data = [{"check_type": "terraform"}]
        adapter = CheckovScannerAdapter()
        assert adapter.parse_list(data) == []

    def test_missing_severity_defaults_to_medium(self):
        data = [{
            "check_type": "terraform",
            "results": {"failed_checks": [{
                "check_id": "CKV_TEST_1",
                "check_name": "Test check",
                "resource": "test.res",
                "file_path": "/test.tf",
                "file_line_range": [1, 5],
            }]},
        }]
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(data)
        assert findings[0].severity == "medium"

    def test_missing_file_line_range(self):
        data = [{
            "check_type": "terraform",
            "results": {"failed_checks": [{
                "check_id": "CKV_TEST_1",
                "check_name": "Test",
                "resource": "r",
                "file_path": "/test.tf",
                "severity": "LOW",
            }]},
        }]
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(data)
        assert findings[0].location == "test.tf"

    def test_long_title_truncated(self):
        data = [{
            "check_type": "terraform",
            "results": {"failed_checks": [{
                "check_id": "CKV_TEST_1",
                "check_name": "A" * 120,
                "resource": "some.resource.with.long.name",
                "file_path": "/test.tf",
                "file_line_range": [1, 5],
                "severity": "LOW",
            }]},
        }]
        adapter = CheckovScannerAdapter()
        findings = adapter.parse_list(data)
        assert len(findings[0].title) == 120
        assert findings[0].title.endswith("...")

    def test_single_dict_input_via_parse(self, tmp_path):
        """Checkov may output a single dict instead of a list."""
        single = {
            "check_type": "terraform",
            "results": {"failed_checks": [{
                "check_id": "CKV_TEST_1",
                "check_name": "Test",
                "resource": "r",
                "file_path": "/test.tf",
                "file_line_range": [1, 5],
                "severity": "LOW",
            }]},
        }
        f = tmp_path / "checkov.json"
        f.write_text(json.dumps(single))
        adapter = CheckovScannerAdapter()
        findings = adapter.parse(f)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

class TestFileIO:
    def test_parse_reads_file(self, tmp_path):
        f = tmp_path / "checkov.json"
        f.write_text(json.dumps(SAMPLE_CHECKOV_OUTPUT))
        adapter = CheckovScannerAdapter()
        findings = adapter.parse(f)
        assert len(findings) == 2
        assert findings[0].id == "CKV_AWS_18"

    def test_parse_from_string_path(self, tmp_path):
        f = tmp_path / "checkov.json"
        f.write_text(json.dumps(SAMPLE_CHECKOV_OUTPUT))
        adapter = CheckovScannerAdapter()
        findings = adapter.parse(str(f))
        assert len(findings) == 2
