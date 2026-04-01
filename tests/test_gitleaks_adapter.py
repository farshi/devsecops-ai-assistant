"""Tests for GitleaksScannerAdapter."""

import json
import tempfile
from pathlib import Path

import pytest

from agent.models import Finding
from agent.plugins.base import ScannerAdapter
from agent.plugins.scanners.gitleaks import GitleaksScannerAdapter

SAMPLE_GITLEAKS_OUTPUT = [
    {
        "Description": "AWS Access Key ID",
        "StartLine": 10,
        "EndLine": 10,
        "File": "config.py",
        "RuleID": "aws-access-key-id",
        "Fingerprint": "abc:config.py:aws-access-key-id:10",
    },
    {
        "Description": "Generic API Key",
        "StartLine": 25,
        "EndLine": 25,
        "File": "utils.py",
        "RuleID": "generic-api-key",
        "Fingerprint": "def:utils.py:generic-api-key:25",
    },
    {
        "Description": "RSA Private Key",
        "StartLine": 1,
        "EndLine": 20,
        "File": "keys/server.pem",
        "RuleID": "private-key",
        "Fingerprint": "ghi:keys/server.pem:private-key:1",
    },
]


@pytest.fixture
def adapter():
    return GitleaksScannerAdapter()


@pytest.fixture
def findings(adapter):
    return adapter.parse_list(SAMPLE_GITLEAKS_OUTPUT)


def test_parse_returns_finding_instances(findings):
    assert all(isinstance(f, Finding) for f in findings)
    assert len(findings) == 3


def test_finding_type_is_secret(findings):
    assert all(f.finding_type == "secret" for f in findings)


def test_reachable_is_not_applicable(findings):
    assert all(f.reachable == "not_applicable" for f in findings)


def test_source_scanner_is_gitleaks(findings):
    assert all(f.source_scanner == "gitleaks" for f in findings)


def test_id_prefixed_with_secret(findings):
    assert all(f.id.startswith("SECRET:") for f in findings)


def test_location_includes_file_and_line(findings):
    # config.py:10
    aws_finding = next(f for f in findings if "aws-access-key-id" in f.id)
    assert aws_finding.location == "config.py:10"

    # utils.py:25
    generic_finding = next(f for f in findings if "generic-api-key" in f.id)
    assert generic_finding.location == "utils.py:25"

    # keys/server.pem:1
    key_finding = next(f for f in findings if "private-key" in f.id)
    assert key_finding.location == "keys/server.pem:1"


def test_severity_aws_key_is_high(findings):
    aws_finding = next(f for f in findings if "aws-access-key-id" in f.id)
    assert aws_finding.severity == "high"


def test_severity_private_key_is_critical(findings):
    key_finding = next(f for f in findings if f.id == "SECRET:private-key")
    assert key_finding.severity == "critical"


def test_severity_generic_is_medium(findings):
    generic_finding = next(f for f in findings if "generic-api-key" in f.id)
    assert generic_finding.severity == "medium"


def test_fix_available_always_true(findings):
    assert all(f.fix_available is True for f in findings)


def test_fix_evidence_mentions_rotate(findings):
    assert all("rotate" in (f.fix_evidence or "").lower() for f in findings)


def test_parse_empty_list(adapter):
    result = adapter.parse_list([])
    assert result == []


def test_parse_empty_none(adapter):
    result = adapter.parse_list(None)
    assert result == []


def test_parse_from_file(adapter):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_GITLEAKS_OUTPUT, f)
        tmp_path = f.name

    findings = adapter.parse(Path(tmp_path))
    assert len(findings) == 3
    assert all(isinstance(f, Finding) for f in findings)


def test_implements_scanner_adapter(adapter):
    assert isinstance(adapter, ScannerAdapter)


def test_name_is_gitleaks(adapter):
    assert adapter.name == "gitleaks"
