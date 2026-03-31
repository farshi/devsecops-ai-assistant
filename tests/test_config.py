"""Tests for agent/config.py — PatchPilot config loading and filtering."""

import pytest

from agent.config import (
    DEFAULT_CONFIG,
    load_config,
    apply_config_filters,
    _parse_simple_yaml,
)
from agent.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_config(tmp_path, content):
    config_dir = tmp_path / ".patchpilot"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text(content)


def _make_finding(cve_id, severity="high", package="test-pkg"):
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=f"Test {cve_id}",
        package=package,
    )


# ---------------------------------------------------------------------------
# load_config tests
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_load_config_defaults(self, tmp_path):
        """No config file — returns DEFAULT_CONFIG values."""
        config = load_config(str(tmp_path))
        assert config["severity_threshold"] is None
        assert config["ignore_cves"] == []
        assert config["ignore_packages"] == []
        assert config["top_n"] == 5
        assert config["llm_provider"] == "claude"
        assert config["reachability"]["enabled"] is True
        assert config["enrichment"]["epss"] is True

    def test_load_config_from_file(self, tmp_path):
        """Config file overrides defaults for specified keys."""
        _write_config(tmp_path, "severity_threshold: high\ntop_n: 3\n")
        config = load_config(str(tmp_path))
        assert config["severity_threshold"] == "high"
        assert config["top_n"] == 3
        # Other defaults intact
        assert config["llm_provider"] == "claude"
        assert config["ignore_cves"] == []

    def test_load_config_merges_nested(self, tmp_path):
        """Nested dicts are deep-merged — only specified keys overridden."""
        _write_config(tmp_path, "enrichment:\n  epss: false\n")
        config = load_config(str(tmp_path))
        assert config["enrichment"]["epss"] is False
        # Sibling keys preserved
        assert config["enrichment"]["kev"] is True
        assert config["enrichment"]["fix_availability"] is True

    def test_load_config_invalid_yaml(self, tmp_path):
        """Garbage content — returns defaults, no crash."""
        _write_config(tmp_path, "}{{{ not yaml at all !!!\n")
        config = load_config(str(tmp_path))
        # Should fall back to defaults (yaml.safe_load may return a string or raise)
        assert config["top_n"] == DEFAULT_CONFIG["top_n"]
        assert config["ignore_cves"] == []

    def test_load_config_empty_file(self, tmp_path):
        """Empty config file — returns defaults."""
        _write_config(tmp_path, "")
        config = load_config(str(tmp_path))
        assert config["top_n"] == 5
        assert config["severity_threshold"] is None

    def test_load_config_no_config_dir(self, tmp_path):
        """No .patchpilot directory at all — returns defaults."""
        config = load_config(str(tmp_path))
        assert config == load_config("/nonexistent/path/that/does/not/exist")


# ---------------------------------------------------------------------------
# apply_config_filters tests
# ---------------------------------------------------------------------------

class TestApplyConfigFilters:
    def test_apply_filters_severity_threshold(self):
        """Only critical+high pass through when threshold=high."""
        findings = [
            _make_finding("CVE-001", severity="critical"),
            _make_finding("CVE-002", severity="high"),
            _make_finding("CVE-003", severity="medium"),
            _make_finding("CVE-004", severity="low"),
            _make_finding("CVE-005", severity="info"),
        ]
        config = {**DEFAULT_CONFIG, "severity_threshold": "high"}
        result = apply_config_filters(findings, config)
        assert len(result) == 2
        assert {f.id for f in result} == {"CVE-001", "CVE-002"}

    def test_apply_filters_ignore_cves(self):
        """Ignored CVE is removed."""
        findings = [
            _make_finding("CVE-2023-001"),
            _make_finding("CVE-2023-002"),
            _make_finding("CVE-2023-003"),
        ]
        config = {**DEFAULT_CONFIG, "ignore_cves": ["CVE-2023-002"]}
        result = apply_config_filters(findings, config)
        assert len(result) == 2
        assert all(f.id != "CVE-2023-002" for f in result)

    def test_apply_filters_ignore_packages(self):
        """Findings for an ignored package are removed."""
        findings = [
            _make_finding("CVE-001", package="safe-pkg"),
            _make_finding("CVE-002", package="ignored-lib"),
            _make_finding("CVE-003", package="safe-pkg"),
        ]
        config = {**DEFAULT_CONFIG, "ignore_packages": ["ignored-lib"]}
        result = apply_config_filters(findings, config)
        assert len(result) == 2
        assert all(f.package != "ignored-lib" for f in result)

    def test_apply_filters_ignore_packages_case_insensitive(self):
        """Package ignore is case-insensitive."""
        findings = [
            _make_finding("CVE-001", package="MyPackage"),
        ]
        config = {**DEFAULT_CONFIG, "ignore_packages": ["mypackage"]}
        result = apply_config_filters(findings, config)
        assert result == []

    def test_apply_filters_combined(self):
        """Threshold + ignore CVE + ignore package all applied together."""
        findings = [
            _make_finding("CVE-001", severity="critical", package="good-pkg"),
            _make_finding("CVE-002", severity="high",     package="good-pkg"),
            _make_finding("CVE-003", severity="medium",   package="good-pkg"),   # filtered by threshold
            _make_finding("CVE-004", severity="critical", package="bad-pkg"),    # filtered by package
            _make_finding("CVE-005", severity="high",     package="good-pkg"),   # filtered by CVE ignore
        ]
        config = {
            **DEFAULT_CONFIG,
            "severity_threshold": "high",
            "ignore_packages": ["bad-pkg"],
            "ignore_cves": ["CVE-005"],
        }
        result = apply_config_filters(findings, config)
        assert len(result) == 2
        assert {f.id for f in result} == {"CVE-001", "CVE-002"}

    def test_apply_filters_no_config(self):
        """Default config — all findings pass through."""
        findings = [
            _make_finding("CVE-001", severity="critical"),
            _make_finding("CVE-002", severity="medium"),
            _make_finding("CVE-003", severity="info"),
        ]
        result = apply_config_filters(findings, DEFAULT_CONFIG)
        assert len(result) == 3

    def test_apply_filters_finding_no_package(self):
        """Findings with no package field are not incorrectly filtered."""
        finding = Finding(
            id="CVE-001",
            source_scanner="trivy_fs",
            finding_type="os_package",
            severity="high",
            title="Test CVE",
            package=None,
        )
        config = {**DEFAULT_CONFIG, "ignore_packages": ["anything"]}
        result = apply_config_filters([finding], config)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _parse_simple_yaml tests
# ---------------------------------------------------------------------------

class TestParseSimpleYaml:
    def test_basic_string_value(self):
        result = _parse_simple_yaml("severity_threshold: high\n")
        assert result["severity_threshold"] == "high"

    def test_boolean_true(self):
        result = _parse_simple_yaml("enabled: true\n")
        assert result["enabled"] is True

    def test_boolean_false(self):
        result = _parse_simple_yaml("enabled: false\n")
        assert result["enabled"] is False

    def test_boolean_yes_no(self):
        result = _parse_simple_yaml("a: yes\nb: no\n")
        assert result["a"] is True
        assert result["b"] is False

    def test_integer_value(self):
        result = _parse_simple_yaml("top_n: 10\n")
        assert result["top_n"] == 10

    def test_list_value(self):
        result = _parse_simple_yaml("ignore_cves: [CVE-2023-001, CVE-2024-999]\n")
        assert result["ignore_cves"] == ["CVE-2023-001", "CVE-2024-999"]

    def test_empty_list(self):
        result = _parse_simple_yaml("ignore_cves: []\n")
        assert result["ignore_cves"] == []

    def test_comments_skipped(self):
        result = _parse_simple_yaml("# this is a comment\ntop_n: 3\n")
        assert "this is a comment" not in result
        assert result["top_n"] == 3

    def test_empty_input(self):
        result = _parse_simple_yaml("")
        assert result == {}

    def test_multiple_keys(self):
        text = "severity_threshold: high\ntop_n: 3\nllm_provider: claude\n"
        result = _parse_simple_yaml(text)
        assert result["severity_threshold"] == "high"
        assert result["top_n"] == 3
        assert result["llm_provider"] == "claude"
