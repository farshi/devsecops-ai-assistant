"""Tests for agent/context_builder.py — detect_repo_structure()."""
import json
import os
from unittest.mock import patch

import pytest

from agent.context_builder import (
    detect_repo_structure,
    extract_dependencies,
    check_reachability,
    build_context,
    MAX_FINDINGS,
)
from agent.models import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_APP_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_app")


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def test_detect_python_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\nuvicorn\n")
    result = detect_repo_structure(str(tmp_path))
    assert "python" in result["languages"]
    assert "fastapi" in result["frameworks"]


def test_detect_node_project(tmp_path):
    pkg = {"dependencies": {"express": "^4.18"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = detect_repo_structure(str(tmp_path))
    assert "javascript" in result["languages"]
    assert "express" in result["frameworks"]


def test_detect_multiple_languages(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    pkg = {"dependencies": {"express": "^4.18"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = detect_repo_structure(str(tmp_path))
    assert "python" in result["languages"]
    assert "javascript" in result["languages"]


# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------

def test_detect_docker_runtime(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    result = detect_repo_structure(str(tmp_path))
    assert result["runtime"] == "docker"


def test_detect_no_docker(tmp_path):
    result = detect_repo_structure(str(tmp_path))
    assert result["runtime"] == "none"


# ---------------------------------------------------------------------------
# CI detection
# ---------------------------------------------------------------------------

def test_detect_ci(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    result = detect_repo_structure(str(tmp_path))
    assert result["has_ci"] is True


def test_detect_no_ci(tmp_path):
    result = detect_repo_structure(str(tmp_path))
    assert result["has_ci"] is False


# ---------------------------------------------------------------------------
# IaC detection
# ---------------------------------------------------------------------------

def test_detect_iac_terraform(tmp_path):
    (tmp_path / "main.tf").write_text('provider "aws" {}\n')
    result = detect_repo_structure(str(tmp_path))
    assert result["has_iac"] is True


def test_detect_no_iac(tmp_path):
    result = detect_repo_structure(str(tmp_path))
    assert result["has_iac"] is False


# ---------------------------------------------------------------------------
# Package files
# ---------------------------------------------------------------------------

def test_package_files_listed(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n")
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "app"\n')
    result = detect_repo_structure(str(tmp_path))
    assert "requirements.txt" in result["package_files"]
    assert "pyproject.toml" in result["package_files"]


# ---------------------------------------------------------------------------
# Integration: sample_app/
# ---------------------------------------------------------------------------

def test_on_sample_app():
    result = detect_repo_structure(SAMPLE_APP_DIR)
    assert result["languages"] == ["python"]
    assert "fastapi" in result["frameworks"]
    assert result["runtime"] == "docker"
    assert result["has_ci"] is False
    assert result["has_iac"] is False


# ---------------------------------------------------------------------------
# Edge case: empty directory
# ---------------------------------------------------------------------------

def test_empty_directory(tmp_path):
    result = detect_repo_structure(str(tmp_path))
    assert result["languages"] == []
    assert result["frameworks"] == []
    assert result["runtime"] == "none"
    assert result["has_ci"] is False
    assert result["has_iac"] is False
    assert isinstance(result["package_files"], list)
    assert isinstance(result["markers"], dict)


# ---------------------------------------------------------------------------
# extract_dependencies tests
# ---------------------------------------------------------------------------

def test_extract_python_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "fastapi==0.110.0\n"
        "uvicorn>=0.29.0\n"
        "# this is a comment\n"
        "\n"
        "pydantic~=2.6\n"
        "httpx\n"
        "-r dev-requirements.txt\n"
    )
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["package_manager"] == "pip"
    assert len(result["direct"]) == 4
    dep_names = result["direct"]
    assert any(d.startswith("fastapi") for d in dep_names)
    assert any(d.startswith("uvicorn") for d in dep_names)
    assert any(d.startswith("pydantic") for d in dep_names)
    assert any(d.startswith("httpx") for d in dep_names)


def test_extract_python_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "myapp"\n'
        'dependencies = [\n'
        '    "fastapi>=0.110.0",\n'
        '    "uvicorn",\n'
        ']\n'
    )
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["package_manager"] == "pip"
    assert len(result["direct"]) == 2
    assert any(d.startswith("fastapi") for d in result["direct"])
    assert any(d.startswith("uvicorn") for d in result["direct"])


def test_extract_node_deps(tmp_path):
    pkg = {
        "dependencies": {"express": "^4.18"},
        "devDependencies": {"jest": "^29.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["package_manager"] == "npm"
    assert len(result["direct"]) == 2
    assert any("express" in d for d in result["direct"])
    assert any("jest" in d for d in result["direct"])


def test_extract_go_deps(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n"
        "\n"
        "go 1.21\n"
        "\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.9.1\n"
        "    github.com/stretchr/testify v1.8.4\n"
        ")\n"
    )
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["package_manager"] == "go"
    assert len(result["direct"]) == 2
    assert any("gin-gonic/gin" in d for d in result["direct"])
    assert any("stretchr/testify" in d for d in result["direct"])


def test_lockfile_detection(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\n")
    (tmp_path / "Pipfile.lock").write_text("{}")
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["lockfile_exists"] is True


def test_no_lockfile(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\n")
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["lockfile_exists"] is False


def test_extract_empty_directory(tmp_path):
    structure = detect_repo_structure(str(tmp_path))
    result = extract_dependencies(str(tmp_path), structure)
    assert result["direct"] == []
    assert result["package_manager"] == "unknown"
    assert result["lockfile_exists"] is False


def test_on_sample_app():
    structure = detect_repo_structure(SAMPLE_APP_DIR)
    result = extract_dependencies(SAMPLE_APP_DIR, structure)
    direct = result["direct"]
    expected = ["fastapi", "uvicorn", "pydantic", "httpx", "pytest"]
    for pkg in expected:
        assert any(d.lower().startswith(pkg) for d in direct), f"{pkg} not found in direct deps"


# ---------------------------------------------------------------------------
# check_reachability tests
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    """Create a minimal Finding with sensible defaults."""
    defaults = dict(
        id="CVE-2024-test",
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title="Test vulnerability",
        package="test-pkg",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_reachability_imported_package(tmp_path):
    """fastapi is in PACKAGE_IMPORT_MAP; import present → high confidence, reachable=true."""
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\n")
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="fastapi")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "true"
    assert results[0].reachability_confidence == "high"
    assert "app.py" in results[0].reachability_evidence


def test_reachability_not_imported(tmp_path):
    """Package not imported; not in map → medium confidence, reachable=false."""
    (tmp_path / "requirements.txt").write_text("unused-pkg==1.0\n")
    (tmp_path / "app.py").write_text("print('hello')\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="unused-pkg")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "false"
    assert results[0].reachability_confidence == "medium"
    assert results[0].reachability_evidence == "not imported in any .py file"


def test_reachability_known_mismatch(tmp_path):
    """pyyaml → yaml mapping confirmed; import yaml found → high confidence."""
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0\n")
    (tmp_path / "config.py").write_text("import yaml\ndata = yaml.safe_load('{}')\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="pyyaml")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "true"
    assert results[0].reachability_confidence == "high"
    assert "config.py" in results[0].reachability_evidence


def test_reachability_os_package_skipped(tmp_path):
    """os_package findings are not modified."""
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(
        finding_type="os_package",
        package="openssl",
        reachable="not_applicable",
        reachability_confidence="none",
    )
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "not_applicable"
    assert results[0].reachability_confidence == "none"


def test_reachability_from_import(tmp_path):
    """from pydantic import BaseModel → pydantic is reachable."""
    (tmp_path / "models.py").write_text("from pydantic import BaseModel\nclass M(BaseModel): pass\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="pydantic")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "true"


def test_reachability_submodule_import(tmp_path):
    """from google.cloud.storage import Client → google-cloud-storage reachable."""
    (tmp_path / "storage.py").write_text("from google.cloud.storage import Client\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="google-cloud-storage")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "true"
    assert results[0].reachability_confidence == "high"


def test_reachability_on_sample_app():
    """Integration: fastapi is imported in sample_app/main.py."""
    structure = detect_repo_structure(SAMPLE_APP_DIR)
    fastapi_finding = _make_finding(package="fastapi")
    results = check_reachability(SAMPLE_APP_DIR, [fastapi_finding], structure)
    assert results[0].reachable == "true"
    assert results[0].reachability_confidence == "high"


def test_reachability_empty_findings(tmp_path):
    """Empty findings list returns empty list without crashing."""
    structure = detect_repo_structure(str(tmp_path))
    results = check_reachability(str(tmp_path), [], structure)
    assert results == []


def test_reachability_skips_venv(tmp_path):
    """Imports inside venv/ are not counted as reachable."""
    venv_dir = tmp_path / "venv" / "lib" / "python3.12" / "site-packages" / "mypkg"
    venv_dir.mkdir(parents=True)
    (venv_dir / "__init__.py").write_text("import secret_pkg\n")
    # No real source file imports secret_pkg
    (tmp_path / "app.py").write_text("print('nothing here')\n")
    structure = detect_repo_structure(str(tmp_path))
    finding = _make_finding(package="secret-pkg")
    results = check_reachability(str(tmp_path), [finding], structure)
    assert results[0].reachable == "false"


# ---------------------------------------------------------------------------
# build_context tests
# ---------------------------------------------------------------------------

MINIMAL_SUMMARY = {
    "version": "1",
    "target": {"name": "test", "slug": "test", "path": "/tmp"},
    "scan": {
        "date": "2026-03-27",
        "profile": "standard",
        "scanners_requested": ["trivy_fs"],
        "scanners_run": ["trivy_fs"],
        "scanners_skipped": [],
    },
    "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    "top_issues": [],
    "findings": {
        "trivy_fs": [
            {
                "id": "CVE-2024-0001",
                "severity": "critical",
                "title": "Test vuln",
                "location": "requirements.txt > pkg@1.0",
                "fix": "Upgrade to 2.0",
            }
        ]
    },
    "risk_summary": "1 critical finding",
    "notes": [],
}


def _write_summary(tmp_path, summary=None) -> str:
    """Write summary JSON to tmp_path and return the file path string."""
    data = summary if summary is not None else MINIMAL_SUMMARY
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(data))
    return str(summary_path)


def _make_repo(tmp_path):
    """Create a minimal Python repo with one source file."""
    (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\n")
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_basic(mock_kev, mock_epss, tmp_path):
    """build_context returns all required top-level keys."""
    _make_repo(tmp_path)
    summary_path = _write_summary(tmp_path)
    result = build_context(str(tmp_path), summary_path)
    assert set(result.keys()) == {"repo", "dependencies", "findings", "scan_meta", "token_budget"}


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_findings_are_dicts(mock_kev, mock_epss, tmp_path):
    """Findings in output are dicts (serialized), not Finding objects."""
    _make_repo(tmp_path)
    summary_path = _write_summary(tmp_path)
    result = build_context(str(tmp_path), summary_path)
    assert isinstance(result["findings"], list)
    for f in result["findings"]:
        assert isinstance(f, dict), f"Expected dict, got {type(f)}"


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_scan_meta(mock_kev, mock_epss, tmp_path):
    """scan_meta contains expected fields from the summary."""
    _make_repo(tmp_path)
    summary_path = _write_summary(tmp_path)
    result = build_context(str(tmp_path), summary_path)
    meta = result["scan_meta"]
    assert meta["date"] == "2026-03-27"
    assert meta["profile"] == "standard"
    assert meta["scanners_run"] == ["trivy_fs"]
    assert meta["total_findings"] == 1
    assert meta["severity_counts"]["critical"] == 1


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_token_budget_no_truncation(mock_kev, mock_epss, tmp_path):
    """Small finding count → truncated=False, included_findings equals total."""
    _make_repo(tmp_path)
    summary_path = _write_summary(tmp_path)
    result = build_context(str(tmp_path), summary_path)
    budget = result["token_budget"]
    assert budget["truncated"] is False
    assert budget["included_findings"] == budget["total_findings"]
    assert budget["max_findings"] == MAX_FINDINGS


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_token_budget_truncation(mock_kev, mock_epss, tmp_path):
    """250+ findings → only MAX_FINDINGS kept, truncated=True."""
    _make_repo(tmp_path)
    # Generate 250 unique findings
    many_findings = [
        {
            "id": f"CVE-2024-{i:04d}",
            "severity": "high",
            "title": f"Vuln {i}",
            "location": f"requirements.txt > pkg{i}@1.0",
        }
        for i in range(250)
    ]
    summary = {**MINIMAL_SUMMARY, "findings": {"trivy_fs": many_findings}}
    summary_path = _write_summary(tmp_path, summary)
    result = build_context(str(tmp_path), summary_path)
    budget = result["token_budget"]
    assert budget["truncated"] is True
    assert budget["included_findings"] == MAX_FINDINGS
    assert len(result["findings"]) == MAX_FINDINGS


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_deduplicates_cves(mock_kev, mock_epss, tmp_path):
    """Same CVE appearing 3 times → collapsed to 1 in output."""
    _make_repo(tmp_path)
    dup_findings = [
        {"id": "CVE-2024-DUPE", "severity": "high", "title": "Dupe vuln", "location": f"file{i}.txt > pkg@1.0"}
        for i in range(3)
    ]
    summary = {**MINIMAL_SUMMARY, "findings": {"trivy_fs": dup_findings}}
    summary_path = _write_summary(tmp_path, summary)
    result = build_context(str(tmp_path), summary_path)
    # Should only have one entry for the duplicated CVE
    ids = [f["id"] for f in result["findings"]]
    assert ids.count("CVE-2024-DUPE") == 1
    # token_budget total_findings still reflects original count
    assert result["token_budget"]["total_findings"] == 3


def test_build_context_enrichment_failure_doesnt_crash(tmp_path):
    """EPSS/KEV plugins raising exceptions must not break build_context."""
    _make_repo(tmp_path)
    summary_path = _write_summary(tmp_path)
    with (
        patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", side_effect=RuntimeError("network down")),
        patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", side_effect=RuntimeError("network down")),
    ):
        result = build_context(str(tmp_path), summary_path)
    # Still returns a valid context bundle
    assert set(result.keys()) == {"repo", "dependencies", "findings", "scan_meta", "token_budget"}


REAL_SUMMARY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "reports", "notes-api_summary_2026-03-27.json"
)
SAMPLE_APP_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_app")


@patch("agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich", return_value=[])
@patch("agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich", return_value=[])
def test_build_context_on_sample_app(mock_kev, mock_epss):
    """Integration: run build_context against real sample_app/ and summary.json."""
    result = build_context(SAMPLE_APP_DIR, REAL_SUMMARY_PATH)
    assert set(result.keys()) == {"repo", "dependencies", "findings", "scan_meta", "token_budget"}
    # Repo should detect Python + fastapi
    assert "python" in result["repo"]["languages"]
    assert "fastapi" in result["repo"]["frameworks"]
    # Dependencies should be populated
    assert len(result["dependencies"]["direct"]) > 0
    # scan_meta should have expected fields
    meta = result["scan_meta"]
    assert "date" in meta
    assert "scanners_run" in meta
    assert "severity_counts" in meta
    # token_budget should have required keys
    budget = result["token_budget"]
    assert "total_findings" in budget
    assert "included_findings" in budget
    assert "truncated" in budget
    assert budget["truncated"] is False  # 0 findings in this summary
