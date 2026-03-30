"""Tests for agent/context_builder.py — detect_repo_structure()."""
import json
import os

import pytest

from agent.context_builder import detect_repo_structure, extract_dependencies

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
