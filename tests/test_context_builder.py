"""Tests for agent/context_builder.py — detect_repo_structure()."""
import json
import os

import pytest

from agent.context_builder import detect_repo_structure

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
