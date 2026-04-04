"""Tests for SPDXFormatter."""

import json

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.spdx import SPDXFormatter, _spdx_id, _purl


def _make_finding(
    id="CVE-2024-00001",
    severity="high",
    title="Test vuln",
    package="testpkg",
    installed_version="1.0.0",
    fixed_version="1.2.0",
    reachable="unknown",
    fix_available=True,
    cvss_score=7.5,
) -> Finding:
    return Finding(
        id=id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=title,
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        reachable=reachable,
        fix_available=fix_available,
        cvss_score=cvss_score,
    )


_CTX = {
    "scan_meta": {"target": "test-app"},
    "dependencies": {
        "package_manager": "pip",
        "direct": ["flask==2.0.0", "requests==2.28.0"],
        "transitive": ["werkzeug==2.0.0"],
    },
}


class TestSPDXFormatter:
    def test_implements_output_formatter(self):
        assert isinstance(SPDXFormatter(), OutputFormatter)

    def test_name(self):
        assert SPDXFormatter().name == "spdx"

    def test_valid_json(self):
        f = _make_finding()
        result = SPDXFormatter().format([f], _CTX)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_spdx_version(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_data_license(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        assert data["dataLicense"] == "CC0-1.0"

    def test_document_namespace(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        assert data["documentNamespace"].startswith("https://patchpilot.dev/spdx/")

    def test_creation_info(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        info = data["creationInfo"]
        assert "created" in info
        assert any("patchpilot" in c for c in info["creators"])

    def test_root_package_present(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        root = data["packages"][0]
        assert root["SPDXID"] == "SPDXRef-RootPackage"
        assert root["name"] == "test-app"

    def test_packages_from_deps(self):
        data = json.loads(SPDXFormatter().format([], _CTX))
        names = [p["name"] for p in data["packages"]]
        assert "flask" in names
        assert "requests" in names
        assert "werkzeug" in names

    def test_packages_from_findings(self):
        f = _make_finding(package="newpkg", installed_version="3.0.0")
        data = json.loads(SPDXFormatter().format([f], _CTX))
        names = [p["name"] for p in data["packages"]]
        assert "newpkg" in names

    def test_no_duplicate_packages(self):
        f = _make_finding(package="flask", installed_version="2.0.0")
        data = json.loads(SPDXFormatter().format([f], _CTX))
        flask_pkgs = [p for p in data["packages"] if p["name"] == "flask"]
        assert len(flask_pkgs) == 1

    def test_purl_in_external_refs(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        pkg = next(p for p in data["packages"] if p["name"] == "testpkg")
        refs = pkg["externalRefs"]
        assert len(refs) == 1
        assert refs[0]["referenceType"] == "purl"
        assert "pkg:pypi/testpkg@1.0.0" in refs[0]["referenceLocator"]

    def test_relationships(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        rels = data["relationships"]
        describes = [r for r in rels if r["relationshipType"] == "DESCRIBES"]
        depends = [r for r in rels if r["relationshipType"] == "DEPENDS_ON"]
        assert len(describes) == 1
        assert len(depends) > 0

    def test_annotations_for_cve_findings(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], _CTX))
        assert "annotations" in data
        assert len(data["annotations"]) == 1
        ann = data["annotations"][0]
        assert "CVE-2024-00001" in ann["comment"]
        assert ann["annotationType"] == "REVIEW"

    def test_no_annotations_without_findings(self):
        data = json.loads(SPDXFormatter().format([], _CTX))
        assert "annotations" not in data

    def test_empty_findings(self):
        data = json.loads(SPDXFormatter().format([], _CTX))
        assert data["spdxVersion"] == "SPDX-2.3"
        assert len(data["packages"]) >= 1  # At least root package

    def test_empty_context(self):
        f = _make_finding()
        data = json.loads(SPDXFormatter().format([f], {}))
        assert data["spdxVersion"] == "SPDX-2.3"


class TestHelpers:
    def test_spdx_id_basic(self):
        assert _spdx_id("flask", "2.0.0") == "SPDXRef-Package-flask-2-0-0"

    def test_spdx_id_no_version(self):
        assert _spdx_id("flask", "") == "SPDXRef-Package-flask"

    def test_spdx_id_scoped_npm(self):
        result = _spdx_id("@scope/pkg", "1.0.0")
        assert "SPDXRef-Package" in result
        assert "@" not in result  # cleaned

    def test_purl_pip(self):
        assert _purl("Flask", "2.0.0", "pip") == "pkg:pypi/flask@2.0.0"

    def test_purl_npm(self):
        assert _purl("express", "4.18.0", "npm") == "pkg:npm/express@4.18.0"

    def test_purl_no_version(self):
        assert _purl("flask", "", "pip") == "pkg:pypi/flask"
