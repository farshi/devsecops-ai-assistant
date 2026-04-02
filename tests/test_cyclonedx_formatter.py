"""Tests for CycloneDXFormatter."""

import json

import pytest
from agent.models import Finding
from agent.plugins.base import OutputFormatter
from agent.plugins.formatters.cyclonedx import CycloneDXFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id="CVE-2024-00001",
    severity="high",
    title="Test vuln",
    package="testpkg",
    installed_version="1.0.0",
    fixed_version="1.2.0",
    in_kev=False,
    epss_score=0.1,
    reachable="unknown",
    reachability_confidence="none",
    fix_available=True,
    priority_score=60,
    priority_tier="high",
    cvss_score=7.5,
    finding_type="language_dep",
    source_scanner="trivy_fs",
) -> Finding:
    return Finding(
        id=id,
        source_scanner=source_scanner,
        finding_type=finding_type,
        severity=severity,
        title=title,
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        in_kev=in_kev,
        epss_score=epss_score,
        reachable=reachable,
        reachability_confidence=reachability_confidence,
        fix_available=fix_available,
        priority_score=priority_score,
        priority_tier=priority_tier,
        cvss_score=cvss_score,
    )


def _base_context(**overrides) -> dict:
    ctx = {
        "scan_meta": {
            "target": "myapp",
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
        },
        "repo": {
            "languages": ["Python"],
            "frameworks": ["FastAPI"],
            "docker": False,
        },
        "dependencies": {
            "direct": ["requests==2.31.0", "fastapi==0.110.0"],
            "transitive": ["starlette==0.36.0"],
            "package_manager": "pip",
            "lockfile": True,
        },
    }
    ctx.update(overrides)
    return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCycloneDXBasic:
    def test_valid_json_output(self):
        """Formatter produces valid JSON."""
        formatter = CycloneDXFormatter()
        output = formatter.format([_make_finding()], _base_context())
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_implements_output_formatter(self):
        """CycloneDXFormatter must be a subclass of OutputFormatter."""
        assert isinstance(CycloneDXFormatter(), OutputFormatter)

    def test_name_property(self):
        """name property returns 'cyclonedx'."""
        assert CycloneDXFormatter().name == "cyclonedx"


class TestCycloneDXMetadata:
    def test_bom_metadata(self):
        """Top-level BOM fields and metadata are correct."""
        output = CycloneDXFormatter().format([_make_finding()], _base_context())
        sbom = json.loads(output)

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert sbom["version"] == 1
        assert sbom["serialNumber"].startswith("urn:uuid:")

        meta = sbom["metadata"]
        assert "timestamp" in meta
        assert "T" in meta["timestamp"]  # ISO 8601 with time component

        tools = meta["tools"]
        assert len(tools) == 1
        assert tools[0]["vendor"] == "PatchPilot"
        assert tools[0]["name"] == "patchpilot"
        assert "version" in tools[0]

        comp = meta["component"]
        assert comp["type"] == "application"
        assert comp["name"] == "myapp"

    def test_metadata_target_name(self):
        """Metadata component name comes from scan_meta.target."""
        ctx = _base_context()
        ctx["scan_meta"]["target"] = "my-service"
        sbom = json.loads(CycloneDXFormatter().format([], ctx))
        assert sbom["metadata"]["component"]["name"] == "my-service"

    def test_serial_number_unique(self):
        """Each SBOM gets a unique serial number."""
        formatter = CycloneDXFormatter()
        ctx = _base_context()
        sbom1 = json.loads(formatter.format([], ctx))
        sbom2 = json.loads(formatter.format([], ctx))
        assert sbom1["serialNumber"] != sbom2["serialNumber"]


class TestCycloneDXComponents:
    def test_components_from_findings(self):
        """Components are generated from findings with correct purl."""
        findings = [_make_finding(package="cryptography", installed_version="42.0.0")]
        ctx = _base_context()
        ctx["dependencies"]["direct"] = []
        ctx["dependencies"]["transitive"] = []
        sbom = json.loads(CycloneDXFormatter().format(findings, ctx))

        refs = [c["bom-ref"] for c in sbom["components"]]
        assert "cryptography@42.0.0" in refs

        comp = next(c for c in sbom["components"] if c["bom-ref"] == "cryptography@42.0.0")
        assert comp["name"] == "cryptography"
        assert comp["version"] == "42.0.0"
        assert comp["purl"] == "pkg:pypi/cryptography@42.0.0"
        assert comp["type"] == "library"

    def test_components_from_dependencies(self):
        """Components are generated from context dependency lists."""
        ctx = _base_context()
        sbom = json.loads(CycloneDXFormatter().format([], ctx))

        refs = [c["bom-ref"] for c in sbom["components"]]
        assert "requests@2.31.0" in refs
        assert "fastapi@0.110.0" in refs
        assert "starlette@0.36.0" in refs

    def test_component_deduplication(self):
        """Same package in findings and deps results in one component entry."""
        # "requests==2.31.0" is in direct deps; also add a finding for it
        findings = [_make_finding(package="requests", installed_version="2.31.0")]
        ctx = _base_context()
        sbom = json.loads(CycloneDXFormatter().format(findings, ctx))

        refs = [c["bom-ref"] for c in sbom["components"]]
        assert refs.count("requests@2.31.0") == 1

    def test_components_have_purl(self):
        """Every component must have a purl field."""
        sbom = json.loads(CycloneDXFormatter().format([_make_finding()], _base_context()))
        for comp in sbom["components"]:
            assert "purl" in comp, f"Component {comp['bom-ref']} missing purl"


class TestCycloneDXVulnerabilities:
    def test_vulnerabilities(self):
        """CVE findings produce vulnerability entries with correct ratings and affects."""
        findings = [_make_finding(
            id="CVE-2024-12345",
            package="requests",
            installed_version="2.31.0",
            cvss_score=8.1,
            severity="high",
            source_scanner="trivy_fs",
            title="SSRF in requests",
        )]
        ctx = _base_context()
        sbom = json.loads(CycloneDXFormatter().format(findings, ctx))

        assert len(sbom["vulnerabilities"]) == 1
        vuln = sbom["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2024-12345"
        assert vuln["source"]["name"] == "trivy_fs"
        assert vuln["description"] == "SSRF in requests"

        rating = vuln["ratings"][0]
        assert rating["score"] == 8.1
        assert rating["severity"] == "high"
        assert rating["method"] == "CVSSv3"

        assert vuln["affects"][0]["ref"] == "requests@2.31.0"

    def test_non_cve_findings_excluded(self):
        """Findings without CVE IDs do not appear in vulnerabilities."""
        findings = [
            _make_finding(id="CVE-2024-00001"),
            _make_finding(id="GHSA-1234-abcd-5678"),
            _make_finding(id="INTERNAL-SEC-001"),
        ]
        sbom = json.loads(CycloneDXFormatter().format(findings, _base_context()))

        vuln_ids = [v["id"] for v in sbom["vulnerabilities"]]
        assert "CVE-2024-00001" in vuln_ids
        assert "GHSA-1234-abcd-5678" not in vuln_ids
        assert "INTERNAL-SEC-001" not in vuln_ids

    def test_empty_findings(self):
        """Empty findings list still produces a valid SBOM with components from deps."""
        sbom = json.loads(CycloneDXFormatter().format([], _base_context()))

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["vulnerabilities"] == []
        # Should still have components from context dependencies
        assert len(sbom["components"]) > 0


class TestCycloneDXReachabilityMapping:
    def test_reachable_true_maps_to_exploitable(self):
        """reachable='true' → analysis.state = 'exploitable'."""
        f = _make_finding(reachable="true")
        sbom = json.loads(CycloneDXFormatter().format([f], _base_context()))
        vuln = sbom["vulnerabilities"][0]
        assert vuln["analysis"]["state"] == "exploitable"

    def test_reachable_false_maps_to_false_positive(self):
        """reachable='false' → analysis.state = 'false_positive'."""
        f = _make_finding(reachable="false")
        sbom = json.loads(CycloneDXFormatter().format([f], _base_context()))
        vuln = sbom["vulnerabilities"][0]
        assert vuln["analysis"]["state"] == "false_positive"

    def test_reachable_unknown_maps_to_in_triage(self):
        """reachable='unknown' → analysis.state = 'in_triage'."""
        f = _make_finding(reachable="unknown")
        sbom = json.loads(CycloneDXFormatter().format([f], _base_context()))
        vuln = sbom["vulnerabilities"][0]
        assert vuln["analysis"]["state"] == "in_triage"

    def test_reachable_not_applicable_omits_analysis(self):
        """reachable='not_applicable' → no analysis block."""
        f = _make_finding(reachable="not_applicable")
        sbom = json.loads(CycloneDXFormatter().format([f], _base_context()))
        vuln = sbom["vulnerabilities"][0]
        assert "analysis" not in vuln

    def test_reachability_mapping(self):
        """All reachability values map to the correct CycloneDX analysis states."""
        mapping = {
            "true":    "exploitable",
            "false":   "false_positive",
            "unknown": "in_triage",
        }
        for reachable, expected_state in mapping.items():
            f = _make_finding(reachable=reachable)
            sbom = json.loads(CycloneDXFormatter().format([f], _base_context()))
            vuln = sbom["vulnerabilities"][0]
            assert vuln["analysis"]["state"] == expected_state, (
                f"reachable={reachable!r} should map to {expected_state!r}"
            )


class TestCycloneDXPurlGeneration:
    def _format_with_pm(self, pkg_manager, dep="mypkg==1.0.0"):
        ctx = _base_context()
        ctx["dependencies"]["direct"] = [dep]
        ctx["dependencies"]["transitive"] = []
        ctx["dependencies"]["package_manager"] = pkg_manager
        return json.loads(CycloneDXFormatter().format([], ctx))

    def test_purl_pip(self):
        """pip package manager → pkg:pypi/ purl."""
        sbom = self._format_with_pm("pip")
        comp = next(c for c in sbom["components"] if c["name"] == "mypkg")
        assert comp["purl"].startswith("pkg:pypi/")

    def test_purl_npm(self):
        """npm package manager → pkg:npm/ purl."""
        sbom = self._format_with_pm("npm")
        comp = next(c for c in sbom["components"] if c["name"] == "mypkg")
        assert comp["purl"].startswith("pkg:npm/")

    def test_purl_unknown(self):
        """Unknown package manager → pkg:generic/ purl."""
        sbom = self._format_with_pm("unknown")
        comp = next(c for c in sbom["components"] if c["name"] == "mypkg")
        assert comp["purl"].startswith("pkg:generic/")

    def test_purl_go(self):
        """go package manager → pkg:golang/ purl."""
        sbom = self._format_with_pm("go")
        comp = next(c for c in sbom["components"] if c["name"] == "mypkg")
        assert comp["purl"].startswith("pkg:golang/")

    def test_purl_generation(self):
        """purl format includes name@version for versioned packages."""
        ctx = _base_context()
        ctx["dependencies"]["direct"] = ["requests==2.31.0"]
        ctx["dependencies"]["transitive"] = []
        sbom = json.loads(CycloneDXFormatter().format([], ctx))
        comp = next(c for c in sbom["components"] if c["name"] == "requests")
        assert comp["purl"] == "pkg:pypi/requests@2.31.0"
