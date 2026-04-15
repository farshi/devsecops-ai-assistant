"""End-to-end tests that exercise the full triage pipeline with compliance enrichment.

Unlike ``test_compliance_enrichment.py`` (unit tests), these tests drive the
summary → context → triage flow so that regressions in plumbing (serialisation,
scoring, markdown rendering, framework filter) are caught.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent.plugins.scoring.default import (
    DefaultScoringStrategy,
    _compliance_score,
)
from agent.models import Finding
from agent.prioritizer import run_triage


# ---------- scoring signal ----------

class TestComplianceScore:
    def test_no_controls_scores_zero(self):
        f = Finding(id="CVE-1", source_scanner="trivy_fs",
                    finding_type="language_dep", severity="high", title="t")
        assert _compliance_score(f) == 0.0

    def test_one_framework_scores_half(self):
        f = Finding(id="CVE-1", source_scanner="trivy_fs",
                    finding_type="language_dep", severity="high", title="t")
        f.compliance_controls = {"nist_800_53_rev5": ["SC-8"]}
        assert _compliance_score(f) == 0.5

    def test_three_plus_frameworks_saturate_to_one(self):
        f = Finding(id="CVE-1", source_scanner="trivy_fs",
                    finding_type="language_dep", severity="high", title="t")
        f.compliance_controls = {
            "nist_800_53_rev5": ["SC-8"],
            "pci_dss_4_0": ["4.2.1"],
            "cis_controls_v8": ["3.10"],
            "iso_27001_2022": ["A.8.24"],
        }
        assert _compliance_score(f) == 1.0

    def test_empty_framework_lists_are_ignored(self):
        # Dict presence alone should not count — the list must be non-empty
        f = Finding(id="CVE-1", source_scanner="trivy_fs",
                    finding_type="language_dep", severity="high", title="t")
        f.compliance_controls = {"nist_800_53_rev5": [], "pci_dss_4_0": []}
        assert _compliance_score(f) == 0.0

    def test_scorer_ranks_compliance_hit_above_plain_finding(self):
        """Integration: a finding that breaks mappings outranks one that doesn't,
        all other signals being equal."""
        base = dict(source_scanner="trivy_fs", finding_type="language_dep",
                    severity="high", title="t", cvss_score=7.0)
        plain = Finding(id="CVE-2024-PLAIN", **base)
        compliance = Finding(id="CVE-2024-MAPPED", **base)
        compliance.compliance_controls = {
            "nist_800_53_rev5": ["SC-8"],
            "pci_dss_4_0": ["4.2.1"],
        }
        DefaultScoringStrategy().score([plain, compliance])
        assert compliance.priority_score > plain.priority_score


# ---------- end-to-end pipeline ----------

FIXTURE_SUMMARY = {
    "version": "1",
    "target": {"name": "demo", "slug": "demo", "path": "."},
    "scan": {
        "date": "2026-04-15T00:00:00Z",
        "profile": "quick",
        "scanners_requested": ["trivy_fs"],
        "scanners_run": ["trivy_fs"],
        "scanners_skipped": [],
    },
    "severity_counts": {"critical": 2, "high": 1, "medium": 0, "low": 0, "info": 0},
    "top_issues": [],
    "findings": {
        "trivy_fs": [
            {
                "id": "CVE-2021-44228",
                "source_scanner": "trivy_fs",
                "finding_type": "language_dep",
                "severity": "critical",
                "title": "Log4j JNDI RCE (log4shell)",
                "package": "log4j-core",
                "installed_version": "2.14.1",
                "fixed_version": "2.17.0",
                "location": "pom.xml > log4j-core@2.14.1",
                "cvss_score": 10.0,
            },
            {
                "id": "CVE-2023-99999",
                "source_scanner": "trivy_fs",
                "finding_type": "language_dep",
                "severity": "critical",
                "title": "Old cryptography lib in project",
                "package": "cryptography",
                "installed_version": "40.0.0",
                "fixed_version": "41.0.0",
                "location": "requirements.txt > cryptography@40.0.0",
                "cvss_score": 9.0,
            },
            {
                "id": "CVE-2099-99999",
                "source_scanner": "trivy_fs",
                "finding_type": "language_dep",
                "severity": "high",
                "title": "Unrelated finding with no mapping",
                "package": "zzz-unmapped-package",
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
                "location": "requirements.txt > zzz-unmapped-package@1.0.0",
                "cvss_score": 7.0,
            },
        ],
    },
    "risk_summary": "2 critical findings",
    "notes": [],
}


@pytest.fixture
def triage_fixture(tmp_path, monkeypatch):
    """Prepare a working directory + summary file that run_triage can consume.

    Patches out the network-calling enrichers (EPSS / KEV) so the test is
    hermetic. The compliance enricher remains real so we can assert it
    wires correctly through the pipeline.
    """
    project = tmp_path / "demo-project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "cryptography==40.0.0\nzzz-unmapped-package==1.0.0\n"
    )

    summary_path = project / "summary.json"
    summary_path.write_text(json.dumps(FIXTURE_SUMMARY))

    # Neutralise network enrichers — compliance is what we are testing.
    monkeypatch.setattr(
        "agent.plugins.enrichment.epss.EPSSEnrichmentPlugin.enrich",
        lambda self, findings, ctx: findings,
    )
    monkeypatch.setattr(
        "agent.plugins.enrichment.kev.KEVEnrichmentPlugin.enrich",
        lambda self, findings, ctx: findings,
    )
    # Keep reachability deterministic
    monkeypatch.setattr("agent.context_builder.check_reachability",
                        lambda path, findings, structure: None)

    return project, summary_path


class TestTriagePipelineWithCompliance:
    def test_compliance_controls_reach_action_items(self, triage_fixture):
        project, summary_path = triage_fixture
        result = run_triage(str(project), str(summary_path), top_n=5)

        action_items = result["triage"]["action_items"]
        by_id = {item["id"]: item for item in action_items}

        # Log4Shell hit PP-0002
        log4 = by_id.get("CVE-2021-44228")
        assert log4 is not None, "log4shell finding missing from triage output"
        assert "PP-0002" in log4["compliance"]["patterns_matched"]
        assert "SI-2" in log4["compliance"]["controls"]["nist_800_53_rev5"]
        assert "6.3.3" in log4["compliance"]["controls"]["pci_dss_4_0"]

        # Unmapped finding stays unmapped
        unmapped = by_id.get("CVE-2099-99999")
        assert unmapped is not None
        assert unmapped["compliance"]["controls"] == {}

    def test_markdown_renders_compliance_impact_block(self, triage_fixture):
        project, summary_path = triage_fixture
        result = run_triage(str(project), str(summary_path), top_n=5)

        md = result["markdown"]
        assert "Compliance impact:" in md
        assert "NIST 800-53:" in md
        assert "PCI DSS 4.0:" in md

    def test_compliance_findings_outrank_unmapped_peers(self, triage_fixture):
        project, summary_path = triage_fixture
        result = run_triage(str(project), str(summary_path), top_n=5)

        action_items = result["triage"]["action_items"]
        scores_by_id = {item["id"]: item["priority_score"] for item in action_items}

        # Log4Shell (mapped + critical) should outrank the unmapped finding
        # even though both carry high severity.
        assert scores_by_id["CVE-2021-44228"] > scores_by_id["CVE-2099-99999"]

    def test_framework_filter_keeps_only_matching_findings(self, triage_fixture):
        project, summary_path = triage_fixture
        result = run_triage(
            str(project), str(summary_path), top_n=5, framework="pci-dss"
        )
        action_items = result["triage"]["action_items"]
        ids = [item["id"] for item in action_items]
        # Both mapped findings carry PCI; unmapped must be filtered out.
        assert "CVE-2099-99999" not in ids
        # At least one of the mapped findings should survive.
        assert {"CVE-2021-44228", "CVE-2023-99999"}.intersection(ids)

    def test_framework_filter_is_case_insensitive(self, triage_fixture):
        project, summary_path = triage_fixture
        result = run_triage(
            str(project), str(summary_path), top_n=5, framework="PCI-DSS"
        )
        ids = [item["id"] for item in result["triage"]["action_items"]]
        assert "CVE-2099-99999" not in ids
