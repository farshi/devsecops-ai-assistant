"""Tests for multi-repo portfolio aggregation."""

import json
import os
import pytest

from agent.portfolio import load_repo_summary, aggregate_repos, format_portfolio_table


def _setup_repo(tmp_path, name, total=10, critical=1, high=3, deadlines=None):
    """Create a fake repo with .patchpilot/ data."""
    repo = tmp_path / name
    repo.mkdir()
    pp = repo / ".patchpilot"
    pp.mkdir()

    # State
    state = {
        "version": 1,
        "dismissed": {"fp1": {"cve": "CVE-D1", "reason": "noise"}},
        "dismissed_cves": {},
        "accepted_risks": {"fp2": {"cve": "CVE-A1", "reason": "mitigated"}},
        "closed": {"fp3": {"cve": "CVE-C1", "reason": "upgraded"}},
        "assignments": {},
        "cra_deadlines": deadlines or {},
    }
    (pp / "state.json").write_text(json.dumps(state))

    # Baseline
    baseline = {"version": 1, "findings": {}, "count": total, "date": "2026-04-04"}
    (pp / "baseline.json").write_text(json.dumps(baseline))

    # History with one snapshot
    history = {
        "version": 1,
        "snapshots": [
            {
                "date": "2026-04-04",
                "total_findings": total,
                "summary": {
                    "critical": critical,
                    "high": high,
                    "medium": total - critical - high,
                    "low": 0,
                    "noise": 0,
                },
                "fingerprints": {},
            }
        ],
    }
    (pp / "history.json").write_text(json.dumps(history))

    return str(repo)


class TestLoadRepoSummary:
    def test_repo_with_data(self, tmp_path):
        repo = _setup_repo(tmp_path, "api", total=15, critical=2, high=5)
        summary = load_repo_summary(repo)
        assert summary["name"] == "api"
        assert summary["has_data"] is True
        assert summary["latest_snapshot"]["total_findings"] == 15
        assert summary["snapshot_count"] == 1

    def test_repo_without_data(self, tmp_path):
        repo = tmp_path / "empty-repo"
        repo.mkdir()
        summary = load_repo_summary(str(repo))
        assert summary["has_data"] is False
        assert summary["latest_snapshot"] is None

    def test_repo_with_deadlines(self, tmp_path):
        deadlines = {
            "fp1": {
                "cve": "CVE-001",
                "severity": "critical",
                "deadline": "2026-04-01",
                "package": "flask",
            },
        }
        repo = _setup_repo(tmp_path, "web", deadlines=deadlines)
        summary = load_repo_summary(repo)
        assert summary["deadline_summary"]["total"] == 1
        assert summary["deadline_summary"]["overdue"] == 1


class TestAggregateRepos:
    def test_multiple_repos(self, tmp_path):
        r1 = _setup_repo(tmp_path, "api", total=10, critical=2, high=3)
        r2 = _setup_repo(tmp_path, "web", total=5, critical=0, high=1)
        agg = aggregate_repos([r1, r2])

        assert agg["totals"]["repos"] == 2
        assert agg["totals"]["repos_with_data"] == 2
        assert agg["totals"]["total_findings"] == 15
        assert agg["totals"]["summary"]["critical"] == 2
        assert agg["totals"]["summary"]["high"] == 4

    def test_mixed_with_empty(self, tmp_path):
        r1 = _setup_repo(tmp_path, "api", total=10)
        r2 = tmp_path / "empty"
        r2.mkdir()
        agg = aggregate_repos([r1, str(r2)])

        assert agg["totals"]["repos"] == 2
        assert agg["totals"]["repos_with_data"] == 1
        assert agg["totals"]["total_findings"] == 10

    def test_aggregates_state_counts(self, tmp_path):
        r1 = _setup_repo(tmp_path, "api")
        r2 = _setup_repo(tmp_path, "web")
        agg = aggregate_repos([r1, r2])

        # Each repo has 1 dismissed, 1 accepted, 1 closed
        assert agg["totals"]["dismissed"] == 2
        assert agg["totals"]["accepted"] == 2
        assert agg["totals"]["closed"] == 2

    def test_aggregates_deadlines(self, tmp_path):
        dl1 = {"fp1": {"cve": "CVE-A", "severity": "high", "deadline": "2026-04-01", "package": "a"}}
        dl2 = {"fp2": {"cve": "CVE-B", "severity": "high", "deadline": "2026-05-01", "package": "b"}}
        r1 = _setup_repo(tmp_path, "api", deadlines=dl1)
        r2 = _setup_repo(tmp_path, "web", deadlines=dl2)
        agg = aggregate_repos([r1, r2])

        assert agg["totals"]["deadlines"]["total"] == 2

    def test_empty_list(self):
        agg = aggregate_repos([])
        assert agg["totals"]["repos"] == 0
        assert agg["totals"]["total_findings"] == 0


class TestFormatPortfolioTable:
    def test_has_header(self, tmp_path):
        r1 = _setup_repo(tmp_path, "api", total=10, critical=2, high=3)
        agg = aggregate_repos([r1])
        output = format_portfolio_table(agg)
        assert "Portfolio:" in output
        assert "api" in output
        assert "10" in output

    def test_shows_no_data_for_empty(self, tmp_path):
        r1 = tmp_path / "empty"
        r1.mkdir()
        agg = aggregate_repos([str(r1)])
        output = format_portfolio_table(agg)
        assert "(no data)" in output

    def test_multiple_repos_formatted(self, tmp_path):
        r1 = _setup_repo(tmp_path, "api", total=10)
        r2 = _setup_repo(tmp_path, "web", total=5)
        agg = aggregate_repos([r1, r2])
        output = format_portfolio_table(agg)
        assert "api" in output
        assert "web" in output
        assert "15" in output  # total
