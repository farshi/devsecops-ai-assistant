"""Tests for agent/trends.py — historical trend tracking."""

import json
import os

import pytest

from agent.models import Finding
from agent.trends import (
    HISTORY_FILE,
    STATE_DIR,
    _history_path,
    load_history,
    append_snapshot,
    compute_trends,
    sparkline,
    format_trend_report_markdown,
    format_trend_report_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(cve_id, package="test-pkg", version="1.0.0"):
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title=f"Test {cve_id}",
        package=package,
        installed_version=version,
    )


def _make_triage_data(total, summary=None):
    if summary is None:
        summary = {"critical": 0, "high": total, "medium": 0, "low": 0, "noise": 0}
    return {"total_findings": total, "summary": summary}


def _make_history(snapshots):
    return {"version": 1, "snapshots": snapshots}


def _make_snapshot(date, total, summary, fingerprints):
    return {
        "date": date,
        "total_findings": total,
        "summary": summary,
        "fingerprints": fingerprints,
    }


# ---------------------------------------------------------------------------
# load_history
# ---------------------------------------------------------------------------

class TestLoadHistory:
    def test_no_file(self, tmp_path):
        result = load_history(str(tmp_path))
        assert result == {"version": 1, "snapshots": []}

    def test_corrupted_json(self, tmp_path):
        os.makedirs(tmp_path / STATE_DIR)
        (tmp_path / STATE_DIR / HISTORY_FILE).write_text("not json{{{")
        result = load_history(str(tmp_path))
        assert result == {"version": 1, "snapshots": []}

    def test_valid_file(self, tmp_path):
        os.makedirs(tmp_path / STATE_DIR)
        data = {"version": 1, "snapshots": [{"date": "2026-04-01"}]}
        (tmp_path / STATE_DIR / HISTORY_FILE).write_text(json.dumps(data))
        result = load_history(str(tmp_path))
        assert len(result["snapshots"]) == 1


# ---------------------------------------------------------------------------
# append_snapshot
# ---------------------------------------------------------------------------

class TestAppendSnapshot:
    def test_creates_file(self, tmp_path):
        findings = [_make_finding("CVE-2024-0001", "requests")]
        triage = _make_triage_data(1)
        append_snapshot(str(tmp_path), triage, findings)

        path = tmp_path / STATE_DIR / HISTORY_FILE
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data["snapshots"]) == 1
        assert data["snapshots"][0]["total_findings"] == 1

    def test_appends_to_existing(self, tmp_path):
        findings = [_make_finding("CVE-2024-0001")]
        triage = _make_triage_data(1)
        append_snapshot(str(tmp_path), triage, findings)
        append_snapshot(str(tmp_path), triage, findings)

        data = json.loads((tmp_path / STATE_DIR / HISTORY_FILE).read_text())
        assert len(data["snapshots"]) == 2

    def test_preserves_existing_snapshots(self, tmp_path):
        os.makedirs(tmp_path / STATE_DIR)
        existing = _make_history([_make_snapshot("2026-03-01", 5, {}, {})])
        (tmp_path / STATE_DIR / HISTORY_FILE).write_text(json.dumps(existing))

        findings = [_make_finding("CVE-2024-0001")]
        append_snapshot(str(tmp_path), _make_triage_data(1), findings)

        data = json.loads((tmp_path / STATE_DIR / HISTORY_FILE).read_text())
        assert len(data["snapshots"]) == 2
        assert data["snapshots"][0]["date"] == "2026-03-01"

    def test_fingerprints_stored(self, tmp_path):
        f1 = _make_finding("CVE-2024-0001", "requests")
        f2 = _make_finding("CVE-2024-0002", "flask")
        append_snapshot(str(tmp_path), _make_triage_data(2), [f1, f2])

        data = json.loads((tmp_path / STATE_DIR / HISTORY_FILE).read_text())
        fps = data["snapshots"][0]["fingerprints"]
        assert len(fps) == 2
        # Check that fingerprint values contain CVE and package
        values = list(fps.values())
        ids = {v["id"] for v in values}
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0002" in ids

    def test_history_file_location(self, tmp_path):
        append_snapshot(str(tmp_path), _make_triage_data(0), [])
        assert (tmp_path / ".patchpilot" / "history.json").exists()


# ---------------------------------------------------------------------------
# compute_trends
# ---------------------------------------------------------------------------

class TestComputeTrends:
    def test_empty_history(self):
        result = compute_trends({"version": 1, "snapshots": []})
        assert result == {}

    def test_two_snapshots_basic(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 10,
                           {"critical": 1, "high": 3, "medium": 4, "low": 1, "noise": 1},
                           {"fp1": {"id": "CVE-A", "package": "pkg1"}}),
            _make_snapshot("2026-04-02", 8,
                           {"critical": 0, "high": 2, "medium": 4, "low": 1, "noise": 1},
                           {"fp2": {"id": "CVE-B", "package": "pkg2"}}),
        ])
        trends = compute_trends(history)
        assert trends["snapshot_count"] == 2
        assert trends["date_range"] == {"first": "2026-04-01", "last": "2026-04-02"}
        assert trends["total_findings_over_time"] == [10, 8]

    def test_direction_decreasing(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 20, {}, {}),
            _make_snapshot("2026-04-02", 10, {}, {}),
        ])
        assert compute_trends(history)["total_findings_direction"] == "decreasing"

    def test_direction_increasing(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 10, {}, {}),
            _make_snapshot("2026-04-02", 20, {}, {}),
        ])
        assert compute_trends(history)["total_findings_direction"] == "increasing"

    def test_direction_stable(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 10, {}, {}),
            _make_snapshot("2026-04-02", 10, {}, {}),
        ])
        assert compute_trends(history)["total_findings_direction"] == "stable"

    def test_direction_stable_within_threshold(self):
        """10% change threshold — 10 to 11 is stable."""
        history = _make_history([
            _make_snapshot("2026-04-01", 10, {}, {}),
            _make_snapshot("2026-04-02", 11, {}, {}),
        ])
        assert compute_trends(history)["total_findings_direction"] == "stable"

    def test_new_findings(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p1"}}),
            _make_snapshot("2026-04-02", 2, {},
                           {"fp1": {"id": "CVE-A", "package": "p1"},
                            "fp2": {"id": "CVE-B", "package": "p2"}}),
        ])
        trends = compute_trends(history)
        assert len(trends["new_since_last"]) == 1
        assert trends["new_since_last"][0]["id"] == "CVE-B"

    def test_resolved_findings(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 2, {},
                           {"fp1": {"id": "CVE-A", "package": "p1"},
                            "fp2": {"id": "CVE-B", "package": "p2"}}),
            _make_snapshot("2026-04-02", 1, {},
                           {"fp2": {"id": "CVE-B", "package": "p2"}}),
        ])
        trends = compute_trends(history)
        assert len(trends["resolved_since_last"]) == 1
        assert trends["resolved_since_last"][0]["id"] == "CVE-A"

    def test_mttr_calculation(self):
        """Finding appears on day 1, disappears by day 4 → 1 day MTTR (last seen day 2)."""
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-02", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-03", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-04", 0, {}, {}),
        ])
        trends = compute_trends(history)
        # first seen 04-01, last seen 04-03 → 2 days
        assert trends["mttr_days"] == 2.0

    def test_mttr_no_resolved(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-02", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
        ])
        assert compute_trends(history)["mttr_days"] is None

    def test_top_recurring_packages(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 3, {}, {
                "fp1": {"id": "CVE-A", "package": "flask"},
                "fp2": {"id": "CVE-B", "package": "flask"},
                "fp3": {"id": "CVE-C", "package": "requests"},
            }),
            _make_snapshot("2026-04-02", 2, {}, {
                "fp1": {"id": "CVE-A", "package": "flask"},
                "fp4": {"id": "CVE-D", "package": "django"},
            }),
        ])
        trends = compute_trends(history)
        recurring = trends["top_recurring_packages"]
        assert recurring[0]["package"] == "flask"
        assert recurring[0]["cve_count"] == 2  # CVE-A and CVE-B
        assert recurring[0]["appearances"] == 2  # present in both snapshots

    def test_single_snapshot(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 5, {"critical": 1}, {"fp1": {"id": "CVE-A", "package": "p"}}),
        ])
        trends = compute_trends(history)
        assert trends["snapshot_count"] == 1
        assert trends["new_since_last"] == []
        assert trends["resolved_since_last"] == []

    def test_tier_directions(self):
        history = _make_history([
            _make_snapshot("2026-04-01", 10,
                           {"critical": 5, "high": 3, "medium": 2, "low": 0, "noise": 0}, {}),
            _make_snapshot("2026-04-02", 10,
                           {"critical": 0, "high": 3, "medium": 5, "low": 2, "noise": 0}, {}),
        ])
        trends = compute_trends(history)
        assert trends["tier_directions"]["critical"] == "decreasing"
        assert trends["tier_directions"]["high"] == "stable"
        assert trends["tier_directions"]["medium"] == "increasing"

    def test_regression_detected(self):
        """Finding appears, disappears, reappears → regression."""
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-02", 0, {}, {}),  # resolved
            _make_snapshot("2026-04-03", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),  # back
        ])
        trends = compute_trends(history)
        assert len(trends["regressions"]) == 1
        assert trends["regressions"][0]["id"] == "CVE-A"

    def test_no_regression_for_continuous(self):
        """Finding present in all snapshots is not a regression."""
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-02", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-03", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
        ])
        trends = compute_trends(history)
        assert len(trends["regressions"]) == 0

    def test_no_regression_for_new(self):
        """Finding that only appears in latest is new, not a regression."""
        history = _make_history([
            _make_snapshot("2026-04-01", 0, {}, {}),
            _make_snapshot("2026-04-02", 0, {}, {}),
            _make_snapshot("2026-04-03", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
        ])
        trends = compute_trends(history)
        assert len(trends["regressions"]) == 0

    def test_regression_needs_three_snapshots(self):
        """Cannot detect regressions with fewer than 3 snapshots."""
        history = _make_history([
            _make_snapshot("2026-04-01", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-02", 1, {}, {"fp1": {"id": "CVE-A", "package": "p"}}),
        ])
        trends = compute_trends(history)
        assert trends["regressions"] == []


# ---------------------------------------------------------------------------
# sparkline
# ---------------------------------------------------------------------------

class TestSparkline:
    def test_ascending(self):
        result = sparkline([0, 5, 10])
        assert len(result) == 3
        assert result[0] < result[-1]  # first char should be "less" than last

    def test_all_same(self):
        result = sparkline([5, 5, 5])
        assert len(result) == 3
        assert result[0] == result[1] == result[2]

    def test_empty(self):
        assert sparkline([]) == ""

    def test_single_value(self):
        result = sparkline([10])
        assert len(result) == 1


# ---------------------------------------------------------------------------
# format_trend_report_markdown
# ---------------------------------------------------------------------------

class TestFormatMarkdown:
    def _sample_trends(self):
        return {
            "snapshot_count": 3,
            "date_range": {"first": "2026-04-01", "last": "2026-04-03"},
            "dates": ["2026-04-01", "2026-04-02", "2026-04-03"],
            "total_findings_over_time": [10, 8, 6],
            "total_findings_direction": "decreasing",
            "tier_breakdown_over_time": {
                "critical": [2, 1, 0],
                "high": [3, 3, 2],
                "medium": [3, 2, 2],
                "low": [1, 1, 1],
                "noise": [1, 1, 1],
            },
            "tier_directions": {
                "critical": "decreasing",
                "high": "decreasing",
                "medium": "stable",
                "low": "stable",
                "noise": "stable",
            },
            "new_since_last": [{"id": "CVE-NEW", "package": "newpkg"}],
            "resolved_since_last": [{"id": "CVE-OLD", "package": "oldpkg"}],
            "mttr_days": 2.5,
            "top_recurring_packages": [
                {"package": "flask", "cve_count": 3, "appearances": 3, "cves": []},
            ],
        }

    def test_contains_title(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "# PatchPilot Trend Report" in md

    def test_contains_period(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "2026-04-01 to 2026-04-03" in md

    def test_contains_tier_table(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "Critical" in md
        assert "decreasing" in md

    def test_contains_new_and_resolved(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "CVE-NEW" in md
        assert "CVE-OLD" in md
        assert "### New (1)" in md
        assert "### Resolved (1)" in md

    def test_contains_mttr(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "2.5 days" in md

    def test_contains_recurring_packages(self):
        md = format_trend_report_markdown(self._sample_trends())
        assert "flask" in md

    def test_empty_trends(self):
        assert format_trend_report_markdown({}) == "No trend data available."


# ---------------------------------------------------------------------------
# format_trend_report_json
# ---------------------------------------------------------------------------

class TestFormatJson:
    def test_valid_json(self):
        trends = {"snapshot_count": 2, "dates": ["2026-04-01", "2026-04-02"]}
        result = format_trend_report_json(trends)
        parsed = json.loads(result)
        assert parsed["snapshot_count"] == 2
