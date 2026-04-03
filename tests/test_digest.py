"""Tests for agent/digest.py — weekly digest generation."""

import json
import os

import pytest

from agent.digest import (
    generate_digest,
    format_digest_json,
    _load_latest_triage,
    _build_digest_data,
    _format_digest_markdown,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_snapshot(date, total, summary=None, fingerprints=None):
    if summary is None:
        summary = {"critical": 0, "high": total, "medium": 0, "low": 0, "noise": 0}
    return {
        "date": date,
        "total_findings": total,
        "summary": summary,
        "fingerprints": fingerprints or {},
    }


def _make_history(snapshots):
    return {"version": 1, "snapshots": snapshots}


def _make_triage(total=5, action_items=None, summary=None):
    if summary is None:
        summary = {"critical": 0, "high": 2, "medium": 2, "low": 1, "noise": 0}
    if action_items is None:
        action_items = [
            {
                "rank": 1,
                "id": "CVE-2024-0001",
                "priority_tier": "high",
                "action": "Upgrade requests to >= 2.31.0",
                "signals": {"fix_available": True},
            },
            {
                "rank": 2,
                "id": "CVE-2024-0002",
                "priority_tier": "medium",
                "action": "Investigate flask",
                "signals": {"fix_available": False},
            },
        ]
    return {
        "total_findings": total,
        "summary": summary,
        "action_items": action_items,
        "scan_date": "2026-04-03",
        "scanner": "trivy_fs",
    }


def _write_patchpilot_files(tmp_path, history=None, state=None, baseline=None):
    """Write .patchpilot/ files to tmp_path."""
    pp_dir = tmp_path / ".patchpilot"
    pp_dir.mkdir(exist_ok=True)

    if history is not None:
        (pp_dir / "history.json").write_text(json.dumps(history))
    if state is not None:
        (pp_dir / "state.json").write_text(json.dumps(state))
    if baseline is not None:
        (pp_dir / "baseline.json").write_text(json.dumps(baseline))


def _write_triage_file(triage_data, target_slug="test"):
    """Write a triage JSON to reports/."""
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{target_slug}_triage_20260403.json"
    with open(path, "w") as f:
        json.dump(triage_data, f)
    return path


# ---------------------------------------------------------------------------
# generate_digest
# ---------------------------------------------------------------------------

class TestGenerateDigest:
    def test_with_history_and_triage(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        history = _make_history([
            _make_snapshot("2026-04-01", 10, fingerprints={"fp1": {"id": "CVE-A", "package": "p"}}),
            _make_snapshot("2026-04-03", 8, fingerprints={"fp2": {"id": "CVE-B", "package": "q"}}),
        ])
        _write_patchpilot_files(tmp_path, history=history)
        _write_triage_file(_make_triage(), "test")

        result = generate_digest(str(tmp_path), "test")
        assert "markdown" in result
        assert "data" in result
        assert "Weekly Digest" in result["markdown"]

    def test_no_data_returns_error(self, tmp_path):
        result = generate_digest(str(tmp_path), "nonexistent")
        assert "error" in result

    def test_single_snapshot_still_works(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        history = _make_history([_make_snapshot("2026-04-03", 5)])
        _write_patchpilot_files(tmp_path, history=history)

        result = generate_digest(str(tmp_path), "test")
        assert "markdown" in result

    def test_triage_only_no_history(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_triage_file(_make_triage(), "test")

        result = generate_digest(str(tmp_path), "test")
        assert "markdown" in result


# ---------------------------------------------------------------------------
# _build_digest_data
# ---------------------------------------------------------------------------

class TestBuildDigestData:
    def test_basic_structure(self):
        data = _build_digest_data(
            snapshots=[_make_snapshot("2026-04-03", 5)],
            trends={},
            state={"dismissed": {}, "accepted_risks": {}},
            baseline={},
            latest_triage=_make_triage(),
            target_name="myapp",
            days=7,
        )
        assert data["target_name"] == "myapp"
        assert data["total_findings"] == 5
        assert data["period"]["days"] == 7

    def test_dismissed_count(self):
        state = {
            "dismissed": {"fp1": {}, "fp2": {}},
            "accepted_risks": {"fp3": {}},
        }
        data = _build_digest_data(
            snapshots=[],
            trends={},
            state=state,
            baseline={},
            latest_triage=_make_triage(),
            target_name="test",
            days=7,
        )
        assert data["decisions"]["dismissed"] == 2
        assert data["decisions"]["accepted"] == 1

    def test_fix_coverage(self):
        triage = _make_triage()  # 1 fixable, 1 not
        data = _build_digest_data(
            snapshots=[],
            trends={},
            state={"dismissed": {}, "accepted_risks": {}},
            baseline={},
            latest_triage=triage,
            target_name="test",
            days=7,
        )
        assert data["fix_coverage"]["fixable"] == 1

    def test_trends_included(self):
        trends = {
            "total_findings_over_time": [10, 8, 6],
            "total_findings_direction": "decreasing",
            "new_since_last": [{"id": "CVE-NEW", "package": "pkg"}],
            "resolved_since_last": [],
            "mttr_days": 3.5,
            "top_recurring_packages": [],
            "snapshot_count": 3,
        }
        data = _build_digest_data(
            snapshots=[_make_snapshot("2026-04-03", 6)],
            trends=trends,
            state={"dismissed": {}, "accepted_risks": {}},
            baseline={},
            latest_triage=None,
            target_name="test",
            days=7,
        )
        assert data["direction"] == "decreasing"
        assert data["mttr_days"] == 3.5
        assert len(data["new_findings"]) == 1


# ---------------------------------------------------------------------------
# _format_digest_markdown
# ---------------------------------------------------------------------------

class TestFormatDigestMarkdown:
    def _sample_data(self):
        return {
            "target_name": "myapp",
            "period": {"start": "2026-03-27", "end": "2026-04-03", "days": 7},
            "generated_at": "2026-04-03",
            "total_findings": 10,
            "summary": {"critical": 1, "high": 3, "medium": 4, "low": 2},
            "direction": "decreasing",
            "sparkline": "█▆▄▂",
            "snapshot_count": 4,
            "new_findings": [{"id": "CVE-NEW", "package": "requests"}],
            "resolved_findings": [{"id": "CVE-OLD", "package": "flask"}],
            "top_priorities": [
                {"rank": 1, "id": "CVE-2024-0001", "priority_tier": "critical",
                 "action": "Upgrade requests to >= 2.31.0"},
            ],
            "mttr_days": 2.5,
            "fix_coverage": {"fixable": 8, "total": 10},
            "decisions": {"dismissed": 2, "accepted": 1},
            "recurring_packages": [
                {"package": "urllib3", "cve_count": 3, "appearances": 4},
            ],
        }

    def test_contains_title(self):
        md = _format_digest_markdown(self._sample_data())
        assert "# PatchPilot Weekly Digest" in md

    def test_contains_period(self):
        md = _format_digest_markdown(self._sample_data())
        assert "2026-03-27 to 2026-04-03" in md

    def test_contains_status(self):
        md = _format_digest_markdown(self._sample_data())
        assert "10 findings" in md
        assert "decreasing" in md

    def test_contains_new_findings(self):
        md = _format_digest_markdown(self._sample_data())
        assert "CVE-NEW" in md
        assert "### New (1)" in md

    def test_contains_resolved(self):
        md = _format_digest_markdown(self._sample_data())
        assert "CVE-OLD" in md
        assert "### Resolved (1)" in md

    def test_contains_top_priorities(self):
        md = _format_digest_markdown(self._sample_data())
        assert "CVE-2024-0001" in md
        assert "CRITICAL" in md

    def test_contains_mttr(self):
        md = _format_digest_markdown(self._sample_data())
        assert "2.5 days" in md

    def test_contains_fix_coverage(self):
        md = _format_digest_markdown(self._sample_data())
        assert "8/10" in md

    def test_contains_decisions(self):
        md = _format_digest_markdown(self._sample_data())
        assert "2 dismissed" in md
        assert "1 risks accepted" in md

    def test_contains_recurring_packages(self):
        md = _format_digest_markdown(self._sample_data())
        assert "urllib3" in md

    def test_no_changes_message(self):
        data = self._sample_data()
        data["new_findings"] = []
        data["resolved_findings"] = []
        md = _format_digest_markdown(data)
        assert "No changes since last scan" in md

    def test_empty_findings(self):
        data = self._sample_data()
        data["total_findings"] = 0
        data["summary"] = {}
        data["top_priorities"] = []
        data["new_findings"] = []
        data["resolved_findings"] = []
        data["mttr_days"] = None
        data["fix_coverage"] = {"fixable": 0, "total": 0}
        data["decisions"] = {"dismissed": 0, "accepted": 0}
        data["recurring_packages"] = []
        md = _format_digest_markdown(data)
        assert "0 findings" in md


# ---------------------------------------------------------------------------
# format_digest_json
# ---------------------------------------------------------------------------

class TestFormatJson:
    def test_valid_json(self):
        data = {"target_name": "test", "total_findings": 5}
        result = format_digest_json(data)
        parsed = json.loads(result)
        assert parsed["total_findings"] == 5


# ---------------------------------------------------------------------------
# _load_latest_triage
# ---------------------------------------------------------------------------

class TestLoadLatestTriage:
    def test_finds_latest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports")
        for name in ["test_triage_20260401.json", "test_triage_20260403.json"]:
            (tmp_path / "reports" / name).write_text(json.dumps({"date": name}))

        result = _load_latest_triage("test")
        assert result["date"] == "test_triage_20260403.json"

    def test_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _load_latest_triage("nonexistent") is None
