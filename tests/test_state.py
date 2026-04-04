"""Tests for agent/state.py — PatchPilot state and baseline tracking."""

import json
import os
import pytest

from agent.models import Finding
from agent.state import (
    STATE_DIR,
    STATE_FILE,
    BASELINE_FILE,
    load_state,
    save_state,
    dismiss_finding,
    dismiss_cve,
    accept_risk,
    close_finding,
    close_cve,
    assign_cve,
    unassign_cve,
    get_assignments,
    filter_dismissed,
    save_baseline,
    load_baseline,
    filter_new_only,
    _state_path,
    _baseline_path,
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


# ---------------------------------------------------------------------------
# fingerprint() tests (on Finding)
# ---------------------------------------------------------------------------

def test_fingerprint_stable():
    """Same CVE + package + version always produces same fingerprint."""
    f1 = _make_finding("CVE-2023-12345", "requests", "2.28.0")
    f2 = _make_finding("CVE-2023-12345", "requests", "2.28.0")
    assert f1.fingerprint() == f2.fingerprint()


def test_fingerprint_differs():
    """Different CVE produces different fingerprint."""
    f1 = _make_finding("CVE-2023-11111")
    f2 = _make_finding("CVE-2023-22222")
    assert f1.fingerprint() != f2.fingerprint()


def test_fingerprint_differs_by_package():
    """Same CVE but different package produces different fingerprint."""
    f1 = _make_finding("CVE-2023-12345", package="pkg-a")
    f2 = _make_finding("CVE-2023-12345", package="pkg-b")
    assert f1.fingerprint() != f2.fingerprint()


def test_fingerprint_length():
    """Fingerprint is 16 hex characters."""
    f = _make_finding("CVE-2023-12345")
    assert len(f.fingerprint()) == 16


# ---------------------------------------------------------------------------
# load_state / save_state
# ---------------------------------------------------------------------------

def test_load_state_no_file(tmp_path):
    """No state.json returns default empty state."""
    state = load_state(str(tmp_path))
    assert state["version"] == 1
    assert state["dismissed"] == {}
    assert state["accepted_risks"] == {}
    assert state["dismissed_cves"] == {}


def test_save_and_load_state(tmp_path):
    """Save state, load it back. Verify roundtrip."""
    state = {
        "version": 1,
        "dismissed": {"abc123": {"cve": "CVE-2023-1", "reason": "test"}},
        "dismissed_cves": {},
        "accepted_risks": {},
    }
    path_written = save_state(str(tmp_path), state)
    assert os.path.isfile(path_written)

    loaded = load_state(str(tmp_path))
    assert loaded["dismissed"]["abc123"]["cve"] == "CVE-2023-1"
    assert loaded["version"] == 1


def test_load_state_corrupted_json(tmp_path):
    """Corrupted state.json returns default empty state."""
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir()
    state_file = state_dir / STATE_FILE
    state_file.write_text("this is not json {{{")

    state = load_state(str(tmp_path))
    assert state["dismissed"] == {}
    assert state["accepted_risks"] == {}


# ---------------------------------------------------------------------------
# dismiss_finding
# ---------------------------------------------------------------------------

def test_dismiss_finding(tmp_path):
    """Dismiss a finding. Verify it appears in state."""
    f = _make_finding("CVE-2023-9999", "flask", "2.0.0")
    dismiss_finding(str(tmp_path), f, reason="false positive")

    state = load_state(str(tmp_path))
    fp = f.fingerprint()
    assert fp in state["dismissed"]
    assert state["dismissed"][fp]["cve"] == "CVE-2023-9999"
    assert state["dismissed"][fp]["reason"] == "false positive"
    assert "dismissed_at" in state["dismissed"][fp]


# ---------------------------------------------------------------------------
# filter_dismissed
# ---------------------------------------------------------------------------

def test_filter_dismissed(tmp_path):
    """3 findings, dismiss one. Verify filter returns 2."""
    f1 = _make_finding("CVE-2023-0001")
    f2 = _make_finding("CVE-2023-0002")
    f3 = _make_finding("CVE-2023-0003")

    dismiss_finding(str(tmp_path), f2, reason="won't fix")

    result = filter_dismissed([f1, f2, f3], str(tmp_path))
    assert len(result) == 2
    ids = [f.id for f in result]
    assert "CVE-2023-0001" in ids
    assert "CVE-2023-0003" in ids
    assert "CVE-2023-0002" not in ids


def test_filter_dismissed_no_state(tmp_path):
    """No state file. All findings returned unchanged."""
    f1 = _make_finding("CVE-2023-1111")
    f2 = _make_finding("CVE-2023-2222")

    result = filter_dismissed([f1, f2], str(tmp_path))
    assert len(result) == 2


# ---------------------------------------------------------------------------
# dismiss_cve
# ---------------------------------------------------------------------------

def test_dismiss_cve(tmp_path):
    """Dismiss by CVE ID. Verify filter catches it."""
    f1 = _make_finding("CVE-2023-ABCD", package="requests", version="2.0.0")
    f2 = _make_finding("CVE-2023-EFGH", package="flask", version="2.0.0")

    dismiss_cve(str(tmp_path), "CVE-2023-ABCD", reason="mitigated by WAF")

    state = load_state(str(tmp_path))
    assert "CVE-2023-ABCD" in state["dismissed_cves"]
    assert state["dismissed_cves"]["CVE-2023-ABCD"]["reason"] == "mitigated by WAF"

    result = filter_dismissed([f1, f2], str(tmp_path))
    assert len(result) == 1
    assert result[0].id == "CVE-2023-EFGH"


# ---------------------------------------------------------------------------
# accept_risk
# ---------------------------------------------------------------------------

def test_accept_risk(tmp_path):
    """Accept a finding. Verify it's in accepted_risks and filtered out."""
    f = _make_finding("CVE-2023-RISK", "django", "3.2.0")
    accept_risk(str(tmp_path), f, reason="mitigated by network policy")

    state = load_state(str(tmp_path))
    fp = f.fingerprint()
    assert fp in state["accepted_risks"]
    assert state["accepted_risks"][fp]["cve"] == "CVE-2023-RISK"
    assert state["accepted_risks"][fp]["reason"] == "mitigated by network policy"

    other = _make_finding("CVE-2023-OTHER")
    result = filter_dismissed([f, other], str(tmp_path))
    assert len(result) == 1
    assert result[0].id == "CVE-2023-OTHER"


# ---------------------------------------------------------------------------
# save_baseline / load_baseline
# ---------------------------------------------------------------------------

def test_save_and_load_baseline(tmp_path):
    """Save baseline, load it. Verify roundtrip."""
    findings = [
        _make_finding("CVE-2023-A"),
        _make_finding("CVE-2023-B"),
        _make_finding("CVE-2023-C"),
    ]
    path_written = save_baseline(str(tmp_path), findings)
    assert os.path.isfile(path_written)

    baseline = load_baseline(str(tmp_path))
    assert baseline["version"] == 1
    assert baseline["count"] == 3
    assert len(baseline["findings"]) == 3

    fps = set(f.fingerprint() for f in findings)
    assert set(baseline["findings"].keys()) == fps


def test_load_baseline_no_file(tmp_path):
    """No baseline.json returns empty baseline."""
    baseline = load_baseline(str(tmp_path))
    assert baseline["findings"] == {}
    assert baseline["count"] == 0


def test_load_baseline_corrupted(tmp_path):
    """Corrupted baseline.json returns empty baseline."""
    baseline_dir = tmp_path / STATE_DIR
    baseline_dir.mkdir()
    baseline_file = baseline_dir / BASELINE_FILE
    baseline_file.write_text("not valid json <<<")

    baseline = load_baseline(str(tmp_path))
    assert baseline["findings"] == {}


# ---------------------------------------------------------------------------
# filter_new_only
# ---------------------------------------------------------------------------

def test_filter_new_only(tmp_path):
    """Save baseline with 3 findings. Add 1 new finding. Filter returns only the new one."""
    existing = [
        _make_finding("CVE-2023-OLD-1"),
        _make_finding("CVE-2023-OLD-2"),
        _make_finding("CVE-2023-OLD-3"),
    ]
    save_baseline(str(tmp_path), existing)

    new_finding = _make_finding("CVE-2024-NEW-1")
    all_findings = existing + [new_finding]

    result = filter_new_only(all_findings, str(tmp_path))
    assert len(result) == 1
    assert result[0].id == "CVE-2024-NEW-1"


def test_filter_new_only_no_baseline(tmp_path):
    """No baseline exists. All findings returned (everything is new)."""
    findings = [
        _make_finding("CVE-2023-A"),
        _make_finding("CVE-2023-B"),
    ]
    result = filter_new_only(findings, str(tmp_path))
    assert len(result) == 2


def test_filter_new_only_all_in_baseline(tmp_path):
    """All findings are in baseline. Returns empty list."""
    findings = [
        _make_finding("CVE-2023-A"),
        _make_finding("CVE-2023-B"),
    ]
    save_baseline(str(tmp_path), findings)

    result = filter_new_only(findings, str(tmp_path))
    assert result == []


# ---------------------------------------------------------------------------
# File path / directory structure tests
# ---------------------------------------------------------------------------

def test_state_file_created_in_patchpilot_dir(tmp_path):
    """Verify state.json goes to .patchpilot/ directory."""
    f = _make_finding("CVE-2023-DIR-TEST")
    dismiss_finding(str(tmp_path), f)

    expected_dir = tmp_path / STATE_DIR
    expected_file = expected_dir / STATE_FILE
    assert expected_dir.is_dir()
    assert expected_file.is_file()


def test_baseline_file_created_in_patchpilot_dir(tmp_path):
    """Verify baseline.json goes to .patchpilot/ directory."""
    findings = [_make_finding("CVE-2023-BASELINE-DIR")]
    save_baseline(str(tmp_path), findings)

    expected_dir = tmp_path / STATE_DIR
    expected_file = expected_dir / BASELINE_FILE
    assert expected_dir.is_dir()
    assert expected_file.is_file()


def test_state_path_helper(tmp_path):
    """_state_path returns path inside .patchpilot/."""
    p = _state_path(str(tmp_path))
    assert p == str(tmp_path / STATE_DIR / STATE_FILE)


def test_baseline_path_helper(tmp_path):
    """_baseline_path returns path inside .patchpilot/."""
    p = _baseline_path(str(tmp_path))
    assert p == str(tmp_path / STATE_DIR / BASELINE_FILE)


# ---------------------------------------------------------------------------
# close_finding / close_cve
# ---------------------------------------------------------------------------


def test_close_finding(tmp_path):
    """close_finding stores fingerprint in closed section."""
    f = _make_finding("CVE-2023-CLOSE", "flask", "2.0.0")
    close_finding(str(tmp_path), f, reason="upgraded to 2.1.0")
    state = load_state(str(tmp_path))
    fp = f.fingerprint()
    assert fp in state["closed"]
    assert state["closed"][fp]["cve"] == "CVE-2023-CLOSE"
    assert state["closed"][fp]["package"] == "flask"
    assert state["closed"][fp]["reason"] == "upgraded to 2.1.0"
    assert "closed_at" in state["closed"][fp]


def test_close_cve(tmp_path):
    """close_cve stores CVE ID in closed section."""
    close_cve(str(tmp_path), "CVE-2023-CLOSE-CVE", reason="patched")
    state = load_state(str(tmp_path))
    assert "CVE-2023-CLOSE-CVE" in state["closed"]
    assert state["closed"]["CVE-2023-CLOSE-CVE"]["reason"] == "patched"
    assert "closed_at" in state["closed"]["CVE-2023-CLOSE-CVE"]


def test_filter_dismissed_includes_closed(tmp_path):
    """Closed findings are filtered from triage results."""
    f1 = _make_finding("CVE-2023-OPEN")
    f2 = _make_finding("CVE-2023-CLOSED", "flask", "2.0.0")
    close_finding(str(tmp_path), f2, reason="fixed")
    result = filter_dismissed([f1, f2], str(tmp_path))
    assert len(result) == 1
    assert result[0].id == "CVE-2023-OPEN"


def test_filter_dismissed_includes_closed_cve(tmp_path):
    """Closed CVEs (by ID) are filtered from triage results."""
    f1 = _make_finding("CVE-2023-OPEN")
    f2 = _make_finding("CVE-2023-CLOSED-BY-CVE")
    close_cve(str(tmp_path), "CVE-2023-CLOSED-BY-CVE", reason="fixed")
    result = filter_dismissed([f1, f2], str(tmp_path))
    assert len(result) == 1
    assert result[0].id == "CVE-2023-OPEN"


def test_load_state_backward_compat_no_closed_key(tmp_path):
    """Old state files without 'closed' key get it added on load."""
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir()
    old_state = {"version": 1, "dismissed": {}, "dismissed_cves": {}, "accepted_risks": {}}
    with open(state_dir / STATE_FILE, "w") as f:
        json.dump(old_state, f)
    state = load_state(str(tmp_path))
    assert "closed" in state
    assert state["closed"] == {}
    assert "assignments" in state
    assert state["assignments"] == {}


# ---------------------------------------------------------------------------
# assign_cve / unassign_cve / get_assignments
# ---------------------------------------------------------------------------


def test_assign_cve(tmp_path):
    """assign_cve stores CVE assignment in state."""
    assign_cve(str(tmp_path), "CVE-2023-ASSIGN", "alice@co.com", reason="owns auth")
    state = load_state(str(tmp_path))
    assert "CVE-2023-ASSIGN" in state["assignments"]
    entry = state["assignments"]["CVE-2023-ASSIGN"]
    assert entry["assigned_to"] == "alice@co.com"
    assert entry["reason"] == "owns auth"
    assert "assigned_at" in entry


def test_assign_cve_overwrite(tmp_path):
    """Reassigning a CVE updates the assignment."""
    assign_cve(str(tmp_path), "CVE-2023-REASSIGN", "alice@co.com")
    assign_cve(str(tmp_path), "CVE-2023-REASSIGN", "bob@co.com", reason="transferred")
    state = load_state(str(tmp_path))
    assert state["assignments"]["CVE-2023-REASSIGN"]["assigned_to"] == "bob@co.com"
    assert state["assignments"]["CVE-2023-REASSIGN"]["reason"] == "transferred"


def test_unassign_cve(tmp_path):
    """unassign_cve removes the assignment."""
    assign_cve(str(tmp_path), "CVE-2023-UNASSIGN", "alice@co.com")
    unassign_cve(str(tmp_path), "CVE-2023-UNASSIGN")
    state = load_state(str(tmp_path))
    assert "CVE-2023-UNASSIGN" not in state["assignments"]


def test_unassign_cve_nonexistent(tmp_path):
    """unassign_cve on missing CVE is a no-op."""
    unassign_cve(str(tmp_path), "CVE-2023-GHOST")
    state = load_state(str(tmp_path))
    assert "CVE-2023-GHOST" not in state["assignments"]


def test_get_assignments(tmp_path):
    """get_assignments returns all assignments."""
    assign_cve(str(tmp_path), "CVE-2023-A", "alice@co.com")
    assign_cve(str(tmp_path), "CVE-2023-B", "bob@co.com")
    assignments = get_assignments(str(tmp_path))
    assert len(assignments) == 2
    assert assignments["CVE-2023-A"]["assigned_to"] == "alice@co.com"
    assert assignments["CVE-2023-B"]["assigned_to"] == "bob@co.com"


def test_get_assignments_empty(tmp_path):
    """get_assignments returns empty dict when none exist."""
    assert get_assignments(str(tmp_path)) == {}
