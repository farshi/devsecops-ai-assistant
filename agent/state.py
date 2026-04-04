"""PatchPilot state management — tracks triage decisions across scans."""

import json
import os
from datetime import datetime
from agent.models import Finding


STATE_DIR = ".patchpilot"
STATE_FILE = "state.json"
BASELINE_FILE = "baseline.json"


def _state_path(project_path: str) -> str:
    return os.path.join(project_path, STATE_DIR, STATE_FILE)


def _baseline_path(project_path: str) -> str:
    return os.path.join(project_path, STATE_DIR, BASELINE_FILE)


def load_state(project_path: str) -> dict:
    """Load triage state from .patchpilot/state.json.

    Returns:
        {
            "version": 1,
            "dismissed": {
                "<fingerprint>": {
                    "cve": "CVE-xxx",
                    "reason": "accepted risk",
                    "dismissed_at": "2026-03-31",
                }
            },
            "dismissed_cves": {
                "CVE-yyy": {
                    "reason": "mitigated by WAF",
                    "dismissed_at": "2026-03-31"
                }
            },
            "accepted_risks": {
                "<fingerprint>": {
                    "cve": "CVE-yyy",
                    "reason": "mitigated by WAF",
                    "accepted_at": "2026-03-31"
                }
            }
        }
    """
    path = _state_path(project_path)
    if not os.path.isfile(path):
        return {"version": 1, "dismissed": {}, "dismissed_cves": {}, "accepted_risks": {}, "closed": {}, "assignments": {}}

    try:
        with open(path) as f:
            state = json.load(f)
        # Ensure dismissed_cves key exists in older state files
        if "dismissed_cves" not in state:
            state["dismissed_cves"] = {}
        if "closed" not in state:
            state["closed"] = {}
        if "assignments" not in state:
            state["assignments"] = {}
        return state
    except (json.JSONDecodeError, OSError):
        return {"version": 1, "dismissed": {}, "dismissed_cves": {}, "accepted_risks": {}, "closed": {}, "assignments": {}}


def save_state(project_path: str, state: dict) -> str:
    """Save triage state to .patchpilot/state.json.

    Returns path of written file.
    """
    os.makedirs(os.path.join(project_path, STATE_DIR), exist_ok=True)
    path = _state_path(project_path)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    return path


def dismiss_finding(project_path: str, finding: Finding, reason: str = "") -> None:
    """Dismiss a finding so it won't appear in future triage."""
    state = load_state(project_path)
    fp = finding.fingerprint()
    state["dismissed"][fp] = {
        "cve": finding.id,
        "package": finding.package,
        "reason": reason,
        "dismissed_at": datetime.now().isoformat()[:10],
    }
    save_state(project_path, state)


def dismiss_cve(project_path: str, cve_id: str, reason: str = "") -> None:
    """Dismiss a CVE by ID (CLI convenience — doesn't need Finding object)."""
    state = load_state(project_path)
    if "dismissed_cves" not in state:
        state["dismissed_cves"] = {}
    state["dismissed_cves"][cve_id] = {
        "reason": reason,
        "dismissed_at": datetime.now().isoformat()[:10],
    }
    save_state(project_path, state)


def accept_risk(project_path: str, finding: Finding, reason: str = "") -> None:
    """Accept a finding as known risk — tracked but not re-alerted."""
    state = load_state(project_path)
    fp = finding.fingerprint()
    state["accepted_risks"][fp] = {
        "cve": finding.id,
        "package": finding.package,
        "reason": reason,
        "accepted_at": datetime.now().isoformat()[:10],
    }
    save_state(project_path, state)


def close_finding(project_path: str, finding: Finding, reason: str = "") -> None:
    """Mark a finding as resolved/remediated."""
    state = load_state(project_path)
    fp = finding.fingerprint()
    state["closed"][fp] = {
        "cve": finding.id,
        "package": finding.package,
        "reason": reason,
        "closed_at": datetime.now().isoformat()[:10],
    }
    save_state(project_path, state)


def close_cve(project_path: str, cve_id: str, reason: str = "") -> None:
    """Mark a CVE as resolved by ID (CLI convenience — doesn't need Finding object)."""
    state = load_state(project_path)
    state["closed"][cve_id] = {
        "reason": reason,
        "closed_at": datetime.now().isoformat()[:10],
    }
    save_state(project_path, state)


def assign_cve(project_path: str, cve_id: str, assigned_to: str, reason: str = "") -> None:
    """Assign a CVE to a person or team for remediation tracking."""
    state = load_state(project_path)
    state["assignments"][cve_id] = {
        "assigned_to": assigned_to,
        "assigned_at": datetime.now().isoformat()[:10],
        "reason": reason,
    }
    save_state(project_path, state)


def unassign_cve(project_path: str, cve_id: str) -> None:
    """Remove assignment for a CVE."""
    state = load_state(project_path)
    state["assignments"].pop(cve_id, None)
    save_state(project_path, state)


def get_assignments(project_path: str) -> dict:
    """Return all CVE assignments from state."""
    state = load_state(project_path)
    return state.get("assignments", {})


def filter_dismissed(findings: list, project_path: str) -> list:
    """Remove dismissed and accepted-risk findings.

    Checks both fingerprint-based dismissals and CVE ID-based dismissals.
    Returns filtered list of findings that are NOT dismissed/accepted.
    """
    state = load_state(project_path)
    dismissed_fps = set(state.get("dismissed", {}).keys())
    accepted_fps = set(state.get("accepted_risks", {}).keys())
    closed_fps = set(state.get("closed", {}).keys())
    dismissed_cves = set(state.get("dismissed_cves", {}).keys())
    # closed section: keys are fingerprints (from close_finding) or CVE IDs
    # (from close_cve). Collect CVE IDs from both key and value.
    closed_cves = set()
    for key, val in state.get("closed", {}).items():
        if "cve" in val:
            closed_cves.add(val["cve"])
        elif key.startswith("CVE-") or key.startswith("GHSA-"):
            # close_cve uses CVE/advisory ID as key directly
            closed_cves.add(key)
    suppressed_fps = dismissed_fps | accepted_fps | closed_fps
    suppressed_cves = dismissed_cves | closed_cves

    if not suppressed_fps and not suppressed_cves:
        return findings

    return [
        f for f in findings
        if f.fingerprint() not in suppressed_fps and f.id not in suppressed_cves
    ]


def save_baseline(project_path: str, findings: list) -> str:
    """Save current findings as baseline for future comparison.

    Returns path of written baseline file.
    """
    os.makedirs(os.path.join(project_path, STATE_DIR), exist_ok=True)
    path = _baseline_path(project_path)

    baseline = {
        "version": 1,
        "date": datetime.now().isoformat()[:10],
        "findings": {f.fingerprint(): f.id for f in findings},
        "count": len(findings),
    }

    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    return path


def load_baseline(project_path: str) -> dict:
    """Load baseline from .patchpilot/baseline.json."""
    path = _baseline_path(project_path)
    if not os.path.isfile(path):
        return {"version": 1, "findings": {}, "count": 0}

    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"version": 1, "findings": {}, "count": 0}


def filter_new_only(findings: list, project_path: str) -> list:
    """Return only findings that are NEW since last baseline.

    A finding is "new" if its fingerprint is not in the baseline.
    """
    baseline = load_baseline(project_path)
    baseline_fps = set(baseline.get("findings", {}).keys())

    if not baseline_fps:
        return findings  # No baseline = everything is new

    return [f for f in findings if f.fingerprint() not in baseline_fps]
