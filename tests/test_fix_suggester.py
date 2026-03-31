"""Tests for agent/fix_suggester.py — fix suggestion engine."""

import pytest

from agent.models import Finding
from agent.fix_suggester import generate_fix_suggestions, _suggest_for_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    cve_id="CVE-2024-0001",
    package="werkzeug",
    installed_version="2.0.0",
    fixed_version="3.0.3",
    fix_available=True,
    fix_evidence=None,
    reachable="unknown",
    reachability_evidence=None,
    in_kev=False,
    epss_score=None,
    **kwargs,
):
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title=f"Vuln in {package}",
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        fix_available=fix_available,
        fix_evidence=fix_evidence,
        reachable=reachable,
        reachability_evidence=reachability_evidence,
        in_kev=in_kev,
        epss_score=epss_score,
        **kwargs,
    )


def _make_context(package_manager="pip"):
    return {
        "dependencies": {
            "package_manager": package_manager,
            "direct": [],
            "transitive": [],
            "lockfile_exists": False,
        }
    }


# ---------------------------------------------------------------------------
# 1. Finding with fix available — basic upgrade suggestion
# ---------------------------------------------------------------------------

def test_suggestion_with_fix_available():
    finding = _make_finding(fix_available=True, fixed_version="2.0.0")
    ctx = _make_context("pip")
    results = generate_fix_suggestions([finding], ctx)

    assert len(results) == 1
    s = results[0]
    assert s["suggestion_type"] == "upgrade"
    assert "pip install" in s["command"]
    assert s["confidence"] in ("high", "medium", "low")
    assert s["id"] == finding.id


# ---------------------------------------------------------------------------
# 2. No fix available — investigate suggestion
# ---------------------------------------------------------------------------

def test_suggestion_no_fix():
    finding = _make_finding(fix_available=False, fixed_version=None)
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    assert len(results) == 1
    s = results[0]
    assert s["suggestion_type"] == "investigate"
    assert s["command"] is None
    caveat_text = " ".join(s["caveats"]).lower()
    assert "no patched version" in caveat_text


# ---------------------------------------------------------------------------
# 3. Patch bump → high confidence, no breaking change risk
# ---------------------------------------------------------------------------

def test_suggestion_patch_bump_high_confidence():
    finding = _make_finding(
        installed_version="1.2.3",
        fixed_version="1.2.4",
        fix_available=True,
        fix_evidence="Upgrade pkg from 1.2.3 to >= 1.2.4 | patch version bump | effort: trivial",
    )
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert s["confidence"] == "high"
    assert s["breaking_change_risk"] == "none"


# ---------------------------------------------------------------------------
# 4. Major bump → low confidence, high breaking change risk, caveats mention "breaking"
# ---------------------------------------------------------------------------

def test_suggestion_major_bump_low_confidence():
    finding = _make_finding(
        installed_version="2.0.0",
        fixed_version="3.0.3",
        fix_available=True,
        fix_evidence="Upgrade werkzeug from 2.0.0 to >= 3.0.3 | major version bump | effort: complex",
    )
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert s["confidence"] == "low"
    assert s["breaking_change_risk"] == "high"
    caveat_text = " ".join(s["caveats"]).lower()
    assert "breaking" in caveat_text


# ---------------------------------------------------------------------------
# 5. npm package manager
# ---------------------------------------------------------------------------

def test_suggestion_npm_command():
    finding = _make_finding(package="express", installed_version="4.0.0", fixed_version="4.18.2")
    ctx = _make_context("npm")
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert s["command"].startswith("npm install")


# ---------------------------------------------------------------------------
# 6. go package manager
# ---------------------------------------------------------------------------

def test_suggestion_go_command():
    finding = _make_finding(
        package="github.com/gin-gonic/gin",
        installed_version="1.9.0",
        fixed_version="1.9.1",
    )
    ctx = _make_context("go")
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert s["command"].startswith("go get")


# ---------------------------------------------------------------------------
# 7. KEV finding — caveats mention KEV
# ---------------------------------------------------------------------------

def test_suggestion_kev_caveat():
    finding = _make_finding(in_kev=True)
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    caveat_text = " ".join(s["caveats"]).lower()
    assert "kev" in caveat_text or "known exploited" in caveat_text


# ---------------------------------------------------------------------------
# 8. Unreachable package — caveats mention "not imported" and "removing"
# ---------------------------------------------------------------------------

def test_suggestion_unreachable_caveat():
    finding = _make_finding(reachable="false")
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    caveat_text = " ".join(s["caveats"]).lower()
    assert "not imported" in caveat_text
    assert "remov" in caveat_text  # "removing" or "remove"


# ---------------------------------------------------------------------------
# 9. High EPSS score — caveats mention EPSS
# ---------------------------------------------------------------------------

def test_suggestion_high_epss_caveat():
    finding = _make_finding(epss_score=0.9)
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    caveat_text = " ".join(s["caveats"]).lower()
    assert "epss" in caveat_text


# ---------------------------------------------------------------------------
# 10. Multiple findings — 3 returned, matched by ID
# ---------------------------------------------------------------------------

def test_suggestions_for_multiple_findings():
    findings = [
        _make_finding(cve_id="CVE-2024-0001", package="pkg-a"),
        _make_finding(cve_id="CVE-2024-0002", package="pkg-b"),
        _make_finding(cve_id="CVE-2024-0003", package="pkg-c", fix_available=False, fixed_version=None),
    ]
    ctx = _make_context()
    results = generate_fix_suggestions(findings, ctx)

    assert len(results) == 3
    ids = [r["id"] for r in results]
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-0002" in ids
    assert "CVE-2024-0003" in ids

    # Third one should be investigate
    result_by_id = {r["id"]: r for r in results}
    assert result_by_id["CVE-2024-0003"]["suggestion_type"] == "investigate"


# ---------------------------------------------------------------------------
# 11. Empty findings — returns empty list
# ---------------------------------------------------------------------------

def test_empty_findings():
    ctx = _make_context()
    results = generate_fix_suggestions([], ctx)
    assert results == []


# ---------------------------------------------------------------------------
# Additional: unknown package manager falls back to generic comment
# ---------------------------------------------------------------------------

def test_suggestion_unknown_package_manager():
    finding = _make_finding(package="some-lib")
    ctx = _make_context("cargo")  # not explicitly handled
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert "some-lib" in s["command"]


# ---------------------------------------------------------------------------
# Additional: fix_available=True but no fixed_version → investigate
# ---------------------------------------------------------------------------

def test_suggestion_fix_available_but_no_fixed_version():
    finding = _make_finding(fix_available=True, fixed_version=None)
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    assert s["suggestion_type"] == "investigate"
    assert s["command"] is None


# ---------------------------------------------------------------------------
# Additional: reachable=true — caveats mention "actively used"
# ---------------------------------------------------------------------------

def test_suggestion_reachable_caveat():
    finding = _make_finding(
        reachable="true",
        reachability_evidence="import found in app/main.py:12",
    )
    ctx = _make_context()
    results = generate_fix_suggestions([finding], ctx)

    s = results[0]
    caveat_text = " ".join(s["caveats"]).lower()
    assert "actively used" in caveat_text
