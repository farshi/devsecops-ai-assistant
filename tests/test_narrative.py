"""Tests for LLM narrative enhancement in agent/prioritizer.py."""

import json
import os
from unittest.mock import patch

import pytest

from agent.models import Finding
from agent.prioritizer import enhance_triage_with_llm, generate_triage, run_triage


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

MOCK_NARRATIVES = [
    {
        "id": "CVE-2024-0001",
        "why_it_matters": "This is critical because it allows remote code execution in your WSGI layer.",
        "recommendation": "Upgrade immediately to werkzeug 3.0.3+. Test WSGI middleware after upgrade.",
    },
]


def _make_finding(cve_id, severity="high", reachable="true", fix_available=True, **kwargs):
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=f"Vuln {cve_id}",
        package="test-pkg",
        installed_version="1.0.0",
        fixed_version="2.0.0" if fix_available else None,
        fix_available=fix_available,
        reachable=reachable,
        reachability_confidence="high",
        **kwargs,
    )


def _make_context(**overrides):
    ctx = {
        "scan_meta": {
            "date": "2026-03-27",
            "scanners_run": ["trivy_fs"],
            "total_findings": 1,
        },
        "repo": {"languages": ["Python"], "frameworks": ["FastAPI"]},
        "dependencies": {"direct": ["werkzeug", "fastapi"]},
        "findings": [],
        "token_budget": {},
    }
    ctx["scan_meta"].update(overrides)
    return ctx


def _make_triage_result(cve_id="CVE-2024-0001"):
    """Build a minimal triage result with one action item."""
    finding = _make_finding(cve_id, severity="critical", reachable="true", epss_score=0.92, in_kev=True)
    context = _make_context()
    return generate_triage([finding], context, top_n=5)


# ---------------------------------------------------------------------------
# test_enhance_adds_narratives
# ---------------------------------------------------------------------------

def test_enhance_adds_narratives():
    """Mock claude_client.call to return JSON narratives — action items should gain narrative fields."""
    triage_result = _make_triage_result()
    context = _make_context()

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("agent.claude_client.call", return_value=json.dumps(MOCK_NARRATIVES)):
            enhanced = enhance_triage_with_llm(triage_result, context)

    items = enhanced["triage"]["action_items"]
    assert len(items) == 1
    item = items[0]
    assert "why_it_matters" in item
    assert "recommendation" in item
    assert item["why_it_matters"] == MOCK_NARRATIVES[0]["why_it_matters"]
    assert item["recommendation"] == MOCK_NARRATIVES[0]["recommendation"]


# ---------------------------------------------------------------------------
# test_enhance_preserves_ranking
# ---------------------------------------------------------------------------

def test_enhance_preserves_ranking():
    """priority_score and priority_tier must be unchanged after LLM enhancement."""
    triage_result = _make_triage_result()
    context = _make_context()

    # Capture original scores/tiers
    original_items = [
        {"id": i["id"], "priority_score": i["priority_score"], "priority_tier": i["priority_tier"]}
        for i in triage_result["triage"]["action_items"]
    ]

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("agent.claude_client.call", return_value=json.dumps(MOCK_NARRATIVES)):
            enhanced = enhance_triage_with_llm(triage_result, context)

    for orig, item in zip(original_items, enhanced["triage"]["action_items"]):
        assert item["priority_score"] == orig["priority_score"], "score must not change"
        assert item["priority_tier"] == orig["priority_tier"], "tier must not change"
        assert item["id"] == orig["id"], "id must not change"


# ---------------------------------------------------------------------------
# test_enhance_without_api_key
# ---------------------------------------------------------------------------

def test_enhance_without_api_key():
    """Without ANTHROPIC_API_KEY, triage is returned unchanged — no crash."""
    triage_result = _make_triage_result()
    context = _make_context()

    # Remove key if set
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}

    with patch.dict(os.environ, env, clear=True):
        result = enhance_triage_with_llm(triage_result, context)

    # Should return the original unchanged
    item = result["triage"]["action_items"][0]
    assert "why_it_matters" not in item
    assert "recommendation" not in item


# ---------------------------------------------------------------------------
# test_enhance_handles_llm_error
# ---------------------------------------------------------------------------

def test_enhance_handles_llm_error():
    """If claude_client.call raises, returns triage unchanged — no crash."""
    triage_result = _make_triage_result()
    context = _make_context()

    original_score = triage_result["triage"]["action_items"][0]["priority_score"]

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("agent.claude_client.call", side_effect=RuntimeError("API error")):
            result = enhance_triage_with_llm(triage_result, context)

    item = result["triage"]["action_items"][0]
    assert item["priority_score"] == original_score
    assert "why_it_matters" not in item


# ---------------------------------------------------------------------------
# test_enhance_handles_invalid_json
# ---------------------------------------------------------------------------

def test_enhance_handles_invalid_json():
    """If LLM returns non-JSON, returns triage unchanged — no crash."""
    triage_result = _make_triage_result()
    context = _make_context()

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("agent.claude_client.call", return_value="This is not JSON at all!"):
            result = enhance_triage_with_llm(triage_result, context)

    item = result["triage"]["action_items"][0]
    assert "why_it_matters" not in item
    assert "recommendation" not in item


# ---------------------------------------------------------------------------
# test_enhanced_markdown_includes_narratives
# ---------------------------------------------------------------------------

def test_enhanced_markdown_includes_narratives():
    """After enhancement, markdown should contain the LLM narrative text."""
    triage_result = _make_triage_result()
    context = _make_context()

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("agent.claude_client.call", return_value=json.dumps(MOCK_NARRATIVES)):
            enhanced = enhance_triage_with_llm(triage_result, context)

    md = enhanced["markdown"]
    assert "Why it matters:" in md
    assert "Recommendation:" in md
    assert MOCK_NARRATIVES[0]["why_it_matters"] in md
    assert MOCK_NARRATIVES[0]["recommendation"] in md


# ---------------------------------------------------------------------------
# test_run_triage_enhance_flag
# ---------------------------------------------------------------------------

def test_run_triage_enhance_flag():
    """run_triage with enhance=True and valid API key should call enhance_triage_with_llm."""
    import json
    import tempfile

    # Build a minimal summary file — findings keyed by scanner name (context_builder format)
    summary_data = {
        "scan": {
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
        },
        "findings": {
            "trivy_fs": [
                {
                    "id": "CVE-2024-0001",
                    "severity": "critical",
                    "title": "Test vuln",
                    "package": "test-pkg",
                    "installed_version": "1.0.0",
                    "fixed_version": "2.0.0",
                    "location": "requirements.txt",
                }
            ]
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(summary_data, f)
        summary_path = f.name

    try:
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            with patch("agent.prioritizer.enhance_triage_with_llm", wraps=lambda r, c: r) as mock_enhance:
                result = run_triage(".", summary_path, top_n=5, enhance=True)

        mock_enhance.assert_called_once()
        # The triage result should still be a valid dict
        assert "triage" in result
        assert "markdown" in result
    finally:
        os.unlink(summary_path)


# ---------------------------------------------------------------------------
# test_run_triage_no_enhance_flag (sanity check)
# ---------------------------------------------------------------------------

def test_run_triage_no_enhance_flag():
    """run_triage with enhance=False should NOT call enhance_triage_with_llm."""
    import json
    import tempfile

    summary_data = {
        "scan": {
            "date": "2026-03-30",
            "scanners_run": ["trivy_fs"],
        },
        "findings": {},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(summary_data, f)
        summary_path = f.name

    try:
        with patch("agent.prioritizer.enhance_triage_with_llm") as mock_enhance:
            run_triage(".", summary_path, top_n=5, enhance=False)

        mock_enhance.assert_not_called()
    finally:
        os.unlink(summary_path)
