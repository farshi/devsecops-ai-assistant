"""Tests for devsecops/runners/run_sonar.py — Sonar REST API pull."""

import base64
import json
from urllib.error import HTTPError, URLError

import pytest

from devsecops.runners import run_sonar


# ---------------------------------------------------------------------------
# Fake HTTP layer
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _make_urlopen(routes, recorder=None):
    """Build a fake urlopen that maps URL substrings → payloads (or exceptions)."""
    def _urlopen(req, timeout=None):
        url = req.full_url
        if recorder is not None:
            recorder.append((url, dict(req.headers), timeout))
        for needle, payload in routes:
            if needle in url:
                if isinstance(payload, Exception):
                    raise payload
                # Support a list of pages for pagination.
                if isinstance(payload, list) and payload and isinstance(payload[0], dict) \
                        and "_page_marker" not in payload[0]:
                    pass
                return _FakeResponse(payload)
        raise AssertionError(f"no route for {url}")
    return _urlopen


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def test_missing_config_raises(tmp_path, monkeypatch):
    for k in ("SONAR_HOST_URL", "SONAR_TOKEN", "SONAR_PROJECT_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError) as exc:
        run_sonar.run(str(tmp_path / "out.json"))
    assert "SONAR_HOST_URL" in str(exc.value)


def test_explicit_args_override_env(tmp_path, monkeypatch):
    recorder = []
    routes = [("/api/issues/search", {"issues": [], "total": 0}),
              ("/api/hotspots/search", {"hotspots": [], "paging": {"total": 0}})]
    monkeypatch.setattr(run_sonar.urllib.request, "urlopen",
                        _make_urlopen(routes, recorder))
    out = tmp_path / "out.json"
    run_sonar.run(str(out), base_url="https://sonar.example",
                  token="tok123", project_key="proj")
    # Auth header is Basic base64("tok123:")
    expected = "Basic " + base64.b64encode(b"tok123:").decode()
    assert any(h.get("Authorization") == expected for _, h, _ in recorder)


# ---------------------------------------------------------------------------
# Happy path + pagination
# ---------------------------------------------------------------------------

def _issue(n):
    return {"rule": f"python:S{n}", "severity": "MAJOR",
            "component": f"proj:src/f{n}.py", "line": n, "type": "BUG",
            "message": f"issue {n}"}


def test_fetches_issues_and_hotspots(tmp_path, monkeypatch):
    routes = [
        ("/api/issues/search", {"issues": [_issue(1), _issue(2)], "total": 2}),
        ("/api/hotspots/search",
         {"hotspots": [{"ruleKey": "python:S5443", "component": "proj:src/h.py",
                        "line": 9, "vulnerabilityProbability": "MEDIUM",
                        "message": "hotspot"}],
          "paging": {"total": 1}}),
    ]
    monkeypatch.setattr(run_sonar.urllib.request, "urlopen", _make_urlopen(routes))
    out = tmp_path / "out.json"
    result = run_sonar.run(str(out), base_url="https://s", token="t",
                           project_key="proj")
    assert len(result["issues"]) == 2
    assert len(result["hotspots"]) == 1
    # File written and matches return value.
    on_disk = json.loads(out.read_text())
    assert on_disk == result


def test_pagination_walks_pages(tmp_path, monkeypatch):
    # First page is full (PAGE_SIZE items) → runner must request page 2.
    full_page = [_issue(i) for i in range(run_sonar.PAGE_SIZE)]
    second_page = [_issue(9001)]
    pages = {"issues": iter([full_page, second_page])}

    def fake_urlopen(req, timeout=None):
        if "/api/issues/search" in req.full_url:
            return _FakeResponse({"issues": next(pages["issues"]), "total": run_sonar.PAGE_SIZE + 1})
        return _FakeResponse({"hotspots": [], "paging": {"total": 0}})

    monkeypatch.setattr(run_sonar.urllib.request, "urlopen", fake_urlopen)
    result = run_sonar.run(str(tmp_path / "o.json"), base_url="https://s",
                           token="t", project_key="proj")
    assert len(result["issues"]) == run_sonar.PAGE_SIZE + 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_http_error_raises_runtimeerror(tmp_path, monkeypatch):
    err = HTTPError("https://s/api/issues/search", 401, "Unauthorized", {}, None)
    monkeypatch.setattr(run_sonar.urllib.request, "urlopen",
                        _make_urlopen([("/api/issues/search", err)]))
    with pytest.raises(RuntimeError) as exc:
        run_sonar.run(str(tmp_path / "o.json"), base_url="https://s",
                      token="t", project_key="proj")
    assert "401" in str(exc.value)


def test_unreachable_raises_runtimeerror(tmp_path, monkeypatch):
    monkeypatch.setattr(run_sonar.urllib.request, "urlopen",
                        _make_urlopen([("/api/issues/search", URLError("refused"))]))
    with pytest.raises(RuntimeError) as exc:
        run_sonar.run(str(tmp_path / "o.json"), base_url="https://s",
                      token="t", project_key="proj")
    assert "unreachable" in str(exc.value).lower()


def test_missing_hotspots_endpoint_tolerated(tmp_path, monkeypatch):
    """A server without the hotspots endpoint must not fail the whole pull."""
    routes = [
        ("/api/issues/search", {"issues": [_issue(1)], "total": 1}),
        ("/api/hotspots/search",
         HTTPError("https://s/api/hotspots/search", 404, "Not Found", {}, None)),
    ]
    monkeypatch.setattr(run_sonar.urllib.request, "urlopen", _make_urlopen(routes))
    result = run_sonar.run(str(tmp_path / "o.json"), base_url="https://s",
                           token="t", project_key="proj")
    assert len(result["issues"]) == 1
    assert result["hotspots"] == []
