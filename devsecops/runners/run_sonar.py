"""
Pull findings from a SonarQube / SonarCloud server via its REST API.

Unlike the other runners, Sonar does not scan locally — it analyses code on a
server and exposes results over HTTP. This runner fetches a project's issues
(``api/issues/search``) and security hotspots (``api/hotspots/search``),
paginating through all results, and writes a single combined JSON document that
``SonarScannerAdapter`` can parse.

Configuration (env vars, aligned with Sonar's own conventions so teams can reuse
existing CI settings):

    SONAR_HOST_URL          e.g. https://sonarcloud.io  or  https://sonar.internal
    SONAR_TOKEN             a user or project analysis token
    SONAR_PROJECT_KEY       the project/component key to fetch

Each can also be passed explicitly to ``run()``. Authentication uses HTTP Basic
with the token as the username and an empty password — the method supported
across SonarQube and SonarCloud versions.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

# Sonar caps paginated search at 10,000 results (page * pageSize <= 10000).
PAGE_SIZE = 500
MAX_RESULTS = 10_000


def _auth_header(token: str) -> dict:
    """Build an HTTP Basic auth header from a Sonar token (token as username)."""
    raw = f"{token}:".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def _get(url: str, headers: dict, timeout: int) -> dict:
    """GET a JSON document, raising RuntimeError with a clear message on failure."""
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode()[:200]
        except Exception:
            pass
        raise RuntimeError(
            f"Sonar API returned HTTP {exc.code} for {url} {detail}".strip()
        )
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Sonar API unreachable ({url}): {exc.reason}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Sonar API returned non-JSON from {url}: {exc}")


def _fetch_paginated(base_url: str, path: str, params: dict, headers: dict,
                     timeout: int, items_key: str) -> list:
    """Page through a Sonar search endpoint and collect all items under *items_key*."""
    items: list = []
    page = 1
    while True:
        query = {**params, "p": page, "ps": PAGE_SIZE}
        url = f"{base_url}{path}?{urllib.parse.urlencode(query)}"
        data = _get(url, headers, timeout)

        batch = data.get(items_key, [])
        items.extend(batch)

        # Stop when the page came back short, we hit Sonar's cap, or paging info says we're done.
        total = data.get("total") or data.get("paging", {}).get("total")
        if not batch or len(batch) < PAGE_SIZE:
            break
        if page * PAGE_SIZE >= MAX_RESULTS:
            break
        if total is not None and page * PAGE_SIZE >= total:
            break
        page += 1

    return items


def run(out_file: str, *, base_url: str = None, token: str = None,
        project_key: str = None, timeout: int = 15,
        include_hotspots: bool = True) -> dict:
    """
    Fetch a Sonar project's issues (and hotspots) and write combined JSON.

    Returns the combined dict ``{"issues": [...], "hotspots": [...]}``.
    Raises RuntimeError if configuration is missing or the API call fails.
    """
    base_url = (base_url or os.environ.get("SONAR_HOST_URL", "")).rstrip("/")
    token = token or os.environ.get("SONAR_TOKEN", "")
    project_key = project_key or os.environ.get("SONAR_PROJECT_KEY", "")

    missing = [n for n, v in
               (("SONAR_HOST_URL", base_url), ("SONAR_TOKEN", token),
                ("SONAR_PROJECT_KEY", project_key)) if not v]
    if missing:
        raise RuntimeError(
            "Sonar runner needs " + ", ".join(missing) +
            " (set env vars or pass base_url/token/project_key)."
        )

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    headers = _auth_header(token)

    issues = _fetch_paginated(
        base_url, "/api/issues/search",
        {"componentKeys": project_key, "resolved": "false"},
        headers, timeout, items_key="issues",
    )

    hotspots: list = []
    if include_hotspots:
        # Hotspots live on a separate endpoint; tolerate servers that lack it.
        try:
            hotspots = _fetch_paginated(
                base_url, "/api/hotspots/search",
                {"projectKey": project_key},
                headers, timeout, items_key="hotspots",
            )
        except RuntimeError:
            hotspots = []

    combined = {"issues": issues, "hotspots": hotspots}
    with open(out_file, "w") as f:
        json.dump(combined, f)
    return combined
