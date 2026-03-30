import json
import socket
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin
from agent.plugins.enrichment.epss import EPSSEnrichmentPlugin
from agent.plugins.enrichment.kev import KEVEnrichmentPlugin


def _make_finding(cve_id, **kwargs):
    """Helper to create a Finding with minimal required fields."""
    return Finding(
        id=cve_id,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity="high",
        title=f"Test vuln {cve_id}",
        **kwargs,
    )


def _mock_urlopen(payload: dict):
    """Build a mock context-manager response for urlopen returning JSON payload."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# EPSS tests
# ---------------------------------------------------------------------------

@patch("agent.plugins.enrichment.epss.urllib.request.urlopen")
def test_epss_enriches_findings(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen(
        {"data": [{"cve": "CVE-2024-0001", "epss": "0.95"}]}
    )
    plugin = EPSSEnrichmentPlugin()
    findings = [_make_finding("CVE-2024-0001")]
    result = plugin.enrich(findings, {})
    assert result[0].epss_score == pytest.approx(0.95)


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen")
def test_epss_batch_multiple_cves(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen({
        "data": [
            {"cve": "CVE-2024-0001", "epss": "0.80"},
            {"cve": "CVE-2024-0002", "epss": "0.30"},
        ]
    })
    plugin = EPSSEnrichmentPlugin()
    findings = [_make_finding("CVE-2024-0001"), _make_finding("CVE-2024-0002")]
    result = plugin.enrich(findings, {})
    scores = {f.id: f.epss_score for f in result}
    assert scores["CVE-2024-0001"] == pytest.approx(0.80)
    assert scores["CVE-2024-0002"] == pytest.approx(0.30)


def test_epss_skips_non_cve_ids():
    plugin = EPSSEnrichmentPlugin()
    finding = _make_finding("GHSA-xxxx-yyyy-zzzz")
    result = plugin.enrich([finding], {})
    assert result[0].epss_score is None


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen")
def test_epss_handles_api_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("connection refused")
    plugin = EPSSEnrichmentPlugin()
    finding = _make_finding("CVE-2024-0001")
    result = plugin.enrich([finding], {})
    assert result[0].epss_score is None


@patch("agent.plugins.enrichment.epss.urllib.request.urlopen")
def test_epss_handles_timeout(mock_urlopen):
    mock_urlopen.side_effect = socket.timeout("timed out")
    plugin = EPSSEnrichmentPlugin()
    finding = _make_finding("CVE-2024-0001")
    result = plugin.enrich([finding], {})
    assert result[0].epss_score is None


# ---------------------------------------------------------------------------
# KEV tests
# ---------------------------------------------------------------------------

def _kev_payload(*cve_ids):
    """Build a minimal KEV catalog payload containing the given CVE IDs."""
    return {
        "vulnerabilities": [{"cveID": cve} for cve in cve_ids]
    }


@patch("agent.plugins.enrichment.kev.urllib.request.urlopen")
def test_kev_marks_known_exploited(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen(_kev_payload("CVE-2024-0001"))
    plugin = KEVEnrichmentPlugin()
    finding = _make_finding("CVE-2024-0001")
    result = plugin.enrich([finding], {})
    assert result[0].in_kev is True


@patch("agent.plugins.enrichment.kev.urllib.request.urlopen")
def test_kev_marks_not_exploited(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen(_kev_payload("CVE-2024-0001"))
    plugin = KEVEnrichmentPlugin()
    finding = _make_finding("CVE-2024-9999")
    result = plugin.enrich([finding], {})
    assert result[0].in_kev is False


def test_kev_skips_non_cve():
    plugin = KEVEnrichmentPlugin()
    finding = _make_finding("GHSA-xxxx-yyyy-zzzz")
    result = plugin.enrich([finding], {})
    assert result[0].in_kev is False


@patch("agent.plugins.enrichment.kev.urllib.request.urlopen")
def test_kev_handles_api_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("network unreachable")
    plugin = KEVEnrichmentPlugin()
    finding = _make_finding("CVE-2024-0001")
    result = plugin.enrich([finding], {})
    assert result[0].in_kev is False


@patch("agent.plugins.enrichment.kev.urllib.request.urlopen")
def test_kev_caches_catalog(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen(_kev_payload("CVE-2024-0001"))
    plugin = KEVEnrichmentPlugin()
    findings_1 = [_make_finding("CVE-2024-0001")]
    findings_2 = [_make_finding("CVE-2024-0001")]
    plugin.enrich(findings_1, {})
    plugin.enrich(findings_2, {})
    assert mock_urlopen.call_count == 1


def test_epss_implements_enrichment_plugin():
    assert isinstance(EPSSEnrichmentPlugin(), EnrichmentPlugin)


def test_kev_implements_enrichment_plugin():
    assert isinstance(KEVEnrichmentPlugin(), EnrichmentPlugin)
