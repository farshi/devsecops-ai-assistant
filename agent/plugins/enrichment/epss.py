"""EPSS enrichment plugin — fetches exploitation probability scores from FIRST.org API."""

import json
import urllib.request
import urllib.error
from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


class EPSSEnrichmentPlugin(EnrichmentPlugin):
    """Fetches EPSS scores from the FIRST.org API.

    EPSS (Exploit Prediction Scoring System) provides a probability (0.0-1.0)
    that a CVE will be exploited in the next 30 days.

    API: https://api.first.org/data/v1/epss?cve=CVE-xxx,CVE-yyy
    Supports batch queries (comma-separated CVEs).
    """

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    BATCH_SIZE = 100  # API supports batching

    @property
    def name(self) -> str:
        return "epss"

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Fetch EPSS scores for all findings with CVE IDs."""
        # Collect unique CVE IDs
        cve_ids = list(set(
            f.id for f in findings
            if f.id.upper().startswith("CVE-")
        ))

        if not cve_ids:
            return findings

        # Fetch scores in batches
        scores = {}
        for i in range(0, len(cve_ids), self.BATCH_SIZE):
            batch = cve_ids[i:i + self.BATCH_SIZE]
            batch_scores = self._fetch_batch(batch)
            scores.update(batch_scores)

        # Apply to findings
        for finding in findings:
            if finding.id in scores:
                finding.epss_score = scores[finding.id]

        return findings

    def _fetch_batch(self, cve_ids: list[str]) -> dict[str, float]:
        """Fetch EPSS scores for a batch of CVE IDs.

        Returns dict mapping CVE ID → EPSS score (0.0-1.0).
        Silently returns empty dict on API errors (enrichment is best-effort).
        """
        try:
            url = f"{self.EPSS_API_URL}?cve={','.join(cve_ids)}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            scores = {}
            for item in data.get("data", []):
                cve = item.get("cve", "")
                epss = item.get("epss")
                if cve and epss is not None:
                    scores[cve] = float(epss)
            return scores
        except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
            return {}
