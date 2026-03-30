"""KEV enrichment plugin — checks findings against CISA Known Exploited Vulnerabilities catalog."""

import json
import urllib.request
import urllib.error
from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


class KEVEnrichmentPlugin(EnrichmentPlugin):
    """Checks findings against the CISA KEV catalog.

    KEV (Known Exploited Vulnerabilities) is a curated list of CVEs
    that are actively being exploited in the wild.

    Catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self._catalog = None  # Lazy-loaded, cached for session

    @property
    def name(self) -> str:
        return "kev"

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Check each finding against the KEV catalog."""
        catalog = self._get_catalog()

        for finding in findings:
            if finding.id.upper().startswith("CVE-"):
                finding.in_kev = finding.id.upper() in catalog

        return findings

    def _get_catalog(self) -> set[str]:
        """Fetch and cache the KEV catalog as a set of CVE IDs."""
        if self._catalog is not None:
            return self._catalog

        try:
            req = urllib.request.Request(self.KEV_URL, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            self._catalog = set(
                vuln.get("cveID", "").upper()
                for vuln in data.get("vulnerabilities", [])
            )
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            self._catalog = set()  # Cache empty set so we don't retry on failure

        return self._catalog
