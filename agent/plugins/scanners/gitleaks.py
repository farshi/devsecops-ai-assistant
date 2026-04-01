"""GitleaksScannerAdapter — implements ScannerAdapter for gitleaks JSON output."""

import json
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import ScannerAdapter


class GitleaksScannerAdapter(ScannerAdapter):
    """Normalizes gitleaks JSON output into canonical Finding instances."""

    @property
    def name(self) -> str:
        return "gitleaks"

    def parse(self, raw_path: Path) -> list[Finding]:
        """Read a gitleaks JSON output file and return normalized Findings."""
        raw_path = Path(raw_path)
        with raw_path.open() as fh:
            raw = json.load(fh)
        return self.parse_list(raw)

    def parse_list(self, raw: list) -> list[Finding]:
        """Parse a pre-loaded gitleaks JSON list into Findings.

        Each gitleaks finding becomes a Finding with:
        - finding_type = "secret"
        - reachable = "not_applicable" (secrets are always reachable if in code)
        - severity = mapped from rule type (API keys = high, generic = medium)
        - id = RuleID (not a CVE — secrets don't have CVEs)
        """
        findings = []

        for item in raw or []:
            rule_id = item.get("RuleID", "unknown-secret")
            description = item.get("Description", "Secret detected")
            file_path = item.get("File", "unknown")
            line = item.get("StartLine", 0)

            # Map severity based on rule type
            severity = _classify_severity(rule_id, description)

            finding = Finding(
                id=f"SECRET:{rule_id}",
                source_scanner="gitleaks",
                finding_type="secret",
                severity=severity,
                title=f"{description} in {file_path}:{line}",
                package=None,  # secrets don't have packages
                installed_version=None,
                fixed_version=None,
                location=f"{file_path}:{line}",
                reachable="not_applicable",
                reachability_confidence="none",
                fix_available=True,  # fix = remove the secret
                fix_evidence="Remove secret from source code and rotate the credential",
            )
            findings.append(finding)

        return findings


# Severity mapping for secret types
_HIGH_SEVERITY_RULES = {
    "aws-access-key-id", "aws-secret-access-key",
    "github-pat", "github-fine-grained-pat", "github-oauth",
    "gitlab-pat", "gitlab-ptt",
    "gcp-service-account", "gcp-api-key",
    "private-key", "rsa-private-key",
    "jwt", "jwt-base64",
    "stripe-access-token", "twilio-api-key",
    "slack-bot-token", "slack-webhook-url",
    "database-url", "postgres-uri", "mysql-uri",
}

_CRITICAL_SEVERITY_RULES = {
    "aws-secret-access-key",
    "private-key", "rsa-private-key",
    "gcp-service-account",
}


def _classify_severity(rule_id: str, description: str) -> str:
    """Classify secret severity based on rule type."""
    rule_lower = rule_id.lower()

    if rule_lower in _CRITICAL_SEVERITY_RULES:
        return "critical"
    if rule_lower in _HIGH_SEVERITY_RULES:
        return "high"

    # Check description for keywords
    desc_lower = description.lower()
    if any(k in desc_lower for k in ("private key", "secret key", "access key")):
        return "high"
    if any(k in desc_lower for k in ("api key", "token", "password", "credential")):
        return "medium"

    return "medium"  # default for unknown secret types
