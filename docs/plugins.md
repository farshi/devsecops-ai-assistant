# PatchPilot Plugin Development Guide

## Overview

PatchPilot is extensible through four plugin types. Each is a Python abstract base class (ABC) in `agent/plugins/base.py`.

## Plugin Types

| Type | What It Does | Method to Implement |
|------|-------------|-------------------|
| **ScannerAdapter** | Normalize scanner output → Finding objects | `parse(raw_path) → list[Finding]` |
| **EnrichmentPlugin** | Add context to findings | `enrich(findings, context) → list[Finding]` |
| **PrioritizationStrategy** | Score and rank findings | `score(findings) → list[Finding]` |
| **OutputFormatter** | Format results for output | `format(findings, context) → str` |

All plugins also require a `name` property.

## Writing a Scanner Adapter

Scanner adapters normalize raw scanner output into canonical `Finding` objects.

### Example: Grype Adapter

```python
"""Grype scanner adapter for PatchPilot."""

import json
from pathlib import Path
from agent.models import Finding
from agent.plugins.base import ScannerAdapter


class GrypeScannerAdapter(ScannerAdapter):

    @property
    def name(self) -> str:
        return "grype"

    def parse(self, raw_path: Path) -> list[Finding]:
        raw_path = Path(raw_path)
        with raw_path.open() as f:
            data = json.load(f)

        findings = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            pkg = match.get("artifact", {})

            finding = Finding(
                id=vuln.get("id", "UNKNOWN"),
                source_scanner="grype",
                finding_type="language_dep",  # or classify by pkg type
                severity=vuln.get("severity", "info").lower(),
                title=vuln.get("description", "")[:120],
                package=pkg.get("name"),
                installed_version=pkg.get("version"),
                fixed_version=vuln.get("fix", {}).get("versions", [None])[0],
                location=f"{pkg.get('name')}@{pkg.get('version')}",
            )
            findings.append(finding)

        return findings
```

### Key Rules
- Return `list[Finding]` — always use the canonical schema
- Set `source_scanner` to your scanner name
- Set `finding_type` correctly: `language_dep`, `os_package`, `iac_misconfig`, `secret`, `code_pattern`
- OS packages should set `reachable="not_applicable"`
- Extract CVSS score into `cvss_score` when available
- Set `fix_available` and `fixed_version` when the scanner provides fix info

## Writing an Enrichment Plugin

Enrichment plugins add context to findings after scanning.

### Example: AWS SecurityHub Enrichment

```python
"""Enrich findings with AWS SecurityHub context."""

from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


class SecurityHubEnrichmentPlugin(EnrichmentPlugin):

    @property
    def name(self) -> str:
        return "aws_securityhub"

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        # Connect to AWS SecurityHub, look up each CVE
        # Add cloud-specific context to findings
        for finding in findings:
            # Example: check if affected resource is internet-facing
            # finding.reachability_evidence = "EC2 instance in public subnet"
            pass
        return findings
```

### Key Rules
- Mutate findings in-place and return the same list
- Be best-effort: catch exceptions, don't crash the pipeline
- Cache where possible (like KEV plugin caches the catalog)
- Network calls should have timeouts

## Writing a Prioritization Strategy

Custom scoring algorithms for different risk appetites.

### Example: Compliance-Focused Scorer

```python
"""Compliance-focused scoring — weights CRA/SOC2 relevance higher."""

from agent.models import Finding
from agent.plugins.base import PrioritizationStrategy


class ComplianceScoringStrategy(PrioritizationStrategy):

    @property
    def name(self) -> str:
        return "compliance"

    def score(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            score = 0

            # KEV = mandatory fix for compliance
            if finding.in_kev:
                score += 40

            # EPSS > 0.5 = compliance risk
            if finding.epss_score and finding.epss_score > 0.5:
                score += 25

            # Fix available = no excuse not to fix
            if finding.fix_available:
                score += 20

            # Severity baseline
            severity_scores = {"critical": 15, "high": 10, "medium": 5}
            score += severity_scores.get(finding.severity, 0)

            finding.priority_score = min(score, 100)
            finding.priority_tier = self._score_to_tier(score)

        findings.sort(key=lambda f: f.priority_score, reverse=True)
        return findings

    def _score_to_tier(self, score):
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        if score >= 20: return "low"
        return "noise"
```

## Writing an Output Formatter

Custom output formats for different audiences.

### Example: SARIF Formatter

```python
"""SARIF output for GitHub Advanced Security integration."""

import json
from agent.models import Finding
from agent.plugins.base import OutputFormatter


class SARIFFormatter(OutputFormatter):

    @property
    def name(self) -> str:
        return "sarif"

    def format(self, findings: list[Finding], context: dict) -> str:
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "PatchPilot"}},
                "results": [
                    {
                        "ruleId": f.id,
                        "level": self._severity_to_level(f.severity),
                        "message": {"text": f.title},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f.location}
                        }}],
                    }
                    for f in findings
                ],
            }],
        }
        return json.dumps(sarif, indent=2)

    def _severity_to_level(self, severity):
        return {"critical": "error", "high": "error",
                "medium": "warning", "low": "note"}.get(severity, "note")
```

## Testing Your Plugin

```python
import pytest
from agent.models import Finding
from your_plugin import YourPlugin

def test_implements_abc():
    """Verify your plugin implements the ABC correctly."""
    plugin = YourPlugin()
    assert hasattr(plugin, 'name')
    assert hasattr(plugin, 'parse')  # or enrich/score/format

def test_returns_findings():
    """Verify your plugin returns Finding objects."""
    plugin = YourPlugin()
    result = plugin.parse(Path("test_data.json"))
    assert all(isinstance(f, Finding) for f in result)
```

## Registration (Current)

Currently plugins are imported directly in the code. Future versions will support:
- Python entry points (`setuptools`) for pip-installable plugins
- Local plugin directory (`.patchpilot/plugins/`)
- Config-based registration

## Reference: Finding Fields

See [docs/concepts.md](concepts.md#finding) for the full Finding schema.

Key fields your plugin should set:

| Field | Who Sets It | Required? |
|-------|-----------|-----------|
| `id` | Scanner adapter | Yes |
| `source_scanner` | Scanner adapter | Yes |
| `finding_type` | Scanner adapter | Yes |
| `severity` | Scanner adapter | Yes |
| `title` | Scanner adapter | Yes |
| `package` | Scanner adapter | If applicable |
| `cvss_score` | Scanner adapter | If available |
| `reachable` | Context builder | Auto |
| `epss_score` | EPSS plugin | Auto |
| `in_kev` | KEV plugin | Auto |
| `fix_available` | Fix plugin | Auto |
| `priority_score` | Scoring strategy | Auto |
