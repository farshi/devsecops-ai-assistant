"""Compliance enrichment plugin — maps findings to NIST / CIS / PCI / ISO controls.

Loads all pattern files under ``mappings/patterns/*.json`` at construction
time. For each finding, checks every pattern's ``match`` clause and merges
the pattern's ``controls`` into ``Finding.compliance_controls``. The matched
pattern IDs are tracked on ``Finding.compliance_patterns_matched``.

Mappings and their attribution live under the repository-root ``mappings/``
directory — see ``mappings/README.md`` and ``mappings/sources.md``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


# Map Trivy's finding_type → our mapping-schema ecosystem values.
# A pattern with ecosystem="generic" matches any finding_type.
_FINDING_TYPE_TO_ECOSYSTEM_HINT = {
    "os_package": {"os", "generic"},
    "language_dep": {"pypi", "npm", "maven", "rubygems", "go", "cargo", "composer", "generic"},
    "iac_misconfig": {"generic"},
    "secret": {"generic"},
    "code_pattern": {"generic"},
}

# Minimum fields a pattern must have to be considered valid.
_REQUIRED_PATTERN_FIELDS = ("pattern_id", "name", "match", "controls", "rationale")


def _parse_version(v: str) -> tuple:
    """Tolerant version parser — returns a tuple of ints for comparison.

    Strips leading 'v', ignores suffixes after first non-numeric segment.
    Good enough for semver / PEP 440 ordering in the common case.
    Unknown formats sort as (0,), which is safe for the "version_below"
    use case (we will not claim a match if we cannot parse).
    """
    if not v:
        return (0,)
    v = v.lstrip("vV").strip()
    parts = re.split(r"[^0-9]+", v)
    nums = []
    for p in parts:
        if not p:
            continue
        try:
            nums.append(int(p))
        except ValueError:
            break
    return tuple(nums) if nums else (0,)


def _version_less_than(installed: str | None, threshold: str) -> bool:
    """Return True iff installed < threshold per the tolerant parser."""
    if not installed:
        return False
    return _parse_version(installed) < _parse_version(threshold)


def _ecosystem_of_finding(finding: Finding) -> set[str]:
    """Return the set of pattern ecosystems a finding could match."""
    return _FINDING_TYPE_TO_ECOSYSTEM_HINT.get(finding.finding_type, {"generic"})


def _pattern_matches_finding(pattern: dict, finding: Finding) -> bool:
    """Return True iff every declared match field matches the finding.

    A pattern with an empty ``match`` block is treated as a no-op and
    never matches (prevents accidental catch-all mappings).
    """
    match = pattern.get("match") or {}
    if not match:
        return False

    if "ecosystem" in match:
        if match["ecosystem"] not in _ecosystem_of_finding(finding):
            return False

    if "package" in match:
        if not finding.package:
            return False
        if finding.package.lower() != str(match["package"]).lower():
            return False

    if "version_below" in match:
        if not _version_less_than(finding.installed_version, str(match["version_below"])):
            return False

    if "cve_ids" in match:
        if finding.id.upper() not in {c.upper() for c in match["cve_ids"]}:
            return False

    if "cwe_ids" in match:
        # We do not currently store CWE on Finding; fall through unless the
        # finding title or id embeds the CWE reference. This is intentionally
        # conservative — false negatives are better than false positives.
        fid = finding.id.upper()
        if not any(c.upper() in fid for c in match["cwe_ids"]):
            return False

    return True


class ComplianceEnrichmentPlugin(EnrichmentPlugin):
    """Attach NIST / CIS / PCI / ISO / ASVS control references to findings.

    Loads patterns from ``<repo_root>/mappings/patterns/*.json`` once at
    construction. Per-finding enrichment is a linear scan over the loaded
    patterns — small-N today, acceptable up to ~10k patterns.
    """

    def __init__(self, mappings_dir: Path | None = None):
        self._mappings_dir = mappings_dir or self._default_mappings_dir()
        self._patterns: list[dict] = self._load_patterns(self._mappings_dir)

    @property
    def name(self) -> str:
        return "compliance"

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        for finding in findings:
            matched_patterns: list[str] = []
            merged_controls: dict[str, list[str]] = {}

            for pattern in self._patterns:
                if not _pattern_matches_finding(pattern, finding):
                    continue
                matched_patterns.append(pattern["pattern_id"])
                for framework, controls in (pattern.get("controls") or {}).items():
                    bucket = merged_controls.setdefault(framework, [])
                    for ctrl in controls:
                        if ctrl not in bucket:
                            bucket.append(ctrl)

            if matched_patterns:
                finding.compliance_patterns_matched = matched_patterns
                finding.compliance_controls = merged_controls

        return findings

    # --- helpers ---

    @staticmethod
    def _default_mappings_dir() -> Path:
        # agent/plugins/enrichment/compliance.py → repo root is 3 levels up
        return Path(__file__).resolve().parents[3] / "mappings" / "patterns"

    @staticmethod
    def _load_patterns(directory: Path) -> list[dict]:
        if not directory.exists():
            return []
        patterns: list[dict] = []
        for path in sorted(directory.glob("*.json")):
            try:
                with path.open() as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            if all(k in data for k in _REQUIRED_PATTERN_FIELDS):
                patterns.append(data)
        return patterns


def framework_filter(findings: Iterable[Finding], framework_key: str) -> list[Finding]:
    """Return only findings that have at least one control under ``framework_key``.

    ``framework_key`` is the mapping-schema key, e.g. ``nist_800_53_rev5``.
    Useful for the forthcoming ``patchpilot triage --framework`` CLI flag.
    """
    return [f for f in findings if f.compliance_controls.get(framework_key)]
