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
import logging
import re
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version

from agent.models import Finding
from agent.plugins.base import EnrichmentPlugin


logger = logging.getLogger(__name__)


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

# Regexes for normalising OS-package / Debian / RPM version strings into
# something packaging.version.Version can parse.
_TILDE_PRERELEASE_RE = re.compile(r"~([a-zA-Z]+)(\d*)")
# "-1ubuntu2.3", "-1.el8_4.1", "-2ubuntu1" — Debian/RPM revision starts with a digit
_DIGIT_REVISION_RE = re.compile(r"-\d\S*$")
# "-deb11u1", "-dfsg-1", "-1+build1" — revisions that don't start with a digit
_NAMED_REVISION_RE = re.compile(
    r"-(?:deb|ubuntu|el|rhel|fc|build|dfsg|git)[^\s]*$", re.IGNORECASE
)


def _normalise_for_packaging(v: str) -> str:
    """Rewrite common OS / Debian / RPM version shapes into PEP-440-friendly form.

    Rules:
    - Strip leading ``v`` / ``V``.
    - Convert Debian tilde pre-release (``~beta1``) to the PEP 440 equivalent
      (``b1``) so ordering vs the final release is preserved: ``1.0~beta1 < 1.0``.
    - Strip Debian/RPM revision suffixes entirely. ``3.0.12-1ubuntu2.3`` becomes
      ``3.0.12`` — distro revisions do not affect upstream compliance-mapping
      semantics and would otherwise poison packaging.Version parsing.
    """
    v = v.strip().lstrip("vV")

    def _tilde_repl(m: re.Match) -> str:
        word = m.group(1).lower()
        num = m.group(2) or "0"
        pep = {"alpha": "a", "beta": "b", "pre": "rc"}.get(word, word)
        return pep + num

    v = _TILDE_PRERELEASE_RE.sub(_tilde_repl, v)
    v = _DIGIT_REVISION_RE.sub("", v)
    v = _NAMED_REVISION_RE.sub("", v)
    return v


def _numeric_tuple(v: str) -> tuple[int, ...]:
    """Fallback ordering — extract numeric segments left-to-right."""
    nums = [int(p) for p in re.findall(r"\d+", v or "")]
    return tuple(nums) if nums else (0,)


def _version_less_than(installed: str | None, threshold: str) -> bool:
    """Return True iff ``installed < threshold``.

    Strategy:
    1. Try ``packaging.version.Version`` on both sides (handles PEP 440
       including epochs, pre-releases, post-releases).
    2. If either side is not a valid PEP 440 version, strip common distro
       suffixes and try again.
    3. Final fallback is numeric-segment tuple ordering — lossy but safe
       for the common semver-ish case. Logs at DEBUG when this path fires
       so operators can see where mapping accuracy may be degraded.
    """
    if not installed or not threshold:
        return False

    for left, right in ((installed, threshold),
                        (_normalise_for_packaging(installed),
                         _normalise_for_packaging(threshold))):
        try:
            return Version(left) < Version(right)
        except InvalidVersion:
            continue

    logger.debug(
        "compliance: falling back to numeric-tuple compare for versions "
        "%r vs %r", installed, threshold,
    )
    return _numeric_tuple(installed) < _numeric_tuple(threshold)


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

    # CWE matching is intentionally not supported in v1: the Finding model
    # does not carry a CWE field. Patterns that declare ``cwe_ids`` without
    # any other discriminator would match too broadly, so we skip them
    # entirely (log at DEBUG to surface the mapping gap to contributors).
    if "cwe_ids" in match and len(match) == 1:
        logger.debug(
            "compliance: pattern matches only by cwe_ids which is "
            "unsupported in v1 — skipping"
        )
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
            logger.info("compliance: no mappings directory at %s", directory)
            return []
        patterns: list[dict] = []
        for path in sorted(directory.glob("*.json")):
            try:
                with path.open() as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("compliance: skipping malformed pattern %s: %s", path.name, exc)
                continue
            missing = [k for k in _REQUIRED_PATTERN_FIELDS if k not in data]
            if missing:
                logger.warning(
                    "compliance: skipping %s (missing fields: %s)",
                    path.name, ", ".join(missing),
                )
                continue
            if not data.get("match"):
                logger.warning(
                    "compliance: skipping %s (empty match block — would never match)",
                    path.name,
                )
                continue
            if not data.get("controls"):
                logger.warning(
                    "compliance: skipping %s (empty controls block — nothing to attach)",
                    path.name,
                )
                continue
            patterns.append(data)
        return patterns


def framework_filter(findings: Iterable[Finding], framework_key: str) -> list[Finding]:
    """Return only findings that have at least one control under ``framework_key``.

    ``framework_key`` is the mapping-schema key, e.g. ``nist_800_53_rev5``.
    Useful for the forthcoming ``patchpilot triage --framework`` CLI flag.
    """
    return [f for f in findings if f.compliance_controls.get(framework_key)]
