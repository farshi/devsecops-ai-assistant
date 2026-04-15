"""
Canonical Finding dataclass — the shared schema across all scanner adapters.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional


FINDING_TYPES = {"os_package", "language_dep", "iac_misconfig", "secret", "code_pattern"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
PRIORITY_TIERS = ("critical", "high", "medium", "low", "noise", "unscored")
REACHABLE_VALUES = ("true", "false", "unknown", "not_applicable")


@dataclass
class Finding:
    # Core fields (set by scanner adapter)
    id: str                                      # CVE-2023-xxxxx or advisory ID
    source_scanner: str                          # trivy_fs, checkov, semgrep, grype, etc.
    finding_type: str                            # os_package | language_dep | iac_misconfig | secret | code_pattern
    severity: str                                # critical | high | medium | low | info
    title: str                                   # Human-readable description
    package: Optional[str] = None               # Package name (for dep findings)
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None         # None = no fix available
    location: str = ""                           # File path or "requirements.txt > package@version"

    # Normalized severity (scanner-agnostic)
    cvss_score: Optional[float] = None          # Numeric CVSS (0.0-10.0)

    # Enrichment fields (added by context builder / enrichment plugins / prioritizer)
    reachable: str = "unknown"                   # true | false | unknown | not_applicable
    reachability_confidence: str = "none"        # high | medium | low | none
    reachability_evidence: Optional[str] = None
    direct_dep: Optional[bool] = None
    epss_score: Optional[float] = None
    in_kev: bool = False
    fix_available: bool = False
    fix_evidence: Optional[str] = None
    priority_score: int = 0
    priority_tier: str = "unscored"

    # Compliance mapping (added by compliance enrichment plugin)
    compliance_controls: dict = field(default_factory=dict)
    # e.g. {"nist_800_53_rev5": ["SC-8", "SC-13"], "pci_dss_4_0": ["4.2.1"]}
    compliance_patterns_matched: list = field(default_factory=list)
    # e.g. ["PP-0001", "PP-0004"]

    def fingerprint(self) -> str:
        """Stable identity for this finding across scans.

        Hash of: CVE ID + package name + installed version.
        Used for state tracking (dismiss, accept, baseline diff).
        """
        key = f"{self.id}:{self.package or ''}:{self.installed_version or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Serialize to dict, dropping None values for cleaner JSON."""
        return {k: v for k, v in asdict(self).items() if v is not None}
