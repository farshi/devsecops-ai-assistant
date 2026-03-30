"""
Abstract base classes for the PatchPilot plugin system.

Four plugin types define the triage pipeline:
  ScannerAdapter        — normalizes raw scanner JSON into canonical Finding instances
  EnrichmentPlugin      — adds context (EPSS, KEV, reachability, etc.) to findings
  PrioritizationStrategy — scores and ranks findings
  OutputFormatter       — formats triage results into a specific output format
"""

from abc import ABC, abstractmethod
from pathlib import Path

from agent.models import Finding


class ScannerAdapter(ABC):
    """Normalizes raw scanner output into canonical Finding instances."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier (e.g., 'trivy_fs', 'grype', 'checkov')."""
        ...

    @abstractmethod
    def parse(self, raw_path: Path) -> list[Finding]:
        """Parse raw scanner output file and return normalized Findings."""
        ...


class EnrichmentPlugin(ABC):
    """Adds context to findings (EPSS, KEV, reachability, etc.)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin identifier."""
        ...

    @abstractmethod
    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Enrich findings with additional data. Returns modified findings."""
        ...


class PrioritizationStrategy(ABC):
    """Scores and ranks findings."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy identifier."""
        ...

    @abstractmethod
    def score(self, findings: list[Finding]) -> list[Finding]:
        """Score each finding and return sorted by priority_score descending."""
        ...


class OutputFormatter(ABC):
    """Formats triage results into a specific output format."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Formatter identifier (e.g., 'markdown', 'json', 'cra')."""
        ...

    @abstractmethod
    def format(self, findings: list[Finding], context: dict) -> str:
        """Format findings into output string."""
        ...
