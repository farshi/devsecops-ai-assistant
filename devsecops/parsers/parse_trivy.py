"""
Thin wrapper for backward compatibility. Core logic in agent/plugins/scanners/trivy.py.
"""

from agent.models import Finding
from agent.plugins.scanners.trivy import TrivyScannerAdapter

_adapter = TrivyScannerAdapter()


def parse(raw: dict) -> list[Finding]:
    """Parse pre-loaded Trivy JSON dict. Legacy interface."""
    return _adapter.parse_dict(raw)
