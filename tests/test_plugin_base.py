"""
Tests for agent/plugins/base.py — ABC definitions for the plugin system.
"""

import pytest
from pathlib import Path

from agent.models import Finding
from agent.plugins.base import (
    ScannerAdapter,
    EnrichmentPlugin,
    PrioritizationStrategy,
    OutputFormatter,
)


# ---------------------------------------------------------------------------
# Helpers: minimal concrete implementations
# ---------------------------------------------------------------------------

class _ConcreteScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "test_scanner"

    def parse(self, raw_path: Path) -> list[Finding]:
        return []


class _ConcreteEnrichment(EnrichmentPlugin):
    @property
    def name(self) -> str:
        return "test_enrichment"

    def enrich(self, findings: list[Finding], context: dict) -> list[Finding]:
        return findings


class _ConcretePrioritization(PrioritizationStrategy):
    @property
    def name(self) -> str:
        return "test_prioritization"

    def score(self, findings: list[Finding]) -> list[Finding]:
        return findings


class _ConcreteFormatter(OutputFormatter):
    @property
    def name(self) -> str:
        return "test_formatter"

    def format(self, findings: list[Finding], context: dict) -> str:
        return ""


# ---------------------------------------------------------------------------
# Instantiation tests — ABCs must not be directly instantiable
# ---------------------------------------------------------------------------

def test_scanner_adapter_is_abstract():
    """ScannerAdapter cannot be instantiated directly."""
    with pytest.raises(TypeError):
        ScannerAdapter()  # type: ignore[abstract]


def test_enrichment_plugin_is_abstract():
    """EnrichmentPlugin cannot be instantiated directly."""
    with pytest.raises(TypeError):
        EnrichmentPlugin()  # type: ignore[abstract]


def test_prioritization_strategy_is_abstract():
    """PrioritizationStrategy cannot be instantiated directly."""
    with pytest.raises(TypeError):
        PrioritizationStrategy()  # type: ignore[abstract]


def test_output_formatter_is_abstract():
    """OutputFormatter cannot be instantiated directly."""
    with pytest.raises(TypeError):
        OutputFormatter()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Concrete implementation tests — must work without error
# ---------------------------------------------------------------------------

def test_concrete_scanner_instantiates():
    adapter = _ConcreteScanner()
    assert adapter.name == "test_scanner"
    assert adapter.parse(Path("/dev/null")) == []


def test_concrete_enrichment_instantiates():
    plugin = _ConcreteEnrichment()
    assert plugin.name == "test_enrichment"
    findings = plugin.enrich([], {})
    assert findings == []


def test_concrete_prioritization_instantiates():
    strategy = _ConcretePrioritization()
    assert strategy.name == "test_prioritization"
    assert strategy.score([]) == []


def test_concrete_formatter_instantiates():
    formatter = _ConcreteFormatter()
    assert formatter.name == "test_formatter"
    assert formatter.format([], {}) == ""


# ---------------------------------------------------------------------------
# Incomplete concrete class tests — missing abstract method raises TypeError
# ---------------------------------------------------------------------------

def test_scanner_missing_parse_raises():
    """A ScannerAdapter subclass that omits parse() raises TypeError on instantiation."""
    class _Incomplete(ScannerAdapter):
        @property
        def name(self) -> str:
            return "incomplete"
        # parse() intentionally omitted

    with pytest.raises(TypeError):
        _Incomplete()


def test_scanner_missing_name_raises():
    """A ScannerAdapter subclass that omits name raises TypeError on instantiation."""
    class _Incomplete(ScannerAdapter):
        def parse(self, raw_path: Path) -> list[Finding]:
            return []
        # name property intentionally omitted

    with pytest.raises(TypeError):
        _Incomplete()


def test_enrichment_missing_enrich_raises():
    """An EnrichmentPlugin subclass that omits enrich() raises TypeError."""
    class _Incomplete(EnrichmentPlugin):
        @property
        def name(self) -> str:
            return "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()


def test_prioritization_missing_score_raises():
    """A PrioritizationStrategy subclass that omits score() raises TypeError."""
    class _Incomplete(PrioritizationStrategy):
        @property
        def name(self) -> str:
            return "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()


def test_formatter_missing_format_raises():
    """An OutputFormatter subclass that omits format() raises TypeError."""
    class _Incomplete(OutputFormatter):
        @property
        def name(self) -> str:
            return "incomplete"

    with pytest.raises(TypeError):
        _Incomplete()
