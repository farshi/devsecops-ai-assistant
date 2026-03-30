# ADR-002: Canonical Finding Schema as Shared Contract

## Context
The current codebase has no formal data model between modules. `parse_trivy.py` outputs dicts with `{id, severity, title, location, fix}`, `summarize_findings.py` adds `scanner` label, and `security_summary.py` passes raw JSON to Claude. As we add more scanners (Grype, Checkov, Semgrep) and new modules (context_builder, prioritizer), each will need to read/write finding data. Without a shared contract, every integration will be fragile.

GPT flagged this as a blocker in both review rounds.

## Options Considered
1. **Loose dicts** — keep current approach, document expected keys in comments. Simple but breaks silently.
2. **Canonical dataclass** — define a `Finding` dataclass that all modules produce/consume. Type-safe, self-documenting, enforced at module boundaries.
3. **JSON Schema + runtime validation** — schema file with jsonschema validation. More formal but heavier.

## Decision
Option 2: Canonical `Finding` dataclass.

## Rationale
- Dataclass is native Python, zero dependencies, IDE-friendly (autocomplete, type checking)
- Scanner adapters normalize INTO this schema (single responsibility)
- Enrichment layers ADD fields (reachable, epss_score, etc.) — dataclass supports defaults
- Prioritizer SCORES it, Reporter FORMATS it — each knows exactly what fields exist
- Easy to serialize to/from JSON for file output and LLM context
- The schema grows with the product: new enrichment = new optional field with a default

## Schema

```python
@dataclass
class Finding:
    id: str                    # CVE-2023-xxxxx or advisory ID
    source_scanner: str        # trivy_fs, checkov, semgrep, grype, etc.
    finding_type: str          # os_package | language_dep | iac_misconfig | secret | code_pattern
    severity: str              # critical | high | medium | low | info
    title: str                 # Human-readable description
    package: str | None        # Package name (for dep findings)
    installed_version: str | None
    fixed_version: str | None  # None = no fix available
    location: str              # File path or "requirements.txt > package@version"

    # Enrichment fields (added by context builder / prioritizer)
    reachable: str = "unknown" # true | false | unknown | not_applicable
    reachability_confidence: str = "none"  # high | medium | low | none
    direct_dep: bool | None = None
    epss_score: float | None = None
    in_kev: bool = False       # CISA Known Exploited Vulnerabilities
    fix_available: bool = False
    priority_score: int = 0    # 0-100, computed by prioritizer
    priority_tier: str = "unscored"  # critical | high | medium | low | noise | unscored
```

## Status
ACCEPTED
