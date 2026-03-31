# PatchPilot Decision Log

Architectural decisions recorded as ADRs in `.tat/decisions/`. Each captures context, options considered, decision, and rationale.

## Decisions

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [001](../.tat/decisions/001-plugin-architecture.md) | Plugin Architecture | Accepted | Extensible via 4 ABCs: ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter. Users can write custom plugins. |
| [002](../.tat/decisions/002-finding-schema.md) | Canonical Finding Schema | Accepted | All modules operate on a shared `Finding` dataclass. Scanner adapters normalize INTO it, enrichment ADD to it, prioritizer SCORES it. |
| [003](../.tat/decisions/003-reachability-honesty.md) | Reachability Honesty | Accepted | Three-state reachability (true/false/unknown) with confidence levels. Says "unknown" instead of guessing wrong. |
| [004](../.tat/decisions/004-finding-type-classifier.md) | Finding Type Classifier | Accepted | Classifies findings as os_package, language_dep, iac_misconfig, secret, code_pattern. Reachability only applies to language_dep. |
| [005](../.tat/decisions/005-competitive-positioning.md) | Competitive Positioning | Accepted | Triage layer, not platform. CLI-first, scanner-agnostic, plugin architecture, honest confidence. Not competing with Snyk/Wiz/Oligo. |
| [006](../.tat/decisions/006-alignment-log.md) | Alignment Log | Accepted | Track plan vs implementation drift after each milestone. |
| [007](../.tat/decisions/007-docs-spec-mapping.md) | Spec→Docs Traceability | Accepted | MAP.md links spec sections to doc sections. Cascade: spec → docs → README. |
| [008](../.tat/decisions/008-vision-evolution.md) | Vision Evolution | Accepted | v0.1: triage tool → v0.2: guardrails → v0.3: metrics/compliance → v0.4: platform. Don't pivot mid-sprint. |

## Key Principles from Decisions

1. **Canonical schema everywhere** — Finding dataclass is the shared contract (ADR-002)
2. **Honesty over coverage** — "unknown" is better than a wrong "unreachable" (ADR-003)
3. **Triage first, platform later** — win the "fix these 3" workflow before expanding (ADR-005, 008)
4. **Extensible but not over-built** — define interfaces early, implement late (ADR-001)
5. **Track what you decide** — ADRs, alignment log, lessons, spec-docs mapping (ADR-006, 007)
