# Decisions

Key architectural decisions. Append-only.

---

### ADR-001: Plugin Architecture
Plugin architecture with well-defined interfaces (ScannerAdapter, EnrichmentPlugin, PrioritizationStrategy, OutputFormatter). Core stays lean, community extends.

### ADR-002: Canonical Finding Schema
Single `Finding` dataclass as shared contract. Scanners normalize INTO it, enrichment ADD fields, prioritizer SCORES it, reporter FORMATS it.

### ADR-003: Reachability Honesty
Three-state reachability (true/false/unknown/not_applicable) with explicit confidence levels. "Unknown" over false confidence. Aligns with VEX standard.

### ADR-004: Finding Type Classifier
Classify findings (os_package, language_dep, iac_misconfig, secret, code_pattern). Each type gets different prioritization signals. Reachability only applies to language_dep.

### ADR-005: Triage Layer, Not Platform
PatchPilot is a thin, extensible triage layer. Not competing with Snyk/Wiz. Competing with developer time wasted manually triaging scanner output.

### ADR-007: Spec-Docs Traceability
`docs/MAP.md` links spec sections to doc sections. Changes to spec trigger doc updates.

### ADR-009: Product Direction
PatchPilot evolves from "vulnerability triage tool" to "AI security engineer in CI/CD." Defensible moat is judgment (scoring + reachability + memory), not summarization.

### ADR-010: Separate Brands (2026-04-04)
PatchPilot = open-source CLI (developer adoption). DynoTrust = commercial compliance product (separate repo, TypeScript, Cloudflare Workers + R2 + Supabase).

### ADR-011: Version-Based Planning (2026-04-04)
Plan by version (v0.5.0, v0.6.0), not by sprint. Tasks grouped by release goal, not time box.
